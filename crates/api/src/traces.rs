//! Trace query endpoints.

use std::sync::Arc;
use axum::extract::{Path, Query, State};
use axum::Json;

use crate::app::SharedState;
use crate::error::ApiError;
use crate::models::{
    ApiResponse, SpanDetail, TraceDetail, TraceDetailQuery, TraceListQuery, TraceSummary,
};

/// GET /api/v1/traces?project_id=...&start_time=...&end_time=...
///
/// List traces matching the query criteria. Returns trace summaries
/// (not full span trees) for the list view.
pub async fn list_traces(
    State(state): State<SharedState>,
    Query(query): Query<TraceListQuery>,
) -> Result<Json<ApiResponse<Vec<TraceSummary>>>, ApiError> {
    let store = state.trace_store.read().await;

    let limit = query.limit.unwrap_or(50) as usize;

    let mut summaries: Vec<TraceSummary> = store
        .traces
        .iter()
        .filter_map(|(trace_id, spans)| {
            if spans.is_empty() {
                return None;
            }

            // Filter by service_id if provided
            if let Some(ref sid) = query.service_id {
                if !spans.iter().any(|s| s.service_id == *sid) {
                    return None;
                }
            }

            // Filter by http_route if provided
            if let Some(ref route) = query.http_route {
                if !spans.iter().any(|s| s.http_route == *route) {
                    return None;
                }
            }

            // Filter errors only
            if query.status.as_deref() == Some("error") {
                if !spans.iter().any(|s| s.is_error) {
                    return None;
                }
            }

            // Find root span (parent_span_id == 0) or first span
            let root = spans
                .iter()
                .find(|s| s.parent_span_id == 0)
                .unwrap_or(&spans[0]);

            let total_duration = spans.iter().map(|s| s.duration_us).max().unwrap_or(0);
            let has_error = spans.iter().any(|s| s.is_error);

            // Filter by min_duration
            if let Some(min_dur) = query.min_duration_us {
                if total_duration < min_dur {
                    return None;
                }
            }

            Some(TraceSummary {
                trace_id: trace_id.clone(),
                root_service: root.service_id.clone(),
                root_path: root.http_path.clone(),
                root_method: root.http_method.clone(),
                total_duration_us: total_duration,
                span_count: spans.len() as u64,
                has_error,
                start_time: root.start_time.clone(),
            })
        })
        .collect();

    // Sort by start_time descending (newest first)
    summaries.sort_by(|a, b| b.start_time.cmp(&a.start_time));
    summaries.truncate(limit);

    Ok(Json(ApiResponse::new(summaries)))
}

/// GET /api/v1/traces/{trace_id}?project_id=...
///
/// Get full trace detail with all spans for waterfall rendering.
pub async fn get_trace(
    State(state): State<SharedState>,
    Path(trace_id): Path<String>,
    Query(_query): Query<TraceDetailQuery>,
) -> Result<Json<ApiResponse<TraceDetail>>, ApiError> {
    let store = state.trace_store.read().await;

    let spans = store
        .traces
        .get(&trace_id)
        .ok_or_else(|| ApiError::NotFound(format!("trace {} not found", trace_id)))?;

    let total_duration = spans.iter().map(|s| s.duration_us).max().unwrap_or(0);
    let has_error = spans.iter().any(|s| s.is_error);

    let detail = TraceDetail {
        trace_id: trace_id.clone(),
        spans: spans.clone(),
        total_duration_us: total_duration,
        span_count: spans.len(),
        has_error,
    };

    Ok(Json(ApiResponse::new(detail)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;

    #[tokio::test]
    async fn list_traces_empty() {
        let state = Arc::new(AppState::new());
        let query = TraceListQuery {
            project_id: "proj".into(),
            service_id: None,
            start_time: "2026-01-01T00:00:00Z".into(),
            end_time: "2026-12-31T23:59:59Z".into(),
            min_duration_us: None,
            status: None,
            http_route: None,
            limit: None,
        };

        let result = list_traces(State(state), Query(query)).await.unwrap();
        assert!(result.0.data.is_empty());
    }

    #[tokio::test]
    async fn list_and_get_trace() {
        let state = Arc::new(AppState::new());

        // Insert spans
        {
            let mut store = state.trace_store.write().await;
            store.insert_span(SpanDetail {
                trace_id: "trace_abc".into(),
                span_id: 1,
                parent_span_id: 0,
                service_id: "svc_api".into(),
                http_method: "GET".into(),
                http_path: "/api/users".into(),
                http_route: "/api/users".into(),
                http_status: 200,
                start_time: "2026-03-14T12:00:00Z".into(),
                duration_us: 1000,
                is_error: false,
            });
            store.insert_span(SpanDetail {
                trace_id: "trace_abc".into(),
                span_id: 2,
                parent_span_id: 1,
                service_id: "svc_users".into(),
                http_method: "GET".into(),
                http_path: "/users/42".into(),
                http_route: "/users/:id".into(),
                http_status: 200,
                start_time: "2026-03-14T12:00:00.001Z".into(),
                duration_us: 500,
                is_error: false,
            });
        }

        // List
        let query = TraceListQuery {
            project_id: "proj".into(),
            service_id: None,
            start_time: "2026-01-01T00:00:00Z".into(),
            end_time: "2026-12-31T23:59:59Z".into(),
            min_duration_us: None,
            status: None,
            http_route: None,
            limit: None,
        };
        let result = list_traces(State(state.clone()), Query(query)).await.unwrap();
        assert_eq!(result.0.data.len(), 1);
        assert_eq!(result.0.data[0].trace_id, "trace_abc");
        assert_eq!(result.0.data[0].span_count, 2);
        assert_eq!(result.0.data[0].total_duration_us, 1000);
        assert!(!result.0.data[0].has_error);

        // Get detail
        let detail_query = TraceDetailQuery {
            project_id: "proj".into(),
        };
        let result = get_trace(
            State(state.clone()),
            Path("trace_abc".into()),
            Query(detail_query),
        )
        .await
        .unwrap();
        assert_eq!(result.0.data.span_count, 2);
        assert_eq!(result.0.data.spans[0].service_id, "svc_api");
    }

    #[tokio::test]
    async fn get_trace_not_found() {
        let state = Arc::new(AppState::new());
        let query = TraceDetailQuery {
            project_id: "proj".into(),
        };
        let result = get_trace(State(state), Path("nonexistent".into()), Query(query)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_traces_filter_errors() {
        let state = Arc::new(AppState::new());
        {
            let mut store = state.trace_store.write().await;
            store.insert_span(SpanDetail {
                trace_id: "trace_ok".into(),
                span_id: 1,
                parent_span_id: 0,
                service_id: "svc".into(),
                http_method: "GET".into(),
                http_path: "/ok".into(),
                http_route: "/ok".into(),
                http_status: 200,
                start_time: "2026-03-14T12:00:00Z".into(),
                duration_us: 100,
                is_error: false,
            });
            store.insert_span(SpanDetail {
                trace_id: "trace_err".into(),
                span_id: 2,
                parent_span_id: 0,
                service_id: "svc".into(),
                http_method: "POST".into(),
                http_path: "/fail".into(),
                http_route: "/fail".into(),
                http_status: 500,
                start_time: "2026-03-14T12:01:00Z".into(),
                duration_us: 200,
                is_error: true,
            });
        }

        let query = TraceListQuery {
            project_id: "proj".into(),
            service_id: None,
            start_time: "2026-01-01T00:00:00Z".into(),
            end_time: "2026-12-31T23:59:59Z".into(),
            min_duration_us: None,
            status: Some("error".into()),
            http_route: None,
            limit: None,
        };
        let result = list_traces(State(state), Query(query)).await.unwrap();
        assert_eq!(result.0.data.len(), 1);
        assert_eq!(result.0.data[0].trace_id, "trace_err");
    }
}
