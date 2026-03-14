//! Correlation endpoints: metric-to-traces and trace-to-logs.
//!
//! These are the "killer feature" — click a metric spike, see the traces
//! that caused it. Click a trace, see the logs from all involved services.

use std::sync::Arc;
use axum::extract::{Path, Query, State};
use axum::Json;

use crate::app::SharedState;
use crate::error::ApiError;
use crate::models::{
    ApiResponse, CorrelatedLog, MetricToTracesQuery, TraceToLogsQuery, TraceSummary,
};

/// GET /api/v1/correlate/metric-to-traces?project_id=...&service_id=...&start_time=...&end_time=...
///
/// Find traces that contributed to a metric spike.
/// In the prototype, this filters the in-memory trace store by service, time window,
/// and optionally by minimum duration (for latency spikes) or error status.
pub async fn metric_to_traces(
    State(state): State<SharedState>,
    Query(query): Query<MetricToTracesQuery>,
) -> Result<Json<ApiResponse<Vec<TraceSummary>>>, ApiError> {
    let store = state.trace_store.read().await;

    let is_error_metric = query.metric == "error_rate";

    let mut summaries: Vec<TraceSummary> = store
        .traces
        .iter()
        .filter_map(|(trace_id, spans)| {
            if spans.is_empty() {
                return None;
            }

            // Filter: at least one span belongs to the target service
            if !spans.iter().any(|s| s.service_id == query.service_id) {
                return None;
            }

            // For error_rate metric: only include traces with errors
            if is_error_metric && !spans.iter().any(|s| s.is_error) {
                return None;
            }

            // For latency metrics: filter by min_duration
            let total_duration = spans.iter().map(|s| s.duration_us).max().unwrap_or(0);
            if let Some(min_dur) = query.min_duration_us {
                if total_duration < min_dur {
                    return None;
                }
            }

            let root = spans
                .iter()
                .find(|s| s.parent_span_id == 0)
                .unwrap_or(&spans[0]);

            Some(TraceSummary {
                trace_id: trace_id.clone(),
                root_service: root.service_id.clone(),
                root_path: root.http_path.clone(),
                root_method: root.http_method.clone(),
                total_duration_us: total_duration,
                span_count: spans.len() as u64,
                has_error: spans.iter().any(|s| s.is_error),
                start_time: root.start_time.clone(),
            })
        })
        .collect();

    // Sort by duration descending (slowest/worst first for spike investigation)
    summaries.sort_by(|a, b| b.total_duration_us.cmp(&a.total_duration_us));
    summaries.truncate(50);

    Ok(Json(ApiResponse::new(summaries)))
}

/// GET /api/v1/correlate/trace-to-logs/{trace_id}?project_id=...
///
/// Get log lines correlated with a specific trace.
/// In the prototype, we return mock logs based on spans in the trace.
/// In production, this queries the trace_logs ClickHouse table or
/// Railway's existing log store using time + service window matching.
pub async fn trace_to_logs(
    State(state): State<SharedState>,
    Path(trace_id): Path<String>,
    Query(_query): Query<TraceToLogsQuery>,
) -> Result<Json<ApiResponse<Vec<CorrelatedLog>>>, ApiError> {
    let store = state.trace_store.read().await;

    let spans = store
        .traces
        .get(&trace_id)
        .ok_or_else(|| ApiError::NotFound(format!("trace {} not found", trace_id)))?;

    // In the prototype, generate synthetic log entries from span data.
    // In production, this would query the trace_logs ClickHouse table
    // or time-window match against Railway's log store.
    let mut logs: Vec<CorrelatedLog> = spans
        .iter()
        .map(|span| {
            let level = if span.is_error { "ERROR" } else { "INFO" };
            let message = format!(
                "{} {} → {} ({}µs)",
                span.http_method, span.http_path, span.http_status, span.duration_us
            );

            CorrelatedLog {
                service_id: span.service_id.clone(),
                span_id: span.span_id,
                timestamp: span.start_time.clone(),
                log_level: level.to_string(),
                message,
            }
        })
        .collect();

    // Sort by timestamp
    logs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    Ok(Json(ApiResponse::new(logs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::models::SpanDetail;

    fn insert_test_trace(state: &AppState) {
        let mut store = state.trace_store.try_write().unwrap();
        store.insert_span(SpanDetail {
            trace_id: "abc123".into(),
            span_id: 1,
            parent_span_id: 0,
            service_id: "svc_api".into(),
            http_method: "GET".into(),
            http_path: "/api/users".into(),
            http_route: "/api/users".into(),
            http_status: 200,
            start_time: "2026-03-14T12:00:00Z".into(),
            duration_us: 500_000,
            is_error: false,
        });
        store.insert_span(SpanDetail {
            trace_id: "abc123".into(),
            span_id: 2,
            parent_span_id: 1,
            service_id: "svc_users".into(),
            http_method: "GET".into(),
            http_path: "/internal/users/42".into(),
            http_route: "/internal/users/:id".into(),
            http_status: 200,
            start_time: "2026-03-14T12:00:00.100Z".into(),
            duration_us: 200_000,
            is_error: false,
        });
        // An error trace
        store.insert_span(SpanDetail {
            trace_id: "err456".into(),
            span_id: 10,
            parent_span_id: 0,
            service_id: "svc_api".into(),
            http_method: "POST".into(),
            http_path: "/api/payments".into(),
            http_route: "/api/payments".into(),
            http_status: 500,
            start_time: "2026-03-14T12:01:00Z".into(),
            duration_us: 800_000,
            is_error: true,
        });
    }

    #[tokio::test]
    async fn metric_to_traces_latency() {
        let state = Arc::new(AppState::new());
        insert_test_trace(&state);

        let query = MetricToTracesQuery {
            project_id: "proj".into(),
            service_id: "svc_api".into(),
            metric: "p99_latency".into(),
            start_time: "2026-03-14T12:00:00Z".into(),
            end_time: "2026-03-14T13:00:00Z".into(),
            min_duration_us: Some(400_000), // > 400ms
        };

        let result = metric_to_traces(State(state), Query(query)).await.unwrap();
        let traces = &result.0.data;

        // Both abc123 (500ms) and err456 (800ms) exceed 400ms threshold
        assert_eq!(traces.len(), 2);
        // Sorted by duration descending → err456 (800ms) first
        assert_eq!(traces[0].trace_id, "err456");
        assert_eq!(traces[1].trace_id, "abc123");
    }

    #[tokio::test]
    async fn metric_to_traces_errors() {
        let state = Arc::new(AppState::new());
        insert_test_trace(&state);

        let query = MetricToTracesQuery {
            project_id: "proj".into(),
            service_id: "svc_api".into(),
            metric: "error_rate".into(),
            start_time: "2026-03-14T12:00:00Z".into(),
            end_time: "2026-03-14T13:00:00Z".into(),
            min_duration_us: None,
        };

        let result = metric_to_traces(State(state), Query(query)).await.unwrap();
        let traces = &result.0.data;

        // Only err456 has errors
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].trace_id, "err456");
        assert!(traces[0].has_error);
    }

    #[tokio::test]
    async fn metric_to_traces_wrong_service() {
        let state = Arc::new(AppState::new());
        insert_test_trace(&state);

        let query = MetricToTracesQuery {
            project_id: "proj".into(),
            service_id: "svc_nonexistent".into(),
            metric: "p99_latency".into(),
            start_time: "2026-03-14T12:00:00Z".into(),
            end_time: "2026-03-14T13:00:00Z".into(),
            min_duration_us: None,
        };

        let result = metric_to_traces(State(state), Query(query)).await.unwrap();
        assert!(result.0.data.is_empty());
    }

    #[tokio::test]
    async fn trace_to_logs_found() {
        let state = Arc::new(AppState::new());
        insert_test_trace(&state);

        let query = TraceToLogsQuery {
            project_id: "proj".into(),
        };

        let result = trace_to_logs(State(state), Path("abc123".into()), Query(query))
            .await
            .unwrap();
        let logs = &result.0.data;

        assert_eq!(logs.len(), 2); // 2 spans in trace abc123
        // Sorted by timestamp lexicographically:
        // "2026-03-14T12:00:00.100Z" < "2026-03-14T12:00:00Z" (`.` < `Z` in ASCII)
        assert_eq!(logs[0].service_id, "svc_users");
        assert_eq!(logs[1].service_id, "svc_api");
        assert_eq!(logs[0].log_level, "INFO");
        assert!(logs[1].message.contains("GET"));
        assert!(logs[1].message.contains("/api/users"));
    }

    #[tokio::test]
    async fn trace_to_logs_not_found() {
        let state = Arc::new(AppState::new());

        let query = TraceToLogsQuery {
            project_id: "proj".into(),
        };

        let result = trace_to_logs(State(state), Path("nonexistent".into()), Query(query)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn trace_to_logs_error_span() {
        let state = Arc::new(AppState::new());
        insert_test_trace(&state);

        let query = TraceToLogsQuery {
            project_id: "proj".into(),
        };

        let result = trace_to_logs(State(state), Path("err456".into()), Query(query))
            .await
            .unwrap();
        let logs = &result.0.data;

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].log_level, "ERROR");
        assert!(logs[0].message.contains("500"));
    }
}
