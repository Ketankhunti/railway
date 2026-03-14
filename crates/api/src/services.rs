//! Service metrics and topology endpoints.

use std::sync::Arc;
use axum::extract::{Path, Query, State};
use axum::Json;

use crate::app::SharedState;
use crate::error::ApiError;
use crate::models::{
    ApiResponse, MetricPoint, MetricsQuery, ServiceMetrics, ServiceTopology, TopologyNode,
    TopologyQuery,
};

/// GET /api/v1/services/{service_id}/metrics?project_id=...&start_time=...&end_time=...
///
/// Get timeseries metrics for a service (from rollup data).
pub async fn get_metrics(
    State(state): State<SharedState>,
    Path(service_id): Path<String>,
    Query(_query): Query<MetricsQuery>,
) -> Result<Json<ApiResponse<ServiceMetrics>>, ApiError> {
    let store = state.metrics_store.read().await;

    let points = store
        .service_metrics
        .get(&service_id)
        .cloned()
        .unwrap_or_default();

    Ok(Json(ApiResponse::new(ServiceMetrics {
        service_id,
        points,
    })))
}

/// GET /api/v1/services/topology?project_id=...&start_time=...&end_time=...
///
/// Get the service dependency graph (auto-discovered from trace data).
pub async fn get_topology(
    State(state): State<SharedState>,
    Query(_query): Query<TopologyQuery>,
) -> Result<Json<ApiResponse<ServiceTopology>>, ApiError> {
    let store = state.metrics_store.read().await;

    // Build nodes from edges (unique services)
    let mut node_map = std::collections::HashMap::new();
    for edge in &store.topology_edges {
        node_map
            .entry(edge.caller.clone())
            .or_insert_with(|| TopologyNode {
                service_id: edge.caller.clone(),
                request_count: 0,
                error_rate: 0.0,
                p99_latency_us: 0.0,
            })
            .request_count += edge.call_count;

        node_map
            .entry(edge.callee.clone())
            .or_insert_with(|| TopologyNode {
                service_id: edge.callee.clone(),
                request_count: 0,
                error_rate: 0.0,
                p99_latency_us: 0.0,
            });
    }

    Ok(Json(ApiResponse::new(ServiceTopology {
        nodes: node_map.into_values().collect(),
        edges: store.topology_edges.clone(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::models::TopologyEdge;

    #[tokio::test]
    async fn get_metrics_empty() {
        let state = Arc::new(AppState::new());
        let query = MetricsQuery {
            project_id: "proj".into(),
            start_time: "2026-01-01T00:00:00Z".into(),
            end_time: "2026-12-31T23:59:59Z".into(),
            granularity: None,
        };
        let result = get_metrics(State(state), Path("svc_api".into()), Query(query))
            .await
            .unwrap();
        assert!(result.0.data.points.is_empty());
        assert_eq!(result.0.data.service_id, "svc_api");
    }

    #[tokio::test]
    async fn get_metrics_with_data() {
        let state = Arc::new(AppState::new());
        {
            let mut store = state.metrics_store.write().await;
            store.service_metrics.insert(
                "svc_api".into(),
                vec![
                    MetricPoint {
                        timestamp: "2026-03-14T12:00:00Z".into(),
                        request_count: 100,
                        error_count: 5,
                        error_rate: 0.05,
                        p50_latency_us: 10_000.0,
                        p95_latency_us: 45_000.0,
                        p99_latency_us: 89_000.0,
                    },
                    MetricPoint {
                        timestamp: "2026-03-14T12:05:00Z".into(),
                        request_count: 120,
                        error_count: 2,
                        error_rate: 0.017,
                        p50_latency_us: 12_000.0,
                        p95_latency_us: 50_000.0,
                        p99_latency_us: 95_000.0,
                    },
                ],
            );
        }

        let query = MetricsQuery {
            project_id: "proj".into(),
            start_time: "2026-03-14T12:00:00Z".into(),
            end_time: "2026-03-14T13:00:00Z".into(),
            granularity: Some("5m".into()),
        };
        let result = get_metrics(State(state), Path("svc_api".into()), Query(query))
            .await
            .unwrap();
        assert_eq!(result.0.data.points.len(), 2);
        assert_eq!(result.0.data.points[0].request_count, 100);
    }

    #[tokio::test]
    async fn topology_empty() {
        let state = Arc::new(AppState::new());
        let query = TopologyQuery {
            project_id: "proj".into(),
            environment_id: None,
            start_time: "2026-01-01T00:00:00Z".into(),
            end_time: "2026-12-31T23:59:59Z".into(),
        };
        let result = get_topology(State(state), Query(query)).await.unwrap();
        assert!(result.0.data.nodes.is_empty());
        assert!(result.0.data.edges.is_empty());
    }

    #[tokio::test]
    async fn topology_with_edges() {
        let state = Arc::new(AppState::new());
        {
            let mut store = state.metrics_store.write().await;
            store.topology_edges = vec![
                TopologyEdge {
                    caller: "svc_api".into(),
                    callee: "svc_users".into(),
                    call_count: 500,
                    error_count: 10,
                    avg_duration_us: 25_000.0,
                },
                TopologyEdge {
                    caller: "svc_api".into(),
                    callee: "svc_payments".into(),
                    call_count: 200,
                    error_count: 5,
                    avg_duration_us: 80_000.0,
                },
            ];
        }

        let query = TopologyQuery {
            project_id: "proj".into(),
            environment_id: None,
            start_time: "2026-01-01T00:00:00Z".into(),
            end_time: "2026-12-31T23:59:59Z".into(),
        };
        let result = get_topology(State(state), Query(query)).await.unwrap();
        assert_eq!(result.0.data.edges.len(), 2);
        // 3 unique services: api, users, payments
        assert_eq!(result.0.data.nodes.len(), 3);
    }
}
