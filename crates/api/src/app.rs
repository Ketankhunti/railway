//! Axum application setup: router, shared state, CORS.
//!
//! ## Tenant Isolation (SECURITY)
//!
//! Every API endpoint requires `project_id` as a query/path parameter.
//! In the prototype, this is trusted from the client (no auth).
//!
//! **In production**, this MUST be replaced with:
//! 1. An auth middleware that validates a JWT/API key from the `Authorization` header
//! 2. The middleware extracts allowed project IDs from the token claims
//! 3. Handlers receive the validated project_id from the middleware, NOT from query params
//! 4. Every ClickHouse/PostgreSQL query includes `WHERE project_id = $validated_id`
//!
//! This is the #1 security boundary in the system. Without it, any user
//! can read any other user's traces, metrics, and alerts.

use std::sync::Arc;
use tokio::sync::RwLock;
use axum::{Router, routing::get, routing::post, routing::put, routing::delete};
use tower_http::cors::{CorsLayer, Any};

use crate::{traces, services, alerts, correlate};

/// Shared application state, accessible from all handlers via Axum's State extractor.
///
/// In the prototype, this holds in-memory stores.
/// In production, these would be ClickHouse/PostgreSQL connection pools.
pub struct AppState {
    /// In-memory trace store (spans indexed by trace_id).
    pub trace_store: RwLock<TraceStore>,
    /// In-memory alert rule store.
    pub alert_store: RwLock<AlertStore>,
    /// In-memory alert event store.
    pub alert_event_store: RwLock<AlertEventStore>,
    /// In-memory service metrics (from alerting engine windows).
    pub metrics_store: RwLock<MetricsStore>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            trace_store: RwLock::new(TraceStore::new()),
            alert_store: RwLock::new(AlertStore::new()),
            alert_event_store: RwLock::new(AlertEventStore::new()),
            metrics_store: RwLock::new(MetricsStore::new()),
        }
    }
}

/// In-memory span storage, indexed by trace_id.
pub struct TraceStore {
    /// All spans, grouped by trace_id.
    pub traces: std::collections::HashMap<String, Vec<crate::models::SpanDetail>>,
}

impl TraceStore {
    pub fn new() -> Self {
        Self {
            traces: std::collections::HashMap::new(),
        }
    }

    /// Ingest a span into the store.
    pub fn insert_span(&mut self, span: crate::models::SpanDetail) {
        self.traces
            .entry(span.trace_id.clone())
            .or_default()
            .push(span);
    }
}

/// In-memory alert rule storage.
pub struct AlertStore {
    pub rules: Vec<crate::models::AlertRuleResponse>,
    next_id: u64,
}

impl AlertStore {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            next_id: 1,
        }
    }

    pub fn add(&mut self, rule: crate::models::AlertRuleResponse) -> String {
        let id = format!("rule_{}", self.next_id);
        self.next_id += 1;
        self.rules.push(crate::models::AlertRuleResponse {
            id: id.clone(),
            ..rule
        });
        id
    }

    pub fn get(&self, id: &str) -> Option<&crate::models::AlertRuleResponse> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn list(&self, project_id: &str) -> Vec<&crate::models::AlertRuleResponse> {
        self.rules.iter().filter(|r| r.project_id == project_id).collect()
    }

    pub fn delete(&mut self, id: &str) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < len_before
    }

    pub fn update(&mut self, id: &str, updated: crate::models::AlertRuleResponse) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            *rule = crate::models::AlertRuleResponse {
                id: id.to_string(),
                ..updated
            };
            true
        } else {
            false
        }
    }
}

/// In-memory alert event storage.
pub struct AlertEventStore {
    pub events: Vec<crate::models::AlertEventResponse>,
}

impl AlertEventStore {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn add(&mut self, event: crate::models::AlertEventResponse) {
        self.events.push(event);
    }

    pub fn list(
        &self,
        project_id: &str,
        status: Option<&str>,
        severity: Option<&str>,
        limit: usize,
    ) -> Vec<&crate::models::AlertEventResponse> {
        self.events
            .iter()
            .filter(|e| e.project_id == project_id)
            .filter(|e| status.map_or(true, |s| e.status == s))
            .filter(|e| severity.map_or(true, |s| e.severity == s))
            .take(limit)
            .collect()
    }
}

/// In-memory service dependency and metrics data.
pub struct MetricsStore {
    pub topology_edges: Vec<crate::models::TopologyEdge>,
    pub service_metrics: std::collections::HashMap<String, Vec<crate::models::MetricPoint>>,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self {
            topology_edges: Vec::new(),
            service_metrics: std::collections::HashMap::new(),
        }
    }
}

pub type SharedState = Arc<AppState>;

/// Create the Axum router with all endpoints.
pub fn create_router(state: SharedState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health
        .route("/health", get(health))
        // Traces
        .route("/api/v1/traces", get(traces::list_traces))
        .route("/api/v1/traces/{trace_id}", get(traces::get_trace))
        // Service metrics
        .route("/api/v1/services/{service_id}/metrics", get(services::get_metrics))
        // Topology
        .route("/api/v1/services/topology", get(services::get_topology))
        // Alerts
        .route("/api/v1/alerts/rules", get(alerts::list_rules).post(alerts::create_rule))
        .route(
            "/api/v1/alerts/rules/{rule_id}",
            put(alerts::update_rule).delete(alerts::delete_rule),
        )
        .route("/api/v1/alerts/events", get(alerts::list_events))
        // Correlation
        .route("/api/v1/correlate/metric-to-traces", get(correlate::metric_to_traces))
        .route("/api/v1/correlate/trace-to-logs/{trace_id}", get(correlate::trace_to_logs))
        .layer(cors)
        .with_state(state)
}

async fn health() -> axum::Json<crate::models::HealthResponse> {
    axum::Json(crate::models::HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_state_creation() {
        let state = AppState::new();
        // Verify stores are initialized empty
        let ts = state.trace_store.try_read().unwrap();
        assert!(ts.traces.is_empty());
    }

    #[test]
    fn alert_store_crud() {
        let mut store = AlertStore::new();

        let rule = crate::models::AlertRuleResponse {
            id: String::new(), // will be overwritten
            project_id: "proj_1".into(),
            name: "Test Rule".into(),
            service_id: "svc_api".into(),
            rule_type: "threshold".into(),
            config: serde_json::json!({}),
            severity: "critical".into(),
            enabled: true,
            cooldown_secs: 300,
        };

        let id = store.add(rule);
        assert!(id.starts_with("rule_"));
        assert_eq!(store.rules.len(), 1);

        // Get
        let found = store.get(&id).unwrap();
        assert_eq!(found.name, "Test Rule");

        // List by project
        assert_eq!(store.list("proj_1").len(), 1);
        assert_eq!(store.list("proj_other").len(), 0);

        // Delete
        assert!(store.delete(&id));
        assert_eq!(store.rules.len(), 0);
        assert!(!store.delete(&id)); // already deleted
    }

    #[test]
    fn alert_event_store_filtering() {
        let mut store = AlertEventStore::new();

        store.add(crate::models::AlertEventResponse {
            id: "e1".into(),
            rule_id: "r1".into(),
            rule_name: "Rule 1".into(),
            project_id: "proj_1".into(),
            service_id: "svc".into(),
            severity: "critical".into(),
            status: "firing".into(),
            message: "high error rate".into(),
            metric_value: 0.15,
            threshold_value: 0.05,
            fired_at: "2026-03-14T12:00:00Z".into(),
            resolved_at: None,
        });
        store.add(crate::models::AlertEventResponse {
            id: "e2".into(),
            rule_id: "r1".into(),
            rule_name: "Rule 1".into(),
            project_id: "proj_1".into(),
            service_id: "svc".into(),
            severity: "warning".into(),
            status: "resolved".into(),
            message: "latency spike".into(),
            metric_value: 0.0,
            threshold_value: 0.0,
            fired_at: "2026-03-14T11:00:00Z".into(),
            resolved_at: Some("2026-03-14T11:30:00Z".into()),
        });

        // All for project
        assert_eq!(store.list("proj_1", None, None, 100).len(), 2);
        // Filter by status
        assert_eq!(store.list("proj_1", Some("firing"), None, 100).len(), 1);
        // Filter by severity
        assert_eq!(store.list("proj_1", None, Some("critical"), 100).len(), 1);
        // Wrong project
        assert_eq!(store.list("proj_other", None, None, 100).len(), 0);
        // Limit
        assert_eq!(store.list("proj_1", None, None, 1).len(), 1);
    }

    #[test]
    fn trace_store_insert_and_group() {
        let mut store = TraceStore::new();

        store.insert_span(crate::models::SpanDetail {
            trace_id: "trace_aaa".into(),
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
        store.insert_span(crate::models::SpanDetail {
            trace_id: "trace_aaa".into(),
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

        assert_eq!(store.traces.len(), 1);
        assert_eq!(store.traces["trace_aaa"].len(), 2);
    }
}
