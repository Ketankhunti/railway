//! API request/response models.

use serde::{Deserialize, Serialize};

// ─── Trace Models ───────────────────────────────────────────────

/// Query parameters for listing traces.
#[derive(Debug, Deserialize)]
pub struct TraceListQuery {
    pub project_id: String,
    pub service_id: Option<String>,
    pub start_time: String,  // ISO 8601
    pub end_time: String,    // ISO 8601
    pub min_duration_us: Option<u64>,
    pub status: Option<String>,    // "error" to filter errors only
    pub http_route: Option<String>,
    pub limit: Option<u32>,
}

/// Summary of a single trace (for list view).
#[derive(Debug, Serialize)]
pub struct TraceSummary {
    pub trace_id: String,
    pub root_service: String,
    pub root_path: String,
    pub root_method: String,
    pub total_duration_us: u64,
    pub span_count: u64,
    pub has_error: bool,
    pub start_time: String,
}

/// Query parameters for getting a single trace.
#[derive(Debug, Deserialize)]
pub struct TraceDetailQuery {
    pub project_id: String,
}

/// A single span within a trace (for waterfall view).
#[derive(Debug, Clone, Serialize)]
pub struct SpanDetail {
    pub trace_id: String,
    pub span_id: u64,
    pub parent_span_id: u64,
    pub service_id: String,
    pub http_method: String,
    pub http_path: String,
    pub http_route: String,
    pub http_status: u16,
    pub start_time: String,
    pub duration_us: u64,
    pub is_error: bool,
}

/// Full trace with all spans (for waterfall view).
#[derive(Debug, Serialize)]
pub struct TraceDetail {
    pub trace_id: String,
    pub spans: Vec<SpanDetail>,
    pub total_duration_us: u64,
    pub span_count: usize,
    pub has_error: bool,
}

// ─── Service Metrics Models ─────────────────────────────────────

/// Query parameters for service metrics.
#[derive(Debug, Deserialize)]
pub struct MetricsQuery {
    pub project_id: String,
    pub start_time: String,
    pub end_time: String,
    pub granularity: Option<String>, // "5m" or "1h"
}

/// A single point in a timeseries.
#[derive(Debug, Clone, Serialize)]
pub struct MetricPoint {
    pub timestamp: String,
    pub request_count: u64,
    pub error_count: u64,
    pub error_rate: f64,
    pub p50_latency_us: f64,
    pub p95_latency_us: f64,
    pub p99_latency_us: f64,
}

/// Timeseries response for a service.
#[derive(Debug, Serialize)]
pub struct ServiceMetrics {
    pub service_id: String,
    pub points: Vec<MetricPoint>,
}

// ─── Topology Models ────────────────────────────────────────────

/// Query parameters for topology.
#[derive(Debug, Deserialize)]
pub struct TopologyQuery {
    pub project_id: String,
    pub environment_id: Option<String>,
    pub start_time: String,
    pub end_time: String,
}

/// A node in the service dependency graph.
#[derive(Debug, Serialize)]
pub struct TopologyNode {
    pub service_id: String,
    pub request_count: u64,
    pub error_rate: f64,
    pub p99_latency_us: f64,
}

/// An edge in the service dependency graph.
#[derive(Debug, Clone, Serialize)]
pub struct TopologyEdge {
    pub caller: String,
    pub callee: String,
    pub call_count: u64,
    pub error_count: u64,
    pub avg_duration_us: f64,
}

/// Full topology response.
#[derive(Debug, Serialize)]
pub struct ServiceTopology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

// ─── Alert Models ───────────────────────────────────────────────

/// Request body for creating/updating an alert rule.
#[derive(Debug, Deserialize)]
pub struct CreateAlertRuleRequest {
    pub project_id: String,
    pub name: String,
    pub service_id: String,
    pub rule_type: String,        // "threshold", "anomaly", "rate_of_change"
    pub config: serde_json::Value, // Rule-specific config
    pub severity: String,          // "critical", "warning", "info"
    pub cooldown_secs: Option<u64>,
}

/// Alert rule in API responses.
#[derive(Debug, Clone, Serialize)]
pub struct AlertRuleResponse {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub service_id: String,
    pub rule_type: String,
    pub config: serde_json::Value,
    pub severity: String,
    pub enabled: bool,
    pub cooldown_secs: u64,
}

/// Query parameters for listing alert events.
#[derive(Debug, Deserialize)]
pub struct AlertEventsQuery {
    pub project_id: String,
    pub status: Option<String>,    // "firing" or "resolved"
    pub severity: Option<String>,
    pub limit: Option<u32>,
}

/// Alert event in API responses.
#[derive(Debug, Clone, Serialize)]
pub struct AlertEventResponse {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub project_id: String,
    pub service_id: String,
    pub severity: String,
    pub status: String,
    pub message: String,
    pub metric_value: f64,
    pub threshold_value: f64,
    pub fired_at: String,
    pub resolved_at: Option<String>,
}

// ─── Correlation Models ─────────────────────────────────────────

/// Query parameters for metric-to-traces correlation.
#[derive(Debug, Deserialize)]
pub struct MetricToTracesQuery {
    pub project_id: String,
    pub service_id: String,
    pub metric: String,           // "p99_latency", "error_rate"
    pub start_time: String,
    pub end_time: String,
    pub min_duration_us: Option<u64>,
}

/// Query parameters for trace-to-logs correlation.
#[derive(Debug, Deserialize)]
pub struct TraceToLogsQuery {
    pub project_id: String,
}

/// Log line correlated to a trace.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelatedLog {
    pub service_id: String,
    pub span_id: u64,
    pub timestamp: String,
    pub log_level: String,
    pub message: String,
}

// ─── Generic Response ───────────────────────────────────────────

/// Generic success response wrapper.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn new(data: T) -> Self {
        Self { data }
    }
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}
