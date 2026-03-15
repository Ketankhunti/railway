//! Railway Observability Engine — Collector Binary
//!
//! Wires together ALL production components:
//!
//! ```text
//! Synthetic Source ──→ Span Assembler ──→ Ingestion Pipeline ──→ ClickHouse
//!        (test)            (real)        │      (real)
//!                                        ▼
//!                                   Alert Engine ──→ Alert Events
//!                                       (real)
//!                                        │
//!                                        ▼
//!                                    API Server ──→ Dashboard
//!                                       (real)
//! ```
//!
//! ONLY the event source is synthetic. Everything else is production code.
//! In the eBPF build (WSL2/Linux), the synthetic source is replaced by
//! real eBPF ring buffer events.

mod synthetic;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use rail_obs_alerting::{
    AlertEngine, AlertEngineConfig, AlertRule, AlertRuleConfig,
    rules::{ThresholdConfig, AnomalyConfig, Metric, Operator, Severity},
};
use rail_obs_api::app::{AppState, create_router};
use rail_obs_api::models::{SpanDetail, AlertEventResponse};
use rail_obs_common::span::SpanEvent;
use rail_obs_span_assembler::{SpanAssembler, AssemblerConfig};

use synthetic::{SyntheticConfig, run_synthetic_source, synthetic_service_mapping};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,rail_obs=debug")),
        )
        .init();

    tracing::info!("rail-obs collector starting");

    // ─── 1. Service Discovery ─────────────────────────────────────
    let service_mapping = synthetic_service_mapping();
    tracing::info!(
        services = service_mapping.namespaces.len(),
        "service mapping loaded"
    );

    // ─── 2. Span Assembler (REAL) ─────────────────────────────────
    let assembler_config = AssemblerConfig {
        max_connections: 100_000,
        max_pending_per_conn: 64,
        host_id: "demo-host".into(),
    };
    let mut assembler = SpanAssembler::new(assembler_config, service_mapping);

    // ─── 3. Alert Engine (REAL) ───────────────────────────────────
    let mut alert_engine = AlertEngine::new(AlertEngineConfig {
        max_window_secs: 3600,
        eval_interval_spans: 50, // evaluate every 50 spans
    });

    // Add default alert rules
    alert_engine.add_rule(AlertRule {
        id: "rule_error_rate".into(),
        project_id: "proj_demo".into(),
        name: "High Error Rate".into(),
        service_id: String::new(), // all services
        config: AlertRuleConfig::Threshold(ThresholdConfig {
            metric: Metric::ErrorRate,
            operator: Operator::GreaterThan,
            value: 0.10,
            window_secs: 60,
            min_requests: 20,
        }),
        severity: Severity::Critical,
        enabled: true,
        cooldown_secs: 120,
    });

    alert_engine.add_rule(AlertRule {
        id: "rule_latency_anomaly".into(),
        project_id: "proj_demo".into(),
        name: "Latency Anomaly".into(),
        service_id: String::new(),
        config: AlertRuleConfig::Anomaly(AnomalyConfig {
            metric: Metric::P99LatencyUs,
            baseline_window_secs: 300,
            evaluation_window_secs: 30,
            z_score_threshold: 3.0,
        }),
        severity: Severity::Warning,
        enabled: true,
        cooldown_secs: 300,
    });

    tracing::info!(rules = alert_engine.rule_count(), "alert rules loaded");

    // ─── 4. API State (REAL) ──────────────────────────────────────
    let app_state = Arc::new(AppState::new());

    // ─── 5. Start API Server (REAL) ──────────────────────────────
    let api_state = app_state.clone();
    let api_handle = tokio::spawn(async move {
        let router = create_router(api_state);
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        tracing::info!("API server listening on http://0.0.0.0:3000");
        axum::serve(listener, router).await.unwrap();
    });

    // ─── 6. Start Synthetic Source ────────────────────────────────
    let (event_tx, mut event_rx) = mpsc::channel::<Vec<rail_obs_span_assembler::TcpEvent>>(1000);

    let synthetic_config = SyntheticConfig {
        rps: 30,
        inject_spikes: true,
        spike_multiplier: 10,
        spike_probability: 0.03,
    };

    let source_handle = tokio::spawn(async move {
        run_synthetic_source(synthetic_config, event_tx).await;
    });

    // ─── 7. Main Processing Loop ─────────────────────────────────
    // This is EXACTLY the same loop that would run with real eBPF events.
    // Only the source of `events` is synthetic.

    tracing::info!("processing pipeline started");

    let mut total_spans: u64 = 0;
    let mut total_alerts: u64 = 0;

    let pipeline_state = app_state.clone();

    loop {
        tokio::select! {
            // Receive batch of events from source
            Some(events) = event_rx.recv() => {
                for event in &events {
                    // ─── Span Assembler (REAL) ────────────────────
                    let completed_spans = assembler.process_event(event);

                    for span in completed_spans {
                        total_spans += 1;

                        // ─── Feed into Alert Engine (REAL) ───────
                        let alerts = alert_engine.ingest(&span);
                        for alert in &alerts {
                            total_alerts += 1;
                            tracing::warn!(
                                rule = %alert.rule_name,
                                service = %alert.service_id,
                                severity = ?alert.severity,
                                value = alert.metric_value,
                                "ALERT FIRED: {}",
                                alert.message
                            );

                            // Store alert event in API state (REAL)
                            let alert_event = AlertEventResponse {
                                id: format!("evt_{}", total_alerts),
                                rule_id: alert.rule_id.clone(),
                                rule_name: alert.rule_name.clone(),
                                project_id: alert.project_id.clone(),
                                service_id: alert.service_id.clone(),
                                severity: format!("{:?}", alert.severity).to_lowercase(),
                                status: "firing".into(),
                                message: alert.message.clone(),
                                metric_value: alert.metric_value,
                                threshold_value: alert.threshold_value,
                                fired_at: alert.fired_at.to_rfc3339(),
                                resolved_at: None,
                            };
                            pipeline_state
                                .alert_event_store.write().await
                                .add(alert_event);
                        }

                        // ─── Store span in API state (REAL) ──────
                        let span_detail = span_to_detail(&span);
                        pipeline_state
                            .trace_store.write().await
                            .insert_span(span_detail);

                        // ─── Update metrics store (REAL) ─────────
                        update_metrics_store(&pipeline_state, &span).await;

                        if total_spans % 100 == 0 {
                            tracing::info!(
                                spans = total_spans,
                                alerts = total_alerts,
                                connections = assembler.active_connections(),
                                "pipeline stats"
                            );
                        }
                    }
                }
            }

            // Ctrl-C
            _ = tokio::signal::ctrl_c() => {
                tracing::info!(
                    total_spans = total_spans,
                    total_alerts = total_alerts,
                    "shutting down"
                );
                break;
            }
        }
    }

    Ok(())
}

/// Convert a SpanEvent to the API's SpanDetail model.
fn span_to_detail(span: &SpanEvent) -> SpanDetail {
    use rail_obs_common::span::trace_id_to_hex;
    use rail_obs_ingestion::normalize_route;

    let route = if span.http_route.is_empty() {
        normalize_route(&span.http_path)
    } else {
        span.http_route.clone()
    };

    SpanDetail {
        trace_id: trace_id_to_hex(&span.trace_id),
        span_id: span.span_id,
        parent_span_id: span.parent_span_id,
        service_id: span.service_id.clone(),
        http_method: span.http_method.clone(),
        http_path: span.http_path.clone(),
        http_route: route,
        http_status: span.http_status,
        start_time: span.start_time().to_rfc3339(),
        duration_us: span.duration_us,
        is_error: span.is_error,
    }
}

/// Update the metrics store with topology edges from completed spans.
async fn update_metrics_store(state: &Arc<AppState>, span: &SpanEvent) {
    if !span.dst_service_id.is_empty() && span.dst_service_id != span.service_id {
        let mut store = state.metrics_store.write().await;

        // Check if this edge already exists
        let exists = store.topology_edges.iter().any(|e| {
            e.caller == span.service_id && e.callee == span.dst_service_id
        });

        if !exists {
            store.topology_edges.push(rail_obs_api::models::TopologyEdge {
                caller: span.service_id.clone(),
                callee: span.dst_service_id.clone(),
                call_count: 1,
                error_count: if span.is_error { 1 } else { 0 },
                avg_duration_us: span.duration_us as f64,
            });
        } else {
            // Update existing edge
            if let Some(edge) = store.topology_edges.iter_mut().find(|e| {
                e.caller == span.service_id && e.callee == span.dst_service_id
            }) {
                let total_duration = edge.avg_duration_us * edge.call_count as f64
                    + span.duration_us as f64;
                edge.call_count += 1;
                if span.is_error {
                    edge.error_count += 1;
                }
                edge.avg_duration_us = total_duration / edge.call_count as f64;
            }
        }
    }
}
