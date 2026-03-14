//! Alert engine: the coordinator that ties rules, windows, and evaluation together.
//!
//! Ingests SpanEvents, maintains per-service sliding windows, evaluates matching
//! rules, deduplicates via fingerprinting, and emits AlertOutput events.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use rail_obs_common::span::SpanEvent;

use crate::evaluator::{EvalResult, RuleEvaluator};
use crate::rules::{AlertRule, Severity};
use crate::window::SlidingWindow;

/// Configuration for the AlertEngine.
#[derive(Debug, Clone)]
pub struct AlertEngineConfig {
    /// Maximum window size across all rules. Determines memory usage.
    /// Default: 3600 (1 hour).
    pub max_window_secs: usize,
    /// How often to evaluate rules (every N spans). Default: 100.
    pub eval_interval_spans: u64,
}

impl Default for AlertEngineConfig {
    fn default() -> Self {
        Self {
            max_window_secs: 3600,
            eval_interval_spans: 100,
        }
    }
}

/// An alert event emitted by the engine.
#[derive(Debug, Clone)]
pub struct AlertOutput {
    pub rule_id: String,
    pub rule_name: String,
    pub project_id: String,
    pub service_id: String,
    pub severity: Severity,
    pub fingerprint: String,
    pub metric_value: f64,
    pub threshold_value: f64,
    pub message: String,
    pub fired_at: DateTime<Utc>,
}

/// Tracks the state of an active (currently firing) alert.
#[derive(Debug)]
struct ActiveAlert {
    fingerprint: String,
    first_fired_at: DateTime<Utc>,
    last_fired_at: DateTime<Utc>,
    cooldown_secs: u64,
}

impl ActiveAlert {
    /// Returns true if the cooldown period has expired and the alert can re-fire.
    fn can_refire(&self, now: DateTime<Utc>) -> bool {
        let elapsed = (now - self.last_fired_at).num_seconds();
        elapsed >= self.cooldown_secs as i64
    }
}

/// The main alerting engine.
pub struct AlertEngine {
    /// Per-service sliding windows, keyed by service_id.
    windows: HashMap<String, SlidingWindow>,
    /// Active rules.
    rules: Vec<AlertRule>,
    /// Active (currently firing) alerts, keyed by fingerprint.
    active_alerts: HashMap<String, ActiveAlert>,
    /// Services that have been seen (for scoping rules).
    known_services: HashSet<String>,
    /// Configuration.
    config: AlertEngineConfig,
    /// Span counter for throttling evaluation frequency.
    span_counter: u64,
}

impl AlertEngine {
    pub fn new(config: AlertEngineConfig) -> Self {
        Self {
            windows: HashMap::new(),
            rules: Vec::new(),
            active_alerts: HashMap::new(),
            known_services: HashSet::new(),
            config,
            span_counter: 0,
        }
    }

    /// Load or replace the set of active alert rules.
    pub fn set_rules(&mut self, rules: Vec<AlertRule>) {
        self.rules = rules.into_iter().filter(|r| r.enabled).collect();
    }

    /// Add a single rule.
    pub fn add_rule(&mut self, rule: AlertRule) {
        if rule.enabled {
            self.rules.push(rule);
        }
    }

    /// Ingest a span: update windows and optionally evaluate rules.
    /// Returns any new alert outputs.
    pub fn ingest(&mut self, span: &SpanEvent) -> Vec<AlertOutput> {
        self.span_counter += 1;

        // Update the window for this service.
        let window = self.windows
            .entry(span.service_id.clone())
            .or_insert_with(|| SlidingWindow::new(self.config.max_window_secs));

        window.record(span.start_time_ns, span.duration_us, span.is_error);
        self.known_services.insert(span.service_id.clone());

        // Only evaluate on every N spans to avoid constant re-evaluation.
        if self.span_counter % self.config.eval_interval_spans != 0 {
            return vec![];
        }

        self.evaluate_rules()
    }

    /// Force evaluation of all rules now (used by tests and on timer).
    pub fn evaluate_rules(&mut self) -> Vec<AlertOutput> {
        let now = Utc::now();
        let mut outputs = vec![];

        for rule in &self.rules {
            // Determine which services to evaluate for this rule.
            let services: Vec<String> = if rule.service_id.is_empty() {
                // Rule applies to all known services.
                self.known_services.iter().cloned().collect()
            } else {
                vec![rule.service_id.clone()]
            };

            for service_id in &services {
                let window = match self.windows.get(service_id) {
                    Some(w) => w,
                    None => continue,
                };

                let result = RuleEvaluator::evaluate(rule, window);

                if result.fired {
                    let fingerprint = rule.fingerprint(service_id);

                    // Deduplication: check if this alert is already active and in cooldown.
                    if let Some(active) = self.active_alerts.get_mut(&fingerprint) {
                        if !active.can_refire(now) {
                            // Still in cooldown — update last_seen but don't emit.
                            active.last_fired_at = now;
                            continue;
                        }
                        // Cooldown expired — re-fire.
                        active.last_fired_at = now;
                    } else {
                        // New alert — register as active.
                        self.active_alerts.insert(
                            fingerprint.clone(),
                            ActiveAlert {
                                fingerprint: fingerprint.clone(),
                                first_fired_at: now,
                                last_fired_at: now,
                                cooldown_secs: rule.cooldown_secs,
                            },
                        );
                    }

                    outputs.push(AlertOutput {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        project_id: rule.project_id.clone(),
                        service_id: service_id.clone(),
                        severity: rule.severity,
                        fingerprint,
                        metric_value: result.metric_value,
                        threshold_value: result.threshold_value,
                        message: result.message,
                        fired_at: now,
                    });
                }
            }
        }

        outputs
    }

    /// Resolve alerts whose fingerprints are no longer firing.
    /// Returns fingerprints of resolved alerts.
    pub fn resolve_stale_alerts(&mut self, max_age_secs: i64) -> Vec<String> {
        let now = Utc::now();
        let mut resolved = vec![];

        self.active_alerts.retain(|fp, alert| {
            let age = (now - alert.last_fired_at).num_seconds();
            if age >= max_age_secs {
                resolved.push(fp.clone());
                false
            } else {
                true
            }
        });

        resolved
    }

    // --- Accessors ---

    pub fn active_alert_count(&self) -> usize {
        self.active_alerts.len()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn window_count(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_span(service: &str, duration_us: u64, status: u16, ts_ns: u64) -> SpanEvent {
        SpanEvent {
            trace_id: [0u8; 16],
            span_id: 1,
            parent_span_id: 0,
            project_id: "proj".into(),
            service_id: service.into(),
            environment_id: "prod".into(),
            http_method: "GET".into(),
            http_path: "/test".into(),
            http_route: "/test".into(),
            http_status: status,
            http_host: "svc".into(),
            start_time_ns: ts_ns,
            duration_us,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 45678,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 8080,
            dst_service_id: String::new(),
            host_id: "host".into(),
            container_id: "ctr".into(),
            is_error: status >= 400,
            is_root: true,
            sample_rate: 1.0,
        }
    }

    #[test]
    fn engine_threshold_fires_on_high_error_rate() {
        let mut engine = AlertEngine::new(AlertEngineConfig {
            max_window_secs: 120,
            eval_interval_spans: 1, // evaluate every span for test
        });

        engine.add_rule(AlertRule {
            id: "rule-1".into(),
            project_id: "proj".into(),
            name: "High error rate".into(),
            service_id: "api-gw".into(),
            config: AlertRuleConfig::Threshold(ThresholdConfig {
                metric: Metric::ErrorRate,
                operator: Operator::GreaterThan,
                value: 0.05,
                window_secs: 60,
                min_requests: 10,
            }),
            severity: Severity::Critical,
            enabled: true,
            cooldown_secs: 60,
        });

        let ts = 1_000_000_000u64;
        // Ingest 100 requests: 20 errors (20% error rate)
        let mut all_outputs = vec![];
        for i in 0..100u64 {
            let is_err = i < 20;
            let status = if is_err { 500 } else { 200 };
            let outputs = engine.ingest(&make_span("api-gw", 100, status, ts + i * 10_000_000));
            all_outputs.extend(outputs);
        }

        assert!(!all_outputs.is_empty(), "should have fired");

        let alert = &all_outputs[0];
        assert_eq!(alert.rule_name, "High error rate");
        assert_eq!(alert.service_id, "api-gw");
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.metric_value > 0.05);
    }

    #[test]
    fn engine_deduplication_via_cooldown() {
        let mut engine = AlertEngine::new(AlertEngineConfig {
            max_window_secs: 120,
            eval_interval_spans: 1,
        });

        engine.add_rule(AlertRule {
            id: "rule-1".into(),
            project_id: "proj".into(),
            name: "Errors".into(),
            service_id: "svc".into(),
            config: AlertRuleConfig::Threshold(ThresholdConfig {
                metric: Metric::ErrorRate,
                operator: Operator::GreaterThan,
                value: 0.05,
                window_secs: 60,
                min_requests: 5,
            }),
            severity: Severity::Warning,
            enabled: true,
            cooldown_secs: 9999, // very long cooldown
        });

        let ts = 1_000_000_000u64;
        let mut fire_count = 0;
        for i in 0..100u64 {
            let outputs = engine.ingest(&make_span("svc", 100, 500, ts + i * 10_000_000));
            fire_count += outputs.len();
        }

        // Should fire ONCE, then be in cooldown for subsequent evaluations.
        assert_eq!(fire_count, 1, "should only fire once due to cooldown");
        assert_eq!(engine.active_alert_count(), 1);
    }

    #[test]
    fn engine_no_fire_below_threshold() {
        let mut engine = AlertEngine::new(AlertEngineConfig {
            max_window_secs: 120,
            eval_interval_spans: 1,
        });

        engine.add_rule(AlertRule {
            id: "rule-1".into(),
            project_id: "proj".into(),
            name: "Errors".into(),
            service_id: "svc".into(),
            config: AlertRuleConfig::Threshold(ThresholdConfig {
                metric: Metric::ErrorRate,
                operator: Operator::GreaterThan,
                value: 0.50,
                window_secs: 60,
                min_requests: 5,
            }),
            severity: Severity::Info,
            enabled: true,
            cooldown_secs: 60,
        });

        let ts = 1_000_000_000u64;
        let mut fire_count = 0;
        for i in 0..50u64 {
            // Interleave: every 10th request is an error → 10% error rate
            let status = if i % 10 == 0 { 500 } else { 200 };
            let outputs = engine.ingest(&make_span("svc", 100, status, ts + i * 10_000_000));
            fire_count += outputs.len();
        }

        assert_eq!(fire_count, 0, "should not fire below threshold");
    }

    #[test]
    fn engine_multiple_services() {
        let mut engine = AlertEngine::new(AlertEngineConfig {
            max_window_secs: 120,
            eval_interval_spans: 1,
        });

        // Rule applies to all services (empty service_id)
        engine.add_rule(AlertRule {
            id: "rule-all".into(),
            project_id: "proj".into(),
            name: "Global errors".into(),
            service_id: String::new(), // matches all
            config: AlertRuleConfig::Threshold(ThresholdConfig {
                metric: Metric::ErrorRate,
                operator: Operator::GreaterThan,
                value: 0.05,
                window_secs: 60,
                min_requests: 5,
            }),
            severity: Severity::Warning,
            enabled: true,
            cooldown_secs: 0, // no cooldown for test
        });

        let ts = 1_000_000_000u64;

        // svc-a: high errors
        for i in 0..20u64 {
            engine.ingest(&make_span("svc-a", 100, 500, ts + i * 10_000_000));
        }

        // svc-b: no errors
        for i in 0..20u64 {
            engine.ingest(&make_span("svc-b", 100, 200, ts + i * 10_000_000));
        }

        let outputs = engine.evaluate_rules();

        // Should have output for svc-a (100% errors > 5%), not svc-b (0%)
        let svc_a_alerts: Vec<_> = outputs.iter().filter(|o| o.service_id == "svc-a").collect();
        let svc_b_alerts: Vec<_> = outputs.iter().filter(|o| o.service_id == "svc-b").collect();

        assert!(!svc_a_alerts.is_empty(), "svc-a should have alerts");
        assert!(svc_b_alerts.is_empty(), "svc-b should have no alerts");
    }

    #[test]
    fn engine_disabled_rules_ignored() {
        let mut engine = AlertEngine::new(AlertEngineConfig::default());

        engine.add_rule(AlertRule {
            id: "rule-1".into(),
            project_id: "proj".into(),
            name: "Disabled rule".into(),
            service_id: "svc".into(),
            config: AlertRuleConfig::Threshold(ThresholdConfig {
                metric: Metric::ErrorRate,
                operator: Operator::GreaterThan,
                value: 0.0,
                window_secs: 60,
                min_requests: 0,
            }),
            severity: Severity::Critical,
            enabled: false, // disabled
            cooldown_secs: 0,
        });

        assert_eq!(engine.rule_count(), 0, "disabled rules should not be loaded");
    }

    #[test]
    fn engine_resolve_stale() {
        let mut engine = AlertEngine::new(AlertEngineConfig {
            max_window_secs: 120,
            eval_interval_spans: 1,
        });

        engine.add_rule(AlertRule {
            id: "r1".into(),
            project_id: "p".into(),
            name: "test".into(),
            service_id: "svc".into(),
            config: AlertRuleConfig::Threshold(ThresholdConfig {
                metric: Metric::ErrorRate,
                operator: Operator::GreaterThan,
                value: 0.0,
                window_secs: 60,
                min_requests: 1,
            }),
            severity: Severity::Info,
            enabled: true,
            cooldown_secs: 0,
        });

        let ts = 1_000_000_000u64;
        engine.ingest(&make_span("svc", 100, 500, ts));
        assert_eq!(engine.active_alert_count(), 1);

        // Resolve with 0 age tolerance → resolves immediately
        let resolved = engine.resolve_stale_alerts(0);
        assert_eq!(resolved.len(), 1);
        assert_eq!(engine.active_alert_count(), 0);
    }
}
