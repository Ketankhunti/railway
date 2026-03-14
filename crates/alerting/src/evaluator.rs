//! Rule evaluator: pure logic that takes a rule + window data and decides
//! whether the rule should fire.
//!
//! No side effects, no I/O — just math. Easy to test.

use crate::rules::*;
use crate::window::{SlidingWindow, WindowAggregate};

/// Result of evaluating a single rule.
#[derive(Debug)]
pub struct EvalResult {
    /// Whether the rule condition was met.
    pub fired: bool,
    /// The computed metric value that was compared.
    pub metric_value: f64,
    /// The threshold/baseline that was compared against.
    pub threshold_value: f64,
    /// Human-readable description of what happened.
    pub message: String,
}

/// Stateless rule evaluator.
pub struct RuleEvaluator;

impl RuleEvaluator {
    /// Evaluate a rule against a sliding window.
    pub fn evaluate(rule: &AlertRule, window: &SlidingWindow) -> EvalResult {
        match &rule.config {
            AlertRuleConfig::Threshold(config) => Self::eval_threshold(config, window),
            AlertRuleConfig::Anomaly(config) => Self::eval_anomaly(config, window),
            AlertRuleConfig::RateOfChange(config) => Self::eval_rate_of_change(config, window),
        }
    }

    /// Threshold: "alert if metric > value for window_secs"
    fn eval_threshold(config: &ThresholdConfig, window: &SlidingWindow) -> EvalResult {
        let agg = window.aggregate(config.window_secs);

        // Don't fire on low traffic
        if agg.count < config.min_requests {
            return EvalResult {
                fired: false,
                metric_value: 0.0,
                threshold_value: config.value,
                message: format!(
                    "insufficient data: {} requests < {} min_requests",
                    agg.count, config.min_requests
                ),
            };
        }

        let metric_value = extract_metric_value(&config.metric, &agg);
        let fired = config.operator.evaluate(metric_value, config.value);

        EvalResult {
            fired,
            metric_value,
            threshold_value: config.value,
            message: if fired {
                format!(
                    "{} {} {} {} (threshold: {})",
                    config.metric, config.operator, metric_value,
                    if fired { "FIRING" } else { "OK" },
                    config.value
                )
            } else {
                format!(
                    "{} = {:.4} (threshold: {} {})",
                    config.metric, metric_value, config.operator, config.value
                )
            },
        }
    }

    /// Anomaly (z-score): "alert if metric deviates by z_score_threshold from baseline"
    fn eval_anomaly(config: &AnomalyConfig, window: &SlidingWindow) -> EvalResult {
        // Baseline: the period BEFORE the evaluation window.
        // This prevents the spike from contaminating the baseline.
        let baseline = window.aggregate_range(
            config.baseline_window_secs,
            config.evaluation_window_secs,
        );
        let current = window.aggregate(config.evaluation_window_secs);

        if baseline.all_durations.len() < 10 {
            return EvalResult {
                fired: false,
                metric_value: 0.0,
                threshold_value: config.z_score_threshold,
                message: "insufficient baseline data".into(),
            };
        }

        let baseline_value = extract_metric_value(&config.metric, &baseline);
        let current_value = extract_metric_value(&config.metric, &current);

        let stddev = compute_stddev_for_metric(&config.metric, &baseline);

        if stddev < 1e-10 {
            // No variance in baseline → can't compute z-score meaningfully
            return EvalResult {
                fired: false,
                metric_value: current_value,
                threshold_value: config.z_score_threshold,
                message: format!("baseline has zero variance for {}", config.metric),
            };
        }

        let z_score = (current_value - baseline_value).abs() / stddev;
        let fired = z_score > config.z_score_threshold;

        EvalResult {
            fired,
            metric_value: current_value,
            threshold_value: baseline_value,
            message: format!(
                "{}: current={:.2}, baseline={:.2}, stddev={:.2}, z_score={:.2} (threshold: {:.1})",
                config.metric, current_value, baseline_value, stddev, z_score, config.z_score_threshold
            ),
        }
    }

    /// Rate-of-change: "alert if metric changes by more than threshold% between windows"
    fn eval_rate_of_change(config: &RateOfChangeConfig, window: &SlidingWindow) -> EvalResult {
        // Previous window: (2×window_secs)..window_secs ago
        let previous = window.aggregate_range(config.window_secs * 2, config.window_secs);
        // Current window: window_secs..0 ago
        let current = window.aggregate_range(config.window_secs, 0);

        let prev_value = extract_metric_value(&config.metric, &previous);
        let curr_value = extract_metric_value(&config.metric, &current);

        if previous.count == 0 {
            return EvalResult {
                fired: false,
                metric_value: curr_value,
                threshold_value: config.change_threshold_pct,
                message: "no previous window data".into(),
            };
        }

        let change_pct = if prev_value.abs() < 1e-10 {
            if curr_value.abs() < 1e-10 { 0.0 } else { 100.0 }
        } else {
            ((curr_value - prev_value) / prev_value) * 100.0
        };

        // For negative thresholds (drops): fire if change_pct <= threshold
        // For positive thresholds (spikes): fire if change_pct >= threshold
        let fired = if config.change_threshold_pct < 0.0 {
            change_pct <= config.change_threshold_pct
        } else {
            change_pct >= config.change_threshold_pct
        };

        EvalResult {
            fired,
            metric_value: curr_value,
            threshold_value: prev_value,
            message: format!(
                "{}: previous={:.2}, current={:.2}, change={:.1}% (threshold: {:.1}%)",
                config.metric, prev_value, curr_value, change_pct, config.change_threshold_pct
            ),
        }
    }
}

/// Extract a scalar metric value from a window aggregate.
fn extract_metric_value(metric: &Metric, agg: &WindowAggregate) -> f64 {
    match metric {
        Metric::ErrorRate => agg.error_rate(),
        Metric::P99LatencyUs => agg.percentile(0.99),
        Metric::P95LatencyUs => agg.percentile(0.95),
        Metric::P50LatencyUs => agg.percentile(0.50),
        Metric::RequestCount => agg.count as f64,
    }
}

/// Compute standard deviation for a metric across the aggregate's samples.
/// For latency metrics, this is stddev of durations.
/// For error_rate, we approximate via Bernoulli stddev: sqrt(p*(1-p)/n).
/// For request_count, we use stddev of per-bucket counts (not from aggregate).
fn compute_stddev_for_metric(metric: &Metric, agg: &WindowAggregate) -> f64 {
    match metric {
        Metric::P99LatencyUs | Metric::P95LatencyUs | Metric::P50LatencyUs => {
            agg.stddev_duration()
        }
        Metric::ErrorRate => {
            // Bernoulli approximation
            let p = agg.error_rate();
            let n = agg.count as f64;
            if n == 0.0 { 0.0 } else { (p * (1.0 - p) / n).sqrt() }
        }
        Metric::RequestCount => {
            // For request count, stddev doesn't make sense from the aggregate
            // directly. Use a fixed fraction as heuristic. In production,
            // we'd track per-bucket counts separately.
            let mean = agg.count as f64;
            if mean == 0.0 { 0.0 } else { mean * 0.1 } // 10% heuristic
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_threshold_rule(metric: Metric, op: Operator, value: f64) -> AlertRule {
        AlertRule {
            id: "test-rule".into(),
            project_id: "proj".into(),
            name: "test".into(),
            service_id: "svc".into(),
            config: AlertRuleConfig::Threshold(ThresholdConfig {
                metric,
                operator: op,
                value,
                window_secs: 60,
                min_requests: 10,
            }),
            severity: Severity::Critical,
            enabled: true,
            cooldown_secs: 300,
        }
    }

    fn make_anomaly_rule(metric: Metric, z_threshold: f64) -> AlertRule {
        AlertRule {
            id: "anomaly-rule".into(),
            project_id: "proj".into(),
            name: "anomaly test".into(),
            service_id: "svc".into(),
            config: AlertRuleConfig::Anomaly(AnomalyConfig {
                metric,
                baseline_window_secs: 60,
                evaluation_window_secs: 10,
                z_score_threshold: z_threshold,
            }),
            severity: Severity::Warning,
            enabled: true,
            cooldown_secs: 300,
        }
    }

    fn make_roc_rule(metric: Metric, threshold_pct: f64) -> AlertRule {
        AlertRule {
            id: "roc-rule".into(),
            project_id: "proj".into(),
            name: "rate of change test".into(),
            service_id: "svc".into(),
            config: AlertRuleConfig::RateOfChange(RateOfChangeConfig {
                metric,
                window_secs: 5,
                change_threshold_pct: threshold_pct,
            }),
            severity: Severity::Critical,
            enabled: true,
            cooldown_secs: 300,
        }
    }

    // --- Threshold tests ---

    #[test]
    fn threshold_error_rate_fires() {
        let rule = make_threshold_rule(Metric::ErrorRate, Operator::GreaterThan, 0.05);
        let mut w = SlidingWindow::new(120);

        // 100 requests, 10 errors → 10% error rate
        let ts = 1_000_000_000u64;
        for i in 0..100u64 {
            w.record(ts + i * 10_000_000, 100, i < 10);
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(result.fired, "should fire at 10% > 5%: {}", result.message);
        assert!((result.metric_value - 0.10).abs() < 0.01);
    }

    #[test]
    fn threshold_error_rate_does_not_fire() {
        let rule = make_threshold_rule(Metric::ErrorRate, Operator::GreaterThan, 0.05);
        let mut w = SlidingWindow::new(120);

        // 100 requests, 2 errors → 2% error rate
        let ts = 1_000_000_000u64;
        for i in 0..100u64 {
            w.record(ts + i * 10_000_000, 100, i < 2);
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(!result.fired, "should not fire at 2% < 5%");
    }

    #[test]
    fn threshold_insufficient_traffic() {
        let rule = make_threshold_rule(Metric::ErrorRate, Operator::GreaterThan, 0.05);
        let mut w = SlidingWindow::new(120);

        // Only 5 requests (min is 10)
        let ts = 1_000_000_000u64;
        for i in 0..5u64 {
            w.record(ts + i * 10_000_000, 100, true); // 100% error rate but too few
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(!result.fired, "should not fire with insufficient traffic");
    }

    #[test]
    fn threshold_p99_latency() {
        let rule = make_threshold_rule(Metric::P99LatencyUs, Operator::GreaterThan, 500_000.0);
        let mut w = SlidingWindow::new(120);

        let ts = 1_000_000_000u64;
        // 95 fast requests + 5 slow ones → p99 should be in the slow range
        for i in 0..95u64 {
            w.record(ts + i * 10_000_000, 50_000, false); // 50ms
        }
        for i in 95..100u64 {
            w.record(ts + i * 10_000_000, 800_000, false); // 800ms
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(result.fired, "p99 should be ~800ms > 500ms: {}", result.message);
    }

    // --- Anomaly (z-score) tests ---

    #[test]
    fn anomaly_detects_latency_spike() {
        let rule = make_anomaly_rule(Metric::P99LatencyUs, 3.0);
        let mut w = SlidingWindow::new(120);

        // Baseline: 50 seconds of ~100µs latency
        for sec in 0..50u64 {
            for i in 0..20u64 {
                w.record(
                    sec * 1_000_000_000 + i * 50_000_000,
                    100 + (i % 10) * 5, // 100-145µs range
                    false,
                );
            }
        }

        // Spike: last 10 seconds with 10x latency
        for sec in 50..60u64 {
            for i in 0..20u64 {
                w.record(
                    sec * 1_000_000_000 + i * 50_000_000,
                    1000 + (i % 10) * 50, // 1000-1450µs
                    false,
                );
            }
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(result.fired, "should detect 10x latency spike: {}", result.message);
    }

    #[test]
    fn anomaly_normal_variation_no_fire() {
        let rule = make_anomaly_rule(Metric::P99LatencyUs, 3.0);
        let mut w = SlidingWindow::new(120);

        // 60 seconds of consistent latency
        for sec in 0..60u64 {
            for i in 0..20u64 {
                w.record(
                    sec * 1_000_000_000 + i * 50_000_000,
                    100 + (i % 20) * 5, // 100-195µs — normal variation
                    false,
                );
            }
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(!result.fired, "normal variation should not fire: {}", result.message);
    }

    // --- Rate of change tests ---

    #[test]
    fn rate_of_change_detects_traffic_drop() {
        let rule = make_roc_rule(Metric::RequestCount, -50.0);
        let mut w = SlidingWindow::new(120);

        // Previous window (seconds 1-5): 100 requests per second
        for sec in 1..=5u64 {
            for i in 0..100u64 {
                w.record(sec * 1_000_000_000 + i * 10_000_000, 100, false);
            }
        }

        // Current window (seconds 6-10): 20 requests per second (80% drop)
        for sec in 6..=10u64 {
            for i in 0..20u64 {
                w.record(sec * 1_000_000_000 + i * 50_000_000, 100, false);
            }
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(result.fired, "80% drop should fire at -50% threshold: {}", result.message);
    }

    #[test]
    fn rate_of_change_stable_traffic_no_fire() {
        let rule = make_roc_rule(Metric::RequestCount, -50.0);
        let mut w = SlidingWindow::new(120);

        // Both windows: 50 requests per second
        for sec in 1..=10u64 {
            for i in 0..50u64 {
                w.record(sec * 1_000_000_000 + i * 20_000_000, 100, false);
            }
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(!result.fired, "stable traffic should not fire: {}", result.message);
    }

    #[test]
    fn rate_of_change_detects_spike() {
        let rule = make_roc_rule(Metric::RequestCount, 100.0); // fire if doubles
        let mut w = SlidingWindow::new(120);

        // Previous: 50 req/sec
        for sec in 1..=5u64 {
            for i in 0..50u64 {
                w.record(sec * 1_000_000_000 + i * 20_000_000, 100, false);
            }
        }

        // Current: 200 req/sec (300% increase)
        for sec in 6..=10u64 {
            for i in 0..200u64 {
                w.record(sec * 1_000_000_000 + i * 5_000_000, 100, false);
            }
        }

        let result = RuleEvaluator::evaluate(&rule, &w);
        assert!(result.fired, "300% spike should fire at 100% threshold: {}", result.message);
    }
}
