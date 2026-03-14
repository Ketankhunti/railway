use serde::{Deserialize, Serialize};

/// Severity level for an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::Warning => write!(f, "warning"),
            Severity::Info => write!(f, "info"),
        }
    }
}

/// The metric to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    ErrorRate,
    P99LatencyUs,
    P95LatencyUs,
    P50LatencyUs,
    RequestCount,
}

impl std::fmt::Display for Metric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Metric::ErrorRate => write!(f, "error_rate"),
            Metric::P99LatencyUs => write!(f, "p99_latency_us"),
            Metric::P95LatencyUs => write!(f, "p95_latency_us"),
            Metric::P50LatencyUs => write!(f, "p50_latency_us"),
            Metric::RequestCount => write!(f, "request_count"),
        }
    }
}

/// Comparison operator for threshold rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operator {
    #[serde(rename = ">")]
    GreaterThan,
    #[serde(rename = "<")]
    LessThan,
    #[serde(rename = ">=")]
    GreaterOrEqual,
    #[serde(rename = "<=")]
    LessOrEqual,
}

impl Operator {
    pub fn evaluate(&self, value: f64, threshold: f64) -> bool {
        match self {
            Operator::GreaterThan => value > threshold,
            Operator::LessThan => value < threshold,
            Operator::GreaterOrEqual => value >= threshold,
            Operator::LessOrEqual => value <= threshold,
        }
    }
}

impl std::fmt::Display for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operator::GreaterThan => write!(f, ">"),
            Operator::LessThan => write!(f, "<"),
            Operator::GreaterOrEqual => write!(f, ">="),
            Operator::LessOrEqual => write!(f, "<="),
        }
    }
}

/// Configuration for a threshold rule.
/// "Alert if `metric` `operator` `value` for `window_secs` seconds."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub metric: Metric,
    pub operator: Operator,
    pub value: f64,
    /// Evaluation window in seconds.
    pub window_secs: u64,
    /// Minimum request count before the rule can fire (avoids alerting on low traffic).
    pub min_requests: u64,
}

/// Configuration for an anomaly detection rule (z-score).
/// "Alert if `metric` deviates by more than `z_score_threshold` standard
/// deviations from the `baseline_window_secs` mean."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyConfig {
    pub metric: Metric,
    /// Baseline window in seconds (e.g., 3600 = 1 hour).
    pub baseline_window_secs: u64,
    /// Evaluation window in seconds (e.g., 300 = 5 minutes).
    pub evaluation_window_secs: u64,
    /// Z-score threshold (e.g., 3.0 = 3 standard deviations).
    pub z_score_threshold: f64,
}

/// Configuration for a rate-of-change rule.
/// "Alert if `metric` changes by more than `change_threshold_pct`% between
/// the current and previous window."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateOfChangeConfig {
    pub metric: Metric,
    /// Window size in seconds for both current and previous comparison.
    pub window_secs: u64,
    /// Percentage change threshold. Negative = drop, positive = spike.
    /// e.g., -50.0 means "alert if metric drops by 50%"
    pub change_threshold_pct: f64,
}

/// Union of all rule configuration types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertRuleConfig {
    Threshold(ThresholdConfig),
    Anomaly(AnomalyConfig),
    RateOfChange(RateOfChangeConfig),
}

impl AlertRuleConfig {
    /// Returns the metric this rule evaluates.
    pub fn metric(&self) -> Metric {
        match self {
            AlertRuleConfig::Threshold(c) => c.metric,
            AlertRuleConfig::Anomaly(c) => c.metric,
            AlertRuleConfig::RateOfChange(c) => c.metric,
        }
    }

    /// Returns the maximum lookback window needed in seconds.
    pub fn max_window_secs(&self) -> u64 {
        match self {
            AlertRuleConfig::Threshold(c) => c.window_secs,
            AlertRuleConfig::Anomaly(c) => c.baseline_window_secs,
            AlertRuleConfig::RateOfChange(c) => c.window_secs * 2, // current + previous
        }
    }
}

/// A complete alert rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub project_id: String,
    pub name: String,
    /// Scope: which service this rule applies to. Empty = all services.
    pub service_id: String,
    pub config: AlertRuleConfig,
    pub severity: Severity,
    pub enabled: bool,
    /// Cooldown in seconds — don't re-fire within this period.
    pub cooldown_secs: u64,
}

impl AlertRule {
    /// Generate a deduplication fingerprint for this rule + service.
    pub fn fingerprint(&self, service_id: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.id.hash(&mut hasher);
        service_id.hash(&mut hasher);
        self.severity.to_string().hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Returns the metric this rule evaluates.
    pub fn metric(&self) -> Metric {
        self.config.metric()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_evaluate() {
        assert!(Operator::GreaterThan.evaluate(10.0, 5.0));
        assert!(!Operator::GreaterThan.evaluate(5.0, 10.0));
        assert!(Operator::LessThan.evaluate(3.0, 5.0));
        assert!(!Operator::LessThan.evaluate(5.0, 3.0));
        assert!(Operator::GreaterOrEqual.evaluate(5.0, 5.0));
        assert!(Operator::LessOrEqual.evaluate(5.0, 5.0));
    }

    #[test]
    fn fingerprint_consistent() {
        let rule = AlertRule {
            id: "rule-1".into(),
            project_id: "proj".into(),
            name: "test".into(),
            service_id: "svc-a".into(),
            config: AlertRuleConfig::Threshold(ThresholdConfig {
                metric: Metric::ErrorRate,
                operator: Operator::GreaterThan,
                value: 0.05,
                window_secs: 300,
                min_requests: 100,
            }),
            severity: Severity::Critical,
            enabled: true,
            cooldown_secs: 900,
        };

        let fp1 = rule.fingerprint("svc-a");
        let fp2 = rule.fingerprint("svc-a");
        assert_eq!(fp1, fp2);

        // Different service → different fingerprint
        let fp3 = rule.fingerprint("svc-b");
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn rule_config_serde_roundtrip() {
        let config = AlertRuleConfig::Threshold(ThresholdConfig {
            metric: Metric::ErrorRate,
            operator: Operator::GreaterThan,
            value: 0.05,
            window_secs: 300,
            min_requests: 100,
        });

        let json = serde_json::to_string(&config).unwrap();
        let parsed: AlertRuleConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.metric(), Metric::ErrorRate);
        assert_eq!(parsed.max_window_secs(), 300);
    }

    #[test]
    fn anomaly_config_max_window() {
        let config = AlertRuleConfig::Anomaly(AnomalyConfig {
            metric: Metric::P99LatencyUs,
            baseline_window_secs: 3600,
            evaluation_window_secs: 300,
            z_score_threshold: 3.0,
        });
        assert_eq!(config.max_window_secs(), 3600);
    }

    #[test]
    fn rate_of_change_max_window() {
        let config = AlertRuleConfig::RateOfChange(RateOfChangeConfig {
            metric: Metric::RequestCount,
            window_secs: 300,
            change_threshold_pct: -50.0,
        });
        // current + previous = 2×300
        assert_eq!(config.max_window_secs(), 600);
    }
}
