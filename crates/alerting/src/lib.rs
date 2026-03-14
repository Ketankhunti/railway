//! Streaming alerting engine: threshold, anomaly detection (z-score),
//! and rate-of-change rules evaluated over sliding windows of span data.
//!
//! ## Architecture
//!
//! ```text
//! SpanEvent (from ingestion pipeline)
//!     │
//!     ▼
//! AlertEngine.ingest(span)
//!     │
//!     ├── Update SlidingWindow for (service_id, metric)
//!     │
//!     ├── Evaluate all matching AlertRules
//!     │     ├── ThresholdRule:     value > threshold for window?
//!     │     ├── AnomalyRule:       z-score > threshold over baseline?
//!     │     └── RateOfChangeRule:  % change between windows?
//!     │
//!     └── If rule fires:
//!           ├── Deduplicate via fingerprint
//!           ├── Route by severity (critical/warning/info)
//!           └── Return AlertEvent
//! ```

pub mod rules;
pub mod window;
pub mod evaluator;
pub mod engine;

pub use rules::{AlertRule, AlertRuleConfig, ThresholdConfig, AnomalyConfig, RateOfChangeConfig, Severity};
pub use window::{SlidingWindow, WindowBucket};
pub use evaluator::RuleEvaluator;
pub use engine::{AlertEngine, AlertEngineConfig, AlertOutput};
