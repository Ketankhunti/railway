use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A unique 128-bit trace identifier, hex-encoded as 32 characters.
pub type TraceId = [u8; 16];

/// A unique 64-bit span identifier.
pub type SpanId = u64;

/// Generate a random trace ID.
pub fn generate_trace_id() -> TraceId {
    rand::random()
}

/// Generate a random span ID.
pub fn generate_span_id() -> SpanId {
    rand::random()
}

/// Hex-encode a trace ID to a 32-character string (for ClickHouse FixedString(32)).
pub fn trace_id_to_hex(id: &TraceId) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a 32-character hex string to a TraceId.
pub fn hex_to_trace_id(hex: &str) -> Option<TraceId> {
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for i in 0..16 {
        id[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

/// The core span event structure. Produced by the span assembler,
/// consumed by the ingestion pipeline and alerting engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    // --- Identity ---
    pub trace_id: TraceId,
    pub span_id: SpanId,
    /// 0 for root spans.
    pub parent_span_id: SpanId,

    // --- Service identity (from Railway / discovery metadata) ---
    pub project_id: String,
    pub service_id: String,
    pub environment_id: String,

    // --- HTTP data (from L7 parsing) ---
    pub http_method: String,
    /// Raw path: /api/users/123
    pub http_path: String,
    /// Normalized route: /api/users/:id (computed by ingestion pipeline)
    pub http_route: String,
    pub http_status: u16,
    pub http_host: String,

    // --- Timing ---
    /// Absolute timestamp in nanoseconds since Unix epoch.
    pub start_time_ns: u64,
    /// Duration in microseconds.
    pub duration_us: u64,

    // --- Network ---
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// Resolved by ingestion pipeline: dst_ip → service_id. Empty if external.
    pub dst_service_id: String,

    // --- Metadata ---
    pub host_id: String,
    pub container_id: String,
    pub is_error: bool,
    pub is_root: bool,

    // --- Sampling ---
    /// 1.0 = kept, 0.1 = 10% sample rate.
    pub sample_rate: f32,
}

impl SpanEvent {
    /// Returns the start time as a `DateTime<Utc>`.
    pub fn start_time(&self) -> DateTime<Utc> {
        let secs = (self.start_time_ns / 1_000_000_000) as i64;
        let nanos = (self.start_time_ns % 1_000_000_000) as u32;
        DateTime::from_timestamp(secs, nanos).unwrap_or_default()
    }

    /// Returns the hex-encoded trace ID.
    pub fn trace_id_hex(&self) -> String {
        trace_id_to_hex(&self.trace_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_id_hex_roundtrip() {
        let id = generate_trace_id();
        let hex = trace_id_to_hex(&id);
        assert_eq!(hex.len(), 32);
        let decoded = hex_to_trace_id(&hex).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn hex_to_trace_id_invalid() {
        assert!(hex_to_trace_id("too_short").is_none());
        assert!(hex_to_trace_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }

    #[test]
    fn span_id_is_nonzero() {
        // Statistical test: 100 random span IDs should not all be zero
        let ids: Vec<SpanId> = (0..100).map(|_| generate_span_id()).collect();
        assert!(ids.iter().any(|&id| id != 0));
    }
}
