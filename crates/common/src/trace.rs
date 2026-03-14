use serde::{Deserialize, Serialize};

/// W3C Trace Context (traceparent header).
/// Format: version-trace_id-parent_id-trace_flags
/// Example: 00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    pub version: u8,
    pub trace_id: [u8; 16],
    pub parent_id: [u8; 8],
    pub trace_flags: u8,
}

impl TraceContext {
    /// Parse a W3C traceparent header value.
    ///
    /// Format: `{version}-{trace_id}-{parent_id}-{trace_flags}`
    /// Example: `00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01`
    pub fn parse(value: &str) -> Option<TraceContext> {
        let parts: Vec<&str> = value.trim().split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = u8::from_str_radix(parts[0], 16).ok()?;
        if parts[1].len() != 32 || parts[2].len() != 16 || parts[3].len() != 2 {
            return None;
        }

        let mut trace_id = [0u8; 16];
        for i in 0..16 {
            trace_id[i] = u8::from_str_radix(&parts[1][i * 2..i * 2 + 2], 16).ok()?;
        }

        let mut parent_id = [0u8; 8];
        for i in 0..8 {
            parent_id[i] = u8::from_str_radix(&parts[2][i * 2..i * 2 + 2], 16).ok()?;
        }

        let trace_flags = u8::from_str_radix(parts[3], 16).ok()?;

        // Validate: trace_id and parent_id must not be all zeros
        if trace_id == [0u8; 16] || parent_id == [0u8; 8] {
            return None;
        }

        Some(TraceContext {
            version,
            trace_id,
            parent_id,
            trace_flags,
        })
    }

    /// Returns the parent_id as a u64 span ID.
    pub fn parent_span_id(&self) -> u64 {
        u64::from_be_bytes(self.parent_id)
    }

    /// Returns true if the sampled flag is set.
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_traceparent() {
        let ctx = TraceContext::parse(
            "00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01",
        )
        .unwrap();

        assert_eq!(ctx.version, 0);
        assert_eq!(ctx.trace_flags, 1);
        assert!(ctx.is_sampled());
        assert_ne!(ctx.parent_span_id(), 0);

        // Verify trace_id bytes
        let expected_trace_id_hex = "4bf92f3577b58681a1038a16d442e168";
        let actual_hex: String = ctx.trace_id.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(actual_hex, expected_trace_id_hex);
    }

    #[test]
    fn parse_unsampled() {
        let ctx = TraceContext::parse(
            "00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-00",
        )
        .unwrap();
        assert!(!ctx.is_sampled());
    }

    #[test]
    fn reject_all_zero_trace_id() {
        assert!(TraceContext::parse(
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
        )
        .is_none());
    }

    #[test]
    fn reject_all_zero_parent_id() {
        assert!(TraceContext::parse(
            "00-4bf92f3577b58681a1038a16d442e168-0000000000000000-01"
        )
        .is_none());
    }

    #[test]
    fn reject_wrong_format() {
        assert!(TraceContext::parse("invalid").is_none());
        assert!(TraceContext::parse("00-short-00f067aa0ba902b7-01").is_none());
        assert!(TraceContext::parse("").is_none());
        assert!(TraceContext::parse("00-4bf92f35-01").is_none());
    }

    #[test]
    fn parse_with_whitespace() {
        let ctx = TraceContext::parse(
            "  00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01  ",
        );
        assert!(ctx.is_some());
    }
}
