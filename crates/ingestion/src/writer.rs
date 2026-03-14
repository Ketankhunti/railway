//! ClickHouse row type for span insertion.

use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::Serialize;
use std::net::Ipv4Addr;

use rail_obs_common::span::SpanEvent;

use crate::route::normalize_route;

/// A row in the ClickHouse `spans` table.
/// Field order and types must match the CREATE TABLE schema exactly.
#[derive(Debug, Clone, Serialize, Row)]
pub struct ClickHouseRow {
    pub trace_id: String,           // FixedString(32) — hex
    pub span_id: u64,
    pub parent_span_id: u64,

    pub project_id: String,
    pub service_id: String,
    pub environment_id: String,

    pub http_method: String,
    pub http_path: String,
    pub http_route: String,
    pub http_status: u16,
    pub http_host: String,

    pub start_time: i64,            // DateTime64(6) as microseconds since epoch
    pub duration_us: u64,

    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,

    pub dst_service_id: String,

    pub host_id: String,
    pub container_id: String,
    pub is_error: u8,
    pub is_root: u8,
    pub sample_rate: f32,
}

impl ClickHouseRow {
    /// Convert a SpanEvent to a ClickHouseRow, applying route normalization.
    pub fn from_span(span: &SpanEvent) -> Self {
        let http_route = if span.http_route.is_empty() {
            normalize_route(&span.http_path)
        } else {
            span.http_route.clone()
        };

        // Convert nanoseconds to microseconds for DateTime64(6)
        let start_time_us = (span.start_time_ns / 1_000) as i64;

        // Extract IPv4 addresses (fallback to 0.0.0.0 for IPv6 in prototype)
        let src_ip = match span.src_ip {
            std::net::IpAddr::V4(v4) => v4,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let dst_ip = match span.dst_ip {
            std::net::IpAddr::V4(v4) => v4,
            _ => Ipv4Addr::UNSPECIFIED,
        };

        Self {
            trace_id: rail_obs_common::span::trace_id_to_hex(&span.trace_id),
            span_id: span.span_id,
            parent_span_id: span.parent_span_id,
            project_id: span.project_id.clone(),
            service_id: span.service_id.clone(),
            environment_id: span.environment_id.clone(),
            http_method: span.http_method.clone(),
            http_path: span.http_path.clone(),
            http_route,
            http_status: span.http_status,
            http_host: span.http_host.clone(),
            start_time: start_time_us,
            duration_us: span.duration_us,
            src_ip,
            src_port: span.src_port,
            dst_ip,
            dst_port: span.dst_port,
            dst_service_id: span.dst_service_id.clone(),
            host_id: span.host_id.clone(),
            container_id: span.container_id.clone(),
            is_error: span.is_error as u8,
            is_root: span.is_root as u8,
            sample_rate: span.sample_rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rail_obs_common::span::{generate_trace_id, generate_span_id};
    use std::net::IpAddr;

    fn test_span() -> SpanEvent {
        SpanEvent {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: 0,
            project_id: "proj_demo".into(),
            service_id: "svc_api".into(),
            environment_id: "production".into(),
            http_method: "GET".into(),
            http_path: "/api/users/123".into(),
            http_route: String::new(),
            http_status: 200,
            http_host: "api-gateway:8001".into(),
            start_time_ns: 1_000_000_000, // 1 second in ns
            duration_us: 500,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2)),
            src_port: 45678,
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 17, 0, 3)),
            dst_port: 8002,
            dst_service_id: "svc_users".into(),
            host_id: "host-1".into(),
            container_id: "ctr_abc".into(),
            is_error: false,
            is_root: true,
            sample_rate: 1.0,
        }
    }

    #[test]
    fn converts_span_to_row() {
        let span = test_span();
        let row = ClickHouseRow::from_span(&span);

        assert_eq!(row.trace_id.len(), 32);
        assert_eq!(row.project_id, "proj_demo");
        assert_eq!(row.http_method, "GET");
        assert_eq!(row.http_route, "/api/users/:id"); // normalized
        assert_eq!(row.http_status, 200);
        assert_eq!(row.is_error, 0);
        assert_eq!(row.is_root, 1);
        assert_eq!(row.start_time, 1_000_000); // ns → µs
        assert_eq!(row.duration_us, 500);
    }

    #[test]
    fn preserves_explicit_route() {
        let mut span = test_span();
        span.http_route = "/api/users/:userId".into();
        let row = ClickHouseRow::from_span(&span);
        assert_eq!(row.http_route, "/api/users/:userId");
    }

    #[test]
    fn error_flag() {
        let mut span = test_span();
        span.is_error = true;
        span.http_status = 500;
        let row = ClickHouseRow::from_span(&span);
        assert_eq!(row.is_error, 1);
    }
}
