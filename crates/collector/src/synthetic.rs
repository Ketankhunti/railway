//! Synthetic TCP event source for testing.
//!
//! Generates realistic HTTP traffic patterns that simulate 3-4 services
//! calling each other. Only THIS module is synthetic — everything downstream
//! (span assembler, ingestion, alerting, API) runs real production code.
//!
//! The synthetic source generates:
//! - API Gateway (port 8001) → User Service (port 8002)
//! - API Gateway (port 8001) → Payment Service (port 8003)
//! - User Service (port 8002) → DB Service (port 8004)
//! - Occasional errors (500s from Payment Service)
//! - Occasional latency spikes (on DB Service)

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::mpsc;

use rail_obs_span_assembler::{TcpEvent, TcpEventKind, Direction};

/// Service definitions for the synthetic topology.
struct SyntheticService {
    name: &'static str,
    ip: Ipv4Addr,
    port: u16,
    netns: u32,
}

const API_GATEWAY: SyntheticService = SyntheticService {
    name: "api-gateway",
    ip: Ipv4Addr::new(172, 17, 0, 2),
    port: 8001,
    netns: 1001,
};

const USER_SERVICE: SyntheticService = SyntheticService {
    name: "user-service",
    ip: Ipv4Addr::new(172, 17, 0, 3),
    port: 8002,
    netns: 1002,
};

const PAYMENT_SERVICE: SyntheticService = SyntheticService {
    name: "payment-service",
    ip: Ipv4Addr::new(172, 17, 0, 4),
    port: 8003,
    netns: 1003,
};

const DB_SERVICE: SyntheticService = SyntheticService {
    name: "db-service",
    ip: Ipv4Addr::new(172, 17, 0, 5),
    port: 8004,
    netns: 1004,
};

/// Request template for generating realistic HTTP traffic.
struct RequestTemplate {
    method: &'static str,
    path: &'static str,
    from: &'static SyntheticService,
    to: &'static SyntheticService,
    /// Base latency in microseconds.
    base_latency_us: u64,
    /// Probability of error (0.0 - 1.0).
    error_rate: f64,
    /// Relative frequency weight.
    weight: u32,
}

/// All request patterns in the synthetic topology.
const PATTERNS: &[RequestTemplate] = &[
    // API Gateway → User Service
    RequestTemplate {
        method: "GET",
        path: "/api/users",
        from: &API_GATEWAY,
        to: &USER_SERVICE,
        base_latency_us: 15_000,
        error_rate: 0.01,
        weight: 30,
    },
    RequestTemplate {
        method: "GET",
        path: "/api/users/42",
        from: &API_GATEWAY,
        to: &USER_SERVICE,
        base_latency_us: 8_000,
        error_rate: 0.005,
        weight: 40,
    },
    RequestTemplate {
        method: "POST",
        path: "/api/users",
        from: &API_GATEWAY,
        to: &USER_SERVICE,
        base_latency_us: 25_000,
        error_rate: 0.02,
        weight: 10,
    },
    // API Gateway → Payment Service
    RequestTemplate {
        method: "POST",
        path: "/api/payments/charge",
        from: &API_GATEWAY,
        to: &PAYMENT_SERVICE,
        base_latency_us: 80_000,
        error_rate: 0.05, // payments fail more often
        weight: 15,
    },
    RequestTemplate {
        method: "GET",
        path: "/api/payments/history",
        from: &API_GATEWAY,
        to: &PAYMENT_SERVICE,
        base_latency_us: 30_000,
        error_rate: 0.01,
        weight: 10,
    },
    // User Service → DB Service
    RequestTemplate {
        method: "GET",
        path: "/internal/db/query",
        from: &USER_SERVICE,
        to: &DB_SERVICE,
        base_latency_us: 5_000,
        error_rate: 0.001,
        weight: 50,
    },
    RequestTemplate {
        method: "POST",
        path: "/internal/db/insert",
        from: &USER_SERVICE,
        to: &DB_SERVICE,
        base_latency_us: 12_000,
        error_rate: 0.002,
        weight: 20,
    },
];

/// Configuration for the synthetic source.
#[derive(Debug, Clone)]
pub struct SyntheticConfig {
    /// Target requests per second.
    pub rps: u32,
    /// Whether to inject occasional latency spikes.
    pub inject_spikes: bool,
    /// Spike multiplier (e.g., 10x normal latency).
    pub spike_multiplier: u64,
    /// Probability of a spike per request.
    pub spike_probability: f64,
}

impl Default for SyntheticConfig {
    fn default() -> Self {
        Self {
            rps: 50,
            inject_spikes: true,
            spike_multiplier: 10,
            spike_probability: 0.02,
        }
    }
}

/// Generate a stream of synthetic TcpEvents.
///
/// Sends events to the provided channel. Runs until the channel is closed.
pub async fn run_synthetic_source(
    config: SyntheticConfig,
    tx: mpsc::Sender<Vec<TcpEvent>>,
) {
    let mut rng = StdRng::from_entropy();
    let mut next_port: u16 = 40000;
    let mut timestamp_ns: u64 = 1_000_000_000; // start at 1 second
    let interval = Duration::from_micros(1_000_000 / config.rps as u64);

    tracing::info!(
        rps = config.rps,
        spikes = config.inject_spikes,
        "synthetic source started"
    );

    loop {
        // Pick a random request pattern based on weights
        let total_weight: u32 = PATTERNS.iter().map(|p| p.weight).sum();
        let roll = rng.gen_range(0..total_weight);
        let mut cumulative = 0;
        let pattern = PATTERNS.iter().find(|p| {
            cumulative += p.weight;
            roll < cumulative
        }).unwrap_or(&PATTERNS[0]);

        // Assign ephemeral port
        let ephemeral_port = next_port;
        next_port = if next_port >= 60000 { 40000 } else { next_port + 1 };

        // Compute latency with optional spike
        let is_spike = config.inject_spikes && rng.gen_bool(config.spike_probability);
        let latency_us = if is_spike {
            pattern.base_latency_us * config.spike_multiplier
        } else {
            // Add ±30% jitter
            let jitter = rng.gen_range(0.7..1.3);
            (pattern.base_latency_us as f64 * jitter) as u64
        };

        // Determine if this request errors
        let is_error = rng.gen_bool(pattern.error_rate);
        let status = if is_error { 500 } else { 200 };

        // Generate the full event sequence for a request:
        // Client: CONNECT → SEND(request) → RECV(response) → CLOSE
        // Server: ACCEPT → RECV(request) → SEND(response) → CLOSE
        let events = generate_request_events(
            pattern,
            ephemeral_port,
            timestamp_ns,
            latency_us,
            status,
        );

        if tx.send(events).await.is_err() {
            tracing::info!("synthetic source channel closed, stopping");
            break;
        }

        timestamp_ns += latency_us * 1000; // advance time by the request duration
        timestamp_ns += rng.gen_range(0..5_000_000); // 0-5ms inter-request gap

        tokio::time::sleep(interval).await;
    }
}

/// Generate all TcpEvents for a single HTTP request/response cycle.
fn generate_request_events(
    pattern: &RequestTemplate,
    ephemeral_port: u16,
    start_ns: u64,
    latency_us: u64,
    status: u16,
) -> Vec<TcpEvent> {
    let client_ip = IpAddr::V4(pattern.from.ip);
    let server_ip = IpAddr::V4(pattern.to.ip);
    let server_port = pattern.to.port;
    let client_netns = pattern.from.netns;
    let server_netns = pattern.to.netns;

    let request_payload = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        pattern.method, pattern.path, pattern.to.name, server_port
    ).into_bytes();

    let status_text = match status {
        200 => "OK",
        201 => "Created",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let response_payload = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\n\r\n",
        status, status_text
    ).into_bytes();

    let latency_ns = latency_us * 1000;

    vec![
        // 1. Client connects
        TcpEvent {
            timestamp_ns: start_ns,
            pid: client_netns * 100,
            netns: client_netns,
            fd: ephemeral_port as u32,
            kind: TcpEventKind::Connect,
            src_ip: client_ip,
            src_port: ephemeral_port,
            dst_ip: server_ip,
            dst_port: server_port,
            payload: vec![],
        },
        // 2. Server accepts
        TcpEvent {
            timestamp_ns: start_ns + 100_000, // 100µs later
            pid: server_netns * 100,
            netns: server_netns,
            fd: server_port as u32 + 1000,
            kind: TcpEventKind::Accept,
            src_ip: client_ip,
            src_port: ephemeral_port,
            dst_ip: server_ip,
            dst_port: server_port,
            payload: vec![],
        },
        // 3. Client sends request
        TcpEvent {
            timestamp_ns: start_ns + 200_000,
            pid: client_netns * 100,
            netns: client_netns,
            fd: ephemeral_port as u32,
            kind: TcpEventKind::Data(Direction::Send),
            src_ip: client_ip,
            src_port: ephemeral_port,
            dst_ip: server_ip,
            dst_port: server_port,
            payload: request_payload.clone(),
        },
        // 4. Server receives request
        TcpEvent {
            timestamp_ns: start_ns + 300_000,
            pid: server_netns * 100,
            netns: server_netns,
            fd: server_port as u32 + 1000,
            kind: TcpEventKind::Data(Direction::Recv),
            src_ip: client_ip,
            src_port: ephemeral_port,
            dst_ip: server_ip,
            dst_port: server_port,
            payload: request_payload,
        },
        // 5. Server sends response (after processing)
        TcpEvent {
            timestamp_ns: start_ns + latency_ns - 200_000,
            pid: server_netns * 100,
            netns: server_netns,
            fd: server_port as u32 + 1000,
            kind: TcpEventKind::Data(Direction::Send),
            src_ip: client_ip,
            src_port: ephemeral_port,
            dst_ip: server_ip,
            dst_port: server_port,
            payload: response_payload.clone(),
        },
        // 6. Client receives response
        TcpEvent {
            timestamp_ns: start_ns + latency_ns - 100_000,
            pid: client_netns * 100,
            netns: client_netns,
            fd: ephemeral_port as u32,
            kind: TcpEventKind::Data(Direction::Recv),
            src_ip: client_ip,
            src_port: ephemeral_port,
            dst_ip: server_ip,
            dst_port: server_port,
            payload: response_payload,
        },
        // 7. Client closes
        TcpEvent {
            timestamp_ns: start_ns + latency_ns,
            pid: client_netns * 100,
            netns: client_netns,
            fd: ephemeral_port as u32,
            kind: TcpEventKind::Close,
            src_ip: client_ip,
            src_port: ephemeral_port,
            dst_ip: server_ip,
            dst_port: server_port,
            payload: vec![],
        },
    ]
}

/// Returns the service metadata mapping for the synthetic topology.
pub fn synthetic_service_mapping() -> rail_obs_common::service::ServiceMapping {
    use rail_obs_common::service::{ServiceMapping, ServiceMeta};

    let mut m = ServiceMapping::new();

    for (svc, netns_id) in [
        (&API_GATEWAY, API_GATEWAY.netns),
        (&USER_SERVICE, USER_SERVICE.netns),
        (&PAYMENT_SERVICE, PAYMENT_SERVICE.netns),
        (&DB_SERVICE, DB_SERVICE.netns),
    ] {
        m.register(netns_id, ServiceMeta {
            project_id: "proj_demo".into(),
            service_id: format!("svc_{}", svc.name.replace('-', "_")),
            service_name: svc.name.to_string(),
            environment_id: "production".into(),
            container_id: format!("ctr_{}", svc.name),
        });
    }

    m
}
