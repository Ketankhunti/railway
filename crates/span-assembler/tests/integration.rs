//! Integration tests for the span assembler.
//!
//! These tests simulate realistic eBPF event sequences and verify
//! that the assembler produces correct SpanEvents with proper
//! trace IDs, parent-child relationships, timing, and metadata.

use std::net::{IpAddr, Ipv4Addr};

use rail_obs_common::service::{ServiceMapping, ServiceMeta};
use rail_obs_span_assembler::*;

// --- Test helpers ---

const SVC_A_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2));
const SVC_B_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 17, 0, 3));
const SVC_C_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 17, 0, 4));
const NETNS_A: u32 = 1001;
const NETNS_B: u32 = 1002;
const NETNS_C: u32 = 1003;

fn http_request(method: &str, path: &str, host: &str) -> Vec<u8> {
    format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        method, path, host
    )
    .into_bytes()
}

fn http_request_with_traceparent(
    method: &str,
    path: &str,
    host: &str,
    traceparent: &str,
) -> Vec<u8> {
    format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\ntraceparent: {}\r\n\r\n",
        method, path, host, traceparent
    )
    .into_bytes()
}

fn http_response(status: u16, reason: &str) -> Vec<u8> {
    format!("HTTP/1.1 {} {}\r\nContent-Length: 0\r\n\r\n", status, reason).into_bytes()
}

fn make_mapping() -> ServiceMapping {
    let mut m = ServiceMapping::new();
    m.register(
        NETNS_A,
        ServiceMeta {
            project_id: "proj_demo".into(),
            service_id: "svc_api_gateway".into(),
            service_name: "api-gateway".into(),
            environment_id: "production".into(),
            container_id: "ctr_a".into(),
        },
    );
    m.register(
        NETNS_B,
        ServiceMeta {
            project_id: "proj_demo".into(),
            service_id: "svc_user_service".into(),
            service_name: "user-service".into(),
            environment_id: "production".into(),
            container_id: "ctr_b".into(),
        },
    );
    m.register(
        NETNS_C,
        ServiceMeta {
            project_id: "proj_demo".into(),
            service_id: "svc_payment".into(),
            service_name: "payment-service".into(),
            environment_id: "production".into(),
            container_id: "ctr_c".into(),
        },
    );
    m
}

fn make_assembler() -> SpanAssembler {
    SpanAssembler::new(
        AssemblerConfig {
            max_connections: 1000,
            max_pending_per_conn: 32,
            host_id: "test-host".into(),
        },
        make_mapping(),
    )
}

// --- Tests ---

#[test]
fn single_request_response_client_side() {
    // Simulates: Client (A) sends GET, receives 200 OK.
    // Spans should be produced on the client-side response recv.
    let mut asm = make_assembler();

    // 1. Client connects
    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    assert_eq!(asm.active_connections(), 1);

    // 2. Client sends GET request
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_100_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("GET", "/api/users", "user-service:8002"),
    });
    assert!(spans.is_empty(), "no span yet — waiting for response");

    // 3. Client receives 200 OK
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_500_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });

    assert_eq!(spans.len(), 1);
    let span = &spans[0];

    assert_eq!(span.http_method, "GET");
    assert_eq!(span.http_path, "/api/users");
    assert_eq!(span.http_status, 200);
    assert!(!span.is_error);
    assert_eq!(span.host_id, "test-host");

    // Duration should be 400µs (1_500_000 - 1_100_000 = 400_000ns = 400µs)
    assert_eq!(span.duration_us, 400);

    // Service metadata should be resolved from NETNS_A
    assert_eq!(span.project_id, "proj_demo");
    assert_eq!(span.service_id, "svc_api_gateway");
    assert_eq!(span.container_id, "ctr_a");

    assert_eq!(asm.spans_emitted(), 1);
    assert_eq!(asm.events_processed(), 3);
}

#[test]
fn server_side_request_response() {
    // Server (B) receives a request and sends a response.
    let mut asm = make_assembler();

    // 1. Server accepts connection
    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 200,
        netns: NETNS_B,
        fd: 10,
        kind: TcpEventKind::Accept,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    // 2. Server receives request
    asm.process_event(&TcpEvent {
        timestamp_ns: 1_100_000,
        pid: 200,
        netns: NETNS_B,
        fd: 10,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("POST", "/api/users", "user-service:8002"),
    });

    // 3. Server sends response
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_300_000,
        pid: 200,
        netns: NETNS_B,
        fd: 10,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(201, "Created"),
    });

    assert_eq!(spans.len(), 1);
    let span = &spans[0];
    assert_eq!(span.http_method, "POST");
    assert_eq!(span.http_path, "/api/users");
    assert_eq!(span.http_status, 201);
    assert!(!span.is_error);
    assert_eq!(span.duration_us, 200); // 200µs
    assert_eq!(span.service_id, "svc_user_service");
}

#[test]
fn keep_alive_sequential_requests() {
    // HTTP/1.1 keep-alive: 3 sequential requests on the same connection.
    let mut asm = make_assembler();

    // Connect
    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    let paths = ["/api/users/1", "/api/users/2", "/api/users/3"];
    let mut all_spans = vec![];

    for (i, path) in paths.iter().enumerate() {
        let t_base = (i as u64 + 1) * 1_000_000;

        // Send request
        asm.process_event(&TcpEvent {
            timestamp_ns: t_base,
            pid: 100,
            netns: NETNS_A,
            fd: 5,
            kind: TcpEventKind::Data(Direction::Send),
            src_ip: SVC_A_IP,
            src_port: 45678,
            dst_ip: SVC_B_IP,
            dst_port: 8002,
            payload: http_request("GET", path, "user-service"),
        });

        // Receive response
        let spans = asm.process_event(&TcpEvent {
            timestamp_ns: t_base + 500_000, // 500µs later
            pid: 100,
            netns: NETNS_A,
            fd: 5,
            kind: TcpEventKind::Data(Direction::Recv),
            src_ip: SVC_A_IP,
            src_port: 45678,
            dst_ip: SVC_B_IP,
            dst_port: 8002,
            payload: http_response(200, "OK"),
        });

        all_spans.extend(spans);
    }

    assert_eq!(all_spans.len(), 3);
    assert_eq!(all_spans[0].http_path, "/api/users/1");
    assert_eq!(all_spans[1].http_path, "/api/users/2");
    assert_eq!(all_spans[2].http_path, "/api/users/3");

    // Each should have 500µs duration
    for span in &all_spans {
        assert_eq!(span.duration_us, 500);
        assert_eq!(span.http_status, 200);
    }

    // All should have the same trace_id (same connection, sequential)
    // Actually no — each is a new root trace since no traceparent is propagated
    // They CAN have different trace IDs (each request is independent)
    assert_eq!(asm.spans_emitted(), 3);
}

#[test]
fn pipelining_fifo_matching() {
    // HTTP/1.1 pipelining: 2 requests sent before any response.
    // Responses must match in FIFO order.
    let mut asm = make_assembler();

    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    // Send request 1
    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("GET", "/first", "svc"),
    });

    // Send request 2 (before response to request 1!)
    asm.process_event(&TcpEvent {
        timestamp_ns: 1_100_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("GET", "/second", "svc"),
    });

    // Response 1 (matches /first — FIFO)
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_500_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].http_path, "/first");
    assert_eq!(spans[0].duration_us, 500); // 1_500_000 - 1_000_000

    // Response 2 (matches /second — FIFO)
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_800_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].http_path, "/second");
    assert_eq!(spans[0].duration_us, 700); // 1_800_000 - 1_100_000
}

#[test]
fn error_response_marks_span() {
    let mut asm = make_assembler();

    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("POST", "/api/pay", "pay-svc"),
    });

    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 2_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(500, "Internal Server Error"),
    });

    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].http_status, 500);
    assert!(spans[0].is_error);
}

#[test]
fn traceparent_extraction() {
    // Request with a traceparent header — should extract trace context.
    let mut asm = make_assembler();

    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    let traceparent = "00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01";

    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request_with_traceparent("GET", "/api/users", "svc", traceparent),
    });

    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_500_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });

    assert_eq!(spans.len(), 1);
    let span = &spans[0];

    // Trace ID should be extracted from traceparent
    let trace_hex = rail_obs_common::span::trace_id_to_hex(&span.trace_id);
    assert_eq!(trace_hex, "4bf92f3577b58681a1038a16d442e168");

    // Parent span ID should be extracted from traceparent
    let expected_parent = u64::from_be_bytes([0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]);
    assert_eq!(span.parent_span_id, expected_parent);

    // Span's own span_id should be a NEW generated value (not the parent)
    assert_ne!(span.span_id, expected_parent);
    assert_ne!(span.span_id, 0);
}

#[test]
fn connection_close_emits_incomplete_spans() {
    let mut asm = make_assembler();

    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    // Send request but never get a response
    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("GET", "/api/timeout", "svc"),
    });

    // Connection closes
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 30_000_000_000, // 30 seconds later
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Close,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].http_path, "/api/timeout");
    assert_eq!(spans[0].http_status, 0); // unknown — no response
    assert_eq!(asm.active_connections(), 0);
}

#[test]
fn non_http_traffic_skipped() {
    let mut asm = make_assembler();

    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 5432,
        payload: vec![],
    });

    // PostgreSQL wire protocol (not HTTP)
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 5432,
        payload: vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f], // PG startup
    });

    assert!(spans.is_empty());
    assert_eq!(asm.non_http_skipped(), 1);
    assert_eq!(asm.spans_emitted(), 0);
}

#[test]
fn concurrent_connections_different_ports() {
    // Service A makes 3 concurrent connections to Service B (different ephemeral ports).
    // Each should be tracked independently.
    let mut asm = make_assembler();

    let ports = [45678u16, 45679, 45680];

    // Connect all three
    for port in ports {
        asm.process_event(&TcpEvent {
            timestamp_ns: 0,
            pid: 100,
            netns: NETNS_A,
            fd: port as u32,
            kind: TcpEventKind::Connect,
            src_ip: SVC_A_IP,
            src_port: port,
            dst_ip: SVC_B_IP,
            dst_port: 8002,
            payload: vec![],
        });
    }

    assert_eq!(asm.active_connections(), 3);

    // Send requests on all three
    for (i, port) in ports.iter().enumerate() {
        asm.process_event(&TcpEvent {
            timestamp_ns: 1_000_000 + i as u64 * 100_000,
            pid: 100,
            netns: NETNS_A,
            fd: *port as u32,
            kind: TcpEventKind::Data(Direction::Send),
            src_ip: SVC_A_IP,
            src_port: *port,
            dst_ip: SVC_B_IP,
            dst_port: 8002,
            payload: http_request("GET", &format!("/api/item/{}", i), "svc"),
        });
    }

    // Responses arrive in a different order (port 45680 first)
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 2_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 45680,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45680,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].http_path, "/api/item/2"); // port 45680 was the 3rd request (i=2)

    // Port 45678 responds
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 2_500_000,
        pid: 100,
        netns: NETNS_A,
        fd: 45678,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].http_path, "/api/item/0");

    assert_eq!(asm.spans_emitted(), 2);
}

#[test]
fn same_host_trace_correlation() {
    // Service A (client) → Service B (server) on the same host.
    // The server should inherit the trace context from the client's request.
    let mut asm = make_assembler();

    // 1. Client connects
    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    // 2. Server accepts
    asm.process_event(&TcpEvent {
        timestamp_ns: 100,
        pid: 200,
        netns: NETNS_B,
        fd: 10,
        kind: TcpEventKind::Accept,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    // 3. Client sends request
    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("GET", "/api/users", "user-service"),
    });

    // 4. Server receives request (same 4-tuple, the reverse side can be matched)
    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_500,
        pid: 200,
        netns: NETNS_B,
        fd: 10,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("GET", "/api/users", "user-service"),
    });

    // 5. Server sends response
    let server_spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_300_000,
        pid: 200,
        netns: NETNS_B,
        fd: 10,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });

    // 6. Client receives response
    let client_spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_500_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });

    // Both sides should produce spans
    assert_eq!(server_spans.len(), 1, "server should emit span on response send");
    assert_eq!(client_spans.len(), 1, "client should emit span on response recv");

    let server_span = &server_spans[0];
    let client_span = &client_spans[0];

    // Both should reference the same trace
    assert_eq!(server_span.trace_id, client_span.trace_id);

    // Server span should be a child of the client span
    assert_eq!(server_span.parent_span_id, client_span.span_id);

    // Service metadata should reflect correct sides
    assert_eq!(server_span.service_id, "svc_user_service");
    assert_eq!(client_span.service_id, "svc_api_gateway");
}

#[test]
fn unknown_service_graceful_handling() {
    // Events from an unknown namespace should still produce spans with "unknown" metadata.
    let mut asm = make_assembler();

    let unknown_netns = 9999u32;

    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 300,
        netns: unknown_netns,
        fd: 7,
        kind: TcpEventKind::Connect,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
        src_port: 55555,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 300,
        netns: unknown_netns,
        fd: 7,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
        src_port: 55555,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_request("GET", "/test", "svc"),
    });

    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 2_000_000,
        pid: 300,
        netns: unknown_netns,
        fd: 7,
        kind: TcpEventKind::Data(Direction::Recv),
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
        src_port: 55555,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: http_response(200, "OK"),
    });

    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].project_id, "unknown");
    assert_eq!(spans[0].service_id, "unknown");
    assert!(spans[0].container_id.starts_with("netns-"));
}

#[test]
fn empty_payload_ignored() {
    let mut asm = make_assembler();

    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    // Empty data event (e.g., TCP ACK with no payload)
    let spans = asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    assert!(spans.is_empty());
    assert_eq!(asm.non_http_skipped(), 0); // empty is not "non-http", just ignored
}

#[test]
fn metrics_tracking() {
    let mut asm = make_assembler();

    assert_eq!(asm.events_processed(), 0);
    assert_eq!(asm.spans_emitted(), 0);
    assert_eq!(asm.active_connections(), 0);

    asm.process_event(&TcpEvent {
        timestamp_ns: 0,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Connect,
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![],
    });

    assert_eq!(asm.events_processed(), 1);
    assert_eq!(asm.active_connections(), 1);

    asm.process_event(&TcpEvent {
        timestamp_ns: 1_000_000,
        pid: 100,
        netns: NETNS_A,
        fd: 5,
        kind: TcpEventKind::Data(Direction::Send),
        src_ip: SVC_A_IP,
        src_port: 45678,
        dst_ip: SVC_B_IP,
        dst_port: 8002,
        payload: vec![0xFF, 0xFE, 0xFD], // not HTTP
    });

    assert_eq!(asm.events_processed(), 2);
    assert_eq!(asm.non_http_skipped(), 1);
}
