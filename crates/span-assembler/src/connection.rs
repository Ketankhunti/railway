use std::collections::VecDeque;

use rail_obs_common::service::ConnectionKey;
use rail_obs_common::span::{SpanId, TraceId, generate_span_id};

/// A request that has been sent but not yet received a response.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub span_id: SpanId,
    pub trace_id: TraceId,
    pub parent_span_id: SpanId,
    pub method: String,
    pub path: String,
    pub host: String,
    pub start_time_ns: u64,
}

/// Per-connection state machine for HTTP/1.1 request/response tracking.
///
/// Lifecycle:
///   Connect/Accept → Idle
///   Idle + Send(request) → has pending request in queue
///   Pending + Recv(response) → pop pending, emit span, back to idle
///   Close → emit any pending as incomplete, remove connection
///
/// Supports HTTP/1.1 keep-alive (sequential requests) and pipelining
/// (multiple requests before any response — FIFO matching).
#[derive(Debug)]
pub struct ConnectionState {
    /// The 4-tuple identifying this connection.
    pub key: ConnectionKey,

    /// Network namespace of the client side (the one that called connect).
    pub client_netns: u32,
    /// Network namespace of the server side (the one that called accept).
    /// 0 if not yet known (e.g., cross-host where we only see one side).
    pub server_netns: u32,

    /// The active trace context for this connection.
    /// Set when we see the first inbound request on a server-side connection.
    pub active_trace_id: Option<TraceId>,
    /// The span ID of the currently active inbound request on this connection.
    pub active_span_id: Option<SpanId>,

    /// Queue of requests sent but not yet responded to.
    /// FIFO order — HTTP/1.1 guarantees responses in request order.
    pub pending_requests: VecDeque<PendingRequest>,

    /// Timestamp of connection establishment.
    pub connect_time_ns: u64,

    /// Total bytes sent on this connection.
    pub bytes_sent: u64,
    /// Total bytes received on this connection.
    pub bytes_recv: u64,
}

impl ConnectionState {
    /// Create a new connection state for an outbound connection (client side).
    pub fn new_client(key: ConnectionKey, client_netns: u32, timestamp_ns: u64) -> Self {
        Self {
            key,
            client_netns,
            server_netns: 0,
            active_trace_id: None,
            active_span_id: None,
            pending_requests: VecDeque::new(),
            connect_time_ns: timestamp_ns,
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }

    /// Create a new connection state for an inbound connection (server side).
    pub fn new_server(key: ConnectionKey, server_netns: u32, timestamp_ns: u64) -> Self {
        Self {
            key,
            client_netns: 0,
            server_netns,
            active_trace_id: None,
            active_span_id: None,
            pending_requests: VecDeque::new(),
            connect_time_ns: timestamp_ns,
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }

    /// Push a new pending request onto the queue.
    pub fn push_request(&mut self, req: PendingRequest) {
        self.pending_requests.push_back(req);
    }

    /// Pop the oldest pending request (FIFO — matches HTTP/1.1 response order).
    pub fn pop_request(&mut self) -> Option<PendingRequest> {
        self.pending_requests.pop_front()
    }

    /// Returns true if there are pending requests awaiting responses.
    pub fn has_pending(&self) -> bool {
        !self.pending_requests.is_empty()
    }

    /// Returns the number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Set the active trace context for this connection.
    pub fn set_trace_context(&mut self, trace_id: TraceId, span_id: SpanId) {
        self.active_trace_id = Some(trace_id);
        self.active_span_id = Some(span_id);
    }

    /// Generate a new child span ID under the current trace context.
    /// Returns (trace_id, new_span_id, parent_span_id).
    /// If no trace context is set, returns None.
    pub fn new_child_span(&self) -> Option<(TraceId, SpanId, SpanId)> {
        let trace_id = self.active_trace_id?;
        let parent = self.active_span_id?;
        Some((trace_id, generate_span_id(), parent))
    }

    /// Drain all pending requests as incomplete (for connection close).
    pub fn drain_pending(&mut self) -> Vec<PendingRequest> {
        self.pending_requests.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use rail_obs_common::span::generate_trace_id;

    fn test_key() -> ConnectionKey {
        ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2)),
            45678,
            IpAddr::V4(Ipv4Addr::new(172, 17, 0, 3)),
            8002,
        )
    }

    #[test]
    fn new_client_connection() {
        let conn = ConnectionState::new_client(test_key(), 1001, 1_000_000);
        assert_eq!(conn.client_netns, 1001);
        assert_eq!(conn.server_netns, 0);
        assert!(!conn.has_pending());
        assert_eq!(conn.pending_count(), 0);
        assert!(conn.active_trace_id.is_none());
    }

    #[test]
    fn new_server_connection() {
        let conn = ConnectionState::new_server(test_key(), 2002, 2_000_000);
        assert_eq!(conn.client_netns, 0);
        assert_eq!(conn.server_netns, 2002);
    }

    #[test]
    fn push_pop_fifo_order() {
        let mut conn = ConnectionState::new_client(test_key(), 1001, 0);

        conn.push_request(PendingRequest {
            span_id: 100,
            trace_id: [1; 16],
            parent_span_id: 0,
            method: "GET".into(),
            path: "/first".into(),
            host: "svc".into(),
            start_time_ns: 1000,
        });
        conn.push_request(PendingRequest {
            span_id: 200,
            trace_id: [1; 16],
            parent_span_id: 0,
            method: "GET".into(),
            path: "/second".into(),
            host: "svc".into(),
            start_time_ns: 2000,
        });

        assert_eq!(conn.pending_count(), 2);
        assert!(conn.has_pending());

        let first = conn.pop_request().unwrap();
        assert_eq!(first.path, "/first");
        assert_eq!(first.span_id, 100);

        let second = conn.pop_request().unwrap();
        assert_eq!(second.path, "/second");
        assert_eq!(second.span_id, 200);

        assert!(!conn.has_pending());
        assert!(conn.pop_request().is_none());
    }

    #[test]
    fn trace_context_management() {
        let mut conn = ConnectionState::new_client(test_key(), 1001, 0);

        assert!(conn.new_child_span().is_none());

        let trace_id = generate_trace_id();
        conn.set_trace_context(trace_id, 42);

        let (child_trace, child_span, parent) = conn.new_child_span().unwrap();
        assert_eq!(child_trace, trace_id);
        assert_eq!(parent, 42);
        assert_ne!(child_span, 0);
        assert_ne!(child_span, 42);
    }

    #[test]
    fn drain_pending_on_close() {
        let mut conn = ConnectionState::new_client(test_key(), 1001, 0);

        for i in 0..5 {
            conn.push_request(PendingRequest {
                span_id: i,
                trace_id: [1; 16],
                parent_span_id: 0,
                method: "GET".into(),
                path: format!("/req-{}", i),
                host: "svc".into(),
                start_time_ns: i as u64 * 1000,
            });
        }

        assert_eq!(conn.pending_count(), 5);

        let drained = conn.drain_pending();
        assert_eq!(drained.len(), 5);
        assert_eq!(drained[0].path, "/req-0");
        assert_eq!(drained[4].path, "/req-4");
        assert!(!conn.has_pending());
    }
}
