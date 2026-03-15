use std::collections::HashMap;
use std::net::IpAddr;

use rail_obs_common::service::{ConnectionKey, ServiceMapping};
use rail_obs_common::span::{
    SpanEvent, generate_span_id, generate_trace_id,
};
use rail_obs_common::trace::TraceContext;
use rail_obs_http_parser::{is_http_request, is_http_response, parse_request, parse_response};

use crate::connection::{ConnectionState, PendingRequest};
use crate::event::{Direction, TcpEvent, TcpEventKind};

/// Composite key: (4-tuple, network namespace) to differentiate client and
/// server connections sharing the same 4-tuple on the same host.
type ConnMapKey = (ConnectionKey, u32);

/// Configuration for the span assembler.
#[derive(Debug, Clone)]
pub struct AssemblerConfig {
    /// Maximum number of tracked connections before eviction.
    pub max_connections: usize,
    /// Maximum pending requests per connection before dropping old ones.
    pub max_pending_per_conn: usize,
    /// Host identifier for metadata tagging.
    pub host_id: String,
}

impl Default for AssemblerConfig {
    fn default() -> Self {
        Self {
            max_connections: 100_000,
            max_pending_per_conn: 64,
            host_id: "unknown".into(),
        }
    }
}

/// Assembles completed SpanEvents from raw TcpEvents.
///
/// Connections are keyed by `(4-tuple, netns)`. This allows the same TCP
/// connection seen from the client container (Connect) and server container
/// (Accept) to coexist in the map when both are on the same host.
pub struct SpanAssembler {
    connections: HashMap<ConnMapKey, ConnectionState>,
    service_mapping: ServiceMapping,
    config: AssemblerConfig,

    events_processed: u64,
    spans_emitted: u64,
    non_http_skipped: u64,
}

impl SpanAssembler {
    pub fn new(config: AssemblerConfig, service_mapping: ServiceMapping) -> Self {
        Self {
            connections: HashMap::new(),
            service_mapping,
            config,
            events_processed: 0,
            spans_emitted: 0,
            non_http_skipped: 0,
        }
    }

    pub fn update_service_mapping(&mut self, mapping: ServiceMapping) {
        self.service_mapping = mapping;
    }

    pub fn process_event(&mut self, event: &TcpEvent) -> Vec<SpanEvent> {
        self.events_processed += 1;

        match event.kind {
            TcpEventKind::Connect => {
                self.handle_connect(event);
                vec![]
            }
            TcpEventKind::Accept => {
                self.handle_accept(event);
                vec![]
            }
            TcpEventKind::Data(Direction::Send) => self.handle_send(event),
            TcpEventKind::Data(Direction::Recv) => self.handle_recv(event),
            TcpEventKind::Close => self.handle_close(event),
        }
    }

    fn map_key(event: &TcpEvent) -> ConnMapKey {
        (event.connection_key(), event.netns)
    }

    fn handle_connect(&mut self, event: &TcpEvent) {
        let key = Self::map_key(event);
        self.evict_if_full();
        self.connections.insert(
            key,
            ConnectionState::new_client(event.connection_key(), event.netns, event.timestamp_ns),
        );
    }

    fn handle_accept(&mut self, event: &TcpEvent) {
        let key = Self::map_key(event);
        self.evict_if_full();
        self.connections.insert(
            key,
            ConnectionState::new_server(event.connection_key(), event.netns, event.timestamp_ns),
        );
    }

    fn handle_send(&mut self, event: &TcpEvent) -> Vec<SpanEvent> {
        let key = Self::map_key(event);

        if event.payload.is_empty() {
            // No payload (e.g., eBPF kprobe captured metadata only).
            // Still register/update the connection so CLOSE can emit a span.
            self.connections.entry(key).or_insert_with(|| {
                ConnectionState::new_client(event.connection_key(), event.netns, event.timestamp_ns)
            });
            return vec![];
        }

        if is_http_request(&event.payload) {
            self.handle_client_request(event, key);
            vec![]
        } else if is_http_response(&event.payload) {
            self.handle_server_response(event, key)
        } else {
            self.non_http_skipped += 1;
            vec![]
        }
    }

    fn handle_recv(&mut self, event: &TcpEvent) -> Vec<SpanEvent> {
        let key = Self::map_key(event);

        if event.payload.is_empty() {
            // No payload — still register connection.
            self.connections.entry(key).or_insert_with(|| {
                ConnectionState::new_server(event.connection_key(), event.netns, event.timestamp_ns)
            });
            return vec![];
        }

        if is_http_request(&event.payload) {
            self.handle_server_request(event, key);
            vec![]
        } else if is_http_response(&event.payload) {
            self.handle_client_response(event, key)
        } else {
            self.non_http_skipped += 1;
            vec![]
        }
    }

    /// Client sends an HTTP request.
    fn handle_client_request(&mut self, event: &TcpEvent, key: ConnMapKey) {
        let parsed = match parse_request(&event.payload) {
            Ok(req) => req,
            Err(_) => return,
        };

        let conn = self.connections.entry(key).or_insert_with(|| {
            ConnectionState::new_client(event.connection_key(), event.netns, event.timestamp_ns)
        });

        let (trace_id, span_id, parent_span_id) =
            if let Some(tp) = parsed.traceparent().and_then(TraceContext::parse) {
                (tp.trace_id, generate_span_id(), tp.parent_span_id())
            } else if let Some((tid, sid, pid)) = conn.new_child_span() {
                (tid, sid, pid)
            } else {
                (generate_trace_id(), generate_span_id(), 0)
            };

        if conn.pending_count() >= self.config.max_pending_per_conn {
            conn.pop_request();
        }

        conn.push_request(PendingRequest {
            span_id,
            trace_id,
            parent_span_id,
            method: parsed.method.clone(),
            path: parsed.path.clone(),
            host: parsed.host().unwrap_or("").to_string(),
            start_time_ns: event.timestamp_ns,
        });

        conn.bytes_sent += event.payload.len() as u64;
    }

    /// Server receives an HTTP request.
    /// Scans for a client-side entry with the same 4-tuple but different netns
    /// to inherit trace context for same-host correlation.
    fn handle_server_request(&mut self, event: &TcpEvent, key: ConnMapKey) {
        let parsed = match parse_request(&event.payload) {
            Ok(req) => req,
            Err(_) => return,
        };

        let conn_key = event.connection_key();

        // Resolve trace context BEFORE taking mutable entry.
        let (trace_id, span_id, parent_span_id) =
            if let Some(tp) = parsed.traceparent().and_then(TraceContext::parse) {
                (tp.trace_id, generate_span_id(), tp.parent_span_id())
            } else {
                // Look for a client-side entry with the same 4-tuple but
                // different netns (the other side of this connection on the same host).
                let found = self.connections.iter()
                    .find(|((ck, ns), _)| *ck == conn_key && *ns != event.netns)
                    .and_then(|(_, conn)| conn.pending_requests.back())
                    .map(|p| (p.trace_id, generate_span_id(), p.span_id));

                found.unwrap_or_else(|| (generate_trace_id(), generate_span_id(), 0))
            };

        let conn = self.connections.entry(key).or_insert_with(|| {
            ConnectionState::new_server(conn_key, event.netns, event.timestamp_ns)
        });

        conn.set_trace_context(trace_id, span_id);

        if conn.pending_count() >= self.config.max_pending_per_conn {
            conn.pop_request();
        }

        conn.push_request(PendingRequest {
            span_id,
            trace_id,
            parent_span_id,
            method: parsed.method.clone(),
            path: parsed.path.clone(),
            host: parsed.host().unwrap_or("").to_string(),
            start_time_ns: event.timestamp_ns,
        });

        conn.bytes_recv += event.payload.len() as u64;
    }

    /// Client receives an HTTP response → span complete.
    fn handle_client_response(&mut self, event: &TcpEvent, key: ConnMapKey) -> Vec<SpanEvent> {
        let parsed = match parse_response(&event.payload) {
            Ok(resp) => resp,
            Err(_) => return vec![],
        };

        let conn = match self.connections.get_mut(&key) {
            Some(c) => c,
            None => return vec![],
        };

        let pending = match conn.pop_request() {
            Some(p) => p,
            None => return vec![],
        };

        conn.bytes_recv += event.payload.len() as u64;

        let span = self.build_span(&pending, parsed.status_code, event.timestamp_ns, event.netns, &event.connection_key());
        self.spans_emitted += 1;
        vec![span]
    }

    /// Server sends an HTTP response → server-side span complete.
    fn handle_server_response(&mut self, event: &TcpEvent, key: ConnMapKey) -> Vec<SpanEvent> {
        let parsed = match parse_response(&event.payload) {
            Ok(resp) => resp,
            Err(_) => return vec![],
        };

        let conn = match self.connections.get_mut(&key) {
            Some(c) => c,
            None => return vec![],
        };

        let pending = match conn.pop_request() {
            Some(p) => p,
            None => return vec![],
        };

        conn.bytes_sent += event.payload.len() as u64;

        let span = self.build_span(&pending, parsed.status_code, event.timestamp_ns, event.netns, &event.connection_key());
        self.spans_emitted += 1;
        vec![span]
    }

    /// Handle connection close: emit pending as incomplete, clean up both sides.
    fn handle_close(&mut self, event: &TcpEvent) -> Vec<SpanEvent> {
        let conn_key = event.connection_key();
        let mut spans = vec![];

        // Remove all entries with the same 4-tuple (could be client + server)
        let matching_keys: Vec<ConnMapKey> = self.connections.keys()
            .filter(|(ck, _)| *ck == conn_key)
            .copied()
            .collect();

        for mk in matching_keys {
            if let Some(mut conn) = self.connections.remove(&mk) {
                let drained = conn.drain_pending();
                if drained.is_empty() {
                    // No HTTP requests were parsed on this connection (e.g., eBPF
                    // kprobes captured metadata but no payload). Emit a connection-
                    // level span so the trace pipeline still records the connection.
                    let span = self.build_connection_span(
                        &conn, event.timestamp_ns, mk.1, &conn_key,
                    );
                    spans.push(span);
                    self.spans_emitted += 1;
                } else {
                    for pending in drained {
                        let span = self.build_span(
                            &pending, 0, event.timestamp_ns, mk.1, &conn_key,
                        );
                        spans.push(span);
                        self.spans_emitted += 1;
                    }
                }
            }
        }

        spans
    }

    /// Build a connection-level span when no HTTP was parsed.
    /// Uses connection metadata (4-tuple, timing, bytes) instead of HTTP fields.
    fn build_connection_span(
        &self,
        conn: &ConnectionState,
        end_time_ns: u64,
        netns: u32,
        key: &ConnectionKey,
    ) -> SpanEvent {
        let duration_us = if end_time_ns > conn.connect_time_ns {
            (end_time_ns - conn.connect_time_ns) / 1_000
        } else {
            0
        };

        let (project_id, service_id, environment_id, container_id) =
            if let Some(meta) = self.service_mapping.resolve(netns) {
                (
                    meta.project_id.clone(),
                    meta.service_id.clone(),
                    meta.environment_id.clone(),
                    meta.container_id.clone(),
                )
            } else {
                (
                    "unknown".into(),
                    "unknown".into(),
                    "unknown".into(),
                    format!("netns-{}", netns),
                )
            };

        SpanEvent {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: 0,
            project_id,
            service_id,
            environment_id,
            http_method: "TCP".into(),
            http_path: format!("{}:{}", key.dst_ip, key.dst_port),
            http_route: String::new(),
            http_status: 0,
            http_host: format!("{}:{}", key.dst_ip, key.dst_port),
            start_time_ns: conn.connect_time_ns,
            duration_us,
            src_ip: key.src_ip,
            src_port: key.src_port,
            dst_ip: key.dst_ip,
            dst_port: key.dst_port,
            dst_service_id: String::new(),
            host_id: self.config.host_id.clone(),
            container_id,
            is_error: false,
            is_root: true,
            sample_rate: 1.0,
        }
    }

    fn build_span(
        &self,
        pending: &PendingRequest,
        status_code: u16,
        end_time_ns: u64,
        netns: u32,
        key: &ConnectionKey,
    ) -> SpanEvent {
        let duration_us = if end_time_ns > pending.start_time_ns {
            (end_time_ns - pending.start_time_ns) / 1_000
        } else {
            0
        };

        let is_error = status_code >= 400;
        let is_root = pending.parent_span_id == 0;

        let (project_id, service_id, environment_id, container_id) =
            if let Some(meta) = self.service_mapping.resolve(netns) {
                (
                    meta.project_id.clone(),
                    meta.service_id.clone(),
                    meta.environment_id.clone(),
                    meta.container_id.clone(),
                )
            } else {
                (
                    "unknown".into(),
                    "unknown".into(),
                    "unknown".into(),
                    format!("netns-{}", netns),
                )
            };

        SpanEvent {
            trace_id: pending.trace_id,
            span_id: pending.span_id,
            parent_span_id: pending.parent_span_id,
            project_id,
            service_id,
            environment_id,
            http_method: pending.method.clone(),
            http_path: pending.path.clone(),
            http_route: String::new(),
            http_status: status_code,
            http_host: pending.host.clone(),
            start_time_ns: pending.start_time_ns,
            duration_us,
            src_ip: key.src_ip,
            src_port: key.src_port,
            dst_ip: key.dst_ip,
            dst_port: key.dst_port,
            dst_service_id: String::new(),
            host_id: self.config.host_id.clone(),
            container_id,
            is_error,
            is_root,
            sample_rate: 1.0,
        }
    }

    fn evict_if_full(&mut self) {
        if self.connections.len() >= self.config.max_connections {
            tracing::warn!(connections = self.connections.len(), "connection table full, evicting");
            if let Some(first_key) = self.connections.keys().next().copied() {
                self.connections.remove(&first_key);
            }
        }
    }

    pub fn events_processed(&self) -> u64 { self.events_processed }
    pub fn spans_emitted(&self) -> u64 { self.spans_emitted }
    pub fn non_http_skipped(&self) -> u64 { self.non_http_skipped }
    pub fn active_connections(&self) -> usize { self.connections.len() }
}
