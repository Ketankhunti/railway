//! Railway Observability Engine — eBPF-powered Collector
//!
//! Real pipeline: eBPF ring buffer → span assembler → API server
//! Must be run as root (or with CAP_BPF + CAP_NET_ADMIN).

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::programs::KProbe;
use aya::maps::RingBuf;
use aya_log::EbpfLogger;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use rail_obs_ebpf_common::{TcpEventHeader, TcpDataEvent, MAX_PAYLOAD_LEN};
use rail_obs_common::service::{ServiceMapping, ServiceMeta};
use rail_obs_common::span::trace_id_to_hex;
use rail_obs_span_assembler::{SpanAssembler, AssemblerConfig, TcpEvent, TcpEventKind, Direction};
use rail_obs_alerting::{
    AlertEngine, AlertEngineConfig, AlertRule, AlertRuleConfig,
    rules::{ThresholdConfig, Metric, Operator, Severity},
};
use rail_obs_api::app::{AppState, create_router};
use rail_obs_api::models::SpanDetail;
use rail_obs_ingestion::normalize_route;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("rail-obs eBPF collector starting");

    // ─── Load eBPF ───────────────────────────────────────────────
    let bpf_path = std::env::args().nth(1)
        .unwrap_or_else(|| "target/bpfel-unknown-none/release/rail-obs-probes".into());
    let mut ebpf = Ebpf::load(&std::fs::read(&bpf_path)?)?;
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("eBPF logger: {} (non-fatal)", e);
    }

    // ─── Attach probes ───────────────────────────────────────────
    for name in ["tcp_v4_connect", "inet_csk_accept", "tcp_sendmsg", "tcp_recvmsg", "tcp_close"] {
        let prog: &mut KProbe = ebpf.program_mut(name).context(name)?.try_into()?;
        prog.load()?;
        prog.attach(name, 0)?;
        info!("attached kprobe: {}", name);
    }

    // Attach tracepoint probes for payload capture
    use aya::programs::TracePoint;
    for (prog_name, category, tp_name) in [
        ("sys_enter_write", "syscalls", "sys_enter_write"),
        ("sys_enter_read", "syscalls", "sys_enter_read"),
        ("sys_exit_read", "syscalls", "sys_exit_read"),
    ] {
        let prog: &mut TracePoint = ebpf.program_mut(prog_name)
            .with_context(|| format!("tracepoint '{}' not found", prog_name))?
            .try_into()?;
        prog.load()?;
        prog.attach(category, tp_name)?;
        info!("attached tracepoint: {}/{}", category, tp_name);
    }

    // ─── Pipeline ────────────────────────────────────────────────
    let mut assembler = SpanAssembler::new(
        AssemblerConfig { max_connections: 100_000, max_pending_per_conn: 64, host_id: "wsl2".into() },
        demo_mapping(),
    );
    let mut alert_engine = AlertEngine::new(AlertEngineConfig { max_window_secs: 3600, eval_interval_spans: 50 });
    alert_engine.add_rule(AlertRule {
        id: "r1".into(), project_id: "proj_demo".into(), name: "Errors".into(),
        service_id: String::new(),
        config: AlertRuleConfig::Threshold(ThresholdConfig {
            metric: Metric::ErrorRate, operator: Operator::GreaterThan,
            value: 0.10, window_secs: 60, min_requests: 20,
        }),
        severity: Severity::Critical, enabled: true, cooldown_secs: 120,
    });

    let state = Arc::new(AppState::new());

    // ─── API server (on a separate tokio runtime to not block ring buffer) ───
    let api_state = state.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let r = create_router(api_state);
            let l = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
            info!("API on http://0.0.0.0:3000");
            axum::serve(l, r).await.unwrap();
        });
    });

    // ─── Ring buffer → pipeline (same pattern as working binary) ─
    let mut ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS")?)?;
    info!("pipeline ready");

    let mut n: u64 = 0;
    let mut spans_total: u64 = 0;

    // PID → last known 4-tuple mapping.
    // kprobes (tcp_sendmsg/recvmsg) provide the 4-tuple.
    // Tracepoints (sys_enter_write) provide the payload but no 4-tuple.
    // We match them by PID: when a tracepoint event has 0.0.0.0 addresses,
    // we look up the PID's last known 4-tuple from a recent kprobe.
    use std::collections::HashMap;
    let mut pid_to_addr: HashMap<u32, (Ipv4Addr, u16, Ipv4Addr, u16)> = HashMap::new();

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!(events=n, spans=spans_total, "bye");
                break;
            }
            _ = async {
                // Drain ring buffer (synchronous, no .await inside)
                let mut batch = Vec::new();
                while let Some(ev) = ring_buf.next() {
                    let b: &[u8] = ev.as_ref();
                    if b.len() < core::mem::size_of::<TcpEventHeader>() {
                        continue;
                    }

                    let h: &TcpEventHeader = unsafe { &*(b.as_ptr() as *const TcpEventHeader) };
                    n += 1;
                    let mut src = Ipv4Addr::from(u32::from_be(h.src_addr));
                    let mut dst = Ipv4Addr::from(u32::from_be(h.dst_addr));
                    let mut sport = h.src_port;
                    let mut dport = h.dst_port;

                    // If kprobe event has a real 4-tuple, store it by PID
                    let has_real_addr = h.src_addr != 0 || h.dst_addr != 0;
                    if has_real_addr {
                        pid_to_addr.insert(h.pid, (src, sport, dst, dport));
                    }

                    // Extract payload if present (TcpDataEvent)
                    let payload = if h.payload_len > 0 && b.len() >= core::mem::size_of::<TcpDataEvent>() {
                        let data_event: &TcpDataEvent = unsafe { &*(b.as_ptr() as *const TcpDataEvent) };
                        let len = (h.payload_len as usize).min(MAX_PAYLOAD_LEN);
                        data_event.payload[..len].to_vec()
                    } else {
                        vec![]
                    };

                    if !payload.is_empty() {
                        // Tracepoint events have 0.0.0.0 addresses — resolve from PID map
                        if !has_real_addr {
                            if let Some(&(s, sp, d, dp)) = pid_to_addr.get(&h.pid) {
                                src = s;
                                sport = sp;
                                dst = d;
                                dport = dp;
                            }
                        }

                        let preview = std::str::from_utf8(&payload[..payload.len().min(80)])
                            .unwrap_or("<binary>");
                        info!(
                            "HTTP: pid={} {}:{} -> {}:{} len={} '{}'",
                            h.pid, src, sport, dst, dport, payload.len(), preview
                        );
                    }

                    batch.push(TcpEvent {
                        timestamp_ns: h.timestamp_ns, pid: h.pid, netns: h.netns, fd: h.fd,
                            kind: match h.kind {
                                0 => TcpEventKind::Connect, 1 => TcpEventKind::Accept,
                                2 => TcpEventKind::Data(Direction::Send),
                                3 => TcpEventKind::Data(Direction::Recv),
                                _ => TcpEventKind::Close,
                            },
                            src_ip: src.into(), src_port: sport,
                            dst_ip: dst.into(), dst_port: dport,
                            payload,
                        });
                }
                // ring_buf borrow is released here — safe to .await below

                // Process batch through real pipeline
                for ev in &batch {
                    let completed = assembler.process_event(ev);
                    if !completed.is_empty() {
                        info!(
                            "span: {} {} duration={}µs",
                            completed[0].http_method,
                            completed[0].http_path,
                            completed[0].duration_us,
                        );
                    }
                    for span in &completed {
                        spans_total += 1;
                        alert_engine.ingest(span);
                        let d = to_detail(span);
                        state.trace_store.write().await.insert_span(d);
                    }
                }

                if !batch.is_empty() {
                    info!(events=n, batch=batch.len(), spans=spans_total, conns=assembler.active_connections(), "processed");
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            } => {}
        }
    }
    Ok(())
}

fn to_detail(s: &rail_obs_common::span::SpanEvent) -> SpanDetail {
    SpanDetail {
        trace_id: trace_id_to_hex(&s.trace_id), span_id: s.span_id,
        parent_span_id: s.parent_span_id, service_id: s.service_id.clone(),
        http_method: s.http_method.clone(), http_path: s.http_path.clone(),
        http_route: if s.http_route.is_empty() { normalize_route(&s.http_path) } else { s.http_route.clone() },
        http_status: s.http_status,
        start_time: s.start_time().to_rfc3339(), duration_us: s.duration_us, is_error: s.is_error,
    }
}

fn demo_mapping() -> ServiceMapping {
    let mut m = ServiceMapping::new();
    m.register(0, ServiceMeta {
        project_id: "proj_demo".into(), service_id: "svc_wsl2".into(),
        service_name: "wsl2".into(), environment_id: "dev".into(), container_id: "wsl2".into(),
    });
    m
}
