//! Userspace eBPF loader for the Railway Observability Engine.
//!
//! Loads the compiled BPF bytecode, attaches all 5 probes,
//! and reads events from the ring buffer.
//!
//! Must be run as root (or with CAP_BPF + CAP_NET_ADMIN).

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::programs::KProbe;
use aya::maps::RingBuf;
use aya_log::EbpfLogger;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use rail_obs_ebpf_common::TcpEventHeader;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("rail-obs userspace loader starting");

    let bpf_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/bpfel-unknown-none/debug/rail-obs-probes".into());

    info!(path = %bpf_path, "loading eBPF program");

    let bpf_bytes = std::fs::read(&bpf_path)
        .with_context(|| format!("failed to read BPF binary at {}", bpf_path))?;

    let mut ebpf = Ebpf::load(&bpf_bytes)
        .context("failed to load eBPF program into kernel")?;

    // Initialize eBPF logging
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("eBPF logger init: {} (non-fatal)", e);
    }

    // ─── Attach all 5 probes ──────────────────────────────────────

    // 1. kprobe: tcp_v4_connect
    attach_kprobe(&mut ebpf, "tcp_v4_connect", "tcp_v4_connect")?;

    // 2. kretprobe: inet_csk_accept (uses kprobe attach with ret=true internally)
    attach_kprobe(&mut ebpf, "inet_csk_accept", "inet_csk_accept")?;

    // 3. kprobe: tcp_sendmsg
    attach_kprobe(&mut ebpf, "tcp_sendmsg", "tcp_sendmsg")?;

    // 4. kprobe: tcp_recvmsg
    attach_kprobe(&mut ebpf, "tcp_recvmsg", "tcp_recvmsg")?;

    // 5. kprobe: tcp_close
    attach_kprobe(&mut ebpf, "tcp_close", "tcp_close")?;

    info!("all 5 probes attached successfully");

    // ─── Read ring buffer ─────────────────────────────────────────

    let mut ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS").context("EVENTS map not found")?
    ).context("failed to create RingBuf")?;

    info!("ring buffer connected — listening for events");
    info!("press Ctrl-C to stop");

    let mut event_count: u64 = 0;
    let mut last_report: u64 = 0;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!(total_events = event_count, "shutting down");
                break;
            }
            _ = async {
                while let Some(event) = ring_buf.next() {
                    let data = event.as_ref();
                    if data.len() < core::mem::size_of::<TcpEventHeader>() {
                        warn!(len = data.len(), "event too small, skipping");
                        continue;
                    }

                    let header: &TcpEventHeader =
                        unsafe { &*(data.as_ptr() as *const TcpEventHeader) };

                    event_count += 1;
                    log_event(header, event_count);
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            } => {}
        }
    }

    Ok(())
}

/// Attach a kprobe (or kretprobe) by program name and kernel function.
fn attach_kprobe(ebpf: &mut Ebpf, prog_name: &str, fn_name: &str) -> Result<()> {
    let program: &mut KProbe = ebpf.program_mut(prog_name)
        .with_context(|| format!("program '{}' not found in BPF binary", prog_name))?
        .try_into()
        .with_context(|| format!("'{}' is not a KProbe", prog_name))?;
    program.load()
        .with_context(|| format!("failed to load '{}'", prog_name))?;
    program.attach(fn_name, 0)
        .with_context(|| format!("failed to attach '{}' to kernel function '{}'", prog_name, fn_name))?;
    info!(program = prog_name, function = fn_name, "probe attached");
    Ok(())
}

/// Log a single event with the decoded 4-tuple.
fn log_event(header: &TcpEventHeader, count: u64) {
    let kind_str = match header.kind {
        0 => "CONNECT",
        1 => "ACCEPT",
        2 => "SEND",
        3 => "RECV",
        4 => "CLOSE",
        _ => "???",
    };

    // Convert network-byte-order IPv4 to human readable
    let src_ip = Ipv4Addr::from(u32::from_be(header.src_addr));
    let dst_ip = Ipv4Addr::from(u32::from_be(header.dst_addr));

    info!(
        "#{} {} pid={} {}:{} -> {}:{} len={}",
        count,
        kind_str,
        header.pid,
        src_ip,
        header.src_port,
        dst_ip,
        header.dst_port,
        header.payload_len,
    );
}
