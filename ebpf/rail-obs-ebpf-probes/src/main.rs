//! eBPF probes for the Railway Observability Engine.
//!
//! Attaches to 5 kernel probe points:
//! 1. kprobe/tcp_v4_connect     — outbound connection (client side)
//! 2. kretprobe/inet_csk_accept — inbound connection (server side)
//! 3. kprobe/tcp_sendmsg        — data sent (captures payload header)
//! 4. kprobe/tcp_recvmsg        — data received (captures payload header)
//! 5. kprobe/tcp_close          — connection teardown
//!
//! struct sock_common offsets (from pahole on WSL2 kernel 6.6.87):
//!   offset 0:  skc_daddr       (__be32, network byte order)
//!   offset 4:  skc_rcv_saddr   (__be32, network byte order)
//!   offset 12: skc_dport       (__be16, network byte order)
//!   offset 14: skc_num         (__u16,  host byte order)
//!
//! Build: cargo +nightly build --target bpfel-unknown-none -Z build-std=core

#![no_std]
#![no_main]
#![allow(unused_mut)]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe, map},
    maps::RingBuf,
    programs::{ProbeContext, RetProbeContext},
};

use rail_obs_ebpf_common::{TcpEventHeader, EventKind};

// ─── Maps ──────────────────────────────────────────────────────────

/// Ring buffer for sending events to userspace (16MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

// ─── struct sock field offsets (from pahole on kernel 6.6) ─────────
// These are stable across 5.x-6.x kernels. In production, use CO-RE/BTF.

const SK_COMMON_DADDR_OFF: usize = 0;      // __be32 skc_daddr
const SK_COMMON_SADDR_OFF: usize = 4;      // __be32 skc_rcv_saddr
const SK_COMMON_DPORT_OFF: usize = 12;     // __be16 skc_dport (network byte order)
const SK_COMMON_SPORT_OFF: usize = 14;     // __u16  skc_num   (host byte order)

// ─── Helper: read 4-tuple from struct sock ─────────────────────────

/// Read the connection 4-tuple from a struct sock pointer.
/// Returns (src_addr, src_port, dst_addr, dst_port).
#[inline(always)]
unsafe fn read_sock_tuple(sk: *const u8) -> Result<(u32, u16, u32, u16), i64> {
    let src_addr: u32 = bpf_probe_read_kernel(
        (sk as *const u8).add(SK_COMMON_SADDR_OFF) as *const u32
    ).map_err(|e| e as i64)?;

    let dst_addr: u32 = bpf_probe_read_kernel(
        (sk as *const u8).add(SK_COMMON_DADDR_OFF) as *const u32
    ).map_err(|e| e as i64)?;

    let dst_port_be: u16 = bpf_probe_read_kernel(
        (sk as *const u8).add(SK_COMMON_DPORT_OFF) as *const u16
    ).map_err(|e| e as i64)?;

    let src_port: u16 = bpf_probe_read_kernel(
        (sk as *const u8).add(SK_COMMON_SPORT_OFF) as *const u16
    ).map_err(|e| e as i64)?;

    // dst_port is in network byte order, convert to host
    let dst_port = u16::from_be(dst_port_be);

    Ok((src_addr, src_port, dst_addr, dst_port))
}

/// Emit a header-only event (no payload) to the ring buffer.
#[inline(always)]
fn emit_event(header: &TcpEventHeader) {
    if let Some(mut buf) = EVENTS.reserve::<TcpEventHeader>(0) {
        buf.write(*header);
        buf.submit(0);
    }
}

/// Build a basic event header with PID and timestamp.
#[inline(always)]
fn make_header(kind: EventKind) -> TcpEventHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    let timestamp = unsafe { bpf_ktime_get_ns() };

    TcpEventHeader {
        kind: kind as u8,
        pid: (pid_tgid >> 32) as u32,
        tgid: pid_tgid as u32,
        netns: 0, // TODO: read from task->nsproxy->net_ns->ns.inum via CO-RE
        fd: 0,
        timestamp_ns: timestamp,
        src_addr: 0,
        src_port: 0,
        dst_addr: 0,
        dst_port: 0,
        payload_len: 0,
    }
}

// ─── Probe 1: tcp_v4_connect ───────────────────────────────────────
// Fires when a process initiates an outbound TCP connection.
// fn tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_v4_connect(&ctx) {
        Ok(()) | Err(_) => 0,
    }
}

fn try_tcp_v4_connect(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;

    let mut header = make_header(EventKind::Connect);

    // Read 4-tuple from struct sock.
    // NOTE: At the time of tcp_v4_connect, skc_rcv_saddr (source IP) may not
    // be assigned yet (it's set later during routing). Source addr may be 0.
    // Userspace handles this by resolving from /proc/net/tcp as fallback.
    if let Ok((src_addr, src_port, dst_addr, dst_port)) = unsafe { read_sock_tuple(sk) } {
        header.src_addr = src_addr;
        header.src_port = src_port;
        header.dst_addr = dst_addr;
        header.dst_port = dst_port;
    }

    emit_event(&header);
    Ok(())
}

// ─── Probe 2: inet_csk_accept (kretprobe) ──────────────────────────
// Fires when a process RETURNS from accepting an inbound connection.
// We use kretprobe because the return value is the new struct sock*.
// struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern)

#[kretprobe]
pub fn inet_csk_accept(ctx: RetProbeContext) -> u32 {
    match try_inet_csk_accept(&ctx) {
        Ok(()) | Err(_) => 0,
    }
}

fn try_inet_csk_accept(ctx: &RetProbeContext) -> Result<(), i64> {
    // The return value of inet_csk_accept is the NEW accepted socket.
    let newsk: *const u8 = ctx.ret().ok_or(0i64)?;
    if newsk.is_null() {
        return Ok(()); // accept failed
    }

    let mut header = make_header(EventKind::Accept);

    if let Ok((src_addr, src_port, dst_addr, dst_port)) = unsafe { read_sock_tuple(newsk) } {
        header.src_addr = src_addr;
        header.src_port = src_port;
        header.dst_addr = dst_addr;
        header.dst_port = dst_port;
    }

    emit_event(&header);
    Ok(())
}

// ─── Probe 3: tcp_sendmsg ─────────────────────────────────────────
// Fires when data is sent on a TCP socket.
// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
//
// We extract the 4-tuple from struct sock (reliable at this point).
// We do NOT read the payload from msghdr here (iov_iter is too complex
// for the BPF verifier). Instead, we emit the 4-tuple + metadata,
// and in PRODUCTION would add a separate tracepoint on sys_enter_sendto
// for payload capture. For the prototype, userspace uses the 4-tuple
// to match with /proc data or application-level correlation.

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(&ctx) {
        Ok(()) | Err(_) => 0,
    }
}

fn try_tcp_sendmsg(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;

    // Read the size argument (3rd arg) to know how much data is being sent
    let size: usize = ctx.arg(2).unwrap_or(0);

    let mut header = make_header(EventKind::DataSend);

    if let Ok((src_addr, src_port, dst_addr, dst_port)) = unsafe { read_sock_tuple(sk) } {
        header.src_addr = src_addr;
        header.src_port = src_port;
        header.dst_addr = dst_addr;
        header.dst_port = dst_port;
    }

    // Store the message size in payload_len (not actual payload — just metadata).
    // This tells userspace "a send of N bytes happened on this connection".
    header.payload_len = if size > u16::MAX as usize { u16::MAX } else { size as u16 };

    emit_event(&header);
    Ok(())
}

// ─── Probe 4: tcp_recvmsg ─────────────────────────────────────────
// Fires when data is received on a TCP socket.
// int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
//                 int flags, int *addr_len)

#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_recvmsg(&ctx) {
        Ok(()) | Err(_) => 0,
    }
}

fn try_tcp_recvmsg(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
    let size: usize = ctx.arg(2).unwrap_or(0);

    let mut header = make_header(EventKind::DataRecv);

    if let Ok((src_addr, src_port, dst_addr, dst_port)) = unsafe { read_sock_tuple(sk) } {
        header.src_addr = src_addr;
        header.src_port = src_port;
        header.dst_addr = dst_addr;
        header.dst_port = dst_port;
    }

    header.payload_len = if size > u16::MAX as usize { u16::MAX } else { size as u16 };

    emit_event(&header);
    Ok(())
}

// ─── Probe 5: tcp_close ───────────────────────────────────────────
// Fires when a TCP connection is closed.
// void tcp_close(struct sock *sk, long timeout)

#[kprobe]
pub fn tcp_close(ctx: ProbeContext) -> u32 {
    match try_tcp_close(&ctx) {
        Ok(()) | Err(_) => 0,
    }
}

fn try_tcp_close(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;

    let mut header = make_header(EventKind::Close);

    if let Ok((src_addr, src_port, dst_addr, dst_port)) = unsafe { read_sock_tuple(sk) } {
        header.src_addr = src_addr;
        header.src_port = src_port;
        header.dst_addr = dst_addr;
        header.dst_port = dst_port;
    }

    emit_event(&header);
    Ok(())
}

// ─── Panic handler (required for no_std) ──────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
