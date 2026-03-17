//! eBPF probes for the Railway Observability Engine.
//!
//! Comprehensive coverage — captures ALL TCP syscall variants:
//!
//! Connection lifecycle (kprobes):
//!   1. kprobe/tcp_v4_connect      — outbound connection
//!   2. kretprobe/inet_csk_accept  — inbound connection
//!   3. kprobe/tcp_close           — connection teardown
//!   4. kprobe/tcp_sendmsg         — send metadata (4-tuple, any syscall)
//!   5. kprobe/tcp_recvmsg         — recv metadata (4-tuple, any syscall)
//!
//! Outbound payload capture (tracepoints):
//!   6.  tp/syscalls/sys_enter_write    — Go, some C
//!   7.  tp/syscalls/sys_enter_sendto   — Python, curl, most frameworks
//!   8.  tp/syscalls/sys_enter_writev   — Node.js, Rust/tokio
//!
//! Inbound payload capture (tracepoints):
//!   9.  tp/syscalls/sys_enter_read     — save buf ptr
//!   10. tp/syscalls/sys_exit_read      — read captured payload
//!   11. tp/syscalls/sys_enter_recvfrom — save buf ptr
//!   12. tp/syscalls/sys_exit_recvfrom  — read captured payload
//!
//! Total: 12 probes covering ALL common TCP send/recv patterns.
//!
//! Key insight: write/sendto/recvfrom all have the SAME field layout
//! (fd=off16, buf=off24, count=off32), so they share the same BPF logic.
//! writev needs special handling for struct iovec.
//!
//! Build: cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release

#![no_std]
#![no_main]
#![allow(unused_mut)]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user},
    macros::{kprobe, kretprobe, tracepoint, map},
    maps::{HashMap as BpfHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};

use rail_obs_ebpf_common::{
    TcpEventHeader, TcpDataEvent, EventKind, MAX_PAYLOAD_LEN, CHUNK_SIZE,
};

// ─── Maps ──────────────────────────────────────────────────────────

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Temp storage for read/recvfrom args (buf pointer saved on enter, read on exit).
/// Key: pid_tgid. Cleaned up on sys_exit.
#[map]
static READ_ARGS: BpfHashMap<u64, ReadArgs> = BpfHashMap::with_max_entries(8192, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadArgs {
    fd: u64,
    buf_ptr: u64,
    count: u64,
}

/// struct iovec layout (for writev).
#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec {
    iov_base: u64,  // void __user *
    iov_len: u64,   // size_t
}

// ─── struct sock offsets (kernel 6.6, from pahole) ────────────────

const SK_DADDR: usize = 0;
const SK_SADDR: usize = 4;
const SK_DPORT: usize = 12;
const SK_SPORT: usize = 14;

// ─── Helpers ──────────────────────────────────────────────────────

#[inline(always)]
unsafe fn read_sock_tuple(sk: *const u8) -> Result<(u32, u16, u32, u16), i64> {
    let sa: u32 = bpf_probe_read_kernel(sk.add(SK_SADDR) as *const u32).map_err(|e| e as i64)?;
    let da: u32 = bpf_probe_read_kernel(sk.add(SK_DADDR) as *const u32).map_err(|e| e as i64)?;
    let dp: u16 = bpf_probe_read_kernel(sk.add(SK_DPORT) as *const u16).map_err(|e| e as i64)?;
    let sp: u16 = bpf_probe_read_kernel(sk.add(SK_SPORT) as *const u16).map_err(|e| e as i64)?;
    Ok((sa, sp, da, u16::from_be(dp)))
}

#[inline(always)]
fn make_header(kind: EventKind) -> TcpEventHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    TcpEventHeader {
        kind: kind as u8,
        pid: (pid_tgid >> 32) as u32,
        tgid: pid_tgid as u32,
        netns: 0, fd: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        src_addr: 0, src_port: 0, dst_addr: 0, dst_port: 0,
        payload_len: 0,
    }
}

#[inline(always)]
fn emit_header(h: &TcpEventHeader) {
    if let Some(mut buf) = EVENTS.reserve::<TcpEventHeader>(0) {
        buf.write(*h);
        buf.submit(0);
    }
}

/// Check first 4 bytes for HTTP method or response.
#[inline(always)]
fn looks_like_http(peek: &[u8; 4]) -> bool {
    // GET, POST, PUT, PATCH, DELETE, HEAD, HTTP, OPTIONS, CONNECT, TRACE
    (peek[0] == b'G' && peek[1] == b'E')       // GET
    || (peek[0] == b'P' && peek[1] == b'O')    // POST
    || (peek[0] == b'P' && peek[1] == b'U')    // PUT
    || (peek[0] == b'P' && peek[1] == b'A')    // PATCH
    || (peek[0] == b'D' && peek[1] == b'E')    // DELETE
    || (peek[0] == b'H' && peek[1] == b'E')    // HEAD
    || (peek[0] == b'H' && peek[1] == b'T')    // HTTP/ (response)
    || (peek[0] == b'O' && peek[1] == b'P')    // OPTIONS
    || (peek[0] == b'C' && peek[1] == b'O')    // CONNECT
    || (peek[0] == b'T' && peek[1] == b'R')    // TRACE
}

/// Capture payload from a user buffer pointer and emit as TcpDataEvent.
/// Uses FIXED 512-byte reads — the BPF verifier requires constant size
/// arguments to bpf_probe_read_user. We always read full 512-byte chunks
/// and store the actual length in payload_len for userspace to trim.
#[inline(always)]
unsafe fn capture_and_emit(kind: EventKind, fd: u32, buf_ptr: u64, data_len: usize) {
    if buf_ptr == 0 || data_len == 0 {
        return;
    }

    let capture_len = if data_len > MAX_PAYLOAD_LEN { MAX_PAYLOAD_LEN } else { data_len };

    // Quick HTTP check on first 4 bytes
    let peek = match bpf_probe_read_user(buf_ptr as *const [u8; 4]) {
        Ok(p) => p,
        Err(_) => return,
    };

    if !looks_like_http(&peek) {
        return;
    }

    // Reserve and fill TcpDataEvent
    if let Some(mut buf) = EVENTS.reserve::<TcpDataEvent>(0) {
        let event = buf.as_mut_ptr();
        let header = &mut (*event).header;
        let pid_tgid = bpf_get_current_pid_tgid();
        header.kind = kind as u8;
        header.pid = (pid_tgid >> 32) as u32;
        header.tgid = pid_tgid as u32;
        header.netns = 0;
        header.fd = fd;
        header.timestamp_ns = bpf_ktime_get_ns();
        header.src_addr = 0;
        header.src_port = 0;
        header.dst_addr = 0;
        header.dst_port = 0;
        header.payload_len = capture_len as u16;

        let payload = &mut (*event).payload;
        let base = buf_ptr as *const u8;

        // FIXED 512-byte reads — verifier requires constant size.
        // We always read full chunks; payload_len tells userspace actual size.
        // Chunk 1: bytes 0..512
        if capture_len > 0 {
            let _ = bpf_probe_read_user_buf(base, &mut payload[0..512]);
        }
        // Chunk 2: bytes 512..1024
        if capture_len > 512 {
            let _ = bpf_probe_read_user_buf(base.add(512), &mut payload[512..1024]);
        }
        // Chunk 3: bytes 1024..1536
        if capture_len > 1024 {
            let _ = bpf_probe_read_user_buf(base.add(1024), &mut payload[1024..1536]);
        }
        // Chunk 4: bytes 1536..2048
        if capture_len > 1536 {
            let _ = bpf_probe_read_user_buf(base.add(1536), &mut payload[1536..2048]);
        }

        buf.submit(0);
    }
}

#[inline(always)]
unsafe fn bpf_probe_read_user_buf(src: *const u8, dst: &mut [u8]) -> Result<(), i64> {
    aya_ebpf::helpers::bpf_probe_read_user_buf(src, dst).map_err(|e| e as i64)
}

/// Save read/recvfrom args on syscall entry. Used by sys_exit to read the buffer.
#[inline(always)]
fn save_read_args(ctx: &TracePointContext) -> Result<(), i64> {
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };
    let buf_ptr: u64 = unsafe { ctx.read_at(24).map_err(|e| e as i64)? };
    let count: u64 = unsafe { ctx.read_at(32).map_err(|e| e as i64)? };
    if buf_ptr == 0 || count == 0 { return Ok(()); }
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = READ_ARGS.insert(&pid_tgid, &ReadArgs { fd, buf_ptr, count }, 0);
    Ok(())
}

/// On syscall exit, read the buffer that was filled by the kernel.
#[inline(always)]
fn handle_read_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let ret: i64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };
    let pid_tgid = bpf_get_current_pid_tgid();
    if ret <= 0 {
        let _ = READ_ARGS.remove(&pid_tgid);
        return Ok(());
    }
    let args = match unsafe { READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(()),
    };
    let _ = READ_ARGS.remove(&pid_tgid);
    unsafe { capture_and_emit(EventKind::DataRecv, args.fd as u32, args.buf_ptr, ret as usize); }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// KPROBES — Connection lifecycle + metadata
// ═══════════════════════════════════════════════════════════════════

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let _ = (|| -> Result<(), i64> {
        let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
        let mut h = make_header(EventKind::Connect);
        if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
            h.src_addr = sa; h.src_port = sp; h.dst_addr = da; h.dst_port = dp;
        }
        emit_header(&h);
        Ok(())
    })();
    0
}

#[kretprobe]
pub fn inet_csk_accept(ctx: RetProbeContext) -> u32 {
    let _ = (|| -> Result<(), i64> {
        let sk: *const u8 = ctx.ret().ok_or(0i64)?;
        if sk.is_null() { return Ok(()); }
        let mut h = make_header(EventKind::Accept);
        if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
            h.src_addr = sa; h.src_port = sp; h.dst_addr = da; h.dst_port = dp;
        }
        emit_header(&h);
        Ok(())
    })();
    0
}

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let _ = (|| -> Result<(), i64> {
        let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
        let size: usize = ctx.arg(2).unwrap_or(0);
        let mut h = make_header(EventKind::DataSend);
        if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
            h.src_addr = sa; h.src_port = sp; h.dst_addr = da; h.dst_port = dp;
        }
        h.payload_len = if size > 65535 { 65535 } else { size as u16 };
        emit_header(&h);
        Ok(())
    })();
    0
}

#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    let _ = (|| -> Result<(), i64> {
        let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
        let size: usize = ctx.arg(2).unwrap_or(0);
        let mut h = make_header(EventKind::DataRecv);
        if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
            h.src_addr = sa; h.src_port = sp; h.dst_addr = da; h.dst_port = dp;
        }
        h.payload_len = if size > 65535 { 65535 } else { size as u16 };
        emit_header(&h);
        Ok(())
    })();
    0
}

#[kprobe]
pub fn tcp_close(ctx: ProbeContext) -> u32 {
    let _ = (|| -> Result<(), i64> {
        let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
        let mut h = make_header(EventKind::Close);
        if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
            h.src_addr = sa; h.src_port = sp; h.dst_addr = da; h.dst_port = dp;
        }
        emit_header(&h);
        Ok(())
    })();
    0
}

// ═══════════════════════════════════════════════════════════════════
// OUTBOUND PAYLOAD — sys_enter_write, sys_enter_sendto, sys_enter_writev
// All fire BEFORE data leaves the process. Buffer is in user memory.
// ═══════════════════════════════════════════════════════════════════

// write(fd, buf, count) — fields: fd=off16, buf=off24, count=off32
#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    let _ = try_send_capture(&ctx);
    0
}

// sendto(fd, buf, len, flags, addr, addrlen) — fields: fd=off16, buff=off24, len=off32
// Note: send() is sendto() with null addr. Same field layout as write.
#[tracepoint]
pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    let _ = try_send_capture(&ctx);
    0
}

/// Shared logic for write() and sendto() — same field layout.
fn try_send_capture(ctx: &TracePointContext) -> Result<(), i64> {
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };
    let buf_ptr: u64 = unsafe { ctx.read_at(24).map_err(|e| e as i64)? };
    let count: u64 = unsafe { ctx.read_at(32).map_err(|e| e as i64)? };
    unsafe { capture_and_emit(EventKind::DataSend, fd as u32, buf_ptr, count as usize); }
    Ok(())
}

// writev(fd, iov, iovcnt) — fields: fd=off16, vec=off24, vlen=off32
// Node.js and Rust/tokio use this. We read the first iovec entry.
#[tracepoint]
pub fn sys_enter_writev(ctx: TracePointContext) -> u32 {
    let _ = try_writev_capture(&ctx);
    0
}

fn try_writev_capture(ctx: &TracePointContext) -> Result<(), i64> {
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };
    let iov_ptr: u64 = unsafe { ctx.read_at(24).map_err(|e| e as i64)? };
    let iovcnt: u64 = unsafe { ctx.read_at(32).map_err(|e| e as i64)? };

    if iov_ptr == 0 || iovcnt == 0 {
        return Ok(());
    }

    // Read the first iovec entry to get the buffer pointer and length
    let iov: Iovec = unsafe {
        bpf_probe_read_user(iov_ptr as *const Iovec).map_err(|e| e as i64)?
    };

    unsafe { capture_and_emit(EventKind::DataSend, fd as u32, iov.iov_base, iov.iov_len as usize); }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// INBOUND PAYLOAD — sys_enter/exit_read, sys_enter/exit_recvfrom
// Must save buf ptr on ENTER, read data on EXIT (after kernel fills buffer).
// ═══════════════════════════════════════════════════════════════════

// read(fd, buf, count) — fields: fd=off16, buf=off24, count=off32
#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    let _ = save_read_args(&ctx);
    0
}

#[tracepoint]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    let _ = handle_read_exit(&ctx);
    0
}

// recvfrom(fd, ubuf, size, ...) — fields: fd=off16, ubuf=off24, size=off32
// Same layout as read for the first 3 fields.
#[tracepoint]
pub fn sys_enter_recvfrom(ctx: TracePointContext) -> u32 {
    let _ = save_read_args(&ctx); // same logic — fd/buf/count at same offsets
    0
}

#[tracepoint]
pub fn sys_exit_recvfrom(ctx: TracePointContext) -> u32 {
    let _ = handle_read_exit(&ctx); // same logic
    0
}

// ─── Panic handler ────────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
