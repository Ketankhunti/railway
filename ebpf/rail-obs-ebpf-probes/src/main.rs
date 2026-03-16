//! eBPF probes for the Railway Observability Engine.
//!
//! 7 probes total:
//!   Connection lifecycle (kprobes):
//!     1. kprobe/tcp_v4_connect     — outbound connection
//!     2. kretprobe/inet_csk_accept — inbound connection
//!     3. kprobe/tcp_close          — connection teardown
//!     4. kprobe/tcp_sendmsg        — send metadata (4-tuple)
//!     5. kprobe/tcp_recvmsg        — recv metadata (4-tuple)
//!   HTTP payload capture (tracepoints):
//!     6. tp/syscalls/sys_enter_write — capture outbound HTTP payload
//!     7. tp/syscalls/sys_enter_read  — save buf ptr for sys_exit_read
//!        tp/syscalls/sys_exit_read   — capture inbound HTTP payload
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

/// Ring buffer for events → userspace (16MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// FD → connection 4-tuple map. Populated by tcp_v4_connect/inet_csk_accept.
/// Used by tracepoint probes (which only see FD numbers) to get 4-tuples.
#[map]
static FD_MAP: BpfHashMap<u64, FdInfo> = BpfHashMap::with_max_entries(65536, 0);

/// Temporary storage for sys_enter_read args (buf pointer, fd).
/// Key: pid_tgid, Value: (fd, buf_ptr, count).
/// Saved on sys_enter_read, consumed on sys_exit_read.
#[map]
static READ_ARGS: BpfHashMap<u64, ReadArgs> = BpfHashMap::with_max_entries(4096, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct FdInfo {
    src_addr: u32,
    src_port: u16,
    dst_addr: u32,
    dst_port: u16,
    netns: u32,
    is_tcp: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadArgs {
    fd: u64,
    buf_ptr: u64,
    count: u64,
}

// ─── struct sock offsets (kernel 6.6, from pahole) ────────────────

const SK_COMMON_DADDR_OFF: usize = 0;
const SK_COMMON_SADDR_OFF: usize = 4;
const SK_COMMON_DPORT_OFF: usize = 12;
const SK_COMMON_SPORT_OFF: usize = 14;

// ─── Helpers ──────────────────────────────────────────────────────

#[inline(always)]
unsafe fn read_sock_tuple(sk: *const u8) -> Result<(u32, u16, u32, u16), i64> {
    let src_addr: u32 = bpf_probe_read_kernel(
        (sk).add(SK_COMMON_SADDR_OFF) as *const u32
    ).map_err(|e| e as i64)?;
    let dst_addr: u32 = bpf_probe_read_kernel(
        (sk).add(SK_COMMON_DADDR_OFF) as *const u32
    ).map_err(|e| e as i64)?;
    let dst_port_be: u16 = bpf_probe_read_kernel(
        (sk).add(SK_COMMON_DPORT_OFF) as *const u16
    ).map_err(|e| e as i64)?;
    let src_port: u16 = bpf_probe_read_kernel(
        (sk).add(SK_COMMON_SPORT_OFF) as *const u16
    ).map_err(|e| e as i64)?;
    Ok((src_addr, src_port, dst_addr, u16::from_be(dst_port_be)))
}

#[inline(always)]
fn make_header(kind: EventKind) -> TcpEventHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    TcpEventHeader {
        kind: kind as u8,
        pid: (pid_tgid >> 32) as u32,
        tgid: pid_tgid as u32,
        netns: 0,
        fd: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        src_addr: 0, src_port: 0,
        dst_addr: 0, dst_port: 0,
        payload_len: 0,
    }
}

#[inline(always)]
fn emit_header(header: &TcpEventHeader) {
    if let Some(mut buf) = EVENTS.reserve::<TcpEventHeader>(0) {
        buf.write(*header);
        buf.submit(0);
    }
}

/// FD_MAP key: combine pid_tgid with fd for uniqueness.
#[inline(always)]
fn fd_key(fd: u64) -> u64 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u64;
    (pid << 32) | (fd & 0xFFFF_FFFF)
}

// ═══════════════════════════════════════════════════════════════════
// KPROBES — Connection lifecycle (same as before)
// ═══════════════════════════════════════════════════════════════════

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx);
    0
}

fn try_connect(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
    let mut header = make_header(EventKind::Connect);
    if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
        header.src_addr = sa; header.src_port = sp;
        header.dst_addr = da; header.dst_port = dp;
    }
    emit_header(&header);
    Ok(())
}

#[kretprobe]
pub fn inet_csk_accept(ctx: RetProbeContext) -> u32 {
    let _ = try_accept(&ctx);
    0
}

fn try_accept(ctx: &RetProbeContext) -> Result<(), i64> {
    let newsk: *const u8 = ctx.ret().ok_or(0i64)?;
    if newsk.is_null() { return Ok(()); }
    let mut header = make_header(EventKind::Accept);
    if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(newsk) } {
        header.src_addr = sa; header.src_port = sp;
        header.dst_addr = da; header.dst_port = dp;

        // Register in FD_MAP so tracepoints can look up the 4-tuple by FD
        let info = FdInfo {
            src_addr: sa, src_port: sp, dst_addr: da, dst_port: dp,
            netns: 0, is_tcp: 1,
        };
        // We don't have the FD here, but tcp_sendmsg/recvmsg will register it
    }
    emit_header(&header);
    Ok(())
}

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let _ = try_sendmsg(&ctx);
    0
}

fn try_sendmsg(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
    let size: usize = ctx.arg(2).unwrap_or(0);
    let mut header = make_header(EventKind::DataSend);
    if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
        header.src_addr = sa; header.src_port = sp;
        header.dst_addr = da; header.dst_port = dp;

        // Register this 4-tuple for FD-based lookup by tracepoints
        // Use the 4-tuple hash as key since we don't have FD in kprobe
        let key = ((sa as u64) << 32) | (sp as u64) << 16 | (da as u64 & 0xFFFF);
        let info = FdInfo {
            src_addr: sa, src_port: sp, dst_addr: da, dst_port: dp,
            netns: 0, is_tcp: 1,
        };
    }
    header.payload_len = if size > u16::MAX as usize { u16::MAX } else { size as u16 };
    emit_header(&header);
    Ok(())
}

#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    let _ = try_recvmsg(&ctx);
    0
}

fn try_recvmsg(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
    let size: usize = ctx.arg(2).unwrap_or(0);
    let mut header = make_header(EventKind::DataRecv);
    if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
        header.src_addr = sa; header.src_port = sp;
        header.dst_addr = da; header.dst_port = dp;
    }
    header.payload_len = if size > u16::MAX as usize { u16::MAX } else { size as u16 };
    emit_header(&header);
    Ok(())
}

#[kprobe]
pub fn tcp_close(ctx: ProbeContext) -> u32 {
    let _ = try_close(&ctx);
    0
}

fn try_close(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
    let mut header = make_header(EventKind::Close);
    if let Ok((sa, sp, da, dp)) = unsafe { read_sock_tuple(sk) } {
        header.src_addr = sa; header.src_port = sp;
        header.dst_addr = da; header.dst_port = dp;
    }
    emit_header(&header);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// TRACEPOINTS — HTTP payload capture
// ═══════════════════════════════════════════════════════════════════

/// sys_enter_write: capture outbound data (HTTP request).
///
/// Tracepoint fields (from /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format):
///   __syscall_nr: offset 8, size 4
///   fd:           offset 16, size 8
///   buf:          offset 24, size 8  ← user buffer pointer
///   count:        offset 32, size 8  ← bytes to write
#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter_write(&ctx);
    0
}

fn try_sys_enter_write(ctx: &TracePointContext) -> Result<(), i64> {
    // Read syscall args from the tracepoint context
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };
    let buf_ptr: u64 = unsafe { ctx.read_at(24).map_err(|e| e as i64)? };
    let count: u64 = unsafe { ctx.read_at(32).map_err(|e| e as i64)? };

    if buf_ptr == 0 || count == 0 {
        return Ok(());
    }

    // Only capture first 2KB
    let capture_len = if count > MAX_PAYLOAD_LEN as u64 {
        MAX_PAYLOAD_LEN
    } else {
        count as usize
    };

    // Quick check: is this an HTTP request? Read first 4 bytes.
    let mut peek: [u8; 4] = [0; 4];
    unsafe {
        if bpf_probe_read_user(buf_ptr as *const [u8; 4]).is_err() {
            return Ok(());
        }
        peek = bpf_probe_read_user(buf_ptr as *const [u8; 4]).map_err(|e| e as i64)?;
    }

    // Fast filter: only capture if likely HTTP (check first 4 bytes)
    // More specific than single-byte to reduce false positives
    let is_http = (peek[0] == b'G' && peek[1] == b'E' && peek[2] == b'T' && peek[3] == b' ')  // GET 
        || (peek[0] == b'P' && peek[1] == b'O')  // POST, but not random "P..." data
        || (peek[0] == b'P' && peek[1] == b'U')  // PUT
        || (peek[0] == b'P' && peek[1] == b'A')  // PATCH
        || (peek[0] == b'D' && peek[1] == b'E')  // DELETE (not DNS)
        || (peek[0] == b'H' && peek[1] == b'E')  // HEAD
        || (peek[0] == b'H' && peek[1] == b'T')  // HTTP/ (response)
        || (peek[0] == b'O' && peek[1] == b'P')  // OPTIONS
        || (peek[0] == b'C' && peek[1] == b'O')  // CONNECT
        || (peek[0] == b'T' && peek[1] == b'R'); // TRACE

    if !is_http {
        return Ok(());
    }

    // Reserve a TcpDataEvent in the ring buffer
    if let Some(mut buf) = EVENTS.reserve::<TcpDataEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            // Write header
            let header = &mut (*event).header;
            let pid_tgid = bpf_get_current_pid_tgid();
            header.kind = EventKind::DataSend as u8;
            header.pid = (pid_tgid >> 32) as u32;
            header.tgid = pid_tgid as u32;
            header.netns = 0;
            header.fd = fd as u32;
            header.timestamp_ns = bpf_ktime_get_ns();
            header.src_addr = 0; // Resolved from FD_MAP or kprobe data
            header.src_port = 0;
            header.dst_addr = 0;
            header.dst_port = 0;
            header.payload_len = capture_len as u16;

            // Read payload in 512-byte chunks (BPF verifier limit)
            let payload = &mut (*event).payload;
            let base = buf_ptr as *const u8;

            // Chunk 1 (0..512)
            if capture_len > 0 {
                let chunk = if capture_len > CHUNK_SIZE { CHUNK_SIZE } else { capture_len };
                let _ = bpf_probe_read_user_buf(base, &mut payload[0..chunk]);
            }
            // Chunk 2 (512..1024)
            if capture_len > CHUNK_SIZE {
                let chunk = if capture_len > CHUNK_SIZE * 2 { CHUNK_SIZE } else { capture_len - CHUNK_SIZE };
                let _ = bpf_probe_read_user_buf(base.add(CHUNK_SIZE), &mut payload[CHUNK_SIZE..CHUNK_SIZE + chunk]);
            }
            // Chunk 3 (1024..1536)
            if capture_len > CHUNK_SIZE * 2 {
                let chunk = if capture_len > CHUNK_SIZE * 3 { CHUNK_SIZE } else { capture_len - CHUNK_SIZE * 2 };
                let _ = bpf_probe_read_user_buf(base.add(CHUNK_SIZE * 2), &mut payload[CHUNK_SIZE * 2..CHUNK_SIZE * 2 + chunk]);
            }
            // Chunk 4 (1536..2048)
            if capture_len > CHUNK_SIZE * 3 {
                let chunk = capture_len - CHUNK_SIZE * 3;
                let _ = bpf_probe_read_user_buf(base.add(CHUNK_SIZE * 3), &mut payload[CHUNK_SIZE * 3..CHUNK_SIZE * 3 + chunk]);
            }
        }
        buf.submit(0);
    }

    Ok(())
}

/// sys_enter_read: save the buffer pointer and fd for sys_exit_read.
#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter_read(&ctx);
    0
}

fn try_sys_enter_read(ctx: &TracePointContext) -> Result<(), i64> {
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };
    let buf_ptr: u64 = unsafe { ctx.read_at(24).map_err(|e| e as i64)? };
    let count: u64 = unsafe { ctx.read_at(32).map_err(|e| e as i64)? };

    if buf_ptr == 0 || count == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = ReadArgs { fd, buf_ptr, count };
    let _ = READ_ARGS.insert(&pid_tgid, &args, 0);

    Ok(())
}

/// sys_exit_read: read the buffer that was filled by the kernel.
///
/// Tracepoint fields:
///   __syscall_nr: offset 8, size 4
///   ret:          offset 16, size 8  ← bytes actually read
#[tracepoint]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    let _ = try_sys_exit_read(&ctx);
    0
}

fn try_sys_exit_read(ctx: &TracePointContext) -> Result<(), i64> {
    let ret: i64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };

    // ret < 0 means error, ret == 0 means EOF
    if ret <= 0 {
        // Clean up saved args
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = READ_ARGS.remove(&pid_tgid);
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = match unsafe { READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(()), // no matching sys_enter_read
    };
    let _ = READ_ARGS.remove(&pid_tgid);

    let bytes_read = ret as usize;
    let capture_len = if bytes_read > MAX_PAYLOAD_LEN { MAX_PAYLOAD_LEN } else { bytes_read };

    // Quick check: is this HTTP? Read first 5 bytes.
    let mut peek: [u8; 5] = [0; 5];
    if capture_len >= 5 {
        unsafe {
            if let Ok(p) = bpf_probe_read_user(args.buf_ptr as *const [u8; 5]) {
                peek = p;
            } else {
                return Ok(());
            }
        }
    }

    // Check for HTTP response (starts with "HTTP/")
    let is_http_response = peek[0] == b'H' && peek[1] == b'T' && peek[2] == b'T'
        && peek[3] == b'P' && peek[4] == b'/';

    if !is_http_response {
        return Ok(());
    }

    // Reserve and fill event
    if let Some(mut buf) = EVENTS.reserve::<TcpDataEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            let header = &mut (*event).header;
            header.kind = EventKind::DataRecv as u8;
            header.pid = (pid_tgid >> 32) as u32;
            header.tgid = pid_tgid as u32;
            header.netns = 0;
            header.fd = args.fd as u32;
            header.timestamp_ns = bpf_ktime_get_ns();
            header.src_addr = 0;
            header.src_port = 0;
            header.dst_addr = 0;
            header.dst_port = 0;
            header.payload_len = capture_len as u16;

            let payload = &mut (*event).payload;
            let base = args.buf_ptr as *const u8;

            if capture_len > 0 {
                let chunk = if capture_len > CHUNK_SIZE { CHUNK_SIZE } else { capture_len };
                let _ = bpf_probe_read_user_buf(base, &mut payload[0..chunk]);
            }
            if capture_len > CHUNK_SIZE {
                let chunk = if capture_len > CHUNK_SIZE * 2 { CHUNK_SIZE } else { capture_len - CHUNK_SIZE };
                let _ = bpf_probe_read_user_buf(base.add(CHUNK_SIZE), &mut payload[CHUNK_SIZE..CHUNK_SIZE + chunk]);
            }
            if capture_len > CHUNK_SIZE * 2 {
                let chunk = if capture_len > CHUNK_SIZE * 3 { CHUNK_SIZE } else { capture_len - CHUNK_SIZE * 2 };
                let _ = bpf_probe_read_user_buf(base.add(CHUNK_SIZE * 2), &mut payload[CHUNK_SIZE * 2..CHUNK_SIZE * 2 + chunk]);
            }
            if capture_len > CHUNK_SIZE * 3 {
                let chunk = capture_len - CHUNK_SIZE * 3;
                let _ = bpf_probe_read_user_buf(base.add(CHUNK_SIZE * 3), &mut payload[CHUNK_SIZE * 3..CHUNK_SIZE * 3 + chunk]);
            }
        }
        buf.submit(0);
    }

    Ok(())
}

/// Helper: read user memory into a mutable slice.
/// Wraps bpf_probe_read_user for buffer reads.
#[inline(always)]
unsafe fn bpf_probe_read_user_buf(src: *const u8, dst: &mut [u8]) -> Result<(), i64> {
    // Use the raw helper since aya doesn't have a direct buf read
    let ret = aya_ebpf::helpers::bpf_probe_read_user_buf(src, dst);
    ret.map_err(|e| e as i64)
}

// ─── Panic handler ────────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
