//! Shared types between eBPF kernel programs and userspace.
//!
//! This crate is `#![no_std]` compatible so it can be used in BPF programs.
//! Every struct here must be:
//! - `#[repr(C)]` for stable layout across BPF and userspace
//! - Fixed-size (no heap, no Vec, no String)
//! - Pod-safe (plain old data)

#![no_std]

/// Maximum payload bytes captured per event.
/// We capture up to 2KB via 4×512-byte chunked bpf_probe_read_user() calls.
pub const MAX_PAYLOAD_LEN: usize = 2048;

/// Event types that the BPF probes emit to the ring buffer.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// tcp_v4_connect: client initiates connection.
    Connect = 0,
    /// inet_csk_accept: server accepts connection.
    Accept = 1,
    /// sys_enter_sendto / sys_enter_write: data sent.
    DataSend = 2,
    /// sys_exit_recvfrom / sys_exit_read: data received.
    DataRecv = 3,
    /// tcp_close: connection closed.
    Close = 4,
}

/// A TCP event emitted from the BPF ring buffer to userspace.
///
/// This is the wire format between kernel and userspace.
/// Variable-length: the actual payload may be shorter than MAX_PAYLOAD_LEN.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpEventHeader {
    /// Event type.
    pub kind: u8, // EventKind as u8

    /// Process ID.
    pub pid: u32,

    /// Thread group ID.
    pub tgid: u32,

    /// Network namespace inode (identifies the container).
    pub netns: u32,

    /// File descriptor for this socket.
    pub fd: u32,

    /// Timestamp in nanoseconds (bpf_ktime_get_ns — monotonic).
    pub timestamp_ns: u64,

    /// Source IPv4 address (network byte order).
    pub src_addr: u32,
    /// Source port (host byte order).
    pub src_port: u16,
    /// Destination IPv4 address (network byte order).
    pub dst_addr: u32,
    /// Destination port (host byte order).
    pub dst_port: u16,

    /// Number of payload bytes captured (0 for connect/accept/close).
    pub payload_len: u16,
}

/// Maximum payload capture per chunk (BPF verifier limit per bpf_probe_read_user call).
pub const CHUNK_SIZE: usize = 512;

/// Number of chunks (4 × 512 = 2048 bytes max).
pub const NUM_CHUNKS: usize = 4;

/// A full event with payload. Used for data events (sys_enter_write, sys_exit_read).
/// Ring buffer reserves this entire struct; only `header.payload_len` bytes are valid.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpDataEvent {
    pub header: TcpEventHeader,
    pub payload: [u8; MAX_PAYLOAD_LEN],
}

// Safety: TcpEventHeader is #[repr(C)] with only fixed-size primitive fields.
// This is required for reading from the BPF ring buffer.
#[cfg(not(feature = "no-std-check"))]
unsafe impl Send for TcpEventHeader {}
#[cfg(not(feature = "no-std-check"))]
unsafe impl Sync for TcpEventHeader {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn event_header_size() {
        // Verify the struct size is reasonable and predictable.
        // With repr(C), this should be stable across compilations.
        let size = mem::size_of::<TcpEventHeader>();
        assert!(size <= 64, "TcpEventHeader is {} bytes — should fit in a cache line", size);
        assert!(size >= 32, "TcpEventHeader is {} bytes — seems too small", size);
    }

    #[test]
    fn event_kind_values() {
        assert_eq!(EventKind::Connect as u8, 0);
        assert_eq!(EventKind::Accept as u8, 1);
        assert_eq!(EventKind::DataSend as u8, 2);
        assert_eq!(EventKind::DataRecv as u8, 3);
        assert_eq!(EventKind::Close as u8, 4);
    }
}
