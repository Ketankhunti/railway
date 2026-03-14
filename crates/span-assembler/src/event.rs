use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Direction of a TCP data event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Data sent by the process (outbound from this container).
    Send,
    /// Data received by the process (inbound to this container).
    Recv,
}

/// The type of TCP event captured by eBPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpEventKind {
    /// tcp_v4_connect: process initiates outbound connection.
    Connect,
    /// inet_csk_accept: process accepts inbound connection.
    Accept,
    /// sys_enter_sendto / sys_enter_write: process sends data.
    Data(Direction),
    /// tcp_close: connection closed.
    Close,
}

/// A raw TCP event as produced by the eBPF probes + userspace ring buffer reader.
///
/// This is the input to the span assembler. In the real system, these come
/// from the eBPF ring buffer. For testing, we construct them directly.
#[derive(Debug, Clone)]
pub struct TcpEvent {
    /// Kernel timestamp in nanoseconds (monotonic, from bpf_ktime_get_ns).
    pub timestamp_ns: u64,

    /// Process ID that triggered the event.
    pub pid: u32,

    /// Network namespace inode (identifies the container).
    pub netns: u32,

    /// File descriptor for this socket.
    pub fd: u32,

    /// The event type.
    pub kind: TcpEventKind,

    /// Source IP address.
    pub src_ip: IpAddr,
    /// Source port.
    pub src_port: u16,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Destination port.
    pub dst_port: u16,

    /// Captured payload bytes (up to 2KB for data events, empty for connect/accept/close).
    pub payload: Vec<u8>,
}

impl TcpEvent {
    /// Returns the connection 4-tuple as a ConnectionKey.
    pub fn connection_key(&self) -> rail_obs_common::service::ConnectionKey {
        rail_obs_common::service::ConnectionKey::new(
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
        )
    }

    /// Returns the direction for data events, None for connect/accept/close.
    pub fn direction(&self) -> Option<Direction> {
        match self.kind {
            TcpEventKind::Data(dir) => Some(dir),
            _ => None,
        }
    }
}
