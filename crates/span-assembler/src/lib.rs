//! Connection state machine and span assembler.
//!
//! Tracks per-connection state (IDLE → REQUEST_SENT → IDLE) for HTTP/1.1,
//! handles keep-alive and pipelining, and produces completed SpanEvents.
//!
//! ## Architecture
//!
//! ```text
//! TcpEvent (from eBPF ring buffer)
//!     │
//!     ▼
//! SpanAssembler.process_event()
//!     │
//!     ├── Connect/Accept → register connection in HashMap
//!     ├── Data(Send) + HTTP request → push PendingRequest
//!     ├── Data(Recv) + HTTP response → pop PendingRequest, emit SpanEvent
//!     └── Close → drain pending, emit incomplete spans
//! ```

pub mod event;
pub mod connection;
pub mod assembler;

pub use event::{TcpEvent, TcpEventKind, Direction};
pub use connection::{ConnectionState, PendingRequest};
pub use assembler::{SpanAssembler, AssemblerConfig};
