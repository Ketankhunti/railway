//! HTTP/1.1 request and response parser for eBPF-captured payloads.
//!
//! This parser operates on raw byte slices captured from TCP payloads via
//! syscall tracepoints. It extracts:
//! - Request line: method, path, HTTP version
//! - Response status line: HTTP version, status code, reason phrase
//! - Key headers: Host, Content-Length, traceparent, tracestate
//!
//! Design constraints:
//! - Input may be truncated (captured up to 2KB from eBPF)
//! - Must not allocate excessively — called per-packet at high frequency
//! - Must gracefully handle non-HTTP data (binary protocols, TLS ciphertext)
//! - Must handle partial headers (truncation mid-header)

mod request;
mod response;
mod headers;

pub use request::{HttpRequest, parse_request};
pub use response::{HttpResponse, parse_response};
pub use headers::Headers;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("not HTTP: payload does not start with an HTTP method or status line")]
    NotHttp,

    #[error("incomplete: payload truncated before end of request/status line")]
    Incomplete,

    #[error("invalid method: {0}")]
    InvalidMethod(String),

    #[error("invalid status code: {0}")]
    InvalidStatus(String),

    #[error("malformed request line")]
    MalformedRequestLine,

    #[error("malformed status line")]
    MalformedStatusLine,
}

/// Determine if a payload looks like an HTTP request (starts with a method).
pub fn is_http_request(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    // Check first bytes against known HTTP methods
    payload.starts_with(b"GET ")
        || payload.starts_with(b"POST ")
        || payload.starts_with(b"PUT ")
        || payload.starts_with(b"DELETE ")
        || payload.starts_with(b"PATCH ")
        || payload.starts_with(b"HEAD ")
        || payload.starts_with(b"OPTIONS ")
        || payload.starts_with(b"CONNECT ")
        || payload.starts_with(b"TRACE ")
}

/// Determine if a payload looks like an HTTP response (starts with "HTTP/").
pub fn is_http_response(payload: &[u8]) -> bool {
    payload.starts_with(b"HTTP/")
}

/// Determine if a payload is HTTP at all (request or response).
pub fn is_http(payload: &[u8]) -> bool {
    is_http_request(payload) || is_http_response(payload)
}

/// Find the position of \r\n in a byte slice, starting from offset.
fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    if data.len() < start + 2 {
        return None;
    }
    data[start..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| p + start)
}

/// Find the end-of-headers marker (\r\n\r\n) in a byte slice.
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
}
