use crate::{find_crlf, is_http_request, ParseError};
use crate::headers::{Headers, parse_headers};

/// Parsed HTTP request from a captured payload.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Headers,
}

impl HttpRequest {
    /// Returns the Host header value, if present.
    pub fn host(&self) -> Option<&str> {
        self.headers.get("host")
    }

    /// Returns the traceparent header value, if present.
    pub fn traceparent(&self) -> Option<&str> {
        self.headers.get("traceparent")
    }

    /// Returns the Content-Length header value, if present.
    pub fn content_length(&self) -> Option<usize> {
        self.headers.get("content-length")?.parse().ok()
    }
}

/// Parse an HTTP request from raw payload bytes.
///
/// Returns `Err(NotHttp)` if the payload doesn't start with an HTTP method.
/// Returns `Err(Incomplete)` if the request line is truncated.
/// Headers may be partially parsed if the payload is truncated mid-headers.
pub fn parse_request(payload: &[u8]) -> Result<HttpRequest, ParseError> {
    if !is_http_request(payload) {
        return Err(ParseError::NotHttp);
    }

    // Find the end of the request line (\r\n)
    let line_end = find_crlf(payload, 0).ok_or(ParseError::Incomplete)?;
    let request_line = &payload[..line_end];

    // Parse "METHOD /path HTTP/1.1"
    let request_str = std::str::from_utf8(request_line)
        .map_err(|_| ParseError::MalformedRequestLine)?;

    let mut parts = request_str.splitn(3, ' ');
    let method = parts.next().ok_or(ParseError::MalformedRequestLine)?;
    let path = parts.next().ok_or(ParseError::MalformedRequestLine)?;
    let version = parts.next().ok_or(ParseError::MalformedRequestLine)?;

    // Validate method
    let valid_methods = [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
    ];
    if !valid_methods.contains(&method) {
        return Err(ParseError::InvalidMethod(method.to_string()));
    }

    // Parse headers (starts after \r\n of request line)
    let header_start = line_end + 2; // skip \r\n
    let headers = if header_start < payload.len() {
        parse_headers(&payload[header_start..])
    } else {
        Headers::new()
    };

    Ok(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        version: version.to_string(),
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(s: &str) -> Vec<u8> {
        s.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn parse_simple_get() {
        let payload = make_request("GET /api/users HTTP/1.1\nHost: example.com\n\n");
        let req = parse_request(&payload).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/users");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.host(), Some("example.com"));
    }

    #[test]
    fn parse_post_with_headers() {
        let payload = make_request(
            "POST /api/users HTTP/1.1\n\
             Host: api.railway.app\n\
             Content-Type: application/json\n\
             Content-Length: 42\n\
             traceparent: 00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01\n\
             \n\
             {\"name\": \"test\"}"
        );
        let req = parse_request(&payload).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/users");
        assert_eq!(req.host(), Some("api.railway.app"));
        assert_eq!(req.content_length(), Some(42));
        assert_eq!(
            req.traceparent(),
            Some("00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01")
        );
    }

    #[test]
    fn parse_with_query_string() {
        let payload = make_request("GET /api/users?page=2&limit=50 HTTP/1.1\nHost: example.com\n\n");
        let req = parse_request(&payload).unwrap();
        assert_eq!(req.path, "/api/users?page=2&limit=50");
    }

    #[test]
    fn parse_all_methods() {
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let payload = make_request(&format!("{} /test HTTP/1.1\n\n", method));
            let req = parse_request(&payload).unwrap();
            assert_eq!(req.method, *method);
        }
    }

    #[test]
    fn reject_non_http() {
        // TLS ClientHello
        let tls = vec![0x16, 0x03, 0x01, 0x00, 0x05];
        assert!(matches!(parse_request(&tls), Err(ParseError::NotHttp)));

        // Empty
        assert!(matches!(parse_request(b""), Err(ParseError::NotHttp)));

        // Binary garbage
        assert!(matches!(
            parse_request(&[0xFF, 0xFE, 0xFD, 0xFC]),
            Err(ParseError::NotHttp)
        ));

        // gRPC frame (starts with 0x00)
        assert!(matches!(
            parse_request(&[0x00, 0x00, 0x00, 0x00, 0x1A]),
            Err(ParseError::NotHttp)
        ));
    }

    #[test]
    fn truncated_request_line() {
        // No \r\n — the line is incomplete
        let payload = b"GET /api/users HTTP/1.1";
        assert!(matches!(parse_request(payload), Err(ParseError::Incomplete)));
    }

    #[test]
    fn truncated_headers() {
        // Request line is complete but headers are cut off
        let payload = make_request("GET /api/users HTTP/1.1\nHost: exam");
        let req = parse_request(&payload).unwrap();
        assert_eq!(req.method, "GET");
        // Host header may be partially parsed or missing (graceful degradation)
        // The parser should not crash
    }

    #[test]
    fn large_headers_within_2kb() {
        // Simulate a request with Authorization header pushing traceparent past 512 bytes
        let auth_value = "Bearer ".to_string() + &"x".repeat(400);
        let payload = make_request(&format!(
            "POST /api/payments/charge HTTP/1.1\n\
             Host: payment-service.internal:8080\n\
             Content-Type: application/json\n\
             Authorization: {}\n\
             traceparent: 00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01\n\
             \n",
            auth_value
        ));

        // traceparent is well past byte 512 — this validates our 2KB capture decision
        let traceparent_pos = payload
            .windows(b"traceparent".len())
            .position(|w| w == b"traceparent")
            .unwrap();
        assert!(traceparent_pos > 400, "traceparent should be deep in the headers");

        let req = parse_request(&payload).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(
            req.traceparent(),
            Some("00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01")
        );
    }

    #[test]
    fn http_10() {
        let payload = make_request("GET / HTTP/1.0\n\n");
        let req = parse_request(&payload).unwrap();
        assert_eq!(req.version, "HTTP/1.0");
    }

    #[test]
    fn path_with_encoded_chars() {
        let payload = make_request("GET /api/users/hello%20world HTTP/1.1\nHost: x\n\n");
        let req = parse_request(&payload).unwrap();
        assert_eq!(req.path, "/api/users/hello%20world");
    }
}
