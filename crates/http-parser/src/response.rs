use crate::{find_crlf, is_http_response, ParseError};
use crate::headers::{Headers, parse_headers};

/// Parsed HTTP response from a captured payload.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Headers,
}

impl HttpResponse {
    /// Returns true if the status code indicates an error (>= 400).
    pub fn is_error(&self) -> bool {
        self.status_code >= 400
    }

    /// Returns true if the status code indicates a server error (>= 500).
    pub fn is_server_error(&self) -> bool {
        self.status_code >= 500
    }

    /// Returns the Content-Length header value, if present.
    pub fn content_length(&self) -> Option<usize> {
        self.headers.get("content-length")?.parse().ok()
    }
}

/// Parse an HTTP response from raw payload bytes.
///
/// Returns `Err(NotHttp)` if the payload doesn't start with "HTTP/".
/// Returns `Err(Incomplete)` if the status line is truncated.
pub fn parse_response(payload: &[u8]) -> Result<HttpResponse, ParseError> {
    if !is_http_response(payload) {
        return Err(ParseError::NotHttp);
    }

    // Find end of status line
    let line_end = find_crlf(payload, 0).ok_or(ParseError::Incomplete)?;
    let status_line = &payload[..line_end];

    let status_str = std::str::from_utf8(status_line)
        .map_err(|_| ParseError::MalformedStatusLine)?;

    // Parse "HTTP/1.1 200 OK"
    let mut parts = status_str.splitn(3, ' ');
    let version = parts.next().ok_or(ParseError::MalformedStatusLine)?;
    let status_code_str = parts.next().ok_or(ParseError::MalformedStatusLine)?;
    let reason = parts.next().unwrap_or(""); // reason phrase is optional

    let status_code: u16 = status_code_str
        .parse()
        .map_err(|_| ParseError::InvalidStatus(status_code_str.to_string()))?;

    if !(100..=599).contains(&status_code) {
        return Err(ParseError::InvalidStatus(status_code_str.to_string()));
    }

    // Parse headers
    let header_start = line_end + 2;
    let headers = if header_start < payload.len() {
        parse_headers(&payload[header_start..])
    } else {
        Headers::new()
    };

    Ok(HttpResponse {
        version: version.to_string(),
        status_code,
        reason: reason.to_string(),
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(s: &str) -> Vec<u8> {
        s.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn parse_200_ok() {
        let payload = make_response("HTTP/1.1 200 OK\nContent-Length: 13\n\n{\"ok\": true}");
        let resp = parse_response(&payload).unwrap();
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert!(!resp.is_error());
        assert_eq!(resp.content_length(), Some(13));
    }

    #[test]
    fn parse_404() {
        let payload = make_response("HTTP/1.1 404 Not Found\n\n");
        let resp = parse_response(&payload).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
        assert!(resp.is_error());
        assert!(!resp.is_server_error());
    }

    #[test]
    fn parse_500() {
        let payload = make_response("HTTP/1.1 500 Internal Server Error\n\n");
        let resp = parse_response(&payload).unwrap();
        assert_eq!(resp.status_code, 500);
        assert!(resp.is_error());
        assert!(resp.is_server_error());
    }

    #[test]
    fn parse_201_created() {
        let payload = make_response("HTTP/1.1 201 Created\nLocation: /api/users/42\n\n");
        let resp = parse_response(&payload).unwrap();
        assert_eq!(resp.status_code, 201);
        assert!(!resp.is_error());
    }

    #[test]
    fn parse_204_no_content() {
        let payload = make_response("HTTP/1.1 204 No Content\n\n");
        let resp = parse_response(&payload).unwrap();
        assert_eq!(resp.status_code, 204);
        assert_eq!(resp.reason, "No Content");
    }

    #[test]
    fn parse_301_redirect() {
        let payload = make_response(
            "HTTP/1.1 301 Moved Permanently\nLocation: https://new.example.com/\n\n"
        );
        let resp = parse_response(&payload).unwrap();
        assert_eq!(resp.status_code, 301);
    }

    #[test]
    fn reject_non_http_response() {
        assert!(matches!(
            parse_response(b"GET /test HTTP/1.1\r\n"),
            Err(ParseError::NotHttp)
        ));
        assert!(matches!(
            parse_response(b"\x16\x03\x01"),
            Err(ParseError::NotHttp)
        ));
    }

    #[test]
    fn truncated_status_line() {
        assert!(matches!(
            parse_response(b"HTTP/1.1 200"),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn invalid_status_code() {
        let payload = make_response("HTTP/1.1 abc OK\n\n");
        assert!(matches!(
            parse_response(&payload),
            Err(ParseError::InvalidStatus(_))
        ));
    }

    #[test]
    fn status_code_out_of_range() {
        let payload = make_response("HTTP/1.1 999 Weird\n\n");
        assert!(matches!(
            parse_response(&payload),
            Err(ParseError::InvalidStatus(_))
        ));
    }

    #[test]
    fn http_10_response() {
        let payload = make_response("HTTP/1.0 200 OK\n\n");
        let resp = parse_response(&payload).unwrap();
        assert_eq!(resp.version, "HTTP/1.0");
    }

    #[test]
    fn no_reason_phrase() {
        // Some servers omit the reason phrase
        let payload = b"HTTP/1.1 200\r\n\r\n";
        // This should be split as ["HTTP/1.1", "200"] with no third part.
        // splitn(3, ' ') with only 2 parts → reason = ""
        let resp = parse_response(payload).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "");
    }
}
