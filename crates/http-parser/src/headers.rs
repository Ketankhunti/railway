use crate::find_crlf;
use std::collections::HashMap;

/// Parsed HTTP headers. Keys are stored lowercase for case-insensitive lookup.
#[derive(Debug, Clone)]
pub struct Headers {
    inner: HashMap<String, String>,
}

impl Headers {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Get a header value by name (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.inner.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }

    /// Returns the number of parsed headers.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if no headers were parsed.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over all headers as (name, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.inner.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse HTTP headers from a byte slice starting AFTER the request/status line.
///
/// Stops at \r\n\r\n (end of headers) or end of payload (truncated capture).
/// Gracefully handles truncation mid-header by discarding the incomplete line.
pub fn parse_headers(data: &[u8]) -> Headers {
    let mut headers = Headers::new();
    let mut pos = 0;

    loop {
        // Check for end of headers (\r\n alone = empty line)
        if pos + 1 < data.len() && data[pos] == b'\r' && data[pos + 1] == b'\n' {
            break; // end of headers
        }

        // Find end of this header line
        let line_end = match find_crlf(data, pos) {
            Some(end) => end,
            None => break, // truncated — no more complete lines
        };

        // Parse "Name: Value"
        let line = &data[pos..line_end];
        if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
            if let (Ok(name), Ok(value)) = (
                std::str::from_utf8(&line[..colon_pos]),
                std::str::from_utf8(&line[colon_pos + 1..]),
            ) {
                let name = name.trim().to_ascii_lowercase();
                let value = value.trim().to_string();
                if !name.is_empty() {
                    headers.inner.insert(name, value);
                }
            }
        }

        pos = line_end + 2; // skip \r\n
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(s: &str) -> Vec<u8> {
        s.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn parse_basic_headers() {
        let data = make_headers("Host: example.com\nContent-Type: application/json\n\n");
        let headers = parse_headers(&data);
        assert_eq!(headers.get("host"), Some("example.com"));
        assert_eq!(headers.get("content-type"), Some("application/json"));
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn case_insensitive_lookup() {
        let data = make_headers("Content-Type: text/html\n\n");
        let headers = parse_headers(&data);
        assert_eq!(headers.get("content-type"), Some("text/html"));
        assert_eq!(headers.get("Content-Type"), Some("text/html"));
        assert_eq!(headers.get("CONTENT-TYPE"), Some("text/html"));
    }

    #[test]
    fn header_value_with_colon() {
        // Values can contain colons (e.g., URLs, time values)
        let data = make_headers("Location: https://example.com:8080/path\n\n");
        let headers = parse_headers(&data);
        assert_eq!(
            headers.get("location"),
            Some("https://example.com:8080/path")
        );
    }

    #[test]
    fn traceparent_header() {
        let data = make_headers(
            "Host: svc.internal\ntraceparent: 00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01\n\n"
        );
        let headers = parse_headers(&data);
        assert_eq!(
            headers.get("traceparent"),
            Some("00-4bf92f3577b58681a1038a16d442e168-00f067aa0ba902b7-01")
        );
    }

    #[test]
    fn truncated_mid_header() {
        // Payload cut off in the middle of a header line — no trailing \r\n
        let data = b"Host: example.com\r\nContent-Type: appli";
        let headers = parse_headers(data);
        assert_eq!(headers.get("host"), Some("example.com"));
        // Content-Type is truncated (no \r\n) — should be discarded, not crash
        assert!(headers.get("content-type").is_none());
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn empty_payload() {
        let headers = parse_headers(b"");
        assert!(headers.is_empty());
    }

    #[test]
    fn immediate_end_of_headers() {
        let data = b"\r\n";
        let headers = parse_headers(data);
        assert!(headers.is_empty());
    }

    #[test]
    fn whitespace_in_values() {
        let data = make_headers("X-Custom:   value with spaces   \n\n");
        let headers = parse_headers(&data);
        assert_eq!(headers.get("x-custom"), Some("value with spaces"));
    }

    #[test]
    fn many_headers() {
        let mut raw = String::new();
        for i in 0..20 {
            raw.push_str(&format!("X-Header-{}: value-{}\n", i, i));
        }
        raw.push('\n');
        let data = make_headers(&raw);
        let headers = parse_headers(&data);
        assert_eq!(headers.len(), 20);
        assert_eq!(headers.get("x-header-0"), Some("value-0"));
        assert_eq!(headers.get("x-header-19"), Some("value-19"));
    }

    #[test]
    fn header_without_value() {
        let data = make_headers("X-Empty:\nHost: test\n\n");
        let headers = parse_headers(&data);
        assert_eq!(headers.get("x-empty"), Some(""));
        assert_eq!(headers.get("host"), Some("test"));
    }

    #[test]
    fn malformed_line_no_colon() {
        let data = make_headers("Host: test\nthis-has-no-colon\nOther: val\n\n");
        let headers = parse_headers(&data);
        assert_eq!(headers.get("host"), Some("test"));
        assert_eq!(headers.get("other"), Some("val"));
        // The malformed line is skipped
        assert_eq!(headers.len(), 2);
    }
}
