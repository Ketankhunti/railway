//! HTTP path → route normalization.
//!
//! Converts raw paths like `/api/users/123` into route patterns like
//! `/api/users/:id`. This is critical for aggregation — without it,
//! every unique user ID creates a separate row in GROUP BY.
//!
//! Heuristic-based: replaces path segments that look like IDs with `:id`.

/// Normalize an HTTP path to a route pattern.
///
/// Rules:
/// 1. Pure numeric segments → `:id` (e.g., /users/123 → /users/:id)
/// 2. UUID-like segments (32+ hex chars with dashes) → `:id`
/// 3. Segments that are hex strings of 16+ chars → `:id`
/// 4. Everything else kept as-is
/// 5. Query string stripped (only path normalized)
///
/// # Examples
/// ```
/// use rail_obs_ingestion::normalize_route;
/// assert_eq!(normalize_route("/api/users/123"), "/api/users/:id");
/// assert_eq!(normalize_route("/api/users/123/posts/456"), "/api/users/:id/posts/:id");
/// assert_eq!(normalize_route("/health"), "/health");
/// assert_eq!(normalize_route("/api/users?page=2"), "/api/users");
/// ```
pub fn normalize_route(path: &str) -> String {
    // Strip query string
    let path = path.split('?').next().unwrap_or(path);
    // Strip fragment
    let path = path.split('#').next().unwrap_or(path);

    if path.is_empty() || path == "/" {
        return "/".to_string();
    }

    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<String> = segments
        .iter()
        .map(|seg| {
            if seg.is_empty() {
                String::new()
            } else if looks_like_id(seg) {
                ":id".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect();

    let result = normalized.join("/");
    if result.is_empty() {
        "/".to_string()
    } else {
        result
    }
}

/// Returns true if a path segment looks like a dynamic ID.
fn looks_like_id(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }

    // Pure numeric (123, 42, etc.)
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    // UUID format: 8-4-4-4-12 hex chars with dashes (36 chars total)
    if segment.len() == 36 && segment.chars().filter(|c| *c == '-').count() == 4 {
        let hex_only: String = segment.chars().filter(|c| *c != '-').collect();
        if hex_only.len() == 32 && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }

    // Long hex string (16+ chars, like trace IDs, mongo ObjectIds, etc.)
    if segment.len() >= 16 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // Base64-ish JWT tokens or long random strings (32+ chars mixed alphanumeric)
    if segment.len() >= 32
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_ids() {
        assert_eq!(normalize_route("/api/users/123"), "/api/users/:id");
        assert_eq!(normalize_route("/api/users/0"), "/api/users/:id");
        assert_eq!(
            normalize_route("/api/users/42/posts/99"),
            "/api/users/:id/posts/:id"
        );
    }

    #[test]
    fn uuid_ids() {
        assert_eq!(
            normalize_route("/api/users/550e8400-e29b-41d4-a716-446655440000"),
            "/api/users/:id"
        );
    }

    #[test]
    fn hex_ids() {
        assert_eq!(
            normalize_route("/api/traces/4bf92f3577b58681a1038a16d442e168"),
            "/api/traces/:id"
        );
        // MongoDB ObjectId (24 hex chars)
        assert_eq!(
            normalize_route("/api/docs/507f1f77bcf86cd799439011"),
            "/api/docs/:id"
        );
    }

    #[test]
    fn static_paths() {
        assert_eq!(normalize_route("/health"), "/health");
        assert_eq!(normalize_route("/api/users"), "/api/users");
        assert_eq!(normalize_route("/"), "/");
        assert_eq!(normalize_route(""), "/");
        assert_eq!(
            normalize_route("/api/v1/metrics"),
            "/api/v1/metrics"
        );
    }

    #[test]
    fn strips_query_string() {
        assert_eq!(normalize_route("/api/users?page=2&limit=50"), "/api/users");
        assert_eq!(
            normalize_route("/api/users/123?fields=name"),
            "/api/users/:id"
        );
    }

    #[test]
    fn strips_fragment() {
        assert_eq!(normalize_route("/api/docs#section"), "/api/docs");
    }

    #[test]
    fn mixed_static_and_dynamic() {
        // abc123 is only 6 chars — too short to be classified as an ID.
        // Only the numeric segment 42 is replaced.
        assert_eq!(
            normalize_route("/api/projects/42/services/abc123/logs"),
            "/api/projects/:id/services/abc123/logs"
        );
        // With a 24-char hex segment (like a Mongo ObjectId), it IS replaced:
        assert_eq!(
            normalize_route("/api/projects/42/services/507f1f77bcf86cd799439011/logs"),
            "/api/projects/:id/services/:id/logs"
        );
    }

    #[test]
    fn short_hex_not_id() {
        // Short hex strings (< 16 chars) are NOT treated as IDs
        // "abcdef" could be a valid service name
        assert_eq!(normalize_route("/api/abcdef"), "/api/abcdef");
    }

    #[test]
    fn v1_v2_not_id() {
        // "v1", "v2" are not numeric (contain 'v')
        assert_eq!(normalize_route("/api/v1/users"), "/api/v1/users");
        assert_eq!(normalize_route("/api/v2/users"), "/api/v2/users");
    }
}
