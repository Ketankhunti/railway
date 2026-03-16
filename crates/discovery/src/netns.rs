//! Network namespace inode resolution.
//!
//! Reads /proc/{pid}/ns/net to get the network namespace inode number.
//! This inode uniquely identifies the namespace and is what eBPF reports
//! (via task->nsproxy->net_ns->ns.inum).

use std::fs;
use std::path::Path;

/// Read the network namespace inode for a given PID.
///
/// Reads the symlink at `/proc/{pid}/ns/net` which looks like:
/// `net:[4026532198]`
///
/// Returns the inode number (e.g., `4026532198`).
pub fn read_netns_inode(pid: u32) -> anyhow::Result<u32> {
    read_netns_inode_from_path(&format!("/proc/{}/ns/net", pid))
}

/// Read netns inode from a specific path (testable).
pub fn read_netns_inode_from_path(path: &str) -> anyhow::Result<u32> {
    let link = fs::read_link(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path, e))?;

    let link_str = link.to_string_lossy();
    parse_netns_link(&link_str)
}

/// Parse a netns symlink target like "net:[4026532198]" into the inode number.
pub fn parse_netns_link(link: &str) -> anyhow::Result<u32> {
    // Format: "net:[INODE_NUMBER]"
    let stripped = link
        .strip_prefix("net:[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| anyhow::anyhow!("unexpected netns format: '{}'", link))?;

    stripped
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("invalid netns inode '{}': {}", stripped, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_netns_link() {
        assert_eq!(parse_netns_link("net:[4026532198]").unwrap(), 4026532198);
    }

    #[test]
    fn parse_netns_link_small_inode() {
        assert_eq!(parse_netns_link("net:[1]").unwrap(), 1);
    }

    #[test]
    fn parse_netns_link_max_u32() {
        assert_eq!(parse_netns_link("net:[4294967295]").unwrap(), 4294967295);
    }

    #[test]
    fn parse_invalid_format() {
        assert!(parse_netns_link("").is_err());
        assert!(parse_netns_link("net:[]").is_err());
        assert!(parse_netns_link("net:[abc]").is_err());
        assert!(parse_netns_link("mnt:[123]").is_err());
        assert!(parse_netns_link("net:123").is_err());
        assert!(parse_netns_link("[123]").is_err());
    }

    #[test]
    fn parse_overflow() {
        // u32::MAX + 1 should fail
        assert!(parse_netns_link("net:[4294967296]").is_err());
    }
}
