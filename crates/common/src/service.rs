use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Metadata about a Railway service, resolved from network namespace ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMeta {
    pub project_id: String,
    pub service_id: String,
    pub service_name: String,
    pub environment_id: String,
    pub container_id: String,
}

/// Maps network namespace inode → service metadata.
/// This is the contract between the discovery shim and the collector.
///
/// In production: Railway's orchestrator writes `/var/run/railway/services.json`
/// In development: Docker event shim writes the same file from container labels
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceMapping {
    pub namespaces: HashMap<u32, ServiceMeta>,
}

impl ServiceMapping {
    pub fn new() -> Self {
        Self {
            namespaces: HashMap::new(),
        }
    }

    /// Look up service metadata by network namespace inode.
    pub fn resolve(&self, netns_inode: u32) -> Option<&ServiceMeta> {
        self.namespaces.get(&netns_inode)
    }

    /// Register a namespace → service mapping.
    pub fn register(&mut self, netns_inode: u32, meta: ServiceMeta) {
        self.namespaces.insert(netns_inode, meta);
    }

    /// Remove a mapping (on container destroy).
    pub fn unregister(&mut self, netns_inode: u32) {
        self.namespaces.remove(&netns_inode);
    }
}

/// Identifies a TCP connection uniquely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl ConnectionKey {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }

    /// Returns the reverse key (swap src/dst) for matching the other side.
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn service_mapping_crud() {
        let mut mapping = ServiceMapping::new();

        let meta = ServiceMeta {
            project_id: "proj_123".into(),
            service_id: "svc_api".into(),
            service_name: "api-gateway".into(),
            environment_id: "production".into(),
            container_id: "ctr_abc".into(),
        };

        mapping.register(4026531001, meta.clone());

        let resolved = mapping.resolve(4026531001).unwrap();
        assert_eq!(resolved.project_id, "proj_123");
        assert_eq!(resolved.service_name, "api-gateway");

        assert!(mapping.resolve(9999999).is_none());

        mapping.unregister(4026531001);
        assert!(mapping.resolve(4026531001).is_none());
    }

    #[test]
    fn connection_key_reverse() {
        let key = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2)),
            45678,
            IpAddr::V4(Ipv4Addr::new(172, 17, 0, 3)),
            8002,
        );

        let rev = key.reverse();
        assert_eq!(rev.src_ip, key.dst_ip);
        assert_eq!(rev.src_port, key.dst_port);
        assert_eq!(rev.dst_ip, key.src_ip);
        assert_eq!(rev.dst_port, key.src_port);

        assert_eq!(key.reverse().reverse(), key);
    }

    #[test]
    fn connection_key_hash_equality() {
        let a = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080,
        );
        let b = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080,
        );
        assert_eq!(a, b);

        let mut map = HashMap::new();
        map.insert(a, "test");
        assert_eq!(map.get(&b), Some(&"test"));
    }

    #[test]
    fn service_mapping_json_roundtrip() {
        let mut mapping = ServiceMapping::new();
        mapping.register(
            100,
            ServiceMeta {
                project_id: "p1".into(),
                service_id: "s1".into(),
                service_name: "svc-a".into(),
                environment_id: "dev".into(),
                container_id: "c1".into(),
            },
        );

        let json = serde_json::to_string(&mapping).unwrap();
        let decoded: ServiceMapping = serde_json::from_str(&json).unwrap();
        assert!(decoded.resolve(100).is_some());
        assert_eq!(decoded.resolve(100).unwrap().service_name, "svc-a");
    }
}
