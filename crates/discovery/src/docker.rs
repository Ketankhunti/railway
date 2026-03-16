//! Docker container discovery.
//!
//! Discovers running containers, reads their labels for service metadata,
//! and resolves their network namespace inodes.
//!
//! Uses `docker inspect` CLI for simplicity (no heavy Docker SDK dependency).
//! In production, this could use the Docker Engine API via Unix socket.

use anyhow::{Context, Result};
use serde::Deserialize;

use rail_obs_common::service::ServiceMeta;

/// Docker label prefix for Railway Observability metadata.
pub const LABEL_PREFIX: &str = "rail.";
pub const LABEL_PROJECT: &str = "rail.project";
pub const LABEL_SERVICE: &str = "rail.service";
pub const LABEL_ENV: &str = "rail.env";

/// Information extracted from a Docker container.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub container_id: String,
    pub name: String,
    pub pid: u32,
    pub project_id: String,
    pub service_id: String,
    pub service_name: String,
    pub environment_id: String,
}

impl ContainerInfo {
    /// Convert to a ServiceMeta for the mapping file.
    pub fn to_service_meta(&self) -> ServiceMeta {
        ServiceMeta {
            project_id: self.project_id.clone(),
            service_id: self.service_id.clone(),
            service_name: self.service_name.clone(),
            environment_id: self.environment_id.clone(),
            container_id: self.container_id.clone(),
        }
    }
}

/// Partial Docker inspect JSON output (only fields we need).
#[derive(Debug, Deserialize)]
struct DockerInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "State")]
    state: DockerState,
    #[serde(rename = "Config")]
    config: DockerConfig,
}

#[derive(Debug, Deserialize)]
struct DockerState {
    #[serde(rename = "Pid")]
    pid: u32,
    #[serde(rename = "Running")]
    running: bool,
}

#[derive(Debug, Deserialize)]
struct DockerConfig {
    #[serde(rename = "Labels")]
    labels: Option<std::collections::HashMap<String, String>>,
}

/// Docker discovery for the service discovery shim.
pub struct DockerDiscovery;

impl DockerDiscovery {
    /// Inspect a container by ID or name and extract service metadata.
    ///
    /// Runs `docker inspect {container_id}` and parses the JSON output.
    /// Returns `None` if the container is not running or has no rail.* labels.
    pub fn inspect_container(container_id_or_name: &str) -> Result<Option<ContainerInfo>> {
        let output = std::process::Command::new("docker")
            .args(["inspect", container_id_or_name])
            .output()
            .context("failed to run 'docker inspect'")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                container = container_id_or_name,
                stderr = %stderr,
                "docker inspect failed"
            );
            return Ok(None);
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        Self::parse_inspect_output(&json_str)
    }

    /// Parse the JSON output from `docker inspect`.
    /// Extracted for testability without needing a real Docker daemon.
    pub fn parse_inspect_output(json_str: &str) -> Result<Option<ContainerInfo>> {
        let inspects: Vec<DockerInspect> = serde_json::from_str(json_str)
            .context("failed to parse docker inspect output")?;

        let inspect = match inspects.first() {
            Some(i) => i,
            None => return Ok(None),
        };

        // Skip non-running containers
        if !inspect.state.running || inspect.state.pid == 0 {
            tracing::debug!(
                container = %inspect.id,
                "container not running, skipping"
            );
            return Ok(None);
        }

        // Extract labels
        let labels = match &inspect.config.labels {
            Some(l) => l,
            None => {
                tracing::debug!(
                    container = %inspect.id,
                    "no labels, skipping"
                );
                return Ok(None);
            }
        };

        // Require at least rail.service label
        let service_name = match labels.get(LABEL_SERVICE) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => {
                tracing::debug!(
                    container = %inspect.id,
                    "no rail.service label, skipping"
                );
                return Ok(None);
            }
        };

        let project_id = labels
            .get(LABEL_PROJECT)
            .cloned()
            .unwrap_or_else(|| "default".into());

        let environment_id = labels
            .get(LABEL_ENV)
            .cloned()
            .unwrap_or_else(|| "development".into());

        // Clean container name (Docker prepends '/')
        let name = inspect.name.trim_start_matches('/').to_string();

        // Generate service_id from service_name
        let service_id = format!("svc_{}", service_name.replace('-', "_"));

        let short_id = if inspect.id.len() > 12 {
            inspect.id[..12].to_string()
        } else {
            inspect.id.clone()
        };

        Ok(Some(ContainerInfo {
            container_id: short_id,
            name,
            pid: inspect.state.pid,
            project_id,
            service_id,
            service_name,
            environment_id,
        }))
    }

    /// List all running containers with rail.* labels.
    /// Uses `docker ps --filter label=rail.service --format {{.ID}}`.
    pub fn list_rail_containers() -> Result<Vec<String>> {
        let output = std::process::Command::new("docker")
            .args([
                "ps", "-q",
                "--filter", &format!("label={}", LABEL_SERVICE),
            ])
            .output()
            .context("failed to run 'docker ps'")?;

        if !output.status.success() {
            return Ok(vec![]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let ids: Vec<String> = stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        Ok(ids)
    }

    /// Parse a Docker event line from `docker events --format`.
    /// Expected format: "ACTION CONTAINER_ID"
    /// e.g., "start abc123def456" or "die abc123def456"
    pub fn parse_event_line(line: &str) -> Option<(DockerEventAction, String)> {
        let parts: Vec<&str> = line.trim().splitn(2, ' ').collect();
        if parts.len() != 2 {
            return None;
        }

        let action = match parts[0] {
            "start" => DockerEventAction::Start,
            "die" => DockerEventAction::Die,
            _ => return None,
        };

        Some((action, parts[1].to_string()))
    }
}

/// Docker event actions we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerEventAction {
    /// Container started
    Start,
    /// Container stopped/died
    Die,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_INSPECT: &str = r#"[
        {
            "Id": "abc123def4567890abcdef1234567890abcdef1234567890abcdef12345678",
            "Name": "/api-gateway",
            "State": {
                "Status": "running",
                "Running": true,
                "Paused": false,
                "Pid": 12345,
                "ExitCode": 0
            },
            "Config": {
                "Labels": {
                    "rail.project": "proj_demo",
                    "rail.service": "api-gateway",
                    "rail.env": "production",
                    "other.label": "ignored"
                }
            }
        }
    ]"#;

    const STOPPED_INSPECT: &str = r#"[
        {
            "Id": "stopped123",
            "Name": "/stopped-svc",
            "State": {
                "Status": "exited",
                "Running": false,
                "Paused": false,
                "Pid": 0,
                "ExitCode": 0
            },
            "Config": {
                "Labels": {
                    "rail.service": "stopped-svc"
                }
            }
        }
    ]"#;

    const NO_LABELS_INSPECT: &str = r#"[
        {
            "Id": "nolabels123",
            "Name": "/no-labels",
            "State": {
                "Status": "running",
                "Running": true,
                "Paused": false,
                "Pid": 54321,
                "ExitCode": 0
            },
            "Config": {
                "Labels": {}
            }
        }
    ]"#;

    const NULL_LABELS_INSPECT: &str = r#"[
        {
            "Id": "nulllabels123",
            "Name": "/null-labels",
            "State": {
                "Status": "running",
                "Running": true,
                "Paused": false,
                "Pid": 54321,
                "ExitCode": 0
            },
            "Config": {
                "Labels": null
            }
        }
    ]"#;

    const MINIMAL_LABELS_INSPECT: &str = r#"[
        {
            "Id": "minimal123",
            "Name": "/minimal-svc",
            "State": {
                "Running": true,
                "Pid": 99999
            },
            "Config": {
                "Labels": {
                    "rail.service": "my-service"
                }
            }
        }
    ]"#;

    #[test]
    fn parse_full_inspect() {
        let info = DockerDiscovery::parse_inspect_output(SAMPLE_INSPECT)
            .unwrap()
            .unwrap();

        assert_eq!(info.container_id, "abc123def456"); // truncated to 12
        assert_eq!(info.name, "api-gateway"); // leading '/' stripped
        assert_eq!(info.pid, 12345);
        assert_eq!(info.project_id, "proj_demo");
        assert_eq!(info.service_id, "svc_api_gateway"); // dashes → underscores
        assert_eq!(info.service_name, "api-gateway");
        assert_eq!(info.environment_id, "production");
    }

    #[test]
    fn parse_stopped_container() {
        let result = DockerDiscovery::parse_inspect_output(STOPPED_INSPECT).unwrap();
        assert!(result.is_none(), "stopped containers should be skipped");
    }

    #[test]
    fn parse_no_labels() {
        let result = DockerDiscovery::parse_inspect_output(NO_LABELS_INSPECT).unwrap();
        assert!(result.is_none(), "containers without rail.service label should be skipped");
    }

    #[test]
    fn parse_null_labels() {
        let result = DockerDiscovery::parse_inspect_output(NULL_LABELS_INSPECT).unwrap();
        assert!(result.is_none(), "containers with null labels should be skipped");
    }

    #[test]
    fn parse_minimal_labels() {
        let info = DockerDiscovery::parse_inspect_output(MINIMAL_LABELS_INSPECT)
            .unwrap()
            .unwrap();

        assert_eq!(info.service_name, "my-service");
        assert_eq!(info.project_id, "default"); // default when not specified
        assert_eq!(info.environment_id, "development"); // default
    }

    #[test]
    fn service_meta_conversion() {
        let info = DockerDiscovery::parse_inspect_output(SAMPLE_INSPECT)
            .unwrap()
            .unwrap();

        let meta = info.to_service_meta();
        assert_eq!(meta.project_id, "proj_demo");
        assert_eq!(meta.service_id, "svc_api_gateway");
        assert_eq!(meta.container_id, "abc123def456");
    }

    #[test]
    fn parse_empty_array() {
        let result = DockerDiscovery::parse_inspect_output("[]").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_invalid_json() {
        let result = DockerDiscovery::parse_inspect_output("not json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_event_start() {
        let (action, id) = DockerDiscovery::parse_event_line("start abc123def456").unwrap();
        assert_eq!(action, DockerEventAction::Start);
        assert_eq!(id, "abc123def456");
    }

    #[test]
    fn parse_event_die() {
        let (action, id) = DockerDiscovery::parse_event_line("die abc123def456").unwrap();
        assert_eq!(action, DockerEventAction::Die);
        assert_eq!(id, "abc123def456");
    }

    #[test]
    fn parse_event_unknown_action() {
        assert!(DockerDiscovery::parse_event_line("pause abc123").is_none());
        assert!(DockerDiscovery::parse_event_line("restart abc123").is_none());
    }

    #[test]
    fn parse_event_malformed() {
        assert!(DockerDiscovery::parse_event_line("").is_none());
        assert!(DockerDiscovery::parse_event_line("start").is_none());
        assert!(DockerDiscovery::parse_event_line("   ").is_none());
    }

    #[test]
    fn parse_event_with_whitespace() {
        let (action, id) = DockerDiscovery::parse_event_line("  start abc123  ").unwrap();
        assert_eq!(action, DockerEventAction::Start);
        assert_eq!(id, "abc123"); // line is trimmed before splitting
    }

    #[test]
    fn container_id_truncated_to_12() {
        // Docker full IDs are 64 chars; we store first 12
        let info = DockerDiscovery::parse_inspect_output(SAMPLE_INSPECT)
            .unwrap()
            .unwrap();
        assert_eq!(info.container_id.len(), 12);
    }
}
