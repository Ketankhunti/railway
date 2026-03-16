//! Mapping file management: read, write, update services.json.
//!
//! The mapping file is the contract between the discovery shim and the collector.
//! Format: `ServiceMapping` from `rail-obs-common`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rail_obs_common::service::{ServiceMapping, ServiceMeta};

/// Default path for the services mapping file.
pub const SERVICES_FILE_PATH: &str = "/var/run/rail-obs/services.json";

/// Manages reading and writing the services.json mapping file.
#[derive(Debug)]
pub struct MappingFile {
    path: PathBuf,
    mapping: ServiceMapping,
}

impl MappingFile {
    /// Create a new MappingFile at the given path.
    /// Creates the parent directory if it doesn't exist.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create directory {:?}", parent))?;
            }
        }

        // Load existing mapping if file exists
        let mapping = if path.exists() {
            Self::read_from_path(&path)?
        } else {
            ServiceMapping::new()
        };

        Ok(Self { path, mapping })
    }

    /// Read a ServiceMapping from a JSON file.
    pub fn read_from_path(path: &Path) -> Result<ServiceMapping> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {:?}", path))?;
        let mapping: ServiceMapping = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {:?} as ServiceMapping", path))?;
        Ok(mapping)
    }

    /// Get a reference to the current mapping.
    pub fn mapping(&self) -> &ServiceMapping {
        &self.mapping
    }

    /// Get a mutable reference to the current mapping.
    pub fn mapping_mut(&mut self) -> &mut ServiceMapping {
        &mut self.mapping
    }

    /// Register a service and write the updated mapping to disk.
    pub fn register(&mut self, netns_inode: u32, meta: ServiceMeta) -> Result<()> {
        self.mapping.register(netns_inode, meta);
        self.write()
    }

    /// Unregister a service by netns inode and write the updated mapping.
    pub fn unregister(&mut self, netns_inode: u32) -> Result<()> {
        self.mapping.unregister(netns_inode);
        self.write()
    }

    /// Unregister a service by container ID and write the updated mapping.
    /// Returns the netns inode if found.
    pub fn unregister_by_container(&mut self, container_id: &str) -> Result<Option<u32>> {
        let found = self.mapping.namespaces.iter()
            .find(|(_, meta)| meta.container_id == container_id)
            .map(|(&inode, _)| inode);

        if let Some(inode) = found {
            self.mapping.unregister(inode);
            self.write()?;
            Ok(Some(inode))
        } else {
            Ok(None)
        }
    }

    /// Write the current mapping to disk atomically.
    /// Uses write-to-temp-then-rename to avoid partial reads by the collector.
    pub fn write(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.mapping)
            .context("failed to serialize ServiceMapping")?;

        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, &json)
            .with_context(|| format!("failed to write {:?}", tmp_path))?;

        fs::rename(&tmp_path, &self.path)
            .with_context(|| format!("failed to rename {:?} → {:?}", tmp_path, self.path))?;

        tracing::debug!(
            path = %self.path.display(),
            services = self.mapping.namespaces.len(),
            "services.json updated"
        );

        Ok(())
    }

    /// Returns the number of registered services.
    pub fn service_count(&self) -> usize {
        self.mapping.namespaces.len()
    }

    /// Returns the file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_meta(name: &str) -> ServiceMeta {
        ServiceMeta {
            project_id: "proj_demo".into(),
            service_id: format!("svc_{}", name),
            service_name: name.into(),
            environment_id: "production".into(),
            container_id: format!("ctr_{}", name),
        }
    }

    #[test]
    fn create_new_mapping_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rail-obs").join("services.json");

        let mf = MappingFile::new(&path).unwrap();
        assert_eq!(mf.service_count(), 0);
        assert!(path.parent().unwrap().exists());
    }

    #[test]
    fn register_and_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("services.json");

        let mut mf = MappingFile::new(&path).unwrap();
        mf.register(1001, test_meta("api-gateway")).unwrap();
        mf.register(1002, test_meta("user-service")).unwrap();

        assert_eq!(mf.service_count(), 2);

        // Verify file on disk
        let contents = fs::read_to_string(&path).unwrap();
        let loaded: ServiceMapping = serde_json::from_str(&contents).unwrap();
        assert_eq!(loaded.namespaces.len(), 2);
        assert_eq!(loaded.resolve(1001).unwrap().service_name, "api-gateway");
        assert_eq!(loaded.resolve(1002).unwrap().service_name, "user-service");
    }

    #[test]
    fn unregister_by_inode() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("services.json");

        let mut mf = MappingFile::new(&path).unwrap();
        mf.register(1001, test_meta("api-gateway")).unwrap();
        mf.register(1002, test_meta("user-service")).unwrap();
        assert_eq!(mf.service_count(), 2);

        mf.unregister(1001).unwrap();
        assert_eq!(mf.service_count(), 1);
        assert!(mf.mapping().resolve(1001).is_none());
        assert!(mf.mapping().resolve(1002).is_some());

        // Verify persisted
        let loaded = MappingFile::read_from_path(&path).unwrap();
        assert_eq!(loaded.namespaces.len(), 1);
    }

    #[test]
    fn unregister_by_container_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("services.json");

        let mut mf = MappingFile::new(&path).unwrap();
        mf.register(1001, test_meta("api-gateway")).unwrap();
        mf.register(1002, test_meta("user-service")).unwrap();

        let removed = mf.unregister_by_container("ctr_api-gateway").unwrap();
        assert_eq!(removed, Some(1001));
        assert_eq!(mf.service_count(), 1);

        // Not found
        let removed = mf.unregister_by_container("ctr_nonexistent").unwrap();
        assert_eq!(removed, None);
    }

    #[test]
    fn load_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("services.json");

        // Write a file first
        {
            let mut mf = MappingFile::new(&path).unwrap();
            mf.register(1001, test_meta("api-gateway")).unwrap();
            mf.register(1002, test_meta("user-service")).unwrap();
        }

        // Load from existing file
        let mf = MappingFile::new(&path).unwrap();
        assert_eq!(mf.service_count(), 2);
        assert_eq!(mf.mapping().resolve(1001).unwrap().service_name, "api-gateway");
    }

    #[test]
    fn atomic_write_survives_concurrent_read() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("services.json");

        let mut mf = MappingFile::new(&path).unwrap();
        mf.register(1001, test_meta("api-gateway")).unwrap();

        // Reading while writing (simulated by reading the file)
        let contents_before = fs::read_to_string(&path).unwrap();
        mf.register(1002, test_meta("user-service")).unwrap();
        let contents_after = fs::read_to_string(&path).unwrap();

        // Both should be valid JSON
        let _: ServiceMapping = serde_json::from_str(&contents_before).unwrap();
        let after: ServiceMapping = serde_json::from_str(&contents_after).unwrap();
        assert_eq!(after.namespaces.len(), 2);
    }

    #[test]
    fn overwrite_existing_entry() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("services.json");

        let mut mf = MappingFile::new(&path).unwrap();
        mf.register(1001, test_meta("old-name")).unwrap();
        assert_eq!(mf.mapping().resolve(1001).unwrap().service_name, "old-name");

        // Re-register with same inode but different metadata
        mf.register(1001, test_meta("new-name")).unwrap();
        assert_eq!(mf.service_count(), 1); // not duplicated
        assert_eq!(mf.mapping().resolve(1001).unwrap().service_name, "new-name");
    }

    #[test]
    fn empty_mapping_is_valid_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("services.json");

        let mf = MappingFile::new(&path).unwrap();
        mf.write().unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let loaded: ServiceMapping = serde_json::from_str(&contents).unwrap();
        assert!(loaded.namespaces.is_empty());
    }

    #[test]
    fn handles_corrupt_file_gracefully() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("services.json");

        // Write corrupt JSON
        fs::write(&path, "not valid json {{{").unwrap();

        // Should fail with a clear error
        let result = MappingFile::new(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parse"), "error should mention parsing: {}", err);
    }
}
