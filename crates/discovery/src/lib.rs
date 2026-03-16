//! Service discovery for the Railway Observability Engine.
//!
//! Two modes:
//! - **Writer (shim):** Watches Docker events, resolves network namespaces,
//!   writes `/var/run/rail-obs/services.json`.
//! - **Reader (collector):** Watches `services.json` for changes, reloads
//!   the mapping into the span assembler.
//!
//! ## Contract
//!
//! The shim and collector communicate via a single JSON file whose schema
//! is `ServiceMapping` from `rail-obs-common`. Docker labels on containers
//! provide the service metadata:
//!
//! ```text
//! docker run --label rail.project=proj_demo \
//!            --label rail.service=api-gateway \
//!            --label rail.env=production \
//!            my-image
//! ```

pub mod netns;
pub mod mapping;
pub mod docker;

pub use mapping::{MappingFile, SERVICES_FILE_PATH};
pub use docker::{ContainerInfo, DockerDiscovery};
pub use netns::read_netns_inode;
