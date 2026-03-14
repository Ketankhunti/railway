//! Service discovery: watches services.json for namespace → service mappings.
//!
//! In production: Railway's orchestrator writes the file.
//! In development: Docker event shim writes the file.
