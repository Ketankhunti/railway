//! REST API for the Railway Observability Engine.
//!
//! Provides endpoints for:
//! - Trace queries and waterfall views
//! - Service metrics (timeseries from rollup tables)
//! - Service topology (dependency graph)
//! - Alert rule CRUD and alert event listing
//! - Metric → Trace and Trace → Log correlation

pub mod app;
pub mod models;
pub mod traces;
pub mod services;
pub mod alerts;
pub mod correlate;
mod error;

pub use app::{create_router, AppState};
