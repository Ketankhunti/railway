//! Ingestion pipeline: enrichment, route normalization, batching, ClickHouse writer.
//!
//! Takes SpanEvents from the span assembler, enriches them (http_route,
//! dst_service_id), batches, and inserts into ClickHouse.

pub mod route;
pub mod writer;
pub mod pipeline;

pub use pipeline::{IngestionPipeline, IngestionConfig};
pub use route::normalize_route;
pub use writer::ClickHouseRow;
