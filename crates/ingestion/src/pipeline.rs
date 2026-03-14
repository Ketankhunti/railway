//! Ingestion pipeline: batches spans and writes to ClickHouse.
//!
//! Operates as an async task that receives SpanEvents via a channel,
//! batches them (by count or time), and inserts into ClickHouse.

use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing;

use rail_obs_common::span::SpanEvent;
use crate::writer::ClickHouseRow;

/// Configuration for the ingestion pipeline.
#[derive(Debug, Clone)]
pub struct IngestionConfig {
    /// ClickHouse URL (e.g., "http://localhost:8123").
    pub clickhouse_url: String,
    /// ClickHouse database name.
    pub clickhouse_db: String,
    /// Maximum spans per batch before flushing.
    pub batch_size: usize,
    /// Maximum time before flushing a partial batch.
    pub flush_interval: Duration,
    /// Maximum buffer capacity before applying backpressure.
    pub buffer_capacity: usize,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            clickhouse_url: "http://localhost:8123".into(),
            clickhouse_db: "default".into(),
            batch_size: 10_000,
            flush_interval: Duration::from_secs(1),
            buffer_capacity: 100_000,
        }
    }
}

/// The ingestion pipeline. Receives spans and writes to ClickHouse.
pub struct IngestionPipeline {
    config: IngestionConfig,
    tx: mpsc::Sender<SpanEvent>,
    rx: Option<mpsc::Receiver<SpanEvent>>,

    // Metrics
    spans_received: u64,
    spans_written: u64,
    batches_written: u64,
    write_errors: u64,
}

impl IngestionPipeline {
    pub fn new(config: IngestionConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.buffer_capacity);
        Self {
            config,
            tx,
            rx: Some(rx),
            spans_received: 0,
            spans_written: 0,
            batches_written: 0,
            write_errors: 0,
        }
    }

    /// Get a sender handle for submitting spans.
    pub fn sender(&self) -> mpsc::Sender<SpanEvent> {
        self.tx.clone()
    }

    /// Run the pipeline. Consumes self. Call in a tokio::spawn.
    pub async fn run(mut self) -> Result<()> {
        let mut rx = self.rx.take().expect("pipeline already started");

        let client = clickhouse::Client::default()
            .with_url(&self.config.clickhouse_url)
            .with_database(&self.config.clickhouse_db);

        let mut batch: Vec<ClickHouseRow> = Vec::with_capacity(self.config.batch_size);
        let mut interval = tokio::time::interval(self.config.flush_interval);

        tracing::info!(
            url = %self.config.clickhouse_url,
            db = %self.config.clickhouse_db,
            batch_size = self.config.batch_size,
            "ingestion pipeline started"
        );

        loop {
            tokio::select! {
                // Receive a span from the channel
                span = rx.recv() => {
                    match span {
                        Some(span) => {
                            self.spans_received += 1;
                            batch.push(ClickHouseRow::from_span(&span));

                            if batch.len() >= self.config.batch_size {
                                self.flush_batch(&client, &mut batch).await;
                            }
                        }
                        None => {
                            // Channel closed — flush remaining and exit
                            if !batch.is_empty() {
                                self.flush_batch(&client, &mut batch).await;
                            }
                            tracing::info!(
                                received = self.spans_received,
                                written = self.spans_written,
                                batches = self.batches_written,
                                errors = self.write_errors,
                                "ingestion pipeline shutting down"
                            );
                            return Ok(());
                        }
                    }
                }
                // Timer tick — flush partial batch
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        self.flush_batch(&client, &mut batch).await;
                    }
                }
            }
        }
    }

    /// Write a batch of rows to ClickHouse.
    async fn flush_batch(&mut self, client: &clickhouse::Client, batch: &mut Vec<ClickHouseRow>) {
        let count = batch.len();

        match self.write_to_clickhouse(client, batch).await {
            Ok(()) => {
                self.spans_written += count as u64;
                self.batches_written += 1;
                tracing::debug!(count, "batch written to ClickHouse");
            }
            Err(e) => {
                self.write_errors += 1;
                tracing::error!(
                    error = %e,
                    count,
                    "failed to write batch to ClickHouse — spans dropped"
                );
            }
        }

        batch.clear();
    }

    /// Insert rows into ClickHouse via the native client.
    async fn write_to_clickhouse(
        &self,
        client: &clickhouse::Client,
        rows: &[ClickHouseRow],
    ) -> Result<()> {
        let mut insert = client.insert("spans")?;
        for row in rows {
            insert.write(row).await?;
        }
        insert.end().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rail_obs_common::span::{generate_trace_id, generate_span_id};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_span(path: &str, status: u16) -> SpanEvent {
        SpanEvent {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: 0,
            project_id: "proj_demo".into(),
            service_id: "svc_api".into(),
            environment_id: "production".into(),
            http_method: "GET".into(),
            http_path: path.into(),
            http_route: String::new(),
            http_status: status,
            http_host: "svc:8001".into(),
            start_time_ns: 1_000_000_000,
            duration_us: 100,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 45678,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 8002,
            dst_service_id: String::new(),
            host_id: "host-1".into(),
            container_id: "ctr_1".into(),
            is_error: status >= 400,
            is_root: true,
            sample_rate: 1.0,
        }
    }

    #[test]
    fn pipeline_creates_sender() {
        let pipeline = IngestionPipeline::new(IngestionConfig::default());
        let _sender = pipeline.sender();
    }

    #[tokio::test]
    async fn sender_can_send_spans() {
        let config = IngestionConfig {
            buffer_capacity: 100,
            ..Default::default()
        };
        let pipeline = IngestionPipeline::new(config);
        let sender = pipeline.sender();

        // Should be able to send without blocking
        sender.send(test_span("/api/users/1", 200)).await.unwrap();
        sender.send(test_span("/api/users/2", 404)).await.unwrap();
    }
}
