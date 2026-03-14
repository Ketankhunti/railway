use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("rail-obs collector starting");

    // TODO: Initialize components:
    // 1. Service discovery (read services.json)
    // 2. eBPF probes (Linux only)
    // 3. Span assembler
    // 4. Ingestion pipeline
    // 5. Alerting engine
    // 6. REST API server

    tracing::info!("rail-obs collector ready");

    // Keep running until ctrl-c
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
