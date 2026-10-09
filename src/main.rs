//! Universal ARK Daemon Entrypoint (ARK-Node v1)

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Initializing ARK Node v1...");

    ark_cli::run().await?;

    Ok(())
}
