pub mod commands;

pub use commands::*;

pub async fn run() -> anyhow::Result<()> {
    commands::execute().await
}
