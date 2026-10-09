pub mod commands;
pub mod identity_resolver;
pub mod ping;

pub use commands::*;

pub async fn run() -> anyhow::Result<()> {
    commands::execute().await
}
