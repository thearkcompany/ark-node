use crate::identity_resolver::{get_default_identity_path, resolve_identity, ResolvedIdentitySource};
use crate::ping::ping_peer;
use ark_crypto::identity::PersistentIdentity;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ark-node")]
#[command(about = "Universal sovereign daemon for ARK Protocol v1", long_about = None)]
pub struct Cli {
    #[arg(short, long, value_enum, default_value_t = Role::Server)]
    pub role: Role,

    #[arg(short, long, default_value = "0.0.0.0:8443")]
    pub bind: String,

    /// Path to persistent identity key material
    #[arg(short, long)]
    pub identity: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Role {
    Client,
    Server,
    Relay,
    Bootstrap,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a fresh Post-Quantum keypair (FN-DSA + ML-KEM)
    Keygen {
        /// Optional file path to save identity key with 0600 permissions
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Inspect local node identity and network status
    Status,
    /// Run diagnostic ping to a target peer using ALPN ark-pqc/v1
    Ping {
        #[arg(short, long)]
        target: String,
    },
}

pub async fn execute() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Keygen { out }) => {
            let mut rng = rand::rngs::OsRng;
            let identity = PersistentIdentity::generate(&mut rng);
            println!("Derived ArkID (SHA3-256): {}", identity.ark_id_hex());
            println!("Sender Key ID (16B): {:02x?}", identity.sender_key_id);

            if let Some(out_path) = out {
                identity
                    .save_to_file(out_path)
                    .map_err(|e| anyhow::anyhow!("Failed to save keypair to {:?}: {}", out_path, e))?;
                println!("Saved identity key material to: {:?}", out_path);
            }
        }
        Some(Commands::Status) => {
            println!("Protocol: v1");
            println!("Magic: 0x{:08X}", ark_core::constants::MAGIC_VALUE);
            println!("Safe MTU: {}", ark_core::constants::SAFE_MTU);
            let alpn_str = std::str::from_utf8(ark_core::constants::ALPN_ARK_PQC_V1).unwrap_or("ark-pqc/v1");
            println!("ALPN: {}", alpn_str);
        }
        Some(Commands::Ping { target }) => {
            info!("Probing target peer {} under ALPN ark-pqc/v1...", target);
            match ping_peer(target).await {
                Ok(rtt) => {
                    println!("Ping to {} succeeded (ALPN: ark-pqc/v1) RTT: {:.2?}", target, rtt);
                }
                Err(e) => {
                    eprintln!("Ping to {} failed: {}", target, e);
                    return Err(e);
                }
            }
        }
        None => {
            let env_var = std::env::var("ARK_IDENTITY_KEY").ok();
            let default_home = get_default_identity_path();

            let (identity, source) = resolve_identity(
                cli.identity.as_deref(),
                env_var.as_deref(),
                default_home.as_deref(),
            )?;

            info!("Starting ARK Node with role: {:?}", cli.role);
            info!("Binding on: {}", cli.bind);
            info!("Active Node ArkID: {}", identity.ark_id_hex());
            info!("Identity Source: {:?}", source);

            match source {
                ResolvedIdentitySource::Ephemeral => {
                    info!("Running with ephemeral in-memory identity (session only)");
                }
                ResolvedIdentitySource::Cli => {
                    info!("Loaded identity from CLI option: {:?}", cli.identity);
                }
                ResolvedIdentitySource::Env => {
                    info!("Loaded identity from ARK_IDENTITY_KEY");
                }
                ResolvedIdentitySource::DefaultHome => {
                    info!("Loaded identity from default path: {:?}", default_home);
                }
            }

            info!("Node active in {:?} mode. Awaiting connections...", cli.role);
        }
    }

    Ok(())
}

