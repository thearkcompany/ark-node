//! Unified CLI definition with clap: --role client, --role server, etc.

use clap::{Parser, Subcommand, ValueEnum};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ark-node")]
#[command(about = "Universal sovereign daemon for ARK Protocol v1", long_about = None)]
pub struct Cli {
    #[arg(short, long, value_enum, default_value_t = Role::Server)]
    pub role: Role,

    #[arg(short, long, default_value = "0.0.0.0:8443")]
    pub bind: String,

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
    Keygen,
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

    info!("Starting ARK Node with role: {:?}", cli.role);
    info!("Binding on: {}", cli.bind);

    match &cli.command {
        Some(Commands::Keygen) => {
            let mut rng = rand::rngs::OsRng;
            let keypair = ark_crypto::fn_dsa::FnDsaKeyPair::generate(&mut rng);
            let identity = ark_crypto::identity::Identity::from_public_key(&keypair.public_key);
            println!("Derived ArkID (SHA3-256): {}", identity.ark_id_hex());
            println!("Sender Key ID (16B): {:?}", identity.sender_key_id);
        }
        Some(Commands::Status) => {
            println!("ARK Protocol: v1");
            println!("Magic Value: 0x{:08X}", ark_core::constants::MAGIC_VALUE);
            println!("Safe MTU: {} bytes", ark_core::constants::SAFE_MTU);
            println!("ALPN: ark-pqc/v1");
        }
        Some(Commands::Ping { target }) => {
            info!("Pinging target peer: {} via ark-pqc/v1...", target);
        }
        None => {
            info!("Node active in {:?} mode. Awaiting connections...", cli.role);
        }
    }

    Ok(())
}
