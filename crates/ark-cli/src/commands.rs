use crate::identity_resolver::{get_default_identity_path, resolve_identity};
use crate::ping::ping_peer;
use ark_crypto::identity::PersistentIdentity;
use ark_runtime::{NodeHandle, NodeRuntimeBuilder, Role as RuntimeRole};
use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug, Clone)]
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

    /// Path to node persistent storage directory (defaults to ~/.ark/storage)
    #[arg(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Enable Sovereign DNS subsystem engine
    #[arg(long, default_value_t = true)]
    pub enable_dns: bool,

    /// Enable Distributed Blob storage / PoR engine
    #[arg(long, default_value_t = true)]
    pub enable_blob: bool,

    /// Enable Sovereign PaaS / WASM worker engine
    #[arg(long, default_value_t = true)]
    pub enable_paas: bool,

    /// Enable Overlay VPN mesh engine
    #[arg(long, default_value_t = true)]
    pub enable_vpn: bool,

    /// Enable Web-of-Trust Sybil resistance engine
    #[arg(long, default_value_t = true)]
    pub enable_wot: bool,

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

impl From<Role> for RuntimeRole {
    fn from(r: Role) -> Self {
        match r {
            Role::Client => RuntimeRole::Client,
            Role::Server => RuntimeRole::Server,
            Role::Relay => RuntimeRole::Relay,
            Role::Bootstrap => RuntimeRole::Bootstrap,
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
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

impl Cli {
    pub fn build_runtime(&self) -> anyhow::Result<NodeRuntimeBuilder> {
        let env_var = std::env::var("ARK_IDENTITY_KEY").ok();
        let default_home = get_default_identity_path();

        let (identity, source) = resolve_identity(
            self.identity.as_deref(),
            env_var.as_deref(),
            default_home.as_deref(),
        )?;

        info!("Starting ARK Node with role: {:?}", self.role);
        info!("Binding on: {}", self.bind);
        info!("Active Node ArkID: {}", identity.ark_id_hex());
        info!("Identity Source: {:?}", source);

        let data_dir = self.data_dir.clone().unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|h| h.join(".ark").join("storage"))
                .unwrap_or_else(|| PathBuf::from("./ark-data"))
        });

        let bind_addr: SocketAddr = self
            .bind
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:8443".parse().unwrap());

        let builder = NodeRuntimeBuilder::new()
            .bind_addr(bind_addr)
            .data_dir(data_dir)
            .role(self.role.into())
            .identity(identity)
            .enable_dns(self.enable_dns)
            .enable_blob(self.enable_blob)
            .enable_paas(self.enable_paas)
            .enable_vpn(self.enable_vpn)
            .enable_wot(self.enable_wot);

        Ok(builder)
    }
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
                identity.save_to_file(out_path).map_err(|e| {
                    anyhow::anyhow!("Failed to save keypair to {:?}: {}", out_path, e)
                })?;
                println!("Saved identity key material to: {:?}", out_path);
            }
        }
        Some(Commands::Status) => {
            println!("Protocol: v1");
            println!("Magic: 0x{:08X}", ark_core::constants::MAGIC_VALUE);
            println!("Safe MTU: {}", ark_core::constants::SAFE_MTU);
            let alpn_str =
                std::str::from_utf8(ark_core::constants::ALPN_ARK_PQC_V1).unwrap_or("ark-pqc/v1");
            println!("ALPN: {}", alpn_str);
        }
        Some(Commands::Ping { target }) => {
            info!("Probing target peer {} under ALPN ark-pqc/v1...", target);
            match ping_peer(target).await {
                Ok(rtt) => {
                    println!(
                        "Ping to {} succeeded (ALPN: ark-pqc/v1) RTT: {:.2?}",
                        target, rtt
                    );
                }
                Err(e) => {
                    eprintln!("Ping to {} failed: {}", target, e);
                    return Err(e);
                }
            }
        }
        None => {
            let builder = cli.build_runtime()?;
            let handle: NodeHandle = builder
                .spawn()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to spawn NodeRuntime: {:?}", e))?;

            info!(
                "NodeRuntime active and listening on {}",
                handle.local_addr()
            );

            // Signal handler for SIGINT / SIGTERM
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT/SIGTERM, initiating graceful shutdown...");
                }
            }

            handle
                .shutdown()
                .await
                .map_err(|e| anyhow::anyhow!("Error during graceful shutdown: {:?}", e))?;
            info!("Node shutdown cleanly.");
        }
    }

    Ok(())
}
