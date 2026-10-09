use ark_storage::StorageConfig;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
    Relay,
    Bootstrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRuntimeStatus {
    Starting,
    Running,
    Draining,
    Stopped,
}

#[derive(Debug, Clone)]
pub struct NodeRuntimeConfig {
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub role: Role,
    pub storage_config: StorageConfig,
    pub enable_dns: bool,
    pub enable_blob: bool,
    pub enable_paas: bool,
    pub enable_vpn: bool,
    pub enable_wot: bool,
}

impl Default for NodeRuntimeConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            data_dir: PathBuf::from("./ark-data"),
            role: Role::Server,
            storage_config: StorageConfig::default(),
            enable_dns: true,
            enable_blob: true,
            enable_paas: true,
            enable_vpn: true,
            enable_wot: true,
        }
    }
}
