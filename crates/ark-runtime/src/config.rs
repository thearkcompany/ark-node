use std::path::PathBuf;
use std::net::SocketAddr;
use ark_storage::StorageConfig;

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
}

impl Default for NodeRuntimeConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            data_dir: PathBuf::from("./ark-data"),
            role: Role::Server,
            storage_config: StorageConfig::default(),
        }
    }
}
