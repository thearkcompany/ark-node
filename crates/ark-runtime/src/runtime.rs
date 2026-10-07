use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use ark_crypto::PersistentIdentity;
use ark_storage::{StorageConfig, StorageEngine};
use ark_transport::ArkQuicEndpoint;

use crate::config::{NodeRuntimeConfig, NodeRuntimeStatus, Role};
use crate::error::{ArkRuntimeError, Result};

pub struct NodeRuntimeBuilder {
    config: NodeRuntimeConfig,
    identity: Option<PersistentIdentity>,
}

impl Default for NodeRuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRuntimeBuilder {
    pub fn new() -> Self {
        Self {
            config: NodeRuntimeConfig::default(),
            identity: None,
        }
    }

    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.config.bind_addr = addr;
        self
    }

    pub fn data_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.config.data_dir = path.as_ref().to_path_buf();
        self
    }

    pub fn role(mut self, role: Role) -> Self {
        self.config.role = role;
        self
    }

    pub fn storage_config(mut self, config: StorageConfig) -> Self {
        self.config.storage_config = config;
        self
    }

    pub fn identity(mut self, identity: PersistentIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub async fn spawn(self) -> Result<NodeHandle> {
        let bind_addr = self.config.bind_addr;
        let data_dir = self.config.data_dir.clone();
        std::fs::create_dir_all(&data_dir)?;

        // Storage initialization
        let storage = Arc::new(StorageEngine::open(
            data_dir.join("storage"),
            self.config.storage_config,
        )?);

        // QUIC server endpoint initialization
        let server_endpoint = ArkQuicEndpoint::new_server_self_signed(bind_addr)
            .map_err(|e| ArkRuntimeError::Quic(e.to_string()))?;
        let local_addr = server_endpoint
            .endpoint
            .local_addr()
            .map_err(ArkRuntimeError::Io)?;

        let cancel_token = CancellationToken::new();
        let join_set = Arc::new(tokio::sync::Mutex::new(JoinSet::new()));
        let status = Arc::new(AtomicU8::new(NodeRuntimeStatus::Running as u8));

        let endpoint_arc = Arc::new(server_endpoint);
        let accept_endpoint = endpoint_arc.clone();
        let accept_token = cancel_token.clone();
        let accept_storage = storage.clone();

        // Spawn QUIC accept loop inside JoinSet
        {
            let mut set = join_set.lock().await;
            set.spawn(async move {
                loop {
                    tokio::select! {
                        _ = accept_token.cancelled() => {
                            break;
                        }
                        incoming = accept_endpoint.endpoint.accept() => {
                            let incoming = match incoming {
                                Some(inc) => inc,
                                None => break,
                            };
                            let conn_token = accept_token.clone();
                            let _conn_storage = accept_storage.clone();
                            tokio::spawn(async move {
                                match incoming.await {
                                    Ok(conn) => {
                                        loop {
                                            tokio::select! {
                                                _ = conn_token.cancelled() => {
                                                    conn.close(0u32.into(), b"node shutting down");
                                                    break;
                                                }
                                                stream = conn.accept_bi() => {
                                                    match stream {
                                                        Ok((mut send, mut recv)) => {
                                                            let mut buf = [0u8; 1024];
                                                            if let Ok(n) = recv.read(&mut buf).await {
                                                                if let Some(n) = n {
                                                                    let _ = send.write_all(&buf[..n]).await;
                                                                    let _ = send.finish();
                                                                }
                                                            }
                                                        }
                                                        Err(_) => break,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("QUIC connection handshake error: {:?}", e);
                                    }
                                }
                            });
                        }
                    }
                }
            });
        }

        Ok(NodeHandle {
            local_addr,
            status,
            cancel_token,
            join_set,
            storage,
            endpoint: endpoint_arc,
        })
    }
}

pub struct NodeHandle {
    local_addr: SocketAddr,
    status: Arc<AtomicU8>,
    cancel_token: CancellationToken,
    join_set: Arc<tokio::sync::Mutex<JoinSet<()>>>,
    storage: Arc<StorageEngine>,
    endpoint: Arc<ArkQuicEndpoint>,
}

impl NodeHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn storage(&self) -> Arc<StorageEngine> {
        self.storage.clone()
    }

    pub fn status(&self) -> NodeRuntimeStatus {
        match self.status.load(Ordering::SeqCst) {
            0 => NodeRuntimeStatus::Starting,
            1 => NodeRuntimeStatus::Running,
            2 => NodeRuntimeStatus::Draining,
            _ => NodeRuntimeStatus::Stopped,
        }
    }

    pub async fn shutdown(self) -> Result<()> {
        self.status.store(NodeRuntimeStatus::Draining as u8, Ordering::SeqCst);

        // Cancel background accept loop and connection handlers
        self.cancel_token.cancel();

        // Close QUIC endpoint immediately so no new connections arrive
        self.endpoint.endpoint.close(0u32.into(), b"shutdown");

        // Wait for tasks in JoinSet
        let mut set = self.join_set.lock().await;
        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                warn!("Task in JoinSet terminated with error: {:?}", e);
            }
        }

        self.status.store(NodeRuntimeStatus::Stopped as u8, Ordering::SeqCst);
        info!("NodeRuntime graceful shutdown completed");
        Ok(())
    }
}
