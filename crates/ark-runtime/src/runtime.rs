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

    pub fn enable_dns(mut self, enable: bool) -> Self {
        self.config.enable_dns = enable;
        self
    }

    pub fn enable_blob(mut self, enable: bool) -> Self {
        self.config.enable_blob = enable;
        self
    }

    pub fn enable_paas(mut self, enable: bool) -> Self {
        self.config.enable_paas = enable;
        self
    }

    pub fn enable_vpn(mut self, enable: bool) -> Self {
        self.config.enable_vpn = enable;
        self
    }

    pub fn enable_wot(mut self, enable: bool) -> Self {
        self.config.enable_wot = enable;
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

        let local_root = self.identity.as_ref().map(|id| id.ark_id).unwrap_or([0u8; 32]);
        // Consensus time initialization
        let peer_median = Arc::new(ark_time::PeerMedianTime::new());

        // Initialize DNS Engine if enabled
        let dns_engine = if self.config.enable_dns {
            #[derive(Clone)]
            struct PermissiveDnsVerifier;
            impl ark_dns::L2ContractVerifier for PermissiveDnsVerifier {
                fn verify_escrow_contract(&self, _contract_id: &[u8], _owner_key_id: &[u8]) -> ark_dns::Result<bool> {
                    Ok(true)
                }
            }

            let overlay_store = Arc::new(ark_dns::PrivateOverlayStore::new(&storage)
                .map_err(|e| ArkRuntimeError::Internal(format!("Dns init error: {:?}", e)))?);
            let l2: Arc<dyn ark_dns::L2ContractVerifier> = Arc::new(PermissiveDnsVerifier);
            let dns_clock = Arc::new(ark_time::SystemPmtClock::new(Arc::clone(&peer_median)));
            let dns = ark_dns::SovereignDnsEngine::builder()
                .overlay_store(overlay_store)
                .trie(Arc::new(ark_dns::SovereignDnsTrie::new()))
                .time_provider(dns_clock)
                .l2_verifier(Arc::new(l2))
                .default_caller_ark_id(local_root)
                .build()
                .map_err(|e| ArkRuntimeError::Internal(format!("Dns builder error: {:?}", e)))?;
            Some(Arc::new(dns))
        } else {
            None
        };

        // Initialize Blob Engine if enabled
        let blob_engine = if self.config.enable_blob {
            let hybrid_store = ark_blob::HybridBlobStore::new(data_dir.join("blobs"), storage.clone())
                .map_err(|e| ArkRuntimeError::Internal(format!("Blob store error: {:?}", e)))?;
            let blob = ark_blob::BlobEngine::new(
                hybrid_store,
                Arc::new(ark_blob::PermissiveBlobEscrowVerifier) as Arc<dyn ark_blob::BlobEscrowVerifier>,
            );
            Some(Arc::new(blob))
        } else {
            None
        };

        // Initialize PaaS Engine if enabled
        let paas_engine = if self.config.enable_paas {
            let queue = Arc::new(ark_paas::ArkQueue::open(
                storage.clone(),
                ark_paas::QueueConfig::default(),
            ).map_err(|e| ArkRuntimeError::Internal(format!("Paas queue error: {:?}", e)))?);
            let clock = Arc::new(ark_paas::InMemoryPmtClock::new(1_700_000_000));
            let kv_backend = Arc::new(ark_paas::InMemoryKvStore::new());
            let blob_backend = Arc::new(ark_paas::InMemoryBlobReader::new());
            let envelope_backend = Arc::new(ark_paas::InMemoryEnvelopeEmitter::new());
            let paas = ark_paas::PaasEngine::new(
                queue,
                clock,
                kv_backend,
                blob_backend,
                envelope_backend,
            );
            Some(Arc::new(paas))
        } else {
            None
        };

        // Initialize VPN Engine if enabled and identity exists
        let vpn_engine = if self.config.enable_vpn && self.identity.is_some() {
            let mut rng = rand::rngs::OsRng;
            let vpn_id = PersistentIdentity::generate(&mut rng);
            let tun = Arc::new(ark_vpn::MockTunAdapter::new("ark0", 1280));
            let vpn = ark_vpn::VpnEngine::new(vpn_id, tun, ark_vpn::VpnEngineConfig::default());
            Some(Arc::new(vpn))
        } else {
            None
        };

        // Initialize WoT Engine if enabled
        let wot_engine = if self.config.enable_wot {
            let clock = Arc::new(ark_time::SystemPmtClock::new(Arc::clone(&peer_median)));
            let wot = ark_wot::WotEngine::open(local_root, storage.clone(), clock)
                .map_err(|e| ArkRuntimeError::Internal(format!("Wot error: {:?}", e)))?;
            Some(Arc::new(wot))
        } else {
            None
        };

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

        let dispatcher = Arc::new(crate::dispatcher::EnvelopeDispatcher::new(
            storage.clone(),
            dns_engine,
            blob_engine,
            paas_engine,
            vpn_engine,
            wot_engine,
        )?);

        let endpoint_arc = Arc::new(server_endpoint);
        let accept_endpoint = endpoint_arc.clone();
        let accept_token = cancel_token.clone();
        let accept_dispatcher = dispatcher.clone();

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
                            let conn_dispatcher = accept_dispatcher.clone();
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
                                                            let disp = conn_dispatcher.clone();
                                                            tokio::spawn(async move {
                                                                // Read wire frame with rigid 64KB max envelope ceiling
                                                                let mut wire_buf = Vec::new();
                                                                let mut chunk = [0u8; 4096];
                                                                while let Ok(Some(n)) = recv.read(&mut chunk).await {
                                                                    wire_buf.extend_from_slice(&chunk[..n]);
                                                                    if wire_buf.len() > ark_core::constants::MAX_ENVELOPE_SIZE + 64 {
                                                                        break;
                                                                    }
                                                                }

                                                                if wire_buf.len() >= ark_core::constants::FAST_HEADER_SIZE {
                                                                    match disp.process_wire_frame(&wire_buf) {
                                                                        Ok(_) => {
                                                                            let _ = send.write_all(&[1u8]).await;
                                                                        }
                                                                        Err(e) => {
                                                                            warn!("Dispatch error: {:?}", e);
                                                                            let _ = send.write_all(&[0u8]).await;
                                                                        }
                                                                    }
                                                                } else {
                                                                    // Fallback echo if less than 64B for simple ping
                                                                    let _ = send.write_all(&wire_buf).await;
                                                                }
                                                                let _ = send.finish();
                                                            });
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
            dispatcher,
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
    dispatcher: Arc<crate::dispatcher::EnvelopeDispatcher>,
    endpoint: Arc<ArkQuicEndpoint>,
}

impl NodeHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn storage(&self) -> Arc<StorageEngine> {
        self.storage.clone()
    }

    pub fn dispatcher(&self) -> Arc<crate::dispatcher::EnvelopeDispatcher> {
        self.dispatcher.clone()
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
