use std::sync::Arc;
use tracing::debug;
use ark_core::FastHeader;
use ark_crdt::{MstConfig, MstEngine, KIND_KV_MST_SYNC};
use ark_dns::SovereignDnsEngine;
use ark_blob::BlobEngine;
use ark_paas::PaasEngine;
use ark_vpn::VpnEngine;
use ark_wot::WotEngine;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::wire::WireFrame;
use ark_storage::{get_envelope_kind, RetentionOutcome, StorageEngine};

use crate::error::{ArkRuntimeError, Result};

pub const KIND_DNS_CLAIM_PUBLIC: u32 = 0x3000_0002;
pub const KIND_DEPIN_CHALLENGE: u32 = 0x4000_0002;
pub const KIND_DEPIN_RESPONSE: u32 = 0x4000_0003;
pub const KIND_BLOB_MANIFEST: u32 = 0x1000_0003;
pub const KIND_HOMELAB_ACK: u32 = 0x0000_2011;
pub const KIND_VPN_DATA: u32 = 0x0008;
pub const KIND_VPN_HANDSHAKE: u32 = 0x0009;
pub const KIND_WOT_ATTESTATION: u32 = 0x000A;
pub const KIND_WOT_REVOCATION: u32 = 0x000B;
pub const KIND_PAAS_TASK_RANGE_START: u32 = 0x5000_0000;
pub const KIND_PAAS_TASK_RANGE_END: u32 = 0x5FFF_FFFF;

pub enum DispatchOutcome {
    StoragePersisted(RetentionOutcome),
    CrdtSyncProcessed,
    DnsHandled,
    BlobHandled,
    PaasHandled,
    VpnHandled,
    WotHandled,
    Ignored,
}

pub struct EnvelopeDispatcher {
    storage: Arc<StorageEngine>,
    mst_engine: Arc<MstEngine>,
    dns_engine: Option<Arc<SovereignDnsEngine>>,
    blob_engine: Option<Arc<BlobEngine>>,
    paas_engine: Option<Arc<PaasEngine>>,
    vpn_engine: Option<Arc<VpnEngine>>,
    wot_engine: Option<Arc<WotEngine>>,
}

impl EnvelopeDispatcher {
    pub fn new(
        storage: Arc<StorageEngine>,
        dns_engine: Option<Arc<SovereignDnsEngine>>,
        blob_engine: Option<Arc<BlobEngine>>,
        paas_engine: Option<Arc<PaasEngine>>,
        vpn_engine: Option<Arc<VpnEngine>>,
        wot_engine: Option<Arc<WotEngine>>,
    ) -> Result<Self> {
        let mst_engine = Arc::new(MstEngine::open(storage.clone(), MstConfig::default())
            .map_err(|e| ArkRuntimeError::Internal(format!("Failed to open MstEngine: {:?}", e)))?);
        Ok(Self {
            storage,
            mst_engine,
            dns_engine,
            blob_engine,
            paas_engine,
            vpn_engine,
            wot_engine,
        })
    }

    pub fn storage(&self) -> Arc<StorageEngine> {
        self.storage.clone()
    }

    pub fn mst_engine(&self) -> Arc<MstEngine> {
        self.mst_engine.clone()
    }

    pub fn dns_engine(&self) -> Option<Arc<SovereignDnsEngine>> {
        self.dns_engine.clone()
    }

    pub fn blob_engine(&self) -> Option<Arc<BlobEngine>> {
        self.blob_engine.clone()
    }

    pub fn paas_engine(&self) -> Option<Arc<PaasEngine>> {
        self.paas_engine.clone()
    }

    pub fn vpn_engine(&self) -> Option<Arc<VpnEngine>> {
        self.vpn_engine.clone()
    }

    pub fn wot_engine(&self) -> Option<Arc<WotEngine>> {
        self.wot_engine.clone()
    }

    /// Primary wire processing entrypoint: inspects raw wire frame and dispatches
    pub fn process_wire_frame(&self, wire_bytes: &[u8]) -> Result<DispatchOutcome> {
        let (header, envelope) = WireFrame::decode(wire_bytes)
            .map_err(|e| ArkRuntimeError::Core(e))?;

        self.dispatch_envelope(&header, &envelope)
    }

    /// Dispatch decoded envelope based on kind with strict peripheral fault isolation
    pub fn dispatch_envelope(&self, header: &FastHeader, envelope: &ArkEnvelope) -> Result<DispatchOutcome> {
        let kind = get_envelope_kind(envelope);
        let fast_tag = header.fast_tag;
        debug!("Dispatching envelope kind=0x{:08X}, fast_tag=0x{:08X}", kind, fast_tag);

        // 1. CRDT MST sync
        if kind == KIND_KV_MST_SYNC || fast_tag == KIND_KV_MST_SYNC {
            if let Ok(resp) = prost::Message::decode(envelope.payload.as_slice()) {
                let _ = self.mst_engine.apply_sync_response(&resp);
            }
            return Ok(DispatchOutcome::CrdtSyncProcessed);
        }

        // 2. Sovereign DNS Engine routing
        if kind == KIND_DNS_CLAIM_PUBLIC || fast_tag == KIND_DNS_CLAIM_PUBLIC {
            if let Some(ref dns) = self.dns_engine {
                let fqdn_str = std::str::from_utf8(&envelope.payload).unwrap_or("");
                let _ = dns.resolve(fqdn_str, None);
            }
            let _ = self.storage.put_envelope(envelope);
            return Ok(DispatchOutcome::DnsHandled);
        }

        // 3. Blob Engine / DePIN PoR routing
        if kind == KIND_DEPIN_CHALLENGE
            || kind == KIND_DEPIN_RESPONSE
            || kind == KIND_BLOB_MANIFEST
            || kind == KIND_HOMELAB_ACK
            || fast_tag == KIND_DEPIN_CHALLENGE
            || fast_tag == KIND_DEPIN_RESPONSE
        {
            if let Some(ref blob) = self.blob_engine {
                if kind == KIND_BLOB_MANIFEST {
                    let _ = blob.ingest_manifest_envelope(envelope, false);
                } else if kind == KIND_HOMELAB_ACK {
                    let _ = blob.handle_homelab_ack(envelope, None);
                }
            }
            let _ = self.storage.put_envelope(envelope);
            return Ok(DispatchOutcome::BlobHandled);
        }

        // 4. PaaS Task / Trigger routing
        if (KIND_PAAS_TASK_RANGE_START..=KIND_PAAS_TASK_RANGE_END).contains(&kind)
            || (KIND_PAAS_TASK_RANGE_START..=KIND_PAAS_TASK_RANGE_END).contains(&fast_tag)
        {
            if let Some(ref paas) = self.paas_engine {
                use ark_paas::TriggerSource;
                // Peripheral fault isolation: guest traps or bad payloads must not crash daemon
                let trigger = ark_paas::Trigger::EnvelopeReceived(ark_paas::EnvelopePayload {
                    envelope: envelope.clone(),
                    target_worker_id: None,
                });
                let _ = paas.ingest_trigger(trigger);
            }
            let _ = self.storage.put_envelope(envelope);
            return Ok(DispatchOutcome::PaasHandled);
        }

        // 5. VPN Mesh Packet routing
        if kind == KIND_VPN_DATA
            || kind == KIND_VPN_HANDSHAKE
            || fast_tag == KIND_VPN_DATA
            || fast_tag == KIND_VPN_HANDSHAKE
        {
            // Ephemeral routing: bypasses storage per Retention Class 0
            return Ok(DispatchOutcome::VpnHandled);
        }

        // 6. Web-of-Trust Sybil Resistance routing
        if kind == KIND_WOT_ATTESTATION
            || kind == KIND_WOT_REVOCATION
            || fast_tag == KIND_WOT_ATTESTATION
            || fast_tag == KIND_WOT_REVOCATION
        {
            if let Some(ref _wot) = self.wot_engine {
                // Handled via storage & MST sync
            }
            let _outcome = self.storage.put_envelope(envelope)?;
            return Ok(DispatchOutcome::WotHandled);
        }

        // 7. General storage envelope ingest according to GCP-06 retention classes
        let _outcome = self.storage.put_envelope(envelope)?;
        Ok(DispatchOutcome::StoragePersisted(_outcome))
    }
}
