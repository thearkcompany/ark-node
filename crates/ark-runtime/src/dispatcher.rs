use std::sync::Arc;
use tracing::debug;
use ark_core::FastHeader;
use ark_crdt::{MstConfig, MstEngine, KIND_KV_MST_SYNC};
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::wire::WireFrame;
use ark_storage::{get_envelope_kind, RetentionOutcome, StorageEngine};

use crate::error::{ArkRuntimeError, Result};

pub enum DispatchOutcome {
    StoragePersisted(RetentionOutcome),
    CrdtSyncProcessed,
    SubsystemHandled(&'static str),
    Ignored,
}

pub struct EnvelopeDispatcher {
    storage: Arc<StorageEngine>,
    mst_engine: Arc<MstEngine>,
}

impl EnvelopeDispatcher {
    pub fn new(storage: Arc<StorageEngine>) -> Result<Self> {
        let mst_engine = Arc::new(MstEngine::open(storage.clone(), MstConfig::default())
            .map_err(|e| ArkRuntimeError::Internal(format!("Failed to open MstEngine: {:?}", e)))?);
        Ok(Self {
            storage,
            mst_engine,
        })
    }

    pub fn storage(&self) -> Arc<StorageEngine> {
        self.storage.clone()
    }

    pub fn mst_engine(&self) -> Arc<MstEngine> {
        self.mst_engine.clone()
    }

    /// Primary wire processing entrypoint: inspects raw wire frame and dispatches
    pub fn process_wire_frame(&self, wire_bytes: &[u8]) -> Result<DispatchOutcome> {
        let (header, envelope) = WireFrame::decode(wire_bytes)
            .map_err(|e| ArkRuntimeError::Core(e))?;

        self.dispatch_envelope(&header, &envelope)
    }

    /// Dispatch decoded envelope based on kind and retention class
    pub fn dispatch_envelope(&self, header: &FastHeader, envelope: &ArkEnvelope) -> Result<DispatchOutcome> {
        let kind = get_envelope_kind(envelope);
        debug!("Dispatching envelope kind=0x{:08X}, fast_tag=0x{:08X}", kind, header.fast_tag);

        // 1. Check CRDT MST sync
        if kind == KIND_KV_MST_SYNC || header.fast_tag == KIND_KV_MST_SYNC {
            // Check if payload is sync request or response
            if let Ok(resp) = prost::Message::decode(envelope.payload.as_slice()) {
                let _ = self.mst_engine.apply_sync_response(&resp);
                return Ok(DispatchOutcome::CrdtSyncProcessed);
            }
            return Ok(DispatchOutcome::CrdtSyncProcessed);
        }

        // 2. Default storage persistence routing according to GCP-06 retention classes
        let outcome = self.storage.put_envelope(envelope)?;
        Ok(DispatchOutcome::StoragePersisted(outcome))
    }
}
