//! ark-crdt: Distributed Key-Value Consistency via Merkle Search Trees (MST) & Multi-Value Registers (MVR) (GCP-09).

pub mod cache;
pub mod diff;
pub mod engine;
pub mod error;
pub mod mst;
pub mod store;
pub mod sync;

pub use cache::{estimate_node_size_bytes, LruNodeCache};
pub use diff::{MstDiff, MstSyncItem, MstSyncPlan};
pub use engine::{MstConfig, MstEngine};
pub use error::{ArkCrdtError, Result};
pub use mst::{compute_key_level, MerkleSearchTree, MstEntry, MstNode, MstPutOutcome, MstValue};
pub use store::{MstStore, MstStoreConfig};
pub use sync::{
    apply_sync_response, compute_wire_node_hash, handle_sync_request, node_to_wire, wire_to_node,
    SyncApplyStats, KIND_KV_MST_SYNC, MAX_SYNC_BATCH_KEYS, MAX_SYNC_BATCH_NODES, MAX_TREE_DEPTH,
};

pub struct MultiValueRegister<T> {
    pub value: T,
    pub clock: u64,
}
