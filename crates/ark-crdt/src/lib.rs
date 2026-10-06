//! ark-crdt: Distributed Key-Value Consistency via Merkle Search Trees (MST) & Multi-Value Registers (MVR) (GCP-09).

pub mod mst;
pub mod diff;

pub use mst::{compute_key_level, MerkleSearchTree, MstEntry, MstNode, MstPutOutcome, MstValue};
pub use diff::{MstDiff, MstSyncItem, MstSyncPlan};

pub struct MultiValueRegister<T> {
    pub value: T,
    pub clock: u64,
}
