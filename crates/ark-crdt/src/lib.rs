//! ark-crdt: Distributed Key-Value Consistency via Merkle Search Trees (MST) & Multi-Value Registers (MVR) (GCP-09).

pub mod cache;
pub mod error;
pub mod mst;
pub mod store;

pub use cache::{estimate_node_size_bytes, LruNodeCache};
pub use error::{ArkCrdtError, Result};
pub use mst::{compute_key_level, MerkleSearchTree, MstEntry, MstNode};
pub use store::{MstStore, MstStoreConfig};

pub struct MultiValueRegister<T> {
    pub value: T,
    pub clock: u64,
}
