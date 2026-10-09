//! Canonical protocol and storage constants for ark-blob (GCP-10, ADR-0011).

/// TLV Tag for Content CID / Canonical BlobCID (0x0002).
pub const TAG_CONTENT_CID: u32 = 0x0002;

/// TLV Tag for Shard Index (0x0015).
pub const TAG_SHARD_INDEX: u32 = 0x0015;

/// TLV Tag for Proof-of-Retrievability Challenge Seed (0x0016).
pub const TAG_CHALLENGE_SEED: u32 = 0x0016;

/// TLV Tag for 4 KB Sub-Block Index (0x0017).
pub const TAG_SUB_BLOCK_INDEX: u32 = 0x0017;

/// TLV Tag for Layer 2 Escrow Contract (0x000F).
pub const TAG_L2_CONTRACT: u32 = 0x000F;

/// Envelope Kind for Blob Manifest (0x1000_0003).
pub const KIND_BLOB_MANIFEST: u32 = 0x1000_0003;

/// Envelope Kind for Homelab Acknowledgement (0x0000_2011).
pub const KIND_HOMELAB_ACK: u32 = 0x0000_2011;

/// Envelope Kind for DePIN Challenge (0x4000_0002).
pub const KIND_DEPIN_CHALLENGE: u32 = 0x4000_0002;

/// Envelope Kind for DePIN Challenge Response (0x4000_0003).
pub const KIND_DEPIN_RESPONSE: u32 = 0x4000_0003;

/// Pre-coding sub-chunk size for Tier 1 Merkle tree: 64 KB (65,536 bytes).
pub const SUB_CHUNK_SIZE: usize = 64 * 1024;

/// Standard Cauchy Reed-Solomon shard size: 1 MB (1,048,576 bytes).
pub const SHARD_SIZE: usize = 1024 * 1024;

/// Internal sub-block size for Tier 2 Shard Merkle tree: 4 KB (4,096 bytes).
pub const SUB_BLOCK_SIZE: usize = 4 * 1024;

/// Number of 4 KB sub-blocks per 1 MB shard: 256.
pub const SUB_BLOCKS_PER_SHARD: usize = SHARD_SIZE / SUB_BLOCK_SIZE;

/// Canonical Cauchy RS data shards: 10.
pub const DATA_SHARDS: usize = 10;

/// Canonical Cauchy RS parity shards: 4.
pub const PARITY_SHARDS: usize = 4;

/// Canonical Cauchy RS total shards: 14 (10 + 4).
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

/// Transient TTL window for Staged Full Custody: 72 hours (in seconds).
pub const STAGED_CUSTODY_TTL_SECS: u64 = 72 * 60 * 60; // 259,200 seconds

/// Maximum payload size eligible for Staged Full Custody: < 25 MB (25 * 1024 * 1024 bytes).
pub const STAGED_MAX_FILE_SIZE: u64 = 25 * 1024 * 1024;

/// Minimum remote PoR challenges required to satisfy SafeGhostLock: 10.
pub const REQUIRED_POR_CHALLENGES: usize = 10;
