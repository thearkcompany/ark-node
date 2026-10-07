# Glossary

Vocabulary of canonical terms for the ARK Sovereign P2P Protocol and `ark-node`.

## Protocol Foundations

### ArkID
The 32-byte canonical identity of an ARK network participant, derived deterministically as `SHA3-256(PublicKey)`. Expressed in hexadecimal representation for display and logging.

### SenderKeyID
A 16-byte truncated identifier formed from the first 16 bytes of the `ArkID`, embedded directly into the FastHeader to enable instant zero-copy lookup and routing before full envelope decoding.

### FastHeader
A 64-byte binary header strictly aligned to CPU L1 cache line boundaries (64 bytes). Contains protocol magic bytes (`0x41524B31`), versioning, packet flags, length indicators, and truncated routing IDs, permitting wire-speed packet filtering and anti-DoS checks.

### Safe MTU
The strict upper bound of 1,280 bytes for individual network packets to guarantee traversal across the public IPv6 and IPv4 internet without IP-level packet fragmentation.

### ArkEnvelope
The fundamental transport container of the ARK protocol. Enforces a rigid ceiling of $\le 64\text{ KB}$ and adheres strictly to the Encrypt-then-Sign cryptographic paradigm.

### CoreTagMask
A 64-bit bitmask inside the envelope indicating foundational packet attributes (such as encryption, post-quantum signature presence, compression, and urgency) alongside extensible TLV `BinaryTag` entries.

## Post-Quantum Cryptography (PQC)

### FN-DSA-512
Fast-Fourier Lattice-based Digital Signature Algorithm conforming to FIPS 206 (Falcon-512). Operates in constant-time to produce compact, high-assurance digital signatures.

### ML-KEM-768
Module-Lattice-based Key Encapsulation Mechanism conforming to FIPS 203. Used for asymmetric post-quantum shared secret establishment.

### KMAC256
Keccak Message Authentication Code conforming to NIST SP 800-185, configured with domain separation string `"ARK-KMAC256-V1"`. Used to generate tamper-proof stateless retry tokens and integrity tags.

## Transport & Temporal Consensus

### ALPN `ark-pqc/v1`
Application-Layer Protocol Negotiation token strictly enforced across all QUIC connections. Rejects any connection attempting cryptographic or protocol downgrade.

### Stateless Retry Cookie
An RFC 9000 compliant 40-byte token generated via KMAC256 containing a server timestamp and client network address, enabling zero-state connection admission and anti-amplification DoS protection.

### Dual Cuckoo Filter
A fixed-memory ($\le 24\text{ MB}$) anti-replay structure composed of two generational filters rotated periodically. Rejects replays in $O(1)$ time while strictly bounding memory consumption.

### Peer-Median-Time (PMT)
A decentralized, NTP-independent time synchronization mechanism computed in user-space as the median offset across direct peer connections, enforcing a strict maximum drift window of $\pm 30\text{ seconds}$.

## Persistence & Storage Engine (GCP-06)

### Retention Class
A deterministic classification assigned to an `ArkEnvelope` defining its storage lifecycle, mutability rules, and persistence layer (Class 0: Ephemeral/RAM-only, Class 1: Append-Only, Class 2: Replaceable Simple, Class 3: Replaceable Parameterized, Class 4: Bounded TTL, Class 5: Strict WORM).

### Strict WORM (Write-Once-Read-Many)
An irreversible, tamper-evident storage policy (Retention Class 5) reserved for equivocation proofs and audit receipts. Overwrites with divergent content and deletion requests are rejected with hard errors.

### Parameterized Replaceable
A storage indexing strategy (Retention Class 3) where envelopes retain only the latest version keyed by the composite tuple `(sender_key_id, kind, param_d)`, enabling mutable KV state and DNS record updates while preventing duplicate buildup.

### Bivariate LWW (Last-Write-Wins)
A conflict-resolution rule applied to replaceable storage entries and headless nodes that deterministically orders competing envelopes by `(timestamp, envelope_id)`. The highest timestamp wins, and exact timestamp collisions are resolved by lexicographical comparison of the 32-byte cryptographic envelope digest.

## Distributed Consistency & CRDT (GCP-09)

### Merkle Search Tree (MST)
A probabilistically balanced search tree with average fan-out $b = 16$ whose node levels are determined deterministically by counting trailing zero nibbles in `SHA3-256(key)`. Identical sets of key-value pairs always produce the identical 32-byte root digest regardless of mutation or insertion order.

### Multi-Value Register (MVR)
A conflict-free replicated data type (CRDT) register that captures concurrent mutations from divergent network partitions. In headless server nodes, concurrent versions collapse deterministically via `MERGE_POLICY_LWW_BIVARIATE` to eliminate unbounded sibling multiplication.

### Delta Reconciliation
An asynchronous tree-diffing protocol over QUIC streams (`KIND_KV_MST_SYNC`) executing in $\mathcal{O}(\Delta \log n)$ round-trips. Peers compare MST root hashes and descend into divergent subtrees to exchange only missing or superseded envelopes.

### Tombstone Envelope
A cryptographically signed `ArkEnvelope` carrying a deletion marker and recent timestamp, treated as an active entry in the MST to deterministically supersede earlier versions across peer nodes until expired by garbage collection.

## Sovereign DNS & Anti-Sybil Registry (GCP-08)

### Sovereign DNS (.ark)
The censorship-resistant root naming namespace of the ARK ecosystem, providing deterministic, hardware-independent name resolution without reliance on ICANN, legacy TLD registries, or root DNS authorities.

### Three-Tier Naming Model
The architectural taxonomy dividing `.ark` names into three distinct classes: Cryptographic Names (`ark1...ark`, self-authenticating in $\mathcal{O}(1)$), Private Overlays (local/homelab domains isolated per keyholder in Fjall LSM), and Human-Readable Public Names (short commercial/personal names anchored by L2 bonds and light PoW).

### Cryptographic Domain Name
A deterministic sovereign domain name formatted as `"ark1"` $\parallel$ `Bech32(IdentityHash)` $\parallel$ `".ark"`. Free, unreserved, collision-free, and verifiable in $\mathcal{O}(1)$ time purely from the sender's public key without directory lookups.

### Private Overlay Domain
A local or homelab domain name (such as `nas.ark` or `gateway.ark`) restricted to the owner's authenticated device cluster or local storage engine, resolving without public directory announcements.

### Human-Readable Public Domain
A global public domain name (such as `shop.ark` or `alice.ark`) registered via a canonical `KIND_DNS_CLAIM_PUBLIC` envelope, secured against squatting and Sybil spam via light Proof-of-Work and refundable L2 escrow contracts.

### Anti-Sybil Proof-of-Work (PoW)
A computational cost mechanism requiring domain claim envelopes to contain at least 16 leading zero bits on their canonical SHA3-256 envelope digest, deterring automated spam registration without requiring fee payments on Layer 1.

### L2 Escrow Bond
A verifiable economic stake deposited on Ark Pay Layer 2 associated with a public domain registration via `TAG_L2_CONTRACT` (`0x000F`), deterring malicious name squatting while remaining refundable upon orderly relinquishment.

### Domain Lease Grace Period
A mandatory 14-day quarantine window following the expiration of a domain's `TAG_DNS_LEASE_EPOCH`. During this period, the domain ceases active resolution for external queries but remains exclusively reservable by the original owner key for renewal before release to the public.

### Compressed Patricia Trie (Radix Trie)
An in-memory radix tree data structure optimized for string prefixes that performs domain name lookups in $\mathcal{O}(k) < 10\ \mu\text{s}$ time. Supports atomic, lock-free lookups using Copy-on-Write and atomic pointer swaps.

## Distributed Blob Storage & Erasure Coding (GCP-10)

### Ark Blob
A binary payload exceeding the canonical $64\text{ KB}$ `ArkEnvelope` ceiling, subjected to Cauchy Reed-Solomon erasure coding, content-addressed storage, and Merkle proof-of-retrievability verification.

### Cauchy Reed-Solomon (10+4)
An erasure coding scheme in Galois Field $GF(2^8)$ parameterized with $k=10$ data shards and $m=4$ parity shards of standard $1\text{ MB}$ block size ($1,048,576\text{ bytes}$), guaranteeing complete file reconstruction from any 10 distinct shards among the 14 total.

### Two-Tier Merkle Tree
A hierarchical Merkle tree structure comprising a pre-coding $64\text{ KB}$ sub-chunk integrity tree and a post-coding 14-leaf shard tree whose root constitutes the canonical `BlobCID` (`TAG_CONTENT_CID`).

### Staged Full Custody
A two-phase custody lifecycle for blobs $< 25\text{ MB}$ uploaded from mobile/edge clients, holding all 14 shards ($10+4$) in the DePIN network under a 72-hour transient TTL until the owner's Homelab emits an authenticated `KIND_HOMELAB_ACK`, whereupon data shards are discarded and the network settles on $40\%$ parity retention.

### Safe-Ghost Locking
A client-side safety mechanism physically prohibiting a local node or mobile app from evicting or purging its local cache of an uploaded file until cryptographic confirmation is received via `KIND_HOMELAB_ACK` or successful verification of at least 10 remote Proof-of-Retrievability keeper challenges.

### Proof-of-Retrievability (PoR)
A compact audit protocol (`KIND_DEPIN_CHALLENGE`) allowing verifiers to confirm storage keeper possession of a $1\text{ MB}$ shard by challenging a pseudo-randomly sampled $4\text{ KB}$ sub-block salted with `TAG_CHALLENGE_SEED` and verified via KMAC256 and Merkle inclusion paths without downloading the shard.

## Sovereign Compute & Execution Engine (AEP-01)

### Ark Worker
A sandboxed guest execution environment hosting compiled WebAssembly binaries (`wasm32-unknown-unknown`) powered by Wasmtime, executing deterministically without direct OS network or arbitrary filesystem access.

### Dual-Pool Fuel Metering
A deterministic resource accounting mechanism enforcing isolated quotas for CPU execution (`CpuFuel`, instruction count bounded via Wasmtime fuel) and host interaction (`IoFuel`, byte limit on KV, blob, and envelope I/O), producing explicit `CpuFuelExhausted` and `IoFuelExhausted` traps.

### Ark Host-ABI
A capability-based C-compatible interface (`ark_host_*`) exported by the host to Wasm guests over guest-managed linear memory (`ark_alloc`/`ark_dealloc`), exposing hermetic primitives for KV storage (`ark-storage`), CRDT consistency (`ark-crdt`), blob retrieval (`ark-blob`), envelope emissions, and temporal queries.

### Ark Queue
An asynchronous, causally ordered job bus persisted in `ark-storage` (Fjall LSM) featuring in-memory acknowledgment (ACK) elision: successful executions complete within a bounded `JobLease` without synchronous disk writes, while unacknowledged tasks survive node crashes for at-least-once delivery.

### Ark Cron
A deterministic, event-driven scheduler that triggers recurrent guest Wasm worker invocations based on peer consensus time (Peer-Median-Time / PMT) rather than local wall-clock time, strictly skipping missed intervals upon reconnect to prevent execution bursts.


