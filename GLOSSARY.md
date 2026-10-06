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

