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
