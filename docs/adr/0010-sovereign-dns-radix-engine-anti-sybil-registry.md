# ADR-0010: Sovereign DNS (.ark) Radix Resolution Engine & Anti-Sybil Registry (GCP-08)

## Context

Under the ARK 2026-LTS architectural mandate (GCP-08, ACP-0008), the ARK Sovereign P2P network requires a distributed, censorship-resistant DNS engine (`ark-dns`) resolving `.ark` top-level domains. 

Traditional DNS architectures rely on centralized root servers (ICANN), hierarchical registries, and unauthenticated plain-text or centralized DoH/DoT resolvers. Furthermore, previous decentralized proposals often suffered from slow resolution, heavy blockchain transaction fees, Sybil name squatting, or reliance on hardware identifiers (*MachineRoot*).

The `ark-node` requires an embedded, constant-time resolution engine achieving $\mathcal{O}(k) < 10\ \mu\text{s}$ domain lookups, native integration with the post-quantum identity model (FN-DSA-512), a zero-hardware-fingerprinting Three-Tier naming architecture, and a local loopback stub resolver interface for client integration.

## Decision

We establish the `ark-dns` subsystem implementing GCP-08 and ACP-0008 according to the following architectural decisions:

1. **MachineRoot Abolition & Three-Tier Naming Model:**
   Hardware metrics (DMI, MAC addresses, CPU serials, NVMe UUIDs) are strictly banished. The `.ark` namespace is structured into three distinct tiers:
   - **Cryptographic Names (`ark1<bech32>.ark`):** Deterministically derived from `IdentityHash = SHA3-256(0x01 || FN_DSA_PubKey)` encoded in Bech32. Self-authenticating, collision-free, unreserved, and resolved in $\mathcal{O}(1)$ time without directory queries.
   - **Private Overlays (`<name>.ark`, e.g., `nas.ark`, `gateway.ark`):** Confined to local Fjall LSM records (`dns_private_overlays` keyspace) isolated per user ArkID / homelab cluster, completely invisible to the public network.
   - **Human-Readable Public Names (`<name>.ark`, e.g., `alice.ark`, `shop.ark`):** Global names anchored via canonical `KIND_DNS_CLAIM_PUBLIC` (`0x3000_0002`, Retention Class 3) envelopes.

2. **Compressed Patricia Trie / Radix Trie with RCU Concurrency:**
   The public directory routing table is held in memory as an immutable Compressed Patricia Trie swapped atomically via `ArcSwap` / Copy-on-Write (CoW). Lookups are 100% lock-free, delivering predictable latency $< 10\ \mu\text{s}$ regardless of concurrent write volume.

3. **Anti-Sybil Proof-of-Work & L2 Escrow Verification:**
   Public domain registrations require:
   - **16-bit Proof-of-Work:** Verified in constant time, demanding at least 16 leading zero bits on the canonical SHA3-256 envelope ID using `TAG_NONCE` (`0x000A`).
   - **Layer 2 Escrow Bond:** Verifiable escrow contract identifier deposited on Ark Pay L2 provided via `TAG_L2_CONTRACT` (`0x000F`). A pluggable `L2ContractVerifier` trait validates contract validity.

4. **Deterministic Lease Lifecycle & 14-Day Grace Period Quarantine:**
   Each public domain claim specifies a lease expiration epoch (`TAG_DNS_LEASE_EPOCH`, `0x001B`) up to a maximum duration of 365 days.
   - **Active:** Current timestamp $\le T_{\text{expire}}$. Domain resolves normally.
   - **Grace Period Quarantine:** When $T_{\text{expire}} < \text{now} \le T_{\text{expire}} + 14\text{ days}$, the domain enters quarantine (`in_grace_period = true`). External resolution is suspended, and renewals are restricted exclusively to the original owner `sender_key_id`.
   - **Expired / Released:** After 14 days, the lease expires and the name becomes freely claimable by any valid peer with fresh PoW and L2 escrow.

5. **Local Loopback Stub Resolver (Port 53 UDP):**
   `ark-dns` provides an asynchronous UDP DNS stub server bound to loopback `127.0.0.1:53` supporting RFC 1035 queries for standard record types (`A`, `AAAA`, `TXT`). Queries for `.ark` are resolved locally from the Trie, while non-`.ark` queries can optionally fall back to configured upstream resolvers.

## Consequences

### Positive
- Predictable ultra-low latency ($\mathcal{O}(k) < 10\ \mu\text{s}$) for all lookups in memory via lock-free Radix Trie.
- Zero-cost, self-authenticating cryptographic names require no consensus or Layer 2 settlement.
- Proof-of-Work and Layer 2 escrow bonds prevent mass Sybil squatting without burdening Layer 1 with microtransactions.
- Seamless compatibility with standard operating system networking through the local port 53 stub resolver.

### Negative / Trade-offs
- Memory consumption of the public Patricia Trie scales with registered public domain count (bounded by lease expiration eviction).
- Requiring 16-bit PoW adds ~millisecond compute overhead for clients registering or renewing domains.
- Local stub resolver on port 53 may require system port binding permissions or alternate non-privileged port fallback in unprivileged environments.
