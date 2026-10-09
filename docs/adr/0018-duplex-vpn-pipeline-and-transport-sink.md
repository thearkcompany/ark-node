# ADR-0018: Duplex VPN Pipeline, Transport Sink Seam, and Unified Lifecycle

## Status
Accepted

## Context
Following ADR-0013 and PR #80 (which eliminated the shallow `ZeroTrustOverlayMesh` wrapper into `VpnEngine`), `crates/ark-vpn` established a unified facade. However, the internal outbound packet pipeline remained disconnected:
1. `VpnEngine::spawn_packet_pipeline` actively read IP packets from `VirtualTunAdapter`, performed deterministic IPAM destination resolution, evaluated egress zero-trust ACLs, and encapsulated frames using Post-Quantum Mesh Tunneling (PQMT).
2. The resulting `OutboundPacket` (containing target physical endpoint, route mode, and encapsulated wire bytes) was silently discarded (`let _ = engine.process_outbound_packet(&packet);`) because no outbound transport adapter was connected to the engine.
3. The inbound packet ingestion seam (`VpnEngine::process_inbound_packet`) was detached from the engine's active lifecycle, and callers had to manage background tokio tasks manually instead of controlling the subsystem through unified `start().await` / `stop().await` operations.

## Decision

1. **Pluggable Transport Sink Seam (`VpnTransportSink`)**:
   - Introduce an asynchronous capability trait `VpnTransportSink: Send + Sync` in `ark-vpn` at the outbound network seam:
     ```rust
     #[async_trait]
     pub trait VpnTransportSink: Send + Sync {
         async fn send_packet(&self, packet: OutboundPacket) -> Result<()>;
     }
     ```
   - Satisfy the seam with two distinct adapters:
     - `ChannelTransportSink`: A bounded in-memory `tokio::sync::mpsc::Sender<OutboundPacket>` adapter with default capacity of 1,024 packets for unprivileged CI testing, deterministic integration tests, and sandbox bridging.
     - `QuicTransportSink` (in `ark-runtime`): Transmits wire frames to target physical socket endpoints over ALPN `ark-pqc/v1` datagrams or bi-directional streams.

2. **Dependency Injection & Bounded Backpressure**:
   - Provide `VpnTransportSink` to `VpnEngine` during initialization or builder configuration.
   - The outbound packet pipeline awaits `sink.send_packet(pkt).await`. Transient transmission errors or drops increment atomic observability counters (`metrics.dropped_errors`) without aborting or crashing the background worker.

3. **Unified Duplex Lifecycle (`start` and `stop`)**:
   - Deepen `VpnEngine::start(&self)` to automatically launch and supervise the duplex packet pipeline, managing background `JoinHandle`s internally.
   - `VpnEngine::stop(&self)` signals cancellation via `shutdown_tx` and awaits graceful pipeline drainage.

## Consequences

### Positive
- High leverage: A single `vpn.start().await` call initializes the entire symmetric duplex mesh pipeline (TUN $\leftrightarrow$ Wire Transport).
- Testability at the seam: Deterministic unit and integration tests verify full packet capture, PQMT encapsulation, failover (Direct P2P vs Blind Relay), and transmission using `ChannelTransportSink` and `MockTunAdapter`.
- Zero-loss encapsulation: Eliminates silent packet dropping in `spawn_packet_pipeline`.

### Negative / Trade-offs
- Calling `start()` requires an active `VpnTransportSink` or defaults to an explicit drop counter sink if unconfigured.
