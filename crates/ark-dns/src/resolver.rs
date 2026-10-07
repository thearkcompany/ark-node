//! Asynchronous Tokio UDP DNS Stub Resolver (RFC 1035 / Port 53).
//!
//! Provides a local loopback DNS server listening on UDP `127.0.0.1:53`
//! (port configurable for unprivileged user execution and dynamic port testing).
//!
//! Features:
//! - RFC 1035 binary query parsing (A, AAAA, TXT).
//! - Three-tier resolution dispatch via `SovereignDnsEngine` for `.ark` sovereign namespace.
//! - Synthesis of valid RFC 1035 answers from `DomainResolveResponse` routing addresses and metadata.
//! - Non-`.ark` query handling: optional forwarding to upstream DNS or refusal (`RCODE = Refused`).
//! - Error handling: returns `NXDOMAIN` (NameError) when domain is not found in `.ark`.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::anti_sybil::L2ContractVerifier;
use crate::engine::SovereignDnsEngine;
use crate::error::{DnsError, Result};
use crate::lifecycle::TimeProvider;
use crate::synthesis::synthesize_dns_answers;
use crate::wire::{DnsMessage, DnsOpcode, DnsRcode};

/// Default stub resolver bind address.
pub const DEFAULT_DNS_BIND_ADDR: &str = "127.0.0.1:53";
/// Default fallback TTL for synthesized answers in seconds.
pub const DEFAULT_DNS_TTL_SECS: u32 = 60;

/// Configuration for `StubResolver`.
#[derive(Debug, Clone)]
pub struct StubResolverConfig {
    /// Bind address (e.g. `127.0.0.1:53` or `127.0.0.1:0` for dynamic port).
    pub bind_addr: SocketAddr,
    /// Optional upstream DNS server for non-.ark queries (e.g. `1.1.1.1:53`).
    pub upstream_dns: Option<SocketAddr>,
    /// Default TTL in seconds for synthesized DNS answers.
    pub default_ttl: u32,
}

impl Default for StubResolverConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_DNS_BIND_ADDR.parse().unwrap(),
            upstream_dns: None,
            default_ttl: DEFAULT_DNS_TTL_SECS,
        }
    }
}

/// Asynchronous Tokio UDP DNS stub resolver.
pub struct StubResolver<T: TimeProvider + 'static, V: L2ContractVerifier + 'static> {
    engine: Arc<SovereignDnsEngine<T, V>>,
    config: StubResolverConfig,
    socket: Arc<UdpSocket>,
    forwarder_socket: Option<Arc<UdpSocket>>,
}

impl<T: TimeProvider, V: L2ContractVerifier> StubResolver<T, V> {
    /// Bind UDP socket and construct a new `StubResolver`.
    pub async fn new(
        engine: Arc<SovereignDnsEngine<T, V>>,
        config: StubResolverConfig,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr)
            .await
            .map_err(|e| DnsError::Serialization(format!("Failed to bind UDP socket to {}: {}", config.bind_addr, e)))?;

        info!("StubResolver bound to UDP {}", socket.local_addr().map_err(|e| DnsError::Serialization(e.to_string()))?);

        let forwarder_socket = if config.upstream_dns.is_some() {
            let fwd = UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| DnsError::Serialization(format!("Failed to bind forwarding socket: {}", e)))?;
            Some(Arc::new(fwd))
        } else {
            None
        };

        Ok(Self {
            engine,
            config,
            socket: Arc::new(socket),
            forwarder_socket,
        })
    }

    /// Local socket address the resolver is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| DnsError::Serialization(e.to_string()))
    }

    /// Run the DNS stub resolver event loop until cancelled or error occurs.
    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; 4096];

        loop {
            let (len, src_addr) = match self.socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Error receiving DNS datagram: {}", e);
                    continue;
                }
            };

            let packet_data = &buf[..len];
            let response_bytes = match self.handle_datagram(packet_data).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Failed to process DNS datagram from {}: {}", src_addr, e);
                    continue;
                }
            };

            if let Some(resp_wire) = response_bytes {
                if let Err(e) = self.socket.send_to(&resp_wire, src_addr).await {
                    error!("Failed to send DNS response to {}: {}", src_addr, e);
                }
            }
        }
    }

    /// Run the DNS stub resolver with a cancellation receiver.
    pub async fn run_with_shutdown(&self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let mut buf = vec![0u8; 4096];

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("StubResolver shutting down gracefully");
                    break;
                }
                recv_res = self.socket.recv_from(&mut buf) => {
                    let (len, src_addr) = match recv_res {
                        Ok(res) => res,
                        Err(e) => {
                            error!("Error receiving DNS datagram: {}", e);
                            continue;
                        }
                    };

                    let packet_data = &buf[..len];
                    let response_bytes = match self.handle_datagram(packet_data).await {
                        Ok(resp) => resp,
                        Err(e) => {
                            warn!("Failed to process DNS datagram from {}: {}", src_addr, e);
                            continue;
                        }
                    };

                    if let Some(resp_wire) = response_bytes {
                        if let Err(e) = self.socket.send_to(&resp_wire, src_addr).await {
                            error!("Failed to send DNS response to {}: {}", src_addr, e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process a single incoming raw DNS query packet and return wire response bytes.
    pub async fn handle_datagram(&self, packet_data: &[u8]) -> Result<Option<Vec<u8>>> {
        let query = match DnsMessage::from_wire(packet_data) {
            Ok(msg) => msg,
            Err(e) => {
                debug!("Failed to parse DNS query wire: {}", e);
                return Ok(None);
            }
        };

        // If it's not a standard query, ignore or return FormatError
        if query.header.is_response {
            return Ok(None);
        }

        if query.header.opcode != DnsOpcode::Query {
            let mut resp = DnsMessage::new_response(query.header.id, DnsRcode::NotImplemented);
            resp.questions = query.questions;
            return Ok(Some(resp.to_wire()?));
        }

        if query.questions.is_empty() {
            let resp = DnsMessage::new_response(query.header.id, DnsRcode::FormatError);
            return Ok(Some(resp.to_wire()?));
        }

        let question = &query.questions[0];
        let qname = question.qname.trim().to_ascii_lowercase();

        // Check if query targets the sovereign .ark namespace
        if qname.ends_with(".ark") {
            let mut resp = DnsMessage::new_response(query.header.id, DnsRcode::NoError);
            resp.questions = query.questions.clone();

            match self.engine.resolve(&qname, None) {
                Ok(resolve_response) => {
                    // External resolution suspension during Grace Period:
                    // If the domain is quarantined in grace period, return NXDOMAIN
                    // so external OS resolvers don't connect to suspended / quarantined hosts.
                    if resolve_response.in_grace_period {
                        resp.header.rcode = DnsRcode::NameError; // NXDOMAIN
                        Ok(Some(resp.to_wire()?))
                    } else {
                        let answers = synthesize_dns_answers(
                            &question.qname,
                            question.qtype,
                            &resolve_response,
                            self.config.default_ttl,
                        );
                        resp.answers = answers;
                        Ok(Some(resp.to_wire()?))
                    }
                }
                Err(DnsError::NotFound(_)) => {
                    resp.header.rcode = DnsRcode::NameError; // NXDOMAIN
                    Ok(Some(resp.to_wire()?))
                }
                Err(e) => {
                    warn!("Error resolving {}: {}", qname, e);
                    resp.header.rcode = DnsRcode::ServerFailure;
                    Ok(Some(resp.to_wire()?))
                }
            }
        } else {
            // Non-.ark domain: handle upstream forwarding or refusal
            match self.config.upstream_dns {
                Some(upstream_addr) => {
                    match self.forward_to_upstream(packet_data, upstream_addr).await {
                        Ok(upstream_resp) => Ok(Some(upstream_resp)),
                        Err(e) => {
                            warn!("Upstream forwarding to {} failed: {}", upstream_addr, e);
                            let mut resp = DnsMessage::new_response(query.header.id, DnsRcode::ServerFailure);
                            resp.questions = query.questions;
                            Ok(Some(resp.to_wire()?))
                        }
                    }
                }
                None => {
                    let mut resp = DnsMessage::new_response(query.header.id, DnsRcode::Refused);
                    resp.questions = query.questions;
                    Ok(Some(resp.to_wire()?))
                }
            }
        }
    }

    /// Forward raw DNS query to configured upstream resolver over UDP.
    async fn forward_to_upstream(&self, packet_data: &[u8], upstream_addr: SocketAddr) -> Result<Vec<u8>> {
        let forwarder = match &self.forwarder_socket {
            Some(sock) => sock.clone(),
            None => {
                let sock = UdpSocket::bind("127.0.0.1:0")
                    .await
                    .map_err(|e| DnsError::Serialization(format!("Failed to bind forwarding socket: {}", e)))?;
                Arc::new(sock)
            }
        };

        forwarder
            .send_to(packet_data, upstream_addr)
            .await
            .map_err(|e| DnsError::Serialization(format!("Failed to send to upstream {}: {}", upstream_addr, e)))?;

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            forwarder.recv_from(&mut buf),
        )
        .await
        .map_err(|_| DnsError::Serialization("Upstream DNS query timed out".to_string()))?
        .map_err(|e| DnsError::Serialization(format!("Failed to receive from upstream: {}", e)))?;

        Ok(buf[..len].to_vec())
    }
}
