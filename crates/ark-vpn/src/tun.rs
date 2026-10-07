//! Virtual TUN Adapter Abstraction Layer (ACP-07 / ADR-0013).
//!
//! Safe MTU Calibration:
//! The virtual TUN adapter enforces a strict 1,200-byte MTU ceiling (`DEFAULT_SAFE_MTU`).
//! This is intentionally calibrated to fit comfortably within the 1,280-byte DPLPMTUD WAN floor
//! of the Ark Protocol (ACP-03), leaving up to 80 bytes of headroom for FastHeader (64B) or
//! outer UDP/IP framing without triggering Layer-3 fragmentation or unnecessary Auto-Stream Escalation.
//!
//! Additionally, TCP MSS clamping is performed on TCP SYN packets traversing the adapter
//! to ensure TCP endpoints negotiate segment sizes fitting within the 1,200-byte boundary.

use async_trait::async_trait;
use tokio::sync::mpsc;
use crate::error::{Result, VpnError};

/// Safe MTU ceiling calibrated to fit within 1,280-byte WAN floor with headroom for FastHeader (64B) + outer headers.
pub const DEFAULT_SAFE_MTU: usize = 1200;

/// Default TCP MSS clamp ceiling for IPv4 (1200 MTU - 20 IP - 20 TCP = 1160 bytes).
pub const TCP_MSS_FLOOR: u16 = 1160;

/// TCP MSS clamp ceiling for IPv6 (1200 MTU - 40 IPv6 - 20 TCP = 1140 bytes).
pub const TCP_MSS_IPV6_FLOOR: u16 = 1140;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

/// Abstract Layer-3 TUN adapter interface for packet capture and injection.
#[async_trait]
pub trait VirtualTunAdapter: Send + Sync {
    /// Interface name (e.g., "ark0" or "mock0").
    fn name(&self) -> &str;

    /// Configured MTU for this interface.
    fn mtu(&self) -> usize;

    /// Read an IP packet coming from the virtual interface (to be encrypted/routed over mesh).
    async fn read_packet(&self) -> Result<Vec<u8>>;

    /// Write an IP packet into the virtual interface (decrypted from mesh, destined for OS).
    async fn write_packet(&self, packet: &[u8]) -> Result<()>;
}

/// In-memory mock TUN adapter for unprivileged CI testing, sandboxes, and verification without root.
pub struct MockTunAdapter {
    name: String,
    mtu: usize,
    /// Queue for packets injected from the simulated OS kernel into the adapter
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    /// Queue for packets written by the VPN engine out to the simulated OS kernel
    outbound_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
}

impl MockTunAdapter {
    /// Create a new MockTunAdapter with the given interface name and MTU limit.
    pub fn new(name: impl Into<String>, mtu: usize) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(1024);
        let (outbound_tx, outbound_rx) = mpsc::channel(1024);

        Self {
            name: name.into(),
            mtu,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            inbound_tx,
            outbound_rx: tokio::sync::Mutex::new(outbound_rx),
            outbound_tx,
        }
    }

    /// Simulate OS kernel injecting a packet into the TUN interface.
    /// Rejects packets that exceed the MTU. Applies TCP MSS clamping.
    pub async fn inject_packet(&self, mut packet: Vec<u8>) -> Result<()> {
        if packet.len() > self.mtu {
            return Err(VpnError::MtuExceeded {
                size: packet.len(),
                limit: self.mtu,
            });
        }
        clamp_tcp_mss(&mut packet, self.mtu)?;
        self.inbound_tx
            .send(packet)
            .await
            .map_err(|_| VpnError::InterfaceClosed)?;
        Ok(())
    }

    /// Read a packet that was written by the VPN engine to the simulated OS kernel.
    pub async fn read_outbound(&self) -> Result<Vec<u8>> {
        let mut rx = self.outbound_rx.lock().await;
        rx.recv().await.ok_or(VpnError::InterfaceClosed)
    }
}

#[async_trait]
impl VirtualTunAdapter for MockTunAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn read_packet(&self) -> Result<Vec<u8>> {
        let mut rx = self.inbound_rx.lock().await;
        rx.recv().await.ok_or(VpnError::InterfaceClosed)
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > self.mtu {
            return Err(VpnError::MtuExceeded {
                size: packet.len(),
                limit: self.mtu,
            });
        }
        let mut packet_vec = packet.to_vec();
        clamp_tcp_mss(&mut packet_vec, self.mtu)?;
        self.outbound_tx
            .send(packet_vec)
            .await
            .map_err(|_| VpnError::InterfaceClosed)?;
        Ok(())
    }
}

/// Native OS abstraction for host TUN device (`ark0`).
/// When running without root/privileges or on unsupported platforms, gracefully fails or logs fallback.
pub struct NativeTunAdapter {
    name: String,
    mtu: usize,
}

impl NativeTunAdapter {
    pub fn create(name: &str, mtu: usize) -> Result<Self> {
        // Safe check for root / CAP_NET_ADMIN permissions
        #[cfg(unix)]
        {
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                return Err(VpnError::InterfaceError(format!(
                    "Cannot open native TUN interface '{}': requires root or CAP_NET_ADMIN (running as uid {})",
                    name, uid
                )));
            }
        }

        Ok(Self {
            name: name.to_string(),
            mtu,
        })
    }
}

#[async_trait]
impl VirtualTunAdapter for NativeTunAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn read_packet(&self) -> Result<Vec<u8>> {
        Err(VpnError::InterfaceError(
            "NativeTunAdapter requires native driver backend".into(),
        ))
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > self.mtu {
            return Err(VpnError::MtuExceeded {
                size: packet.len(),
                limit: self.mtu,
            });
        }
        Err(VpnError::InterfaceError(
            "NativeTunAdapter requires native driver backend".into(),
        ))
    }
}

/// Inspect packet and clamp TCP MSS option on TCP SYN packets to fit within MTU.
pub fn clamp_tcp_mss(packet: &mut [u8], mtu: usize) -> Result<()> {
    if packet.is_empty() {
        return Ok(());
    }

    let version = packet[0] >> 4;
    match version {
        4 => clamp_tcp_mss_ipv4(packet, mtu),
        6 => clamp_tcp_mss_ipv6(packet, mtu),
        _ => Ok(()), // Non-IP packet, ignore
    }
}

fn clamp_tcp_mss_ipv4(packet: &mut [u8], mtu: usize) -> Result<()> {
    if packet.len() < 20 {
        return Ok(());
    }

    let ihl = ((packet[0] & 0x0F) * 4) as usize;
    let protocol = packet[9];
    if protocol != 6 {
        return Ok(()); // Not TCP
    }

    // Maximum MSS = MTU - IPv4 header (20B min) - TCP header (20B min)
    let max_mss = (mtu.saturating_sub(40)).min(TCP_MSS_FLOOR as usize) as u16;

    if clamp_tcp_segment(packet, ihl, max_mss) {
        recalculate_tcp_checksum_ipv4(packet, ihl);
    }

    Ok(())
}

fn clamp_tcp_mss_ipv6(packet: &mut [u8], mtu: usize) -> Result<()> {
    if packet.len() < 40 {
        return Ok(());
    }

    let next_header = packet[6];
    if next_header != 6 {
        return Ok(()); // Not TCP (or has extension headers)
    }

    // Maximum MSS = MTU - IPv6 header (40B) - TCP header (20B min)
    let max_mss = (mtu.saturating_sub(60)).min(TCP_MSS_IPV6_FLOOR as usize) as u16;

    if clamp_tcp_segment(packet, 40, max_mss) {
        recalculate_tcp_checksum_ipv6(packet, 40);
    }

    Ok(())
}

/// Common helper to validate TCP SYN packet and clamp MSS in TCP options.
/// Returns true if the TCP options were modified and checksum needs recalculation.
fn clamp_tcp_segment(packet: &mut [u8], tcp_offset: usize, max_mss: u16) -> bool {
    if packet.len() < tcp_offset + 20 {
        return false;
    }

    let tcp_bytes = &mut packet[tcp_offset..];
    let flags = tcp_bytes[13];
    let is_syn = (flags & 0x02) != 0;
    if !is_syn {
        return false;
    }

    let data_offset = ((tcp_bytes[12] >> 4) * 4) as usize;
    if tcp_bytes.len() < data_offset || data_offset < 20 {
        return false;
    }

    clamp_tcp_options(&mut tcp_bytes[20..data_offset], max_mss)
}

/// Iterate over TCP options and clamp MSS option (Kind = 2, Length = 4).
/// Returns true if an MSS option was modified.
fn clamp_tcp_options(options: &mut [u8], max_mss: u16) -> bool {
    let mut i = 0;
    let mut modified = false;

    while i < options.len() {
        let kind = options[i];
        if kind == 0 {
            // End of options
            break;
        }
        if kind == 1 {
            // NOP
            i += 1;
            continue;
        }

        if i + 1 >= options.len() {
            break;
        }
        let len = options[i + 1] as usize;
        if len < 2 || i + len > options.len() {
            break;
        }

        if kind == 2 && len == 4 {
            // MSS Option: Kind(1) + Len(1) + MSS(2)
            let current_mss = u16::from_be_bytes([options[i + 2], options[i + 3]]);
            if current_mss > max_mss {
                let clamped_bytes = max_mss.to_be_bytes();
                options[i + 2] = clamped_bytes[0];
                options[i + 3] = clamped_bytes[1];
                modified = true;
            }
        }

        i += len;
    }

    modified
}

/// Compute Internet Checksum (RFC 1071).
fn compute_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum = sum.wrapping_add((rem as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn recalculate_tcp_checksum_ipv4(packet: &mut [u8], ihl: usize) {
    if packet.len() < ihl + 20 {
        return;
    }

    // Zero out existing TCP checksum field (bytes 16..18 of TCP header)
    packet[ihl + 16] = 0;
    packet[ihl + 17] = 0;

    let src_ip = &packet[12..16];
    let dst_ip = &packet[16..20];
    let tcp_len = (packet.len() - ihl) as u16;

    let mut pseudo_header = Vec::with_capacity(12 + packet.len() - ihl);
    pseudo_header.extend_from_slice(src_ip);
    pseudo_header.extend_from_slice(dst_ip);
    pseudo_header.push(0); // Zero
    pseudo_header.push(6); // Protocol TCP
    pseudo_header.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo_header.extend_from_slice(&packet[ihl..]);

    let checksum = compute_checksum(&pseudo_header);
    let checksum_bytes = checksum.to_be_bytes();
    packet[ihl + 16] = checksum_bytes[0];
    packet[ihl + 17] = checksum_bytes[1];
}

fn recalculate_tcp_checksum_ipv6(packet: &mut [u8], tcp_offset: usize) {
    if packet.len() < tcp_offset + 20 {
        return;
    }

    // Zero out existing TCP checksum
    packet[tcp_offset + 16] = 0;
    packet[tcp_offset + 17] = 0;

    let src_ip = &packet[8..24];
    let dst_ip = &packet[24..40];
    let tcp_len = (packet.len() - tcp_offset) as u32;

    let mut pseudo_header = Vec::with_capacity(40 + packet.len() - tcp_offset);
    pseudo_header.extend_from_slice(src_ip);
    pseudo_header.extend_from_slice(dst_ip);
    pseudo_header.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 6]); // Next header 6
    pseudo_header.extend_from_slice(&packet[tcp_offset..]);

    let checksum = compute_checksum(&pseudo_header);
    let checksum_bytes = checksum.to_be_bytes();
    packet[tcp_offset + 16] = checksum_bytes[0];
    packet[tcp_offset + 17] = checksum_bytes[1];
}
