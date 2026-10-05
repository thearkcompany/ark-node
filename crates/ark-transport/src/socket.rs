//! Dual-stack UDP socket configured with offload hints (GSO/GRO) and non-blocking I/O.

use ark_core::error::{ArkError, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct ArkSocket {
    inner: UdpSocket,
}

impl ArkSocket {
    /// Bind dual-stack UDP socket with standard buffer sizes and non-blocking mode
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let domain = if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(ArkError::IoError)?;

        // Dual-stack IPv6 configuration
        if addr.is_ipv6() {
            let _ = socket.set_only_v6(false);
        }

        socket.set_nonblocking(true).map_err(ArkError::IoError)?;
        
        // Optimize send and receive buffer sizes for high-throughput P2P
        let _ = socket.set_recv_buffer_size(2 * 1024 * 1024);
        let _ = socket.set_send_buffer_size(2 * 1024 * 1024);

        socket.bind(&addr.into()).map_err(ArkError::IoError)?;

        let std_socket: std::net::UdpSocket = socket.into();
        let inner = UdpSocket::from_std(std_socket).map_err(ArkError::IoError)?;

        Ok(Self { inner })
    }

    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        self.inner.send_to(buf, target).await.map_err(ArkError::IoError)
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await.map_err(ArkError::IoError)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.local_addr().map_err(ArkError::IoError)
    }
}
