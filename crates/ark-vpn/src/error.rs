use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VpnError {
    #[error("MTU limit exceeded: packet size {size} bytes exceeds configured safe MTU {limit} bytes")]
    MtuExceeded { size: usize, limit: usize },

    #[error("Invalid IP packet: {0}")]
    InvalidPacket(String),

    #[error("TUN interface error: {0}")]
    InterfaceError(String),

    #[error("Interface closed or channel disconnected")]
    InterfaceClosed,

    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, VpnError>;
