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

    #[error("Invalid session MAC authentication tag")]
    SessionMacInvalid,

    #[error("Handshake negotiation failed: {0}")]
    HandshakeFailed(String),

    #[error("Replay detected or non-monotonic sequence counter: {0}")]
    ReplayDetected(u32),

    #[error("VPN session not found for session id {0}")]
    SessionNotFound(u32),

    #[error("Framing error: {0}")]
    FramingError(String),

    #[error("Clock drift too large: peer delta {0}s exceeds limit ±{1}s")]
    ClockDriftExceeded(i64, i64),

    #[error("Anti-replay filter rejected packet")]
    AntiReplayRejected,

    #[error("Session hijacking detected: endpoint update rejected")]
    HijackingRejected(String),

    #[error("Packet dropped by ACL policy: {0}")]
    AclDenied(String),
}

pub type Result<T> = std::result::Result<T, VpnError>;
