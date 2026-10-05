//! Canonical protocol constants for ARK Protocol v1.

/// Magic Bytes: "ARK1" = 0x41524B31
pub const MAGIC_BYTES: [u8; 4] = [0x41, 0x42, 0x4B, 0x31]; // Note: 'A'=0x41, 'R'=0x52, 'K'=0x4B, '1'=0x31
pub const MAGIC_VALUE: u32 = 0x41524B31;

/// Protocol version number
pub const PROTOCOL_VERSION_V1: u16 = 1;

/// Safe Internet MTU to avoid IP fragmentation (IPv6 minimum MTU: 1280 bytes)
pub const SAFE_MTU: usize = 1280;

/// FastHeader size: strictly 64 bytes (aligned to CPU L1 cache line)
pub const FAST_HEADER_SIZE: usize = 64;

/// Strict maximum envelope size: 64 KB (65,536 bytes)
pub const MAX_ENVELOPE_SIZE: usize = 64 * 1024;

/// Strict maximum payload size (envelope budget excluding overhead)
pub const MAX_PAYLOAD_SIZE: usize = 60 * 1024;

/// ALPN identifier for strict Post-Quantum QUIC
pub const ALPN_ARK_PQC_V1: &[u8] = b"ark-pqc/v1";

/// KMAC256 Customization String for ARK v1
pub const KMAC_CUSTOM_STRING: &[u8] = b"ARK-KMAC256-V1";

/// Maximum allowed clock drift: ±30 seconds
pub const MAX_CLOCK_DRIFT_SECS: i64 = 30;
