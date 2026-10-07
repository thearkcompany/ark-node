//! QUIC FastHeader shard streaming framing (GCP-10, ADR-0011).
//!
//! Transfers 1 MB Cauchy RS shards at line-rate without individual envelope-per-chunk overhead.
//! A streaming shard frame consists of:
//! - Strictly 64-byte `FastHeader` prefix, carrying:
//!   - `magic`: 0x41524B31 (MAGIC_VALUE)
//!   - `version`: 1
//!   - `flags`: `FAST_HEADER_FLAG_BLOB_STREAM` (0x0002)
//!   - `envelope_len`: shard byte length (typically 1,048,576 bytes)
//!   - `fast_tag`: `TAG_SHARD_INDEX` (0x0015) or shard index value
//!   - `sender_key_id`: 16-byte sender / keeper identity prefix
//!   - `recipient_key_id`: 16-byte recipient identity prefix
//!   - `sequence_nonce`: shard index as sequence nonce (0..13)
//! - Raw 1 MB shard payload bytes following immediately after the 64-byte header.
//!
//! Provides zero-copy inspection, streaming encoder, and zero-copy/streaming decoder.

use std::io::{Read, Write};

use ark_core::constants::{FAST_HEADER_SIZE, MAGIC_VALUE};
use ark_core::fast_header::FastHeader;

use crate::constants::TAG_SHARD_INDEX;
use crate::error::{BlobError, Result};

/// Dispatch hint flag denoting bulk QUIC shard streaming.
pub const FAST_HEADER_FLAG_BLOB_STREAM: u16 = 0x0002;

/// Dedicated framing codec for line-rate 1 MB shard transfer across QUIC streams.
pub struct ShardStreamFrame;

impl ShardStreamFrame {
    /// Constructs a 64-byte `FastHeader` specifically formatted for shard streaming.
    pub fn build_header(
        shard_index: u32,
        shard_len: u32,
        sender_prefix: [u8; 16],
        recipient_prefix: [u8; 16],
    ) -> FastHeader {
        FastHeader::new(
            FAST_HEADER_FLAG_BLOB_STREAM,
            shard_len,
            TAG_SHARD_INDEX,
            sender_prefix,
            recipient_prefix,
            shard_index as u64,
        )
    }

    /// Encodes a shard payload into a framed byte buffer: 64-byte FastHeader prefix + shard payload.
    pub fn encode(
        shard_index: u32,
        shard_payload: &[u8],
        sender_prefix: [u8; 16],
        recipient_prefix: [u8; 16],
    ) -> Result<Vec<u8>> {
        let header = Self::build_header(
            shard_index,
            shard_payload.len() as u32,
            sender_prefix,
            recipient_prefix,
        );
        header.validate().map_err(|e| BlobError::InvalidFastHeader(e.to_string()))?;

        let mut out = Vec::with_capacity(FAST_HEADER_SIZE + shard_payload.len());
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(shard_payload);
        Ok(out)
    }

    /// Writes a framed shard directly to a stream writer (e.g. QUIC send stream or TCP).
    pub fn write_to_stream<W: Write>(
        writer: &mut W,
        shard_index: u32,
        shard_payload: &[u8],
        sender_prefix: [u8; 16],
        recipient_prefix: [u8; 16],
    ) -> Result<()> {
        let header = Self::build_header(
            shard_index,
            shard_payload.len() as u32,
            sender_prefix,
            recipient_prefix,
        );
        header.validate().map_err(|e| BlobError::InvalidFastHeader(e.to_string()))?;

        writer.write_all(&header.to_bytes())?;
        writer.write_all(shard_payload)?;
        writer.flush()?;
        Ok(())
    }

    /// Inspects and validates the 64-byte FastHeader from the start of framed data.
    /// Returns `(header, shard_index, shard_len)`.
    pub fn inspect_header(frame_bytes: &[u8]) -> Result<(FastHeader, u32, u32)> {
        if frame_bytes.len() < FAST_HEADER_SIZE {
            return Err(BlobError::InvalidFastHeader(format!(
                "Frame too short: {} bytes, required at least {}",
                frame_bytes.len(),
                FAST_HEADER_SIZE
            )));
        }

        let mut header_buf = [0u8; FAST_HEADER_SIZE];
        header_buf.copy_from_slice(&frame_bytes[..FAST_HEADER_SIZE]);

        let header = FastHeader::from_bytes(&header_buf)
            .map_err(|e| BlobError::InvalidFastHeader(e.to_string()))?;

        if header.magic != MAGIC_VALUE {
            return Err(BlobError::InvalidFastHeader(format!(
                "Invalid magic: 0x{:08X}",
                header.magic
            )));
        }

        let shard_index = header.sequence_nonce as u32;
        let shard_len = header.envelope_len;

        Ok((header, shard_index, shard_len))
    }

    /// Decodes a complete framed byte buffer into `(FastHeader, shard_index, shard_payload)`.
    pub fn decode(frame_bytes: &[u8]) -> Result<(FastHeader, u32, Vec<u8>)> {
        let (header, shard_index, shard_len) = Self::inspect_header(frame_bytes)?;

        let expected_total = FAST_HEADER_SIZE + (shard_len as usize);
        if frame_bytes.len() < expected_total {
            return Err(BlobError::InvalidFastHeader(format!(
                "Incomplete shard frame: got {} bytes, expected {}",
                frame_bytes.len(),
                expected_total
            )));
        }

        let shard_data = frame_bytes[FAST_HEADER_SIZE..expected_total].to_vec();
        Ok((header, shard_index, shard_data))
    }

    /// Reads a framed shard from a streaming reader (e.g. QUIC recv stream).
    pub fn read_from_stream<R: Read>(reader: &mut R) -> Result<(FastHeader, u32, Vec<u8>)> {
        let mut header_buf = [0u8; FAST_HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let header = FastHeader::from_bytes(&header_buf)
            .map_err(|e| BlobError::InvalidFastHeader(e.to_string()))?;

        let shard_index = header.sequence_nonce as u32;
        let shard_len = header.envelope_len as usize;

        let mut shard_payload = vec![0u8; shard_len];
        reader.read_exact(&mut shard_payload)?;

        Ok((header, shard_index, shard_payload))
    }
}
