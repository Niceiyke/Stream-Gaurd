//! StreamGuard control messages, packet envelope and protocol versioning.
//!
//! Wire format v1 is defined in the StreamGuard specification, section 11.
//! The envelope is an application-layer header carried inside each QUIC
//! datagram so the scheduler and gateway can sequence, deduplicate and
//! reorder packets that arrive over independent physical paths.

pub mod control;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use sg_core::{error::Error, PathId, Sequence, SessionId};

/// Envelope version this crate implements.
pub const VERSION: u8 = 0x01;

/// Fixed-size envelope header in bytes (see spec 11.1).
///
/// | field            | size |
/// |------------------|------|
/// | version          | 1    |
/// | type             | 1    |
/// | flags            | 1    |
/// | path_id          | 1    |
/// | session_id       | 4    |
/// | sequence_number  | 6    |
/// | timestamp        | 4    |
/// | payload_length   | 2    |
pub const FIXED_HEADER_LEN: usize = 20;

/// Max payload carried in one envelope.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// Packet types (spec 11.1).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketType {
    Data = 0,
    Duplicate = 1,
    Control = 2,
    Probe = 3,
    Keepalive = 4,
    PathStatus = 5,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Duplicate),
            2 => Ok(Self::Control),
            3 => Ok(Self::Probe),
            4 => Ok(Self::Keepalive),
            5 => Ok(Self::PathStatus),
            other => Err(Error::protocol(format!("unknown packet type {other}"))),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(t: PacketType) -> Self {
        t as u8
    }
}

/// Envelope header carrying routing and sequencing information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u8,
    pub packet_type: PacketType,
    /// Reserved flag bits; 0 in v1.
    pub flags: u8,
    pub path_id: PathId,
    pub session_id: SessionId,
    pub sequence: Sequence,
    /// Milliseconds since session start.
    pub timestamp_ms: u32,
    pub payload: Bytes,
}

impl Envelope {
    /// Serializes the header + payload into the provided buffer.
    /// Returns the number of bytes written.
    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::protocol("payload exceeds u16::MAX"));
        }
        let start = buf.remaining_mut();
        buf.put_u8(self.version);
        buf.put_u8(self.packet_type.into());
        buf.put_u8(self.flags);
        buf.put_u8(self.path_id.get());
        let uuid_bytes = self.session_id.as_guid().as_bytes();
        buf.put_u32(u32::from_be_bytes([
            uuid_bytes[0],
            uuid_bytes[1],
            uuid_bytes[2],
            uuid_bytes[3],
        ]));
        let seq = self.sequence.get();
        buf.put_u8((seq >> 40) as u8);
        buf.put_u8((seq >> 32) as u8);
        buf.put_u8((seq >> 24) as u8);
        buf.put_u8((seq >> 16) as u8);
        buf.put_u8((seq >> 8) as u8);
        buf.put_u8(seq as u8);
        buf.put_u32(self.timestamp_ms);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);
        Ok(start - buf.remaining_mut())
    }

    /// Parses one envelope from the buffer.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Envelope, Error> {
        if buf.remaining() < FIXED_HEADER_LEN {
            return Err(Error::protocol("short envelope header"));
        }
        let version = buf.get_u8();
        let packet_type = PacketType::try_from(buf.get_u8())?;
        let flags = buf.get_u8();
        let path_id = PathId::new(buf.get_u8());
        let mut uuid = [0u8; 16];
        uuid[0..4].copy_from_slice(&[buf.get_u8(), buf.get_u8(), buf.get_u8(), buf.get_u8()]);
        let session_id = SessionId::from_bytes(uuid);
        let mut seq = 0u64;
        for _ in 0..6 {
            seq = (seq << 8) | buf.get_u8() as u64;
        }
        let timestamp_ms = buf.get_u32();
        let payload_len = buf.get_u16() as usize;
        if buf.remaining() < payload_len {
            return Err(Error::protocol("truncated payload"));
        }
        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_slice(&buf.copy_to_bytes(payload_len));
        Ok(Envelope {
            version,
            packet_type,
            flags,
            path_id,
            session_id,
            sequence: Sequence::new(seq),
            timestamp_ms,
            payload: payload.freeze(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use sg_core::{PathId, SessionId, Sequence};

    #[test]
    fn envelope_round_trip() {
        let session = SessionId::new();
        let e = Envelope {
            version: VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            path_id: PathId::new(2),
            session_id: session,
            sequence: Sequence::new(0x0123_4567_89ab),
            timestamp_ms: 12_345,
            payload: Bytes::from_static(b"hello"),
        };
        let mut buf = BytesMut::with_capacity(256);
        e.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), FIXED_HEADER_LEN + 5);

        let mut reader = buf.freeze();
        let decoded = Envelope::decode(&mut reader).unwrap();
        // The wire carries only the first 4 bytes of the session UUID
        // (spec 11.1 `session_id | 4B`); the decode zero-fills the tail.
        assert_eq!(decoded.version, e.version);
        assert_eq!(decoded.packet_type, e.packet_type);
        assert_eq!(decoded.flags, e.flags);
        assert_eq!(decoded.path_id, e.path_id);
        assert_eq!(decoded.sequence, e.sequence);
        assert_eq!(decoded.timestamp_ms, e.timestamp_ms);
        assert_eq!(decoded.payload, e.payload);
        assert_eq!(
            decoded.session_id.as_guid().as_bytes()[..4],
            session.as_guid().as_bytes()[..4]
        );
    }

    #[test]
    fn rejects_unknown_type() {
        assert!(PacketType::try_from(99).is_err());
    }
}