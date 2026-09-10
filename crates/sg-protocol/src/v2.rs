//! V2 datagram framing. Admission and state changes use a reliable control
//! stream; V2 datagrams carry non-control payload only.

pub mod control;

use bytes::{Bytes, BytesMut};
use sg_core::v2::{FlowId, PacketId, PathId, SessionId, TrafficClass};
use std::fmt;
use thiserror::Error;

/// The only accepted V2 datagram version.
pub const VERSION: u8 = 0x02;

/// Bytes in the fixed V2 datagram header.
pub const FIXED_HEADER_LEN: usize = 52;

/// Direction prevents packet identity reuse across the two tunnel directions.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToGateway = 1,
    GatewayToClient = 2,
}

/// A path-specific upper bound supplied by the transport implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadLimit(usize);

/// Validated V2 metadata. The receiver must still bind these values to its
/// authenticated connection before accepting a packet into session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2Header {
    pub traffic_class: TrafficClass,
    pub direction: Direction,
    pub session_id: SessionId,
    pub path_id: PathId,
    pub path_epoch: u64,
    pub key_epoch: u32,
    pub flow_id: FlowId,
    pub packet_id: PacketId,
}

/// One complete V2 QUIC datagram.
#[derive(Clone, PartialEq, Eq)]
pub struct V2Envelope {
    pub header: V2Header,
    pub payload: Bytes,
}

impl fmt::Debug for V2Envelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2Envelope")
            .field("header", &self.header)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum V2EnvelopeError {
    #[error("V2 datagram is shorter than its fixed header")]
    TruncatedHeader,
    #[error("unsupported V2 datagram version {0}")]
    UnsupportedVersion(u8),
    #[error("V2 datagram has nonzero reserved flags {0}")]
    ReservedFlags(u8),
    #[error("unknown V2 traffic class {0}")]
    UnknownTrafficClass(u8),
    #[error("V2 control messages must use the reliable control stream")]
    ControlDatagram,
    #[error("unknown V2 direction {0}")]
    UnknownDirection(u8),
    #[error("V2 path epoch must be nonzero")]
    ZeroPathEpoch,
    #[error("V2 key epoch must be nonzero")]
    ZeroKeyEpoch,
    #[error("V2 datagram payload must not be empty")]
    EmptyPayload,
    #[error("V2 datagram payload length {length} exceeds path limit {limit}")]
    PayloadExceedsLimit { length: usize, limit: usize },
    #[error("V2 datagram payload length exceeds the wire field")]
    PayloadLengthOverflow,
    #[error("V2 datagram payload is truncated: declared {declared}, actual {actual}")]
    TruncatedPayload { declared: usize, actual: usize },
    #[error("V2 datagram has trailing data: declared {declared}, actual {actual}")]
    TrailingData { declared: usize, actual: usize },
}

impl Direction {
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientToGateway),
            2 => Some(Self::GatewayToClient),
            _ => None,
        }
    }

    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

impl PayloadLimit {
    pub const fn new(maximum: usize) -> Self {
        Self(maximum)
    }

    pub const fn maximum(self) -> usize {
        self.0
    }
}

impl V2Envelope {
    pub fn encode(&self, payload_limit: PayloadLimit) -> Result<Bytes, V2EnvelopeError> {
        validate_header(self.header)?;
        validate_payload_len(self.payload.len(), payload_limit)?;

        let mut datagram = BytesMut::with_capacity(FIXED_HEADER_LEN + self.payload.len());
        datagram.extend_from_slice(&[VERSION]);
        datagram.extend_from_slice(&[self.header.traffic_class.to_wire()]);
        datagram.extend_from_slice(&[0]);
        datagram.extend_from_slice(&[self.header.direction.to_wire()]);
        datagram.extend_from_slice(self.header.session_id.as_bytes());
        datagram.extend_from_slice(&self.header.path_id.get().to_be_bytes());
        datagram.extend_from_slice(&self.header.path_epoch.to_be_bytes());
        datagram.extend_from_slice(&self.header.key_epoch.to_be_bytes());
        datagram.extend_from_slice(&self.header.flow_id.get().to_be_bytes());
        datagram.extend_from_slice(&self.header.packet_id.get().to_be_bytes());
        datagram.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        datagram.extend_from_slice(&self.payload);
        Ok(datagram.freeze())
    }

    pub fn decode(datagram: Bytes, payload_limit: PayloadLimit) -> Result<Self, V2EnvelopeError> {
        if datagram.len() < FIXED_HEADER_LEN {
            return Err(V2EnvelopeError::TruncatedHeader);
        }

        if datagram[0] != VERSION {
            return Err(V2EnvelopeError::UnsupportedVersion(datagram[0]));
        }
        let traffic_class = TrafficClass::from_wire(datagram[1])
            .ok_or(V2EnvelopeError::UnknownTrafficClass(datagram[1]))?;
        if datagram[2] != 0 {
            return Err(V2EnvelopeError::ReservedFlags(datagram[2]));
        }
        if traffic_class == TrafficClass::Control {
            return Err(V2EnvelopeError::ControlDatagram);
        }
        let direction = Direction::from_wire(datagram[3])
            .ok_or(V2EnvelopeError::UnknownDirection(datagram[3]))?;
        let mut session_id = [0; 16];
        session_id.copy_from_slice(&datagram[4..20]);
        let path_id = PathId::new(u16::from_be_bytes([datagram[20], datagram[21]]));
        let path_epoch = u64::from_be_bytes(datagram[22..30].try_into().unwrap());
        let key_epoch = u32::from_be_bytes(datagram[30..34].try_into().unwrap());
        let flow_id = FlowId::new(u64::from_be_bytes(datagram[34..42].try_into().unwrap()));
        let packet_id = PacketId::new(u64::from_be_bytes(datagram[42..50].try_into().unwrap()));
        let payload_len = u16::from_be_bytes([datagram[50], datagram[51]]) as usize;
        let actual_payload_len = datagram.len() - FIXED_HEADER_LEN;

        validate_header(V2Header {
            traffic_class,
            direction,
            session_id: SessionId::from_bytes(session_id),
            path_id,
            path_epoch,
            key_epoch,
            flow_id,
            packet_id,
        })?;
        validate_payload_len(payload_len, payload_limit)?;
        if actual_payload_len < payload_len {
            return Err(V2EnvelopeError::TruncatedPayload {
                declared: payload_len,
                actual: actual_payload_len,
            });
        }
        if actual_payload_len > payload_len {
            return Err(V2EnvelopeError::TrailingData {
                declared: payload_len,
                actual: actual_payload_len,
            });
        }

        Ok(Self {
            header: V2Header {
                traffic_class,
                direction,
                session_id: SessionId::from_bytes(session_id),
                path_id,
                path_epoch,
                key_epoch,
                flow_id,
                packet_id,
            },
            payload: datagram.slice(FIXED_HEADER_LEN..),
        })
    }
}

fn validate_header(header: V2Header) -> Result<(), V2EnvelopeError> {
    if header.traffic_class == TrafficClass::Control {
        return Err(V2EnvelopeError::ControlDatagram);
    }
    if header.path_epoch == 0 {
        return Err(V2EnvelopeError::ZeroPathEpoch);
    }
    if header.key_epoch == 0 {
        return Err(V2EnvelopeError::ZeroKeyEpoch);
    }
    Ok(())
}

fn validate_payload_len(len: usize, payload_limit: PayloadLimit) -> Result<(), V2EnvelopeError> {
    if len == 0 {
        return Err(V2EnvelopeError::EmptyPayload);
    }
    if len > payload_limit.maximum() {
        return Err(V2EnvelopeError::PayloadExceedsLimit {
            length: len,
            limit: payload_limit.maximum(),
        });
    }
    if len > u16::MAX as usize {
        return Err(V2EnvelopeError::PayloadLengthOverflow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: PayloadLimit = PayloadLimit::new(1_500);

    fn header(traffic_class: TrafficClass, direction: Direction) -> V2Header {
        V2Header {
            traffic_class,
            direction,
            session_id: SessionId::from_bytes([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ]),
            path_id: PathId::new(0x1234),
            path_epoch: 7,
            key_epoch: 9,
            flow_id: FlowId::new(0x0102_0304_0506_0708),
            packet_id: PacketId::new(0x1112_1314_1516_1718),
        }
    }

    #[test]
    fn round_trips_every_data_class_and_direction_without_copying_payload() {
        for traffic_class in [
            TrafficClass::Realtime,
            TrafficClass::Interactive,
            TrafficClass::Bulk,
        ] {
            for direction in [Direction::ClientToGateway, Direction::GatewayToClient] {
                let envelope = V2Envelope {
                    header: header(traffic_class, direction),
                    payload: Bytes::from_static(b"payload"),
                };
                let datagram = envelope.encode(LIMIT).unwrap();
                let payload_start = datagram.as_ptr().wrapping_add(FIXED_HEADER_LEN);
                let decoded = V2Envelope::decode(datagram, LIMIT).unwrap();

                assert_eq!(decoded, envelope);
                assert_eq!(decoded.payload.as_ptr(), payload_start);
            }
        }
    }

    #[test]
    fn golden_wire_uses_network_byte_order() {
        let envelope = V2Envelope {
            header: header(TrafficClass::Realtime, Direction::ClientToGateway),
            payload: Bytes::from_static(b"abc"),
        };

        assert_eq!(
            envelope.encode(LIMIT).unwrap().as_ref(),
            &[
                0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x12, 0x34, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x09, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17, 0x18, 0x00, 0x03,
                b'a', b'b', b'c',
            ]
        );
    }

    #[test]
    fn path_epoch_preserves_all_64_bits_on_the_wire() {
        let mut header = header(TrafficClass::Realtime, Direction::ClientToGateway);
        header.path_epoch = 0x0102_0304_0506_0708;
        let envelope = V2Envelope {
            header,
            payload: Bytes::from_static(b"epoch"),
        };

        let wire = envelope.encode(LIMIT).unwrap();
        assert_eq!(&wire[22..30], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(V2Envelope::decode(wire, LIMIT).unwrap(), envelope);
    }

    #[test]
    fn decoder_rejects_invalid_framing_and_metadata() {
        let envelope = V2Envelope {
            header: header(TrafficClass::Realtime, Direction::ClientToGateway),
            payload: Bytes::from_static(b"abc"),
        };
        let valid = envelope.encode(LIMIT).unwrap();

        assert_eq!(
            V2Envelope::decode(Bytes::from_static(b"short"), LIMIT),
            Err(V2EnvelopeError::TruncatedHeader)
        );

        let cases = [
            (0, 1, V2EnvelopeError::UnsupportedVersion(1)),
            (1, 4, V2EnvelopeError::UnknownTrafficClass(4)),
            (2, 1, V2EnvelopeError::ReservedFlags(1)),
            (3, 0, V2EnvelopeError::UnknownDirection(0)),
        ];
        for (offset, value, expected) in cases {
            let mut malformed = valid.to_vec();
            malformed[offset] = value;
            assert_eq!(V2Envelope::decode(Bytes::from(malformed), LIMIT), Err(expected));
        }

        let mut zero_path_epoch = valid.to_vec();
        zero_path_epoch[22..30].fill(0);
        assert_eq!(
            V2Envelope::decode(Bytes::from(zero_path_epoch), LIMIT),
            Err(V2EnvelopeError::ZeroPathEpoch)
        );
        let mut zero_key_epoch = valid.to_vec();
        zero_key_epoch[30..34].fill(0);
        assert_eq!(
            V2Envelope::decode(Bytes::from(zero_key_epoch), LIMIT),
            Err(V2EnvelopeError::ZeroKeyEpoch)
        );
        let mut control_datagram = valid.to_vec();
        control_datagram[1] = TrafficClass::Control.to_wire();
        assert_eq!(
            V2Envelope::decode(Bytes::from(control_datagram), LIMIT),
            Err(V2EnvelopeError::ControlDatagram)
        );

        let control = V2Envelope {
            header: header(TrafficClass::Control, Direction::ClientToGateway),
            payload: Bytes::from_static(b"abc"),
        };
        assert_eq!(control.encode(LIMIT), Err(V2EnvelopeError::ControlDatagram));
    }

    #[test]
    fn decoder_requires_exact_payload_length_and_transport_limit() {
        let envelope = V2Envelope {
            header: header(TrafficClass::Realtime, Direction::ClientToGateway),
            payload: Bytes::from_static(b"abc"),
        };
        let valid = envelope.encode(LIMIT).unwrap();

        assert_eq!(
            V2Envelope::decode(valid.slice(..FIXED_HEADER_LEN + 2), LIMIT),
            Err(V2EnvelopeError::TruncatedPayload {
                declared: 3,
                actual: 2,
            })
        );
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert_eq!(
            V2Envelope::decode(Bytes::from(trailing), LIMIT),
            Err(V2EnvelopeError::TrailingData {
                declared: 3,
                actual: 4,
            })
        );
        assert_eq!(
            V2Envelope::decode(valid, PayloadLimit::new(2)),
            Err(V2EnvelopeError::PayloadExceedsLimit {
                length: 3,
                limit: 2,
            })
        );
    }

    #[test]
    fn payload_limit_boundary_is_enforced_before_encoding() {
        let envelope = V2Envelope {
            header: header(TrafficClass::Bulk, Direction::GatewayToClient),
            payload: Bytes::from_static(b"abc"),
        };

        assert!(envelope.encode(PayloadLimit::new(3)).is_ok());
        assert_eq!(
            envelope.encode(PayloadLimit::new(2)),
            Err(V2EnvelopeError::PayloadExceedsLimit {
                length: 3,
                limit: 2,
            })
        );
        assert_eq!(
            envelope.encode(PayloadLimit::new(0)),
            Err(V2EnvelopeError::PayloadExceedsLimit {
                length: 3,
                limit: 0,
            })
        );

        let oversized = V2Envelope {
            header: header(TrafficClass::Bulk, Direction::GatewayToClient),
            payload: Bytes::from(vec![0; u16::MAX as usize + 1]),
        };
        assert_eq!(
            oversized.encode(PayloadLimit::new(u16::MAX as usize + 1)),
            Err(V2EnvelopeError::PayloadLengthOverflow)
        );
    }

    #[test]
    fn arbitrary_datagrams_never_panic() {
        let mut state = 0xD1CE_CAFE_u64;
        for len in 0..128 {
            let mut datagram = vec![0; len];
            for byte in &mut datagram {
                state ^= state << 7;
                state ^= state >> 9;
                state ^= state << 8;
                *byte = state as u8;
            }
            let _ = V2Envelope::decode(Bytes::from(datagram), PayloadLimit::new(len));
        }
    }

    #[test]
    fn debug_output_does_not_include_payload_contents() {
        let envelope = V2Envelope {
            header: header(TrafficClass::Realtime, Direction::ClientToGateway),
            payload: Bytes::from_static(b"sensitive packet contents"),
        };

        let debug = format!("{envelope:?}");
        assert!(debug.contains("payload_len"));
        assert!(!debug.contains("sensitive packet contents"));
    }
}
