//! StreamGuard control-plane payloads (spec section 15.5 / engineering
//! step 8): the path bootstrap handshake.
//!
//! Wire encoding (big-endian):
//!
//! ```text
//! Init:       type(1)=0x00  sid(4)
//!             token_len(2)  token(token_len)
//! Ack:        type(1)=0x01  sid(4)
//! Nack:       type(1)=0x02  sid(4)  reason_len(2)  reason(reason_len)
//! PathSelect: type(1)=0x03  path(1)
//! WeightSet:  type(1)=0x04  count(1)  [path(1) weight(4)] × count
//! ```
//!
//! `PathSelect` is the rev1 path-control message: the client tells the
//! gateway which bound path should carry that session's downlink traffic,
//! so a client-side failover moves the gateway's active path too.
//!
//! `WeightSet` is the phase-3 downlink-bonding advertisement (spec 12
//! Phase 3): the client owns the authoritative health snapshot, so it
//! publishes the normalized per-path weight distribution and the gateway
//! mirrors that distribution when spreading its downlink egress. One
//! `(path, weight)` pair per eligible path, weights summing to ~1; the
//! receiver re-normalizes defensively (the payload rides the public wire).
//!
//! `sid` is the same 4-byte wire prefix the envelope carries (spec 11.1).
//! Carried as the `payload` bytes of a `PacketType::Control` envelope.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use sg_core::error::{Error, Result};
use sg_core::PathId;

/// Phase-3 downlink weights can be zero/one shared by several paths, so
/// `PartialEq` only: `f32` is not `Eq` (NaN != NaN).
#[derive(Debug, Clone, PartialEq)]
pub enum ControlMsg {
    Init { sid: u32, token: String },
    Ack { sid: u32 },
    Nack { sid: u32, reason: String },
    /// Asks the gateway to serve downlink on `path` for the envelope's session.
    PathSelect { path: u8 },
    /// Publishes the phase-3 weighted-bonding distribution for downlink
    /// (spec 12 Phase 3): `weights` is one (path, normalized weight) pair
    /// per eligible path. The gateway adopts them and spreads its downlink
    /// egress with the same smooth-WRR scheduler the client's uplink uses.
    WeightSet { weights: Vec<(PathId, f32)> },
}

impl ControlMsg {
    pub fn encode(&self) -> Result<Bytes> {
        let mut out = BytesMut::with_capacity(64);
        match self {
            ControlMsg::Init { sid, token } => {
                if token.len() > u16::MAX as usize {
                    return Err(Error::protocol("init token too long"));
                }
                out.put_u8(0x00);
                out.put_u32(*sid);
                out.put_u16(token.len() as u16);
                out.put_slice(token.as_bytes());
            }
            ControlMsg::Ack { sid } => {
                out.put_u8(0x01);
                out.put_u32(*sid);
            }
            ControlMsg::Nack { sid, reason } => {
                if reason.len() > u16::MAX as usize {
                    return Err(Error::protocol("nack reason too long"));
                }
                out.put_u8(0x02);
                out.put_u32(*sid);
                out.put_u16(reason.len() as u16);
                out.put_slice(reason.as_bytes());
            }
            ControlMsg::PathSelect { path } => {
                out.put_u8(0x03);
                out.put_u8(*path);
            }
            ControlMsg::WeightSet { weights } => {
                if weights.len() > u8::MAX as usize {
                    return Err(Error::protocol("too many weight entries"));
                }
                out.put_u8(0x04);
                out.put_u8(weights.len() as u8);
                for (path, weight) in weights {
                    out.put_u8(path.get());
                    out.put_f32(*weight);
                }
            }
        }
        Ok(out.freeze())
    }

    pub fn decode(mut buf: &[u8]) -> Result<ControlMsg> {
        if buf.remaining() < 1 {
            return Err(Error::protocol("empty control message"));
        }
        let kind = buf.get_u8();
        match kind {
            0x00 => {
                if buf.remaining() < 6 {
                    return Err(Error::protocol("short init"));
                }
                let sid = buf.get_u32();
                let len = buf.get_u16() as usize;
                if buf.remaining() < len {
                    return Err(Error::protocol("truncated init token"));
                }
                let token = String::from_utf8(buf.copy_to_bytes(len).to_vec())
                    .map_err(|_| Error::protocol("init token not utf-8"))?;
                Ok(ControlMsg::Init { sid, token })
            }
            0x01 => {
                if buf.remaining() < 4 {
                    return Err(Error::protocol("short ack"));
                }
                Ok(ControlMsg::Ack { sid: buf.get_u32() })
            }
            0x02 => {
                if buf.remaining() < 6 {
                    return Err(Error::protocol("short nack"));
                }
                let sid = buf.get_u32();
                let len = buf.get_u16() as usize;
                if buf.remaining() < len {
                    return Err(Error::protocol("truncated nack reason"));
                }
                let reason = String::from_utf8(buf.copy_to_bytes(len).to_vec())
                    .map_err(|_| Error::protocol("nack reason not utf-8"))?;
                Ok(ControlMsg::Nack { sid, reason })
            }
            0x03 => {
                if buf.remaining() < 1 {
                    return Err(Error::protocol("short path select"));
                }
                Ok(ControlMsg::PathSelect { path: buf.get_u8() })
            }
            0x04 => {
                if buf.remaining() < 1 {
                    return Err(Error::protocol("short weight set"));
                }
                let count = buf.get_u8() as usize;
                if buf.remaining() < count * 5 {
                    return Err(Error::protocol("truncated weight set"));
                }
                let mut weights = Vec::with_capacity(count);
                for _ in 0..count {
                    let path = PathId::new(buf.get_u8());
                    let weight = buf.get_f32();
                    weights.push((path, weight));
                }
                Ok(ControlMsg::WeightSet { weights })
            }
            other => Err(Error::protocol(format!("unknown control kind {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_round_trip() {
        for msg in [
            ControlMsg::Init {
                sid: 0xdeadbeef,
                token: "eyJhbGciOiJIUzI1NiJ9.abc.def".into(),
            },
            ControlMsg::Ack { sid: 0xdeadbeef },
            ControlMsg::Nack {
                sid: 0xdeadbeef,
                reason: "bad signature".into(),
            },
            ControlMsg::PathSelect { path: 2 },
            ControlMsg::WeightSet {
                weights: vec![(PathId::new(1), 0.7), (PathId::new(2), 0.3)],
            },
        ] {
            let wire = msg.encode().unwrap();
            assert_eq!(ControlMsg::decode(&wire).unwrap(), msg);
        }
    }

    #[test]
    fn weight_set_round_trip_preserves_f32_bits() {
        // f32 bit patterns must survive the wire unchanged (big-endian), so
        // tiny weights and fractional splits stay exact for the scheduler.
        let msg = ControlMsg::WeightSet {
            weights: vec![
                (PathId::new(3), std::f32::consts::FRAC_1_SQRT_2),
                (PathId::new(7), 0.292_893_2), // 1 - FRAC_1_SQRT_2 rounded
            ],
        };
        let wire = msg.encode().unwrap();
        assert_eq!(
            ControlMsg::decode(&wire).unwrap(),
            msg,
            "weight bit patterns survive encode/decode"
        );
        assert_eq!(wire.len(), 2 + 2 * 5, "kind(1) + count(1) + 2 × (path(1)+weight(4))");
    }

    #[test]
    fn rejects_truncated_and_unknown() {
        // Init claims a 1-byte token but provides none (kind+sid+len only).
        assert!(ControlMsg::decode(&[0x00, 0, 0, 0, 0, 0, 1]).is_err());
        assert!(ControlMsg::decode(&[0x00, 0x00]).is_err());
        assert!(ControlMsg::decode(&[0xff]).is_err());
        // WeightSet(0x04) declares two entries but carries only one.
        assert!(ControlMsg::decode(&[0x04, 0x02, 1, 0x3f, 0x33, 0x33, 0x33, 2]).is_err());
        // WeightSet with no entries at all (count byte present, none follow)
        // is decodable but empty — a valid wire shape the receiver ignores.
        assert_eq!(
            ControlMsg::decode(&[0x04, 0x00]).unwrap(),
            ControlMsg::WeightSet { weights: vec![] }
        );
    }
}