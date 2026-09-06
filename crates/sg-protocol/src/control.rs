//! StreamGuard control-plane payloads (spec section 15.5 / engineering
//! step 8): the path bootstrap handshake.
//!
//! Wire encoding (big-endian):
//!
//! ```text
//! Init:  type(1)=0x00  sid(4)
//!        token_len(2)  token(token_len)
//! Ack:   type(1)=0x01  sid(4)
//! Nack:  type(1)=0x02  sid(4)  reason_len(2)  reason(reason_len)
//! ```
//!
//! `sid` is the same 4-byte wire prefix the envelope carries (spec 11.1).
//! Carried as the `payload` bytes of a `PacketType::Control` envelope.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use sg_core::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMsg {
    Init { sid: u32, token: String },
    Ack { sid: u32 },
    Nack { sid: u32, reason: String },
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
        ] {
            let wire = msg.encode().unwrap();
            assert_eq!(ControlMsg::decode(&wire).unwrap(), msg);
        }
    }

    #[test]
    fn rejects_truncated_and_unknown() {
        // Init claims a 1-byte token but provides none (kind+sid+len only).
        assert!(ControlMsg::decode(&[0x00, 0, 0, 0, 0, 0, 1]).is_err());
        assert!(ControlMsg::decode(&[0x00, 0x00]).is_err());
        assert!(ControlMsg::decode(&[0xff]).is_err());
    }
}