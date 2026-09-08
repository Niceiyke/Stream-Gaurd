//! Bounded V2 reliable-control frames.
//!
//! This module is intentionally independent from V1 datagram control. A
//! transport adds its own stream length prefix around these exact frames.

pub mod state;

use bytes::{Bytes, BytesMut};
use sg_core::v2::{DeviceId, PathId, SessionId};
use std::fmt;
use thiserror::Error;

/// The only accepted V2 reliable-control version.
pub const VERSION: u8 = 0x02;
/// Bytes before a control message body.
pub const FRAME_HEADER_LEN: usize = 16;
/// Conservative upper bound for one complete, unprefixed control frame.
pub const DEFAULT_MAX_FRAME_LEN: usize = 8 * 1024;
pub const MAX_GATEWAY_NAME_LEN: usize = 255;
pub const MAX_TICKET_LEN: usize = 2 * 1024;
pub const MAX_PATH_METADATA_LEN: usize = 512;
pub const MAX_REASON_LEN: usize = 255;
pub const MAX_POLICY_LEN: usize = 4 * 1024;
pub const MAX_SAFE_MODE_POLICY_LEN: usize = 4 * 1024;

/// An admission ticket whose contents must not be emitted through `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct AdmissionTicket(String);

impl AdmissionTicket {
    pub fn new(value: String) -> Result<Self, ControlCodecError> {
        if value.is_empty() {
            return Err(ControlCodecError::InvalidField("ticket"));
        }
        if value.len() > MAX_TICKET_LEN {
            return Err(ControlCodecError::FieldTooLong {
                field: "ticket",
                length: value.len(),
                maximum: MAX_TICKET_LEN,
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdmissionTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionTicket(REDACTED)")
    }
}

/// A bounded Safe Mode policy payload. Its interpretation belongs to the
/// authenticated policy layer; this codec only carries validated bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SafeModePolicy(Bytes);

impl SafeModePolicy {
    pub fn new(value: Bytes) -> Result<Self, ControlCodecError> {
        if value.is_empty() {
            return Err(ControlCodecError::InvalidField("safe mode policy"));
        }
        validate_len("safe mode policy", value.len(), MAX_SAFE_MODE_POLICY_LEN)?;
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }
}

impl fmt::Debug for SafeModePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeModePolicy")
            .field("length", &self.0.len())
            .finish()
    }
}

/// A maximum supplied by the reliable transport before it reads a frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlFrameLimit(usize);

impl ControlFrameLimit {
    pub const fn new(maximum: usize) -> Self {
        Self(maximum)
    }

    pub const fn maximum(self) -> usize {
        self.0
    }
}

impl Default for ControlFrameLimit {
    fn default() -> Self {
        Self(DEFAULT_MAX_FRAME_LEN)
    }
}

/// A complete control message, including its transaction identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    pub transaction_id: u64,
    pub message: ControlMessage,
}

/// V2 reliable-control messages. The frame transaction ID correlates requests
/// and replies; all numeric fields use network byte order on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    ClientHello {
        device_id: DeviceId,
        requested_gateway: String,
        ticket: AdmissionTicket,
    },
    SessionAdmit {
        session_id: SessionId,
        expires_at_ms: u64,
        policy_epoch: u64,
        assigned_ipv4: [u8; 4],
        assigned_ipv4_prefix_len: u8,
        assigned_ipv6_prefix: [u8; 16],
        assigned_ipv6_prefix_len: u8,
        safe_mode_policy: SafeModePolicy,
    },
    PathAttach {
        session_id: SessionId,
        path_nonce: [u8; 16],
        path_epoch: u64,
        metadata: Bytes,
    },
    PathAttached {
        session_id: SessionId,
        path_id: PathId,
        path_epoch: u64,
    },
    PathDetach {
        session_id: SessionId,
        path_id: PathId,
        path_epoch: u64,
        reason: String,
    },
    PathHealth {
        session_id: SessionId,
        path_id: PathId,
        path_epoch: u64,
        rtt_ms: u32,
        loss_ppm: u32,
    },
    PolicyUpdate {
        session_id: SessionId,
        policy_epoch: u64,
        policy: Bytes,
    },
    Close {
        session_id: SessionId,
        reason: String,
    },
    Ack,
    Reject {
        code: RejectCode,
        reason: String,
    },
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCode {
    InvalidState = 1,
    InvalidSession = 2,
    StaleEpoch = 3,
    UnknownPath = 4,
    InvalidRequest = 5,
    Expired = 6,
    InvalidDirection = 7,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControlCodecError {
    #[error("V2 control frame is shorter than its fixed header")]
    TruncatedHeader,
    #[error("unsupported V2 control version {0}")]
    UnsupportedVersion(u8),
    #[error("V2 control frame has nonzero reserved byte {0}")]
    ReservedByte(u8),
    #[error("unknown V2 control message kind {0}")]
    UnknownKind(u8),
    #[error("V2 control transaction ID must be nonzero")]
    ZeroTransactionId,
    #[error("V2 control frame length {length} exceeds limit {limit}")]
    FrameTooLarge { length: usize, limit: usize },
    #[error("V2 control frame is truncated: declared {declared}, actual {actual}")]
    TruncatedFrame { declared: usize, actual: usize },
    #[error("V2 control frame has trailing data: declared {declared}, actual {actual}")]
    TrailingData { declared: usize, actual: usize },
    #[error("V2 control field {0} is invalid")]
    InvalidField(&'static str),
    #[error("V2 control field {field} length {length} exceeds limit {maximum}")]
    FieldTooLong {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    #[error("V2 control field {0} is not valid UTF-8")]
    InvalidUtf8(&'static str),
}

impl RejectCode {
    fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::InvalidState),
            2 => Some(Self::InvalidSession),
            3 => Some(Self::StaleEpoch),
            4 => Some(Self::UnknownPath),
            5 => Some(Self::InvalidRequest),
            6 => Some(Self::Expired),
            7 => Some(Self::InvalidDirection),
            _ => None,
        }
    }
}

impl ControlFrame {
    /// Encodes one complete, unprefixed frame. Stream transports must add a
    /// length prefix and enforce this same limit before allocating a body.
    pub fn encode(&self, limit: ControlFrameLimit) -> Result<Bytes, ControlCodecError> {
        if self.transaction_id == 0 {
            return Err(ControlCodecError::ZeroTransactionId);
        }
        let (kind, body) = encode_message(&self.message)?;
        let length = FRAME_HEADER_LEN + body.len();
        if length > limit.maximum() {
            return Err(ControlCodecError::FrameTooLarge {
                length,
                limit: limit.maximum(),
            });
        }

        let mut frame = BytesMut::with_capacity(length);
        frame.extend_from_slice(&[VERSION, 0, kind, 0]);
        frame.extend_from_slice(&self.transaction_id.to_be_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame.freeze())
    }

    /// Decodes one exact, unprefixed control frame without allocating until all
    /// framing, lengths, field bounds, and trailing-data checks have passed.
    pub fn decode(frame: &[u8], limit: ControlFrameLimit) -> Result<Self, ControlCodecError> {
        if frame.len() < FRAME_HEADER_LEN {
            return Err(ControlCodecError::TruncatedHeader);
        }
        if frame[0] != VERSION {
            return Err(ControlCodecError::UnsupportedVersion(frame[0]));
        }
        if frame[1] != 0 {
            return Err(ControlCodecError::ReservedByte(frame[1]));
        }
        if frame[3] != 0 {
            return Err(ControlCodecError::ReservedByte(frame[3]));
        }
        let kind = frame[2];
        let transaction_id = u64::from_be_bytes(frame[4..12].try_into().unwrap());
        if transaction_id == 0 {
            return Err(ControlCodecError::ZeroTransactionId);
        }
        let body_len = u32::from_be_bytes(frame[12..16].try_into().unwrap()) as usize;
        let declared = FRAME_HEADER_LEN + body_len;
        if declared > limit.maximum() {
            return Err(ControlCodecError::FrameTooLarge {
                length: declared,
                limit: limit.maximum(),
            });
        }
        if frame.len() < declared {
            return Err(ControlCodecError::TruncatedFrame {
                declared,
                actual: frame.len(),
            });
        }
        if frame.len() > declared {
            return Err(ControlCodecError::TrailingData {
                declared,
                actual: frame.len(),
            });
        }

        let message = decode_message(kind, &frame[FRAME_HEADER_LEN..])?;
        Ok(Self {
            transaction_id,
            message,
        })
    }
}

fn encode_message(message: &ControlMessage) -> Result<(u8, Bytes), ControlCodecError> {
    let mut body = BytesMut::with_capacity(64);
    let kind = match message {
        ControlMessage::ClientHello {
            device_id,
            requested_gateway,
            ticket,
        } => {
            validate_id(device_id.as_bytes(), "device ID")?;
            put_string_u8(&mut body, requested_gateway, "gateway", MAX_GATEWAY_NAME_LEN)?;
            put_string_u16(&mut body, ticket.as_str(), "ticket", MAX_TICKET_LEN)?;
            let mut prefix = BytesMut::with_capacity(16 + body.len());
            prefix.extend_from_slice(device_id.as_bytes());
            prefix.extend_from_slice(&body);
            body = prefix;
            1
        }
        ControlMessage::SessionAdmit {
            session_id,
            expires_at_ms,
            policy_epoch,
            assigned_ipv4,
            assigned_ipv4_prefix_len,
            assigned_ipv6_prefix,
            assigned_ipv6_prefix_len,
            safe_mode_policy,
        } => {
            validate_session(session_id)?;
            if *expires_at_ms == 0 || *policy_epoch == 0 {
                return Err(ControlCodecError::InvalidField("session admission epoch"));
            }
            validate_nonzero(assigned_ipv4, "assigned IPv4")?;
            validate_nonzero(assigned_ipv6_prefix, "assigned IPv6 prefix")?;
            validate_prefix(*assigned_ipv4_prefix_len, 32, "IPv4 prefix length")?;
            validate_prefix(*assigned_ipv6_prefix_len, 128, "IPv6 prefix length")?;
            body.extend_from_slice(session_id.as_bytes());
            body.extend_from_slice(&expires_at_ms.to_be_bytes());
            body.extend_from_slice(&policy_epoch.to_be_bytes());
            body.extend_from_slice(assigned_ipv4);
            body.extend_from_slice(&[*assigned_ipv4_prefix_len]);
            body.extend_from_slice(assigned_ipv6_prefix);
            body.extend_from_slice(&[*assigned_ipv6_prefix_len]);
            body.extend_from_slice(&(safe_mode_policy.as_bytes().len() as u16).to_be_bytes());
            body.extend_from_slice(safe_mode_policy.as_bytes());
            2
        }
        ControlMessage::PathAttach {
            session_id,
            path_nonce,
            path_epoch,
            metadata,
        } => {
            validate_session(session_id)?;
            validate_id(path_nonce, "path nonce")?;
            validate_epoch(*path_epoch, "path epoch")?;
            validate_len("path metadata", metadata.len(), MAX_PATH_METADATA_LEN)?;
            body.extend_from_slice(session_id.as_bytes());
            body.extend_from_slice(path_nonce);
            body.extend_from_slice(&path_epoch.to_be_bytes());
            body.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
            body.extend_from_slice(metadata);
            3
        }
        ControlMessage::PathAttached {
            session_id,
            path_id,
            path_epoch,
        } => {
            validate_session(session_id)?;
            validate_path(*path_id)?;
            validate_epoch(*path_epoch, "path epoch")?;
            body.extend_from_slice(session_id.as_bytes());
            body.extend_from_slice(&path_id.get().to_be_bytes());
            body.extend_from_slice(&path_epoch.to_be_bytes());
            4
        }
        ControlMessage::PathDetach {
            session_id,
            path_id,
            path_epoch,
            reason,
        } => {
            validate_session(session_id)?;
            validate_path(*path_id)?;
            validate_epoch(*path_epoch, "path epoch")?;
            body.extend_from_slice(session_id.as_bytes());
            body.extend_from_slice(&path_id.get().to_be_bytes());
            body.extend_from_slice(&path_epoch.to_be_bytes());
            put_string_u8(&mut body, reason, "reason", MAX_REASON_LEN)?;
            5
        }
        ControlMessage::PathHealth {
            session_id,
            path_id,
            path_epoch,
            rtt_ms,
            loss_ppm,
        } => {
            validate_session(session_id)?;
            validate_path(*path_id)?;
            validate_epoch(*path_epoch, "path epoch")?;
            body.extend_from_slice(session_id.as_bytes());
            body.extend_from_slice(&path_id.get().to_be_bytes());
            body.extend_from_slice(&path_epoch.to_be_bytes());
            body.extend_from_slice(&rtt_ms.to_be_bytes());
            body.extend_from_slice(&loss_ppm.to_be_bytes());
            6
        }
        ControlMessage::PolicyUpdate {
            session_id,
            policy_epoch,
            policy,
        } => {
            validate_session(session_id)?;
            validate_epoch(*policy_epoch, "policy epoch")?;
            validate_len("policy", policy.len(), MAX_POLICY_LEN)?;
            body.extend_from_slice(session_id.as_bytes());
            body.extend_from_slice(&policy_epoch.to_be_bytes());
            body.extend_from_slice(&(policy.len() as u16).to_be_bytes());
            body.extend_from_slice(policy);
            7
        }
        ControlMessage::Close { session_id, reason } => {
            validate_session(session_id)?;
            body.extend_from_slice(session_id.as_bytes());
            put_string_u8(&mut body, reason, "reason", MAX_REASON_LEN)?;
            8
        }
        ControlMessage::Ack => 9,
        ControlMessage::Reject { code, reason } => {
            body.extend_from_slice(&(*code as u16).to_be_bytes());
            put_string_u8(&mut body, reason, "reason", MAX_REASON_LEN)?;
            10
        }
    };
    Ok((kind, body.freeze()))
}

fn decode_message(kind: u8, body: &[u8]) -> Result<ControlMessage, ControlCodecError> {
    let mut reader = Reader::new(body);
    match kind {
        1 => {
            let device = reader.id("device ID")?;
            let gateway = reader.string_u8("gateway", MAX_GATEWAY_NAME_LEN)?;
            let ticket = reader.string_u16("ticket", MAX_TICKET_LEN)?;
            if ticket.is_empty() {
                return Err(ControlCodecError::InvalidField("ticket"));
            }
            reader.finish()?;
            Ok(ControlMessage::ClientHello {
                device_id: DeviceId::from_bytes(device),
                requested_gateway: gateway.to_owned(),
                ticket: AdmissionTicket(ticket.to_owned()),
            })
        }
        2 => {
            let session = reader.id("session ID")?;
            let expires_at_ms = reader.u64()?;
            let policy_epoch = reader.u64()?;
            let assigned_ipv4: [u8; 4] = reader.take(4)?.try_into().unwrap();
            let assigned_ipv4_prefix_len = reader.take(1)?[0];
            let assigned_ipv6_prefix: [u8; 16] = reader.take(16)?.try_into().unwrap();
            let assigned_ipv6_prefix_len = reader.take(1)?[0];
            let safe_mode_policy = reader.bytes_u16("safe mode policy", MAX_SAFE_MODE_POLICY_LEN)?;
            if expires_at_ms == 0 || policy_epoch == 0 {
                return Err(ControlCodecError::InvalidField("session admission epoch"));
            }
            validate_nonzero(&assigned_ipv4, "assigned IPv4")?;
            validate_nonzero(&assigned_ipv6_prefix, "assigned IPv6 prefix")?;
            validate_prefix(assigned_ipv4_prefix_len, 32, "IPv4 prefix length")?;
            validate_prefix(assigned_ipv6_prefix_len, 128, "IPv6 prefix length")?;
            if safe_mode_policy.is_empty() {
                return Err(ControlCodecError::InvalidField("safe mode policy"));
            }
            reader.finish()?;
            Ok(ControlMessage::SessionAdmit {
                session_id: SessionId::from_bytes(session),
                expires_at_ms,
                policy_epoch,
                assigned_ipv4,
                assigned_ipv4_prefix_len,
                assigned_ipv6_prefix,
                assigned_ipv6_prefix_len,
                safe_mode_policy: SafeModePolicy(Bytes::copy_from_slice(safe_mode_policy)),
            })
        }
        3 => {
            let session = reader.id("session ID")?;
            let nonce = reader.id("path nonce")?;
            let path_epoch = reader.epoch("path epoch")?;
            let metadata = reader.bytes_u16("path metadata", MAX_PATH_METADATA_LEN)?;
            reader.finish()?;
            Ok(ControlMessage::PathAttach {
                session_id: SessionId::from_bytes(session),
                path_nonce: nonce,
                path_epoch,
                metadata: Bytes::copy_from_slice(metadata),
            })
        }
        4 => {
            let session = reader.id("session ID")?;
            let path_id = reader.path_id()?;
            let path_epoch = reader.epoch("path epoch")?;
            reader.finish()?;
            Ok(ControlMessage::PathAttached {
                session_id: SessionId::from_bytes(session),
                path_id,
                path_epoch,
            })
        }
        5 => {
            let session = reader.id("session ID")?;
            let path_id = reader.path_id()?;
            let path_epoch = reader.epoch("path epoch")?;
            let reason = reader.string_u8("reason", MAX_REASON_LEN)?;
            reader.finish()?;
            Ok(ControlMessage::PathDetach {
                session_id: SessionId::from_bytes(session),
                path_id,
                path_epoch,
                reason: reason.to_owned(),
            })
        }
        6 => {
            let session = reader.id("session ID")?;
            let path_id = reader.path_id()?;
            let path_epoch = reader.epoch("path epoch")?;
            let rtt_ms = reader.u32()?;
            let loss_ppm = reader.u32()?;
            reader.finish()?;
            Ok(ControlMessage::PathHealth {
                session_id: SessionId::from_bytes(session),
                path_id,
                path_epoch,
                rtt_ms,
                loss_ppm,
            })
        }
        7 => {
            let session = reader.id("session ID")?;
            let policy_epoch = reader.epoch("policy epoch")?;
            let policy = reader.bytes_u16("policy", MAX_POLICY_LEN)?;
            reader.finish()?;
            Ok(ControlMessage::PolicyUpdate {
                session_id: SessionId::from_bytes(session),
                policy_epoch,
            policy: Bytes::copy_from_slice(policy),
            })
        }
        8 => {
            let session = reader.id("session ID")?;
            let reason = reader.string_u8("reason", MAX_REASON_LEN)?;
            reader.finish()?;
            Ok(ControlMessage::Close {
                session_id: SessionId::from_bytes(session),
                reason: reason.to_owned(),
            })
        }
        9 => {
            reader.finish()?;
            Ok(ControlMessage::Ack)
        }
        10 => {
            let code = RejectCode::from_wire(reader.u16()?)
                .ok_or(ControlCodecError::InvalidField("reject code"))?;
            let reason = reader.string_u8("reason", MAX_REASON_LEN)?;
            reader.finish()?;
            Ok(ControlMessage::Reject {
                code,
                reason: reason.to_owned(),
            })
        }
        other => Err(ControlCodecError::UnknownKind(other)),
    }
}

fn validate_id(id: &[u8; 16], name: &'static str) -> Result<(), ControlCodecError> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(ControlCodecError::InvalidField(name));
    }
    Ok(())
}

fn validate_session(session_id: &SessionId) -> Result<(), ControlCodecError> {
    validate_id(session_id.as_bytes(), "session ID")
}

fn validate_nonzero(value: &[u8], name: &'static str) -> Result<(), ControlCodecError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(ControlCodecError::InvalidField(name));
    }
    Ok(())
}

fn validate_path(path_id: PathId) -> Result<(), ControlCodecError> {
    if path_id.get() == 0 {
        return Err(ControlCodecError::InvalidField("path ID"));
    }
    Ok(())
}

fn validate_epoch(value: u64, name: &'static str) -> Result<(), ControlCodecError> {
    if value == 0 {
        return Err(ControlCodecError::InvalidField(name));
    }
    Ok(())
}

fn validate_prefix(value: u8, maximum: u8, name: &'static str) -> Result<(), ControlCodecError> {
    if value == 0 || value > maximum {
        return Err(ControlCodecError::InvalidField(name));
    }
    Ok(())
}

fn validate_len(field: &'static str, length: usize, maximum: usize) -> Result<(), ControlCodecError> {
    if length > maximum {
        return Err(ControlCodecError::FieldTooLong {
            field,
            length,
            maximum,
        });
    }
    Ok(())
}

fn put_string_u8(
    body: &mut BytesMut,
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), ControlCodecError> {
    validate_len(field, value.len(), maximum)?;
    body.extend_from_slice(&[value.len() as u8]);
    body.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_string_u16(
    body: &mut BytesMut,
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), ControlCodecError> {
    validate_len(field, value.len(), maximum)?;
    body.extend_from_slice(&(value.len() as u16).to_be_bytes());
    body.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { remaining: body }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ControlCodecError> {
        if self.remaining.len() < count {
            return Err(ControlCodecError::InvalidField("truncated message body"));
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }

    fn id(&mut self, name: &'static str) -> Result<[u8; 16], ControlCodecError> {
        let bytes: [u8; 16] = self.take(16)?.try_into().unwrap();
        validate_id(&bytes, name)?;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, ControlCodecError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, ControlCodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ControlCodecError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn epoch(&mut self, name: &'static str) -> Result<u64, ControlCodecError> {
        let value = self.u64()?;
        validate_epoch(value, name)?;
        Ok(value)
    }

    fn path_id(&mut self) -> Result<PathId, ControlCodecError> {
        let path_id = PathId::new(self.u16()?);
        validate_path(path_id)?;
        Ok(path_id)
    }

    fn string_u8(&mut self, field: &'static str, maximum: usize) -> Result<&'a str, ControlCodecError> {
        let len = self.take(1)?[0] as usize;
        self.string(field, len, maximum)
    }

    fn string_u16(&mut self, field: &'static str, maximum: usize) -> Result<&'a str, ControlCodecError> {
        let len = self.u16()? as usize;
        self.string(field, len, maximum)
    }

    fn string(&mut self, field: &'static str, len: usize, maximum: usize) -> Result<&'a str, ControlCodecError> {
        validate_len(field, len, maximum)?;
        std::str::from_utf8(self.take(len)?).map_err(|_| ControlCodecError::InvalidUtf8(field))
    }

    fn bytes_u16(&mut self, field: &'static str, maximum: usize) -> Result<&'a [u8], ControlCodecError> {
        let len = self.u16()? as usize;
        validate_len(field, len, maximum)?;
        self.take(len)
    }

    fn finish(self) -> Result<(), ControlCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(ControlCodecError::TrailingData {
                declared: 0,
                actual: self.remaining.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionId {
        SessionId::from_bytes([0x11; 16])
    }

    fn client_hello() -> ControlFrame {
        ControlFrame {
            transaction_id: 0x0102_0304_0506_0708,
            message: ControlMessage::ClientHello {
                device_id: DeviceId::from_bytes([0x22; 16]),
                requested_gateway: "iad-1".into(),
                ticket: AdmissionTicket::new("private-ticket".into()).unwrap(),
            },
        }
    }

    #[test]
    fn round_trips_all_messages_and_uses_network_byte_order() {
        let frames = vec![
            client_hello(),
            ControlFrame {
                transaction_id: 2,
                message: ControlMessage::SessionAdmit {
                    session_id: session(),
                    expires_at_ms: 0x0102_0304_0506_0708,
                    policy_epoch: 9,
                    assigned_ipv4: [10, 0, 0, 2],
                    assigned_ipv4_prefix_len: 24,
                    assigned_ipv6_prefix: [0x20; 16],
                    assigned_ipv6_prefix_len: 64,
                    safe_mode_policy: SafeModePolicy::new(Bytes::from_static(b"safe-mode")).unwrap(),
                },
            },
            ControlFrame {
                transaction_id: 3,
                message: ControlMessage::PathAttach {
                    session_id: session(),
                    path_nonce: [0x33; 16],
                    path_epoch: 4,
                    metadata: Bytes::from_static(b"wifi"),
                },
            },
            ControlFrame {
                transaction_id: 4,
                message: ControlMessage::PathAttached {
                    session_id: session(),
                    path_id: PathId::new(0x1234),
                    path_epoch: 4,
                },
            },
            ControlFrame {
                transaction_id: 5,
                message: ControlMessage::PathDetach {
                    session_id: session(),
                    path_id: PathId::new(1),
                    path_epoch: 4,
                    reason: "lost link".into(),
                },
            },
            ControlFrame {
                transaction_id: 6,
                message: ControlMessage::PathHealth {
                    session_id: session(),
                    path_id: PathId::new(1),
                    path_epoch: 4,
                    rtt_ms: 0x0102_0304,
                    loss_ppm: 5,
                },
            },
            ControlFrame {
                transaction_id: 7,
                message: ControlMessage::PolicyUpdate {
                    session_id: session(),
                    policy_epoch: 8,
                    policy: Bytes::from_static(b"safe-mode"),
                },
            },
            ControlFrame {
                transaction_id: 8,
                message: ControlMessage::Close {
                    session_id: session(),
                    reason: "operator request".into(),
                },
            },
            ControlFrame {
                transaction_id: 9,
                message: ControlMessage::Ack,
            },
            ControlFrame {
                transaction_id: 10,
                message: ControlMessage::Reject {
                    code: RejectCode::StaleEpoch,
                    reason: "stale".into(),
                },
            },
        ];

        for frame in frames {
            let wire = frame.encode(ControlFrameLimit::default()).unwrap();
            assert_eq!(ControlFrame::decode(&wire, ControlFrameLimit::default()).unwrap(), frame);
        }

        let wire = ControlFrame {
            transaction_id: 0x0102_0304_0506_0708,
            message: ControlMessage::PathHealth {
                session_id: session(),
                path_id: PathId::new(0x1234),
                path_epoch: 0x0102_0304_0506_0708,
                rtt_ms: 0x1112_1314,
                loss_ppm: 0x1516_1718,
            },
        }
        .encode(ControlFrameLimit::default())
        .unwrap();
        assert_eq!(&wire[4..12], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&wire[16 + 16..16 + 18], &[0x12, 0x34]);
        assert_eq!(&wire[16 + 18..16 + 26], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn decoder_rejects_exact_framing_and_identifier_errors() {
        let valid = client_hello().encode(ControlFrameLimit::default()).unwrap();
        assert_eq!(
            ControlFrame::decode(&valid[..15], ControlFrameLimit::default()),
            Err(ControlCodecError::TruncatedHeader)
        );

        for (offset, value, expected) in [
            (0, 1, ControlCodecError::UnsupportedVersion(1)),
            (1, 1, ControlCodecError::ReservedByte(1)),
            (3, 1, ControlCodecError::ReservedByte(1)),
            (2, 0xff, ControlCodecError::UnknownKind(0xff)),
        ] {
            let mut malformed = valid.to_vec();
            malformed[offset] = value;
            assert_eq!(ControlFrame::decode(&malformed, ControlFrameLimit::default()), Err(expected));
        }

        let mut zero_transaction = valid.to_vec();
        zero_transaction[4..12].fill(0);
        assert_eq!(
            ControlFrame::decode(&zero_transaction, ControlFrameLimit::default()),
            Err(ControlCodecError::ZeroTransactionId)
        );

        let mut zero_device = valid.to_vec();
        zero_device[16..32].fill(0);
        assert_eq!(
            ControlFrame::decode(&zero_device, ControlFrameLimit::default()),
            Err(ControlCodecError::InvalidField("device ID"))
        );

        assert_eq!(
            ControlFrame::decode(&valid[..valid.len() - 1], ControlFrameLimit::default()),
            Err(ControlCodecError::TruncatedFrame {
                declared: valid.len(),
                actual: valid.len() - 1,
            })
        );
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert_eq!(
            ControlFrame::decode(&trailing, ControlFrameLimit::default()),
            Err(ControlCodecError::TrailingData {
                declared: valid.len(),
                actual: valid.len() + 1,
            })
        );
        assert_eq!(
            ControlFrame::decode(&valid, ControlFrameLimit::new(valid.len() - 1)),
            Err(ControlCodecError::FrameTooLarge {
                length: valid.len(),
                limit: valid.len() - 1,
            })
        );
    }

    #[test]
    fn decoder_rejects_message_trailing_data_before_allocating_message_fields() {
        let mut wire = client_hello().encode(ControlFrameLimit::default()).unwrap().to_vec();
        let declared = u32::from_be_bytes(wire[12..16].try_into().unwrap()) + 1;
        wire[12..16].copy_from_slice(&declared.to_be_bytes());
        wire.push(0);
        assert_eq!(
            ControlFrame::decode(&wire, ControlFrameLimit::default()),
            Err(ControlCodecError::TrailingData {
                declared: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn ticket_debug_is_redacted() {
        let ticket = AdmissionTicket::new("do-not-log".into()).unwrap();
        let debug = format!("{ticket:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("do-not-log"));
        assert!(!format!("{:?}", client_hello()).contains("private-ticket"));
    }

    #[test]
    fn session_admit_requires_assigned_prefixes_and_bounded_safe_mode_policy() {
        assert_eq!(
            SafeModePolicy::new(Bytes::new()),
            Err(ControlCodecError::InvalidField("safe mode policy"))
        );
        assert!(matches!(
            SafeModePolicy::new(Bytes::from(vec![0; MAX_SAFE_MODE_POLICY_LEN + 1])),
            Err(ControlCodecError::FieldTooLong {
                field: "safe mode policy",
                ..
            })
        ));
        let invalid = ControlFrame {
            transaction_id: 1,
            message: ControlMessage::SessionAdmit {
                session_id: session(),
                expires_at_ms: 1,
                policy_epoch: 1,
                assigned_ipv4: [0; 4],
                assigned_ipv4_prefix_len: 24,
                assigned_ipv6_prefix: [0x20; 16],
                assigned_ipv6_prefix_len: 64,
                safe_mode_policy: SafeModePolicy::new(Bytes::from_static(b"safe-mode")).unwrap(),
            },
        };
        assert_eq!(
            invalid.encode(ControlFrameLimit::default()),
            Err(ControlCodecError::InvalidField("assigned IPv4"))
        );
    }
}
