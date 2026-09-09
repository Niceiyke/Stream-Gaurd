//! V2 controller-issued admission tickets.
//!
//! This module only verifies compact, controller-signed EdDSA JWTs. Production
//! code cannot mint tickets from this crate.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sg_core::v2::{DeviceId, SessionId};
use thiserror::Error;

use crate::device::AdmissionTicketValidator;

/// Limits are intentionally below the V2 control-frame ticket bound so JWT
/// parsing stays independently bounded before JSON deserialization.
pub const MAX_COMPACT_TICKET_LEN: usize = 2 * 1024;
pub const MAX_HEADER_SEGMENT_LEN: usize = 512;
pub const MAX_CLAIMS_SEGMENT_LEN: usize = 1536;
pub const MAX_SIGNATURE_SEGMENT_LEN: usize = 512;
pub const MAX_KEY_ID_LEN: usize = 64;
pub const MAX_ISSUER_LEN: usize = 128;
pub const MAX_AUDIENCE_LEN: usize = 128;
pub const MAX_REGION_LEN: usize = 32;
pub const MAX_ALLOWED_REGIONS: usize = 16;
pub const MAX_TRUST_KEYS: usize = 32;
pub const MAX_REVOKED_TICKETS: usize = 4096;
pub const MAX_TICKET_LIFETIME_SECONDS: u64 = 15 * 60;
/// A consumed ticket remains unavailable slightly past `exp` for clock skew.
pub const REPLAY_EXPIRY_SKEW_SECONDS: u64 = 30;

/// A canonical 16-byte identifier represented in JWTs as lowercase UUID text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TicketId([u8; 16]);

/// A canonical 16-byte organization identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrganizationId([u8; 16]);

impl TicketId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl OrganizationId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for TicketId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TicketId(REDACTED)")
    }
}

impl fmt::Debug for OrganizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OrganizationId(REDACTED)")
    }
}

/// A single controller verification key. `public_key_x` is the base64url JWK
/// `x` coordinate for an Ed25519 public key, not PEM or private key material.
pub struct ControllerPublicKey {
    key_id: String,
    public_key_x: String,
}

impl ControllerPublicKey {
    pub fn new(key_id: String, public_key_x: String) -> Result<Self, TicketVerificationError> {
        if !valid_key_id(&key_id) || public_key_x.is_empty() || public_key_x.len() > 128 || !is_base64url(&public_key_x) {
            return Err(TicketVerificationError::InvalidTrustSnapshot);
        }
        Ok(Self { key_id, public_key_x })
    }
}

impl fmt::Debug for ControllerPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControllerPublicKey(REDACTED)")
    }
}

/// Immutable controller state supplied by the controller synchronization
/// layer. The gateway never fetches or refreshes it while admitting a peer.
pub struct ControllerTrustSnapshot {
    keys: BTreeMap<String, DecodingKey>,
    revoked_ticket_ids: HashSet<TicketId>,
    fresh_until_unix_seconds: u64,
}

impl ControllerTrustSnapshot {
    pub fn new(
        keys: Vec<ControllerPublicKey>,
        revoked_ticket_ids: Vec<TicketId>,
        fresh_until_unix_seconds: u64,
    ) -> Result<Self, TicketVerificationError> {
        if keys.is_empty()
            || keys.len() > MAX_TRUST_KEYS
            || revoked_ticket_ids.len() > MAX_REVOKED_TICKETS
            || fresh_until_unix_seconds == 0
        {
            return Err(TicketVerificationError::InvalidTrustSnapshot);
        }

        let mut decoded_keys = BTreeMap::new();
        for key in keys {
            let decoding_key = DecodingKey::from_ed_components(&key.public_key_x)
                .map_err(|_| TicketVerificationError::InvalidTrustSnapshot)?;
            if decoded_keys.insert(key.key_id, decoding_key).is_some() {
                return Err(TicketVerificationError::InvalidTrustSnapshot);
            }
        }

        let revoked_ticket_ids = revoked_ticket_ids.into_iter().collect::<HashSet<_>>();
        Ok(Self { keys: decoded_keys, revoked_ticket_ids, fresh_until_unix_seconds })
    }

    #[must_use]
    pub fn availability(&self, now_unix_seconds: u64) -> ControllerTrustAvailability {
        if now_unix_seconds >= self.fresh_until_unix_seconds {
            ControllerTrustAvailability::Stale
        } else {
            ControllerTrustAvailability::Fresh
        }
    }

    #[must_use]
    pub fn is_revoked(&self, ticket_id: TicketId) -> bool {
        self.revoked_ticket_ids.contains(&ticket_id)
    }

    fn key(&self, key_id: &str) -> Option<&DecodingKey> {
        self.keys.get(key_id)
    }
}

/// Reports controller synchronization state without attempting a fetch. New
/// admission is permitted only while the supplied snapshot is fresh.
#[must_use]
pub fn controller_trust_availability(
    trust: Option<&ControllerTrustSnapshot>,
    now_unix_seconds: u64,
) -> ControllerTrustAvailability {
    trust.map_or(ControllerTrustAvailability::Missing, |snapshot| {
        snapshot.availability(now_unix_seconds)
    })
}

impl fmt::Debug for ControllerTrustSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControllerTrustSnapshot(REDACTED)")
    }
}

/// The controller synchronization state presented to admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerTrustAvailability {
    Fresh,
    Missing,
    Stale,
}

/// V2 policy for controller outages is intentionally fixed: no stale or
/// absent trust snapshot can authorize a new session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerUnavailablePolicy {
    FailClosed,
}

/// Verifier configuration pinned by the gateway deployment configuration.
pub struct TicketVerifier {
    issuer: String,
    audience: String,
    current_region: String,
}

impl TicketVerifier {
    pub fn new(
        issuer: String,
        audience: String,
        current_region: String,
    ) -> Result<Self, TicketVerificationError> {
        if !valid_text(&issuer, MAX_ISSUER_LEN)
            || !valid_text(&audience, MAX_AUDIENCE_LEN)
            || !valid_region(&current_region)
        {
            return Err(TicketVerificationError::InvalidConfiguration);
        }
        Ok(Self { issuer, audience, current_region })
    }

    /// Verifies a bounded controller JWT and binds all device identities.
    pub fn verify(
        &self,
        ticket: &str,
        trust: Option<&ControllerTrustSnapshot>,
        now_unix_seconds: u64,
        verified_device: DeviceId,
        client_hello_device: DeviceId,
    ) -> Result<VerifiedAdmissionTicket, TicketVerificationError> {
        if verified_device != client_hello_device {
            return Err(TicketVerificationError::DeviceIdentityMismatch);
        }
        if controller_trust_availability(trust, now_unix_seconds) != ControllerTrustAvailability::Fresh {
            return Err(TicketVerificationError::ControllerUnavailable);
        }
        let trust = trust.ok_or(TicketVerificationError::ControllerUnavailable)?;

        validate_compact_bounds(ticket)?;
        let header = decode_header(ticket).map_err(|_| TicketVerificationError::MalformedTicket)?;
        if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some("JWT") {
            return Err(TicketVerificationError::InvalidHeader);
        }
        let key_id = header.kid.as_deref().ok_or(TicketVerificationError::InvalidHeader)?;
        if !valid_key_id(key_id) {
            return Err(TicketVerificationError::InvalidHeader);
        }
        let key = trust
            .key(key_id)
            .ok_or(TicketVerificationError::UnknownSigningKey)?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 0;
        // jsonwebtoken validates against the host clock. Admission receives an
        // explicit gateway clock so deterministic callers can apply the same
        // strict no-skew lifetime policy below.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);
        let claims = decode::<WireClaims>(ticket, key, &validation)
            .map_err(|_| TicketVerificationError::InvalidSignatureOrClaims)?
            .claims;

        let ticket_id = parse_identifier(&claims.jti).ok_or(TicketVerificationError::InvalidClaims)?;
        let device_id = parse_identifier(&claims.device).ok_or(TicketVerificationError::InvalidClaims)?;
        let organization_id = parse_identifier(&claims.organization).ok_or(TicketVerificationError::InvalidClaims)?;
        let session_id = parse_identifier(&claims.session).ok_or(TicketVerificationError::InvalidClaims)?;
        let nonce = parse_identifier(&claims.nonce).ok_or(TicketVerificationError::InvalidClaims)?;
        if device_id != *verified_device.as_bytes()
            || claims.iss != self.issuer
            || claims.aud != self.audience
            || claims.policy_version == 0
            || claims.iat > now_unix_seconds
            || claims.exp <= now_unix_seconds
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > MAX_TICKET_LIFETIME_SECONDS
            || claims.regions.is_empty()
            || claims.regions.len() > MAX_ALLOWED_REGIONS
            || claims.regions.iter().any(|region| !valid_region(region))
            || !claims.regions.iter().any(|region| region == &self.current_region)
        {
            return Err(TicketVerificationError::InvalidClaims);
        }
        if trust.is_revoked(TicketId(ticket_id)) {
            return Err(TicketVerificationError::Revoked);
        }

        // Parsing nonce proves its canonical 128-bit form even though it is not
        // retained after admission; it is controller-side correlation only.
        let _ = nonce;
        Ok(VerifiedAdmissionTicket {
            ticket_id: TicketId(ticket_id),
            device_id: DeviceId::from_bytes(device_id),
            organization_id: OrganizationId(organization_id),
            session_id: SessionId::from_bytes(session_id),
            expires_at_unix_seconds: claims.exp,
            policy_version: claims.policy_version,
        })
    }
}

impl fmt::Debug for TicketVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TicketVerifier(REDACTED)")
    }
}

/// The only ticket representation available after successful cryptographic
/// and identity validation. It has no public constructor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAdmissionTicket {
    ticket_id: TicketId,
    device_id: DeviceId,
    organization_id: OrganizationId,
    session_id: SessionId,
    expires_at_unix_seconds: u64,
    policy_version: u64,
}

impl VerifiedAdmissionTicket {
    #[must_use]
    pub fn ticket_id(&self) -> TicketId {
        self.ticket_id
    }

    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    #[must_use]
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }
}

impl fmt::Debug for VerifiedAdmissionTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedAdmissionTicket(REDACTED)")
    }
}

/// Errors intentionally carry no compact token, claims, key ID, or key data.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TicketVerificationError {
    #[error("V2 ticket verifier configuration is invalid")]
    InvalidConfiguration,
    #[error("V2 controller trust snapshot is invalid")]
    InvalidTrustSnapshot,
    #[error("V2 controller trust is unavailable")]
    ControllerUnavailable,
    #[error("V2 ticket is malformed")]
    MalformedTicket,
    #[error("V2 ticket header is invalid")]
    InvalidHeader,
    #[error("V2 ticket signing key is unavailable")]
    UnknownSigningKey,
    #[error("V2 ticket signature or claims are invalid")]
    InvalidSignatureOrClaims,
    #[error("V2 ticket claims are invalid")]
    InvalidClaims,
    #[error("V2 ticket device identity does not match mTLS")]
    DeviceIdentityMismatch,
    #[error("V2 ticket is revoked")]
    Revoked,
}

impl AdmissionTicketValidator for TicketVerifier {
    fn validate(
        &self,
        ticket: &str,
        trust: Option<&ControllerTrustSnapshot>,
        now_unix_seconds: u64,
        verified_device: DeviceId,
        client_hello_device: DeviceId,
    ) -> Result<VerifiedAdmissionTicket, TicketVerificationError> {
        self.verify(ticket, trust, now_unix_seconds, verified_device, client_hello_device)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireClaims {
    jti: String,
    iss: String,
    aud: String,
    device: String,
    organization: String,
    session: String,
    iat: u64,
    exp: u64,
    policy_version: u64,
    regions: Vec<String>,
    nonce: String,
}

fn validate_compact_bounds(ticket: &str) -> Result<(), TicketVerificationError> {
    if ticket.is_empty() || ticket.len() > MAX_COMPACT_TICKET_LEN || !ticket.is_ascii() {
        return Err(TicketVerificationError::MalformedTicket);
    }
    let segments = ticket.split('.').collect::<Vec<_>>();
    if segments.len() != 3
        || segments[0].is_empty()
        || segments[1].is_empty()
        || segments[2].is_empty()
        || segments[0].len() > MAX_HEADER_SEGMENT_LEN
        || segments[1].len() > MAX_CLAIMS_SEGMENT_LEN
        || segments[2].len() > MAX_SIGNATURE_SEGMENT_LEN
        || segments.iter().any(|segment| !is_base64url(segment))
    {
        return Err(TicketVerificationError::MalformedTicket);
    }
    Ok(())
}

fn valid_key_id(value: &str) -> bool {
    valid_text(value, MAX_KEY_ID_LEN)
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_region(value: &str) -> bool {
    valid_text(value, MAX_REGION_LEN)
        && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.is_ascii()
}

fn is_base64url(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn parse_identifier(value: &str) -> Option<[u8; 16]> {
    if value.len() != 36 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    let mut source = value.bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) && source.next()? != b'-' {
            return None;
        }
        let high = hex(source.next()?)?;
        let low = hex(source.next()?)?;
        *byte = (high << 4) | low;
    }
    if source.next().is_some() {
        return None;
    }
    Some(bytes)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims {
        jti: String,
        iss: String,
        aud: String,
        device: String,
        organization: String,
        session: String,
        iat: u64,
        exp: u64,
        policy_version: u64,
        regions: Vec<String>,
        nonce: String,
    }

    struct TestAuthority {
        encoding_key: EncodingKey,
        public_key_x: String,
    }

    fn authority() -> TestAuthority {
        let key_bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let encoding_key = EncodingKey::from_ed_der(key_bytes.as_ref());
        let key_pair = Ed25519KeyPair::from_pkcs8(key_bytes.as_ref()).unwrap();
        TestAuthority {
            encoding_key,
            public_key_x: base64url(key_pair.public_key().as_ref()),
        }
    }

    fn base64url(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let first = chunk[0] as u32;
            let second = chunk.get(1).copied().unwrap_or(0) as u32;
            let third = chunk.get(2).copied().unwrap_or(0) as u32;
            output.push(TABLE[(first >> 2) as usize] as char);
            output.push(TABLE[(((first & 3) << 4) | (second >> 4)) as usize] as char);
            if chunk.len() > 1 {
                output.push(TABLE[(((second & 15) << 2) | (third >> 6)) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(TABLE[(third & 63) as usize] as char);
            }
        }
        output
    }

    fn identifier(byte: u8) -> String {
        format!("{byte:02x}{byte:02x}{byte:02x}{byte:02x}-{byte:02x}{byte:02x}-{byte:02x}{byte:02x}-{byte:02x}{byte:02x}-{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}")
    }

    fn claims(now: u64) -> TestClaims {
        TestClaims {
            jti: identifier(1),
            iss: "controller.example".into(),
            aud: "gateway-group-a".into(),
            device: identifier(2),
            organization: identifier(3),
            session: identifier(4),
            iat: now - 1,
            exp: now + 60,
            policy_version: 1,
            regions: vec!["us-east-1".into()],
            nonce: identifier(5),
        }
    }

    fn token(authority: &TestAuthority, claims: &TestClaims) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("controller-1".into());
        encode(&header, claims, &authority.encoding_key).unwrap()
    }

    fn verifier(authority: &TestAuthority, now: u64) -> (TicketVerifier, ControllerTrustSnapshot) {
        (
            TicketVerifier::new("controller.example".into(), "gateway-group-a".into(), "us-east-1".into()).unwrap(),
            ControllerTrustSnapshot::new(
                vec![ControllerPublicKey::new("controller-1".into(), authority.public_key_x.clone()).unwrap()],
                vec![],
                now + 1,
            )
            .unwrap(),
        )
    }

    #[test]
    fn valid_ticket_binds_every_identity_and_redacts_debug() {
        let now = 1_000;
        let authority = authority();
        let (verifier, trust) = verifier(&authority, now);
        let ticket = token(&authority, &claims(now));
        let verified = verifier
            .verify(&ticket, Some(&trust), now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16]))
            .unwrap();
        assert_eq!(verified.session_id(), SessionId::from_bytes([4; 16]));
        assert_eq!(verified.organization_id().as_bytes(), [3; 16]);
        assert!(format!("{verified:?}").contains("REDACTED"));
        assert!(!format!("{trust:?}").contains(&authority.public_key_x));
    }

    #[test]
    fn rejects_invalid_claims_and_identity_bindings() {
        let now = 1_000;
        let authority = authority();
        let (verifier, trust) = verifier(&authority, now);
        let mut invalid = claims(now);
        invalid.policy_version = 0;
        for ticket in [
            token(&authority, &invalid),
            token(&authority, &TestClaims { iss: "other".into(), ..claims(now) }),
            token(&authority, &TestClaims { aud: "other".into(), ..claims(now) }),
            token(&authority, &TestClaims { regions: vec!["other-region".into()], ..claims(now) }),
            token(&authority, &TestClaims { iat: now + 1, ..claims(now) }),
            token(&authority, &TestClaims { exp: now, ..claims(now) }),
            token(&authority, &TestClaims { nonce: "not-an-id".into(), ..claims(now) }),
        ] {
            assert!(verifier.verify(&ticket, Some(&trust), now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16])).is_err());
        }
        let ticket = token(&authority, &claims(now));
        assert_eq!(
            verifier.verify(&ticket, Some(&trust), now, DeviceId::from_bytes([9; 16]), DeviceId::from_bytes([2; 16])),
            Err(TicketVerificationError::DeviceIdentityMismatch)
        );
        assert_eq!(
            verifier.verify(&ticket, Some(&trust), now, DeviceId::from_bytes([9; 16]), DeviceId::from_bytes([9; 16])),
            Err(TicketVerificationError::InvalidClaims)
        );
    }

    #[test]
    fn rejects_unavailable_stale_revoked_and_bad_headers_or_signatures() {
        let now = 1_000;
        let authority = authority();
        let (verifier, trust) = verifier(&authority, now);
        let ticket = token(&authority, &claims(now));
        assert_eq!(
            verifier.verify(&ticket, None, now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16])),
            Err(TicketVerificationError::ControllerUnavailable)
        );
        let stale = ControllerTrustSnapshot::new(
            vec![ControllerPublicKey::new("controller-1".into(), authority.public_key_x.clone()).unwrap()],
            vec![],
            now,
        )
        .unwrap();
        assert_eq!(
            verifier.verify(&ticket, Some(&stale), now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16])),
            Err(TicketVerificationError::ControllerUnavailable)
        );
        let revoked = ControllerTrustSnapshot::new(
            vec![ControllerPublicKey::new("controller-1".into(), authority.public_key_x.clone()).unwrap()],
            vec![TicketId([1; 16])],
            now + 1,
        )
        .unwrap();
        assert_eq!(
            verifier.verify(&ticket, Some(&revoked), now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16])),
            Err(TicketVerificationError::Revoked)
        );
        let mut altered = ticket.clone().into_bytes();
        let last = altered.len() - 1;
        altered[last] = if altered[last] == b'a' { b'b' } else { b'a' };
        assert!(verifier.verify(std::str::from_utf8(&altered).unwrap(), Some(&trust), now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16])).is_err());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("controller-1".into());
        let wrong_algorithm = encode(&header, &claims(now), &EncodingKey::from_secret(b"not-a-controller-key")).unwrap();
        assert_eq!(
            verifier.verify(&wrong_algorithm, Some(&trust), now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16])),
            Err(TicketVerificationError::InvalidHeader)
        );
        assert!(!format!("{:?}", TicketVerificationError::InvalidClaims).contains(&ticket));
    }

    #[test]
    fn canonical_identifiers_and_bounds_are_strict() {
        assert_eq!(parse_identifier("01010101-0101-0101-0101-010101010101"), Some([1; 16]));
        for invalid in ["01010101-0101-0101-0101-01010101010A", "01010101010101010101010101010101", ""] {
            assert_eq!(parse_identifier(invalid), None);
        }
        assert_eq!(validate_compact_bounds("a.b.c"), Ok(()));
        assert_eq!(validate_compact_bounds("a.b.c.d"), Err(TicketVerificationError::MalformedTicket));
    }

    #[test]
    fn rejects_each_missing_required_claim_and_header_key_errors() {
        let now = 1_000;
        let authority = authority();
        let (verifier, trust) = verifier(&authority, now);
        let claim_value = serde_json::to_value(claims(now)).unwrap();
        for claim in [
            "jti", "iss", "aud", "device", "organization", "session", "iat", "exp", "policy_version", "regions", "nonce",
        ] {
            let mut missing = claim_value.clone();
            missing.as_object_mut().unwrap().remove(claim);
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("controller-1".into());
            let ticket = encode(&header, &missing, &authority.encoding_key).unwrap();
            assert!(verifier.verify(&ticket, Some(&trust), now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16])).is_err());
        }
        let ticket = token(&authority, &claims(now));
        let mut unknown_key_header = Header::new(Algorithm::EdDSA);
        unknown_key_header.kid = Some("other-key".into());
        let unknown_key = encode(&unknown_key_header, &claims(now), &authority.encoding_key).unwrap();
        assert_eq!(
            verifier.verify(&unknown_key, Some(&trust), now, DeviceId::from_bytes([2; 16]), DeviceId::from_bytes([2; 16])),
            Err(TicketVerificationError::UnknownSigningKey)
        );
        assert!(ticket.len() <= MAX_COMPACT_TICKET_LEN);
    }

}
