//! StreamGuard gateway authentication (spec 15.5, engineering step 8).
//!
//! The bootstrap handshake lets a client bind a new physical path to a
//! session by presenting a signed bearer token. Tokens are HS256 JWTs
//! (compact format) minted by the gateway / control plane:
//!
//! ```text
//! header.payload.signature
//!   header   = {"alg":"HS256","typ":"JWT"}
//!   payload  = {"sid":"<8 hex chars, first 4 uuid bytes>","iat":...,"exp":...}
//!   signature = HMAC-SHA256(secret, "header.payload") base64url-nopad
//! ```
//!
//! The `sid` claim carries the same 4-byte wire prefix the envelope puts on
//! the line (spec 11.1), so a verified token binds exactly the `SessionId`
//! the gateway demultiplexes on.
//!
//! mTLS client-certificate authentication (the transport-level half of the
//! design) is a follow-up milestone; `sg_transport::quic::server_tls` still
//! uses `with_no_client_auth`.

/// V2 device identity, TLS trust, and admission-validation contracts.
///
/// This module is separate from the V1 HS256 compatibility code below. V2
/// callers must use mutual TLS and the validator-only admission seam.
pub mod device;

use ring::hmac::{HMAC_SHA256, Key as HmacKey, sign as hmac_sign, verify as hmac_verify};
use sg_core::error::{Error, Result};
use sg_core::SessionId;

const HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

/// Issues an HS256 bearer token for `session_id`, valid for `ttl_secs`.
pub fn issue(secret: &[u8], session_id: SessionId, ttl_secs: u64) -> String {
    let now = unix_now();
    let sid = wire_prefix_hex(session_id);
    let payload = format!(
        r#"{{"sid":"{sid}","iat":{now},"exp":{}}}"#,
        now.saturating_add(ttl_secs)
    );
    let header = base64url_nopad(HEADER.as_bytes());
    let body = base64url_nopad(payload.as_bytes());
    let signing_input = format!("{header}.{body}");
    let key = HmacKey::new(HMAC_SHA256, secret);
    let tag = hmac_sign(&key, signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        base64url_nopad(tag.as_ref())
    )
}

/// Verifies `token` against `secret` and returns the bound session id.
///
/// Fails on wrong signature, malformed structure, wrong header algorithm,
/// an expired `exp`, or a missing/invalid `sid` claim.
pub fn verify(token: &str, secret: &[u8]) -> Result<SessionId> {
    let mut parts = token.split('.');
    let header = parts.next().ok_or_else(|| Error::auth("missing token header"))?;
    let body = parts.next().ok_or_else(|| Error::auth("missing token payload"))?;
    let sig = parts
        .next()
        .ok_or_else(|| Error::auth("missing token signature"))?;
    if parts.next().is_some() {
        return Err(Error::auth("token has too many segments"));
    }

    // Constant-time signature check over the raw signing input.
    let decoded_sig = base64url_nopad_decode(sig)
        .ok_or_else(|| Error::auth("signature is not base64url"))?;
    let key = HmacKey::new(HMAC_SHA256, secret);
    hmac_verify(&key, format!("{header}.{body}").as_bytes(), &decoded_sig)
        .map_err(|_| Error::auth("bad signature"))?;

    // Header must claim HS256.
    let header_text = base64url_nopad_decode(header).ok_or_else(|| Error::auth("header is not base64url"))?;
    let header_text = String::from_utf8_lossy(&header_text);
    if !header_text.contains("HS256") {
        return Err(Error::auth(format!("unexpected header {header_text}")));
    }

    let body_text = base64url_nopad_decode(body)
        .ok_or_else(|| Error::auth("payload is not base64url"))?;
    let payload = parse_claims(&body_text)?;
    if payload.exp <= unix_now() {
        return Err(Error::auth("token expired"));
    }
    Ok(SessionId::from_bytes(wire_prefix_from_hex(&payload.sid)?))
}

struct Claims {
    sid: String,
    exp: u64,
}

fn parse_claims(raw: &[u8]) -> Result<Claims> {
    let text = String::from_utf8_lossy(raw);
    let sid = extract_str(&text, "sid")
        .ok_or_else(|| Error::auth("claim sid missing"))?;
    let exp = extract_u64(&text, "exp")
        .ok_or_else(|| Error::auth("claim exp missing"))?;
    Ok(Claims { sid: sid.into(), exp })
}

/// Pulls the `"key":"<value>"` JSON string value from a small claims object.
fn extract_str<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":\"");
    let start = text.find(&needle)? + needle.len();
    let end = text[start..].find('"')? + start;
    Some(&text[start..end])
}

/// Pulls the `"key":<number>` JSON integer value from a small claims object.
fn extract_u64(text: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let start = text.find(&needle)? + needle.len();
    let end = text[start..]
        .find(|c: char| !c.is_ascii_digit())
        .map(|i| start + i)
        .unwrap_or(text.len());
    text[start..end].parse().ok()
}

/// First 4 bytes of the session UUID (what the envelope carries), as hex.
fn wire_prefix_hex(id: SessionId) -> String {
    let b = id.as_guid().as_bytes();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_string()
}

/// Rebuilds a wire-safe `SessionId` from the hex `sid` claim value (which
/// is the decimal u32 prefix, kept unambiguous against serde-free parsing).
fn wire_prefix_from_hex(sid: &str) -> Result<[u8; 16]> {
    let prefix: u32 = sid
        .parse()
        .map_err(|_| Error::auth(format!("claim sid not a u32: {sid}")))?;
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&prefix.to_be_bytes());
    Ok(b)
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// RFC 4648 base64url without padding
// ---------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_nopad(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(B64[(b0 >> 2) as usize] as char);
        out.push(B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            out.push(B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() == 3 {
            out.push(B64[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

fn base64url_nopad_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for &c in s.as_bytes() {
        let v = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(prefix: u32) -> SessionId {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&prefix.to_be_bytes());
        SessionId::from_bytes(b)
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let secret = b"unit-test-secret";
        let id = sid(0xde_ad_be_ef);
        let token = issue(secret, id, 60);
        assert_eq!(verify(&token, secret).unwrap(), id);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token = issue(b"one", sid(1), 60);
        assert!(verify(&token, b"two").is_err());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let token = issue(b"secret", sid(7), 60);
        let mut parts: Vec<&str> = token.split('.').collect();
        parts.pop(); // drop the valid signature
        let tampered = format!("{}.QkFCQkFCQkFC", parts.join("."));
        assert!(verify(&tampered, b"secret").is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        // Hand-build a token with an already-past exp and a valid signature.
        let header = base64url_nopad(HEADER.as_bytes());
        let body = base64url_nopad(br#"{"sid":"9","iat":1,"exp":2}"#);
        let signing_input = format!("{header}.{body}");
        let key = HmacKey::new(HMAC_SHA256, b"secret");
        let tag = hmac_sign(&key, signing_input.as_bytes());
        let stale = format!("{signing_input}.{}", base64url_nopad(tag.as_ref()));
        assert!(verify(&stale, b"secret").is_err());
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(verify("", b"secret").is_err());
        assert!(verify("a.b", b"secret").is_err());
        assert!(verify("a.b.c.d", b"secret").is_err());
        assert!(verify("!!!.b.c", b"secret").is_err());
    }

    #[test]
    fn base64url_round_trip() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"token payload with spaces \x00\xff",
        ] {
            let enc = base64url_nopad(data);
            assert_eq!(base64url_nopad_decode(&enc).unwrap(), data);
        }
    }
}
