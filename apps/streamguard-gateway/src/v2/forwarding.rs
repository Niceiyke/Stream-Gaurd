//! Bounded V2 uplink source validation (REBUILD WP-400).
//!
//! Every client→gateway IP packet is parsed and bound to the session's
//! allocated lease **before** any TUN/NAT forwarding. Only
//! [`ValidatedUplink`] — constructible solely via
//! [`UplinkForwarder::validate`] — may be forwarded, so spoofed sources can
//! never reach the host stack. V1 forwarding (`tunnel.rs`) is untouched.
//!
//! # Validation order (fail closed, no state before parsing)
//!
//! 1. Length: empty and over-`maximum_packet_bytes` packets are dropped as
//!    parse errors before any header read.
//! 2. Strict IP parse: version nibble, IPv4 IHL/total-length, IPv6
//!    payload-length, and source extraction. No ports are read, so fragments
//!    are safe (WP-401 owns the fragment/port policy for the flow table).
//! 3. Lease bind: the session must hold a pool lease (`UnknownSession`
//!    otherwise, counted as spoof), the source must equal the leased IPv4 or
//!    fall inside the leased IPv6 `/64`, and the source must not be the
//!    gateway address itself.
//!
//! # Bounds
//!
//! No collections, queues, or tasks. Only bounded atomic counters.
//! Payload bytes travel as [`bytes::Bytes`]; validation never logs packet
//! contents.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use sg_core::v2::SessionId;
use thiserror::Error;

use super::address_pool::AddressPool;

/// Smallest decodable IP packet (IPv4 header without options).
const MIN_PACKET_BYTES: usize = 20;
/// Smallest IPv6 packet (fixed 40-byte header, possibly zero payload).
const MIN_IPV6_BYTES: usize = 40;
/// Hard upper bound for any uplink packet passed to validation.
const MAX_PACKET_BYTES_HARD_CAP: usize = 65_535;

/// Parsed uplink source. The forwarder compares this against the session's
/// lease; it never carries ports or payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSource {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpSource {
    #[must_use]
    pub const fn is_v4(self) -> bool {
        matches!(self, Self::V4(_))
    }

    #[must_use]
    pub const fn is_v6(self) -> bool {
        matches!(self, Self::V6(_))
    }
}

/// Sealed, validated uplink. Fields are private so only
/// [`UplinkForwarder::validate`] can construct it; forwarding entry points
/// take this type, never raw bytes plus a session. `Debug` reports lengths
/// only, never packet contents.
pub struct ValidatedUplink {
    session_id: SessionId,
    source: IpSource,
    packet: Bytes,
}

impl ValidatedUplink {
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn source(&self) -> IpSource {
        self.source
    }

    #[must_use]
    pub fn packet(&self) -> &Bytes {
        &self.packet
    }

    #[must_use]
    pub fn into_packet(self) -> Bytes {
        self.packet
    }

    #[must_use]
    pub fn packet_len(&self) -> usize {
        self.packet.len()
    }
}

impl std::fmt::Debug for ValidatedUplink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedUplink")
            .field("packet_len", &self.packet.len())
            .field("is_v4", &self.source.is_v4())
            .finish()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ForwardError {
    #[error("uplink packet is empty")]
    Empty,
    #[error("uplink packet exceeds the configured maximum")]
    TooLarge,
    #[error("uplink packet is truncated")]
    Truncated,
    #[error("uplink IP header is invalid")]
    InvalidHeader,
    #[error("uplink IP length is invalid")]
    InvalidLength,
    #[error("uplink IP version is unknown")]
    UnknownVersion,
    #[error("uplink IP source is invalid")]
    InvalidSource,
    #[error("uplink session holds no address lease")]
    UnknownSession,
    #[error("uplink source is not allocated to this session")]
    SourceMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwarderSnapshot {
    pub validated: u64,
    pub parse_dropped: u64,
    pub spoof_dropped: u64,
    pub maximum_packet_bytes: usize,
}

#[derive(Default)]
struct ForwarderMetrics {
    validated: AtomicU64,
    parse_dropped: AtomicU64,
    spoof_dropped: AtomicU64,
}

/// Validates uplink sources against the bounded address pool.
pub struct UplinkForwarder {
    pool: Arc<AddressPool>,
    maximum_packet_bytes: usize,
    metrics: ForwarderMetrics,
}

impl std::fmt::Debug for UplinkForwarder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UplinkForwarder(REDACTED)")
    }
}

impl UplinkForwarder {
    /// Builds a forwarder. `maximum_packet_bytes` must cover the smallest
    /// IPv6 packet (`1280`) and never exceed the IP hard cap (`65535`).
    pub fn new(pool: Arc<AddressPool>, maximum_packet_bytes: usize) -> Result<Self, ForwardError> {
        if !(1280..=MAX_PACKET_BYTES_HARD_CAP).contains(&maximum_packet_bytes) {
            return Err(ForwardError::InvalidLength);
        }
        Ok(Self {
            pool,
            maximum_packet_bytes,
            metrics: ForwarderMetrics::default(),
        })
    }

    /// Parses `packet`, binds its source to `session_id`'s committed Active
    /// lease, and seals the result. Reserved (pre-commit) leases never
    /// authorize payload: a client must complete `reserve -> session commit ->
    /// lease commit -> SessionAdmit` before its source validates. Any failure
    /// drops the packet before forwarding and counts it as parse- or
    /// spoof-dropped. Never logs packet contents.
    pub fn validate(&self, session_id: SessionId, packet: Bytes) -> Result<ValidatedUplink, ForwardError> {
        let source = self.parse_source(&packet)?;
        let lease = self.pool.lookup_active(session_id).ok_or_else(|| {
            self.metrics.spoof_dropped.fetch_add(1, Ordering::Relaxed);
            ForwardError::UnknownSession
        })?;
        let gateway = self.pool.config().ipv4_gateway();
        match source {
            IpSource::V4(src) => {
                if src == [0, 0, 0, 0] || src == gateway || src != lease.ipv4 {
                    self.metrics.spoof_dropped.fetch_add(1, Ordering::Relaxed);
                    return Err(ForwardError::SourceMismatch);
                }
            }
            IpSource::V6(src) => {
                if src.iter().all(|byte| *byte == 0) {
                    self.metrics.spoof_dropped.fetch_add(1, Ordering::Relaxed);
                    return Err(ForwardError::InvalidSource);
                }
                if src[0..8] != lease.ipv6_prefix[0..8] {
                    self.metrics.spoof_dropped.fetch_add(1, Ordering::Relaxed);
                    return Err(ForwardError::SourceMismatch);
                }
            }
        }
        self.metrics.validated.fetch_add(1, Ordering::Relaxed);
        Ok(ValidatedUplink {
            session_id,
            source,
            packet,
            // `_sealed` removed: privacy comes from private fields; this
            // struct literal is only constructible inside this module.
        })
    }

    /// Parses only the IP source. Length and framing are validated before any
    /// pool or session state is consulted.
    fn parse_source(&self, packet: &[u8]) -> Result<IpSource, ForwardError> {
        if packet.is_empty() {
            self.metrics.parse_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(ForwardError::Empty);
        }
        if packet.len() > self.maximum_packet_bytes {
            self.metrics.parse_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(ForwardError::TooLarge);
        }
        let version = packet[0] >> 4;
        let result = match version {
            4 => parse_ipv4_source(packet),
            6 => parse_ipv6_source(packet),
            _ => Err(ForwardError::UnknownVersion),
        };
        if result.is_err() {
            self.metrics.parse_dropped.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    #[must_use]
    pub fn snapshot(&self) -> ForwarderSnapshot {
        ForwarderSnapshot {
            validated: self.metrics.validated.load(Ordering::Relaxed),
            parse_dropped: self.metrics.parse_dropped.load(Ordering::Relaxed),
            spoof_dropped: self.metrics.spoof_dropped.load(Ordering::Relaxed),
            maximum_packet_bytes: self.maximum_packet_bytes,
        }
    }

    #[must_use]
    pub fn pool(&self) -> &Arc<AddressPool> {
        &self.pool
    }
}

/// Sealed V2 uplink egress: the only forwarding entry point.
///
/// The sink accepts solely [`ValidatedUplink`] — constructible only inside
/// this module via [`UplinkForwarder::validate`] — so no caller can forward
/// raw `Bytes` plus a session, replay a spoofed source, or bypass the lease
/// bind. It has no V1 TUN, flow-table, or NAT dependency: it seals the
/// validated packet for the single future TUN/NAT egress (WP-401/WP-402 own
/// the flow table and host wiring) and counts it with bounded atomics. No
/// collections, queues, tasks, or payload logging.
///
/// Usage: `let validated = forwarder.validate(session, packet)?;`
/// `sink.submit(validated);` — the returned [`ForwardedUplink`] carries the
/// session, source, and packet the egress must write.
pub struct V2ForwardingSink {
    metrics: SinkMetrics,
}

#[derive(Default)]
struct SinkMetrics {
    forwarded: AtomicU64,
    bytes_forwarded: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkSnapshot {
    pub forwarded: u64,
    pub bytes_forwarded: u64,
}

/// Validated packet released by the sealed sink for the single TUN/NAT
/// egress. `Debug` reports lengths only, never packet contents.
pub struct ForwardedUplink {
    session_id: SessionId,
    source: IpSource,
    packet: Bytes,
}

impl ForwardedUplink {
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn source(&self) -> IpSource {
        self.source
    }

    #[must_use]
    pub fn packet(&self) -> &Bytes {
        &self.packet
    }

    #[must_use]
    pub fn into_packet(self) -> Bytes {
        self.packet
    }

    #[must_use]
    pub fn packet_len(&self) -> usize {
        self.packet.len()
    }
}

impl std::fmt::Debug for ForwardedUplink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForwardedUplink")
            .field("packet_len", &self.packet.len())
            .field("is_v4", &self.source.is_v4())
            .finish()
    }
}

impl std::fmt::Debug for V2ForwardingSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2ForwardingSink(REDACTED)")
    }
}

impl V2ForwardingSink {
    #[must_use]
    pub fn new() -> Self {
        Self {
            metrics: SinkMetrics::default(),
        }
    }

    /// Forwards one sealed uplink to the egress. This is the only path from a
    /// validated client packet to the host stack; there is no `Bytes`-taking
    /// overload by construction.
    #[must_use]
    pub fn submit(&self, validated: ValidatedUplink) -> ForwardedUplink {
        let packet_len = validated.packet_len() as u64;
        self.metrics.forwarded.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_forwarded
            .fetch_add(packet_len, Ordering::Relaxed);
        ForwardedUplink {
            session_id: validated.session_id,
            source: validated.source,
            packet: validated.packet,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> SinkSnapshot {
        SinkSnapshot {
            forwarded: self.metrics.forwarded.load(Ordering::Relaxed),
            bytes_forwarded: self.metrics.bytes_forwarded.load(Ordering::Relaxed),
        }
    }
}

impl Default for V2ForwardingSink {
    fn default() -> Self {
        Self::new()
    }
}

/// Sealed TUN/NAT egress contract for the single host-stack handoff
/// (WP-400 → WP-401/WP-402).
///
/// The contract accepts solely [`ValidatedUplink`] — constructible only via
/// [`UplinkForwarder::validate`] inside this module — so no TUN, NAT, flow
/// table, or future egress implementation can accept raw `Bytes` plus a
/// session and bypass the lease bind. Implementations must forward the
/// sealed packet without re-parsing untrusted headers and without logging
/// packet contents. `V2ForwardingSink` is the reference implementation;
/// WP-401/WP-402 host wiring must implement this trait rather than adding a
/// `Bytes`-taking write path.
pub trait V2TunNatEgress: Send + Sync + std::fmt::Debug {
    /// Forwards one sealed, source-validated uplink to the TUN/NAT egress.
    /// This is the only egress entry point by construction: there is no
    /// `Bytes`-taking overload.
    fn emit_validated(&self, validated: ValidatedUplink) -> ForwardedUplink;
    /// Bounded egress counters (forwarded packets/bytes). No payload data.
    fn egress_snapshot(&self) -> SinkSnapshot;
}

impl V2TunNatEgress for V2ForwardingSink {
    fn emit_validated(&self, validated: ValidatedUplink) -> ForwardedUplink {
        self.submit(validated)
    }

    fn egress_snapshot(&self) -> SinkSnapshot {
        self.snapshot()
    }
}

fn parse_ipv4_source(packet: &[u8]) -> Result<IpSource, ForwardError> {
    if packet.len() < MIN_PACKET_BYTES {
        return Err(ForwardError::Truncated);
    }
    let ihl_bytes = ((packet[0] & 0x0F) as usize).saturating_mul(4);
    if ihl_bytes < MIN_PACKET_BYTES {
        return Err(ForwardError::InvalidHeader);
    }
    if packet.len() < ihl_bytes {
        return Err(ForwardError::Truncated);
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl_bytes {
        return Err(ForwardError::InvalidLength);
    }
    if total_len != packet.len() {
        return Err(ForwardError::InvalidLength);
    }
    let mut src = [0u8; 4];
    src.copy_from_slice(&packet[12..16]);
    if src == [0, 0, 0, 0] {
        return Err(ForwardError::InvalidSource);
    }
    Ok(IpSource::V4(src))
}

fn parse_ipv6_source(packet: &[u8]) -> Result<IpSource, ForwardError> {
    if packet.len() < MIN_IPV6_BYTES {
        return Err(ForwardError::Truncated);
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if MIN_IPV6_BYTES.saturating_add(payload_len) != packet.len() {
        return Err(ForwardError::InvalidLength);
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    if src.iter().all(|byte| *byte == 0) {
        return Err(ForwardError::InvalidSource);
    }
    Ok(IpSource::V6(src))
}

/// Builds a minimal IPv4 packet with the given source for tests.
#[cfg(test)]
pub(crate) fn test_ipv4_packet(src: [u8; 4], dst: [u8; 4]) -> Bytes {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    Bytes::from(packet)
}

/// Builds a minimal IPv6 packet with the given source for tests.
#[cfg(test)]
pub(crate) fn test_ipv6_packet(src: [u8; 16], dst: [u8; 16]) -> Bytes {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&0u16.to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src);
    packet[24..40].copy_from_slice(&dst);
    Bytes::from(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::address_pool::{AddressPool, AddressPoolConfig};
    use sg_core::v2::DeviceId;

    fn pool_with_two() -> (Arc<AddressPool>, sg_core::v2::SessionId, AssignedLease) {
        let config = AddressPoolConfig::new(
            [10, 64, 0, 0],
            24,
            [10, 64, 0, 1],
            vec![],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            48,
            4,
            5_000,
            60_000,
            4,
        )
        .unwrap();
        let pool = Arc::new(AddressPool::new(config).unwrap());
        let session = sg_core::v2::SessionId::from_bytes([7; 16]);
        let device = DeviceId::from_bytes([8; 16]);
        let lease = pool.reserve(session, device, 1_000).unwrap();
        pool.commit(session, 1_000).unwrap();
        (pool, session, AssignedLease(lease))
    }

    struct AssignedLease(super::super::address_pool::AssignedAddresses);

    #[test]
    fn valid_ipv4_and_ipv6_uplinks_pass_sealed_validation() {
        let (pool, session, lease) = pool_with_two();
        let forwarder = UplinkForwarder::new(pool, 1_500).unwrap();
        let v4 = test_ipv4_packet(lease.0.ipv4, [8, 8, 8, 8]);
        let validated = forwarder.validate(session, v4.clone()).unwrap();
        assert_eq!(validated.session_id(), session);
        assert_eq!(validated.source(), IpSource::V4(lease.0.ipv4));
        assert_eq!(validated.packet(), &v4);
        let mut v6_src = [0u8; 16];
        v6_src[0..8].copy_from_slice(&lease.0.ipv6_prefix[0..8]);
        v6_src[15] = 0x42;
        let v6 = test_ipv6_packet(v6_src, [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let validated_v6 = forwarder.validate(session, v6.clone()).unwrap();
        assert_eq!(validated_v6.source(), IpSource::V6(v6_src));
        let snapshot = forwarder.snapshot();
        assert_eq!(snapshot.validated, 2);
        assert_eq!(snapshot.parse_dropped, 0);
        assert_eq!(snapshot.spoof_dropped, 0);
    }

    #[test]
    fn spoofed_sources_are_dropped_before_forwarding() {
        let (pool, session, lease) = pool_with_two();
        let other_session = sg_core::v2::SessionId::from_bytes([9; 16]);
        let other_device = DeviceId::from_bytes([10; 16]);
        let other_lease = pool.reserve(other_session, other_device, 1_000).unwrap();
        pool.commit(other_session, 1_000).unwrap();
        let forwarder = UplinkForwarder::new(pool, 1_500).unwrap();
        // Cross-session IPv4 spoof.
        assert!(matches!(
            forwarder.validate(session, test_ipv4_packet(other_lease.ipv4, [8, 8, 8, 8])),
            Err(ForwardError::SourceMismatch)
        ));
        // Gateway IPv4 spoof.
        assert!(matches!(
            forwarder.validate(session, test_ipv4_packet([10, 64, 0, 1], [8, 8, 8, 8])),
            Err(ForwardError::SourceMismatch)
        ));
        // IPv6 outside the leased /64.
        let mut outside = [0u8; 16];
        outside[0..8].copy_from_slice(&other_lease.ipv6_prefix[0..8]);
        outside[15] = 0x99;
        assert!(matches!(
            forwarder.validate(session, test_ipv6_packet(outside, [0x20; 16])),
            Err(ForwardError::SourceMismatch)
        ));
        // Unknown session (no lease) is also a spoof drop.
        let unknown = sg_core::v2::SessionId::from_bytes([77; 16]);
        assert!(matches!(
            forwarder.validate(unknown, test_ipv4_packet(lease.0.ipv4, [8, 8, 8, 8])),
            Err(ForwardError::UnknownSession)
        ));
        let snapshot = forwarder.snapshot();
        assert_eq!(snapshot.validated, 0);
        assert_eq!(snapshot.spoof_dropped, 4);
        assert_eq!(snapshot.parse_dropped, 0);
    }

    #[test]
    fn malformed_packets_are_parse_dropped_without_state_lookup() {
        let (pool, session, _) = pool_with_two();
        let forwarder = UplinkForwarder::new(pool, 1_500).unwrap();
        assert!(matches!(forwarder.validate(session, Bytes::new()), Err(ForwardError::Empty)));
        assert!(matches!(
            forwarder.validate(session, Bytes::from(vec![0x40; 8])),
            Err(ForwardError::Truncated)
        ));
        let mut bad_version = test_ipv4_packet([10, 64, 0, 2], [8, 8, 8, 8]).to_vec();
        bad_version[0] = 0x70;
        assert!(matches!(
            forwarder.validate(session, Bytes::from(bad_version)),
            Err(ForwardError::UnknownVersion)
        ));
        let mut bad_len = test_ipv4_packet([10, 64, 0, 2], [8, 8, 8, 8]).to_vec();
        bad_len[2..4].copy_from_slice(&30u16.to_be_bytes());
        assert!(matches!(
            forwarder.validate(session, Bytes::from(bad_len)),
            Err(ForwardError::InvalidLength)
        ));
        let oversized = Bytes::from(vec![0x45; 1_501]);
        assert!(matches!(forwarder.validate(session, oversized), Err(ForwardError::TooLarge)));
        let snapshot = forwarder.snapshot();
        assert_eq!(snapshot.parse_dropped, 5);
        assert_eq!(snapshot.spoof_dropped, 0);
    }

    #[test]
    fn invalid_forwarder_config_is_rejected() {
        let config = AddressPoolConfig::new(
            [10, 64, 0, 0],
            24,
            [10, 64, 0, 1],
            vec![],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            48,
            2,
            5_000,
            60_000,
            2,
        )
        .unwrap();
        let pool = Arc::new(AddressPool::new(config).unwrap());
        assert!(UplinkForwarder::new(pool.clone(), 64).is_err());
        assert!(UplinkForwarder::new(pool, 70_000).is_err());
    }

    #[test]
    fn validated_uplink_debug_never_includes_payload_contents() {
        let (pool, session, lease) = pool_with_two();
        let forwarder = UplinkForwarder::new(pool, 1_500).unwrap();
        let validated = forwarder.validate(session, test_ipv4_packet(lease.0.ipv4, [8, 8, 8, 8])).unwrap();
        let debug = format!("{validated:?}");
        assert!(debug.contains("packet_len"));
        assert!(!debug.contains("8, 8, 8, 8"));
    }

    #[test]
    fn reserved_lease_never_authorizes_payload() {
        // A Reserved (pre-commit) lease must fail as UnknownSession, not as
        // SourceMismatch: the validator requires the Active commit that only
        // happens after the session commits and before SessionAdmit is
        // written. This closes the pre-admission payload window.
        let config = AddressPoolConfig::new(
            [10, 64, 0, 0],
            24,
            [10, 64, 0, 1],
            vec![],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            48,
            4,
            5_000,
            60_000,
            4,
        )
        .unwrap();
        let pool = Arc::new(AddressPool::new(config).unwrap());
        let session = sg_core::v2::SessionId::from_bytes([21; 16]);
        let device = DeviceId::from_bytes([22; 16]);
        let reserved = pool.reserve(session, device, 1_000).unwrap();
        let forwarder = UplinkForwarder::new(Arc::clone(&pool), 1_500).unwrap();
        assert!(matches!(
            forwarder.validate(session, test_ipv4_packet(reserved.ipv4, [8, 8, 8, 8])),
            Err(ForwardError::UnknownSession)
        ));
        assert_eq!(forwarder.snapshot().spoof_dropped, 1);
        assert_eq!(forwarder.snapshot().validated, 0);
        pool.commit(session, 1_000).unwrap();
        assert!(forwarder.validate(session, test_ipv4_packet(reserved.ipv4, [8, 8, 8, 8])).is_ok());
    }

    #[test]
    fn sealed_sink_only_forwards_validated_uplinks() {
        // The sealed sink takes `ValidatedUplink` by value: there is no
        // `Bytes`-taking overload, so spoofed or malformed packets can never
        // reach it (validation fails first). The sink counts the single
        // egress and never logs packet contents.
        let (pool, session, lease) = pool_with_two();
        let forwarder = UplinkForwarder::new(pool, 1_500).unwrap();
        let sink = V2ForwardingSink::new();
        let validated = forwarder
            .validate(session, test_ipv4_packet(lease.0.ipv4, [8, 8, 8, 8]))
            .unwrap();
        let packet_len = validated.packet_len();
        let session_id = validated.session_id();
        let source = validated.source();
        let forwarded = sink.submit(validated);
        assert_eq!(forwarded.session_id(), session_id);
        assert_eq!(forwarded.source(), source);
        assert_eq!(forwarded.packet_len(), packet_len);
        assert_eq!(forwarded.packet().len(), packet_len);
        let snapshot = sink.snapshot();
        assert_eq!(snapshot.forwarded, 1);
        assert_eq!(snapshot.bytes_forwarded, packet_len as u64);
        let debug = format!("{forwarded:?}");
        assert!(debug.contains("packet_len"));
        assert!(!debug.contains("8, 8, 8, 8"));
        // A spoofed source never becomes a `ValidatedUplink`, so the sink
        // count cannot advance for it: validation fails before `submit` is
        // reachable.
        let unknown = sg_core::v2::SessionId::from_bytes([77; 16]);
        assert!(forwarder.validate(unknown, test_ipv4_packet(lease.0.ipv4, [8, 8, 8, 8])).is_err());
        assert_eq!(sink.snapshot().forwarded, 1, "failed validation must not reach the sink");
    }

    #[test]
    fn sink_default_matches_new_and_counts_bytes() {
        let (pool, session, lease) = pool_with_two();
        let forwarder = UplinkForwarder::new(pool, 1_500).unwrap();
        let sink = V2ForwardingSink::default();
        assert_eq!(sink.snapshot(), SinkSnapshot { forwarded: 0, bytes_forwarded: 0 });
        for _ in 0..2 {
            let validated = forwarder
                .validate(session, test_ipv4_packet(lease.0.ipv4, [8, 8, 8, 8]))
                .unwrap();
            let len = validated.packet_len() as u64;
            let _ = sink.submit(validated);
            let _ = len;
        }
        assert_eq!(sink.snapshot().forwarded, 2);
        assert_eq!(sink.snapshot().bytes_forwarded, 40);
    }
}
