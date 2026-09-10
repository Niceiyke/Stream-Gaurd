//! Strict, bounded IP classifier producing a stable flow ID and traffic class.
//!
//! The classifier is a pure function over the received TUN bytes. It parses
//! IPv4 (RFC 791) and IPv6 (RFC 8200) headers with explicit bounds checks and
//! never panics on attacker-controlled input. Fragments never expose transport
//! ports: only the initial fragment's ports are read, and every other
//! fragment is classified conservatively without port bytes.
//!
//! Declared-length slicing: IPv4 is sliced to its declared total length and
//! IPv6 to `40 + payload length` before any L4 or fragment-extension reads.
//! Trailing bytes beyond the declared length are ignored so they can never
//! influence flow hashing or scheduling priority.
//!
//! Flow IDs are deterministic FNV-1a hashes over the network-layer identity
//! actually observed on the wire. Traffic classes are a conservative product
//! default: TCP is bulk (TCP remains the ultimate recovery protocol), UDP is
//! realtime, ICMP/ICMPv6 is interactive, and anything fragmented or unknown
//! is bulk. Later policy work (WP-601/WP-602) may refine this mapping without
//! changing the parsing guarantees.
//!
//! Metrics count packets by outcome only. They never store payloads,
//! addresses, ports, or destination history.

use sg_core::v2::{FlowId, TrafficClass};
use thiserror::Error;

/// Result of classifying one TUN packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Classification {
    /// Stable flow identity for dedup/reorder keying.
    pub flow_id: FlowId,
    /// Scheduling class for deadline selection.
    pub traffic_class: TrafficClass,
}

/// Why a TUN packet could not be classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClassifyError {
    /// No bytes to inspect.
    #[error("packet is empty")]
    Empty,
    /// Header claims more bytes than are present.
    #[error("packet is truncated")]
    Truncated,
    /// First nibble is neither 4 nor 6.
    #[error("packet is not IPv4 or IPv6")]
    NotIp,
    /// Header fields are structurally invalid (bad IHL, bad lengths).
    #[error("IP header is invalid")]
    InvalidHeader,
}

/// Aggregate classifier outcomes. Counts only; no packet content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClassifierMetrics {
    /// Packets successfully classified.
    pub classified: u64,
    /// Classified packets that were fragments.
    pub fragments: u64,
    /// Packets dropped as empty/truncated.
    pub truncated_dropped: u64,
    /// Packets dropped as non-IP or invalid headers.
    pub invalid_dropped: u64,
}

/// Stateful classifier that counts outcomes without retaining packets.
#[derive(Debug, Default)]
pub struct Classifier {
    metrics: ClassifierMetrics,
}

impl Classifier {
    /// Creates an empty classifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classifies one packet and records the outcome in [`Self::metrics`].
    pub fn classify(&mut self, packet: &[u8]) -> Result<Classification, ClassifyError> {
        match classify_packet(packet) {
            Ok(classification) => {
                self.metrics.classified = self.metrics.classified.saturating_add(1);
                if is_fragment(packet) {
                    self.metrics.fragments = self.metrics.fragments.saturating_add(1);
                }
                Ok(classification)
            }
            Err(error) => {
                match error {
                    ClassifyError::Empty | ClassifyError::Truncated => {
                        self.metrics.truncated_dropped =
                            self.metrics.truncated_dropped.saturating_add(1);
                    }
                    ClassifyError::NotIp | ClassifyError::InvalidHeader => {
                        self.metrics.invalid_dropped =
                            self.metrics.invalid_dropped.saturating_add(1);
                    }
                }
                Err(error)
            }
        }
    }

    /// Current outcome counts.
    #[must_use]
    pub const fn metrics(&self) -> ClassifierMetrics {
        self.metrics
    }
}

/// Stateless classification without metrics.
pub fn classify_packet(packet: &[u8]) -> Result<Classification, ClassifyError> {
    let first = *packet.first().ok_or(ClassifyError::Empty)?;
    match first >> 4 {
        4 => classify_ipv4(packet),
        6 => classify_ipv6(packet),
        _ => Err(ClassifyError::NotIp),
    }
}

fn is_fragment(packet: &[u8]) -> bool {
    let Some(first) = packet.first() else {
        return false;
    };
    match first >> 4 {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let ihl_words = packet[0] & 0x0F;
            if ihl_words < 5 {
                return false;
            }
            let header_len = usize::from(ihl_words).saturating_mul(4);
            if header_len > packet.len() {
                return false;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total_len < header_len || total_len > packet.len() {
                return false;
            }
            // Slice to the declared total length so trailing bytes beyond the
            // IP datagram can never influence the fragment decision.
            let packet = &packet[..total_len];
            if packet.len() < 8 {
                return false;
            }
            let flags_offset =
                u16::from_be_bytes([*packet.get(6).unwrap_or(&0), *packet.get(7).unwrap_or(&0)]);
            flags_offset & 0x3FFF != 0 || flags_offset & 0x2000 != 0
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if payload_len.saturating_add(40) > packet.len() {
                return false;
            }
            packet.len() >= 7 && *packet.get(6).unwrap_or(&0) == 44
        }
        _ => false,
    }
}

fn classify_ipv4(packet: &[u8]) -> Result<Classification, ClassifyError> {
    if packet.len() < 20 {
        return Err(ClassifyError::Truncated);
    }
    let ihl_words = packet[0] & 0x0F;
    if ihl_words < 5 {
        return Err(ClassifyError::InvalidHeader);
    }
    let header_len = usize::from(ihl_words).saturating_mul(4);
    if header_len > packet.len() {
        return Err(ClassifyError::Truncated);
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len {
        return Err(ClassifyError::InvalidHeader);
    }
    if total_len > packet.len() {
        return Err(ClassifyError::Truncated);
    }
    // Slice to the declared total length before any L4 or fragment reads so
    // trailing bytes beyond the datagram are ignored (spec: validated
    // envelope limits; no trailing-data influence on flow identity).
    let packet = &packet[..total_len];
    let protocol = packet[9];
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    let more_fragments = flags_offset & 0x2000 != 0;
    let fragment_offset = flags_offset & 0x1FFF;
    let identification = u16::from_be_bytes([packet[4], packet[5]]);
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(packet.get(12..16).ok_or(ClassifyError::Truncated)?);
    dst.copy_from_slice(packet.get(16..20).ok_or(ClassifyError::Truncated)?);

    // Secure fragment policy: never read ports from a non-initial fragment.
    // Every fragment is conservatively bulk so reassembly pressure cannot
    // upgrade scheduling priority.
    if more_fragments || fragment_offset != 0 {
        return Ok(Classification {
            flow_id: hash_flow(&[4, protocol], &src, &dst, None, Some(identification), true),
            traffic_class: TrafficClass::Bulk,
        });
    }

    let ports = transport_ports(packet, header_len, protocol, 1);
    Ok(Classification {
        flow_id: hash_flow(&[4, protocol], &src, &dst, ports, None, false),
        traffic_class: class_for_protocol(protocol),
    })
}

fn classify_ipv6(packet: &[u8]) -> Result<Classification, ClassifyError> {
    if packet.len() < 40 {
        return Err(ClassifyError::Truncated);
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if payload_len.saturating_add(40) > packet.len() {
        return Err(ClassifyError::Truncated);
    }
    // Slice to the declared payload extent before any L4 or fragment
    // extension reads; trailing bytes beyond the datagram are ignored.
    let packet = &packet[..40usize.saturating_add(payload_len)];
    let next_header = packet[6];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(packet.get(8..24).ok_or(ClassifyError::Truncated)?);
    dst.copy_from_slice(packet.get(24..40).ok_or(ClassifyError::Truncated)?);

    // IPv6 fragment extension header (next header 44): never chase ports.
    if next_header == 44 {
        if packet.len() < 48 {
            return Err(ClassifyError::Truncated);
        }
        let identification = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]);
        return Ok(Classification {
            flow_id: hash_flow(&[6, next_header], &src, &dst, None, None, true)
                .combine(identification),
            traffic_class: TrafficClass::Bulk,
        });
    }
    // Other extension headers (hop-by-hop, routing, dest opts): do not chase
    // the chain; classify conservatively without ports.
    if matches!(next_header, 0 | 43 | 60) {
        return Ok(Classification {
            flow_id: hash_flow(&[6, next_header], &src, &dst, None, None, false),
            traffic_class: TrafficClass::Bulk,
        });
    }

    let ports = transport_ports(packet, 40, next_header, 58);
    Ok(Classification {
        flow_id: hash_flow(&[6, next_header], &src, &dst, ports, None, false),
        traffic_class: class_for_protocol(next_header),
    })
}

/// Reads transport identity only when enough bytes are present and the packet
/// is not a fragment. Returns `(src_port_or_id, dst_port)` or `None` when the
/// header is absent. Never panics: every index is bounds-checked.
fn transport_ports(
    packet: &[u8],
    header_len: usize,
    protocol: u8,
    icmp_protocol: u8,
) -> Option<(u16, u16)> {
    match protocol {
        6 | 17 => {
            let base = packet.get(header_len..header_len.saturating_add(4))?;
            Some((
                u16::from_be_bytes([base[0], base[1]]),
                u16::from_be_bytes([base[2], base[3]]),
            ))
        }
        proto if proto == icmp_protocol => {
            // ICMP echo identity is the 2-byte identifier after type/code/csum.
            let base = packet.get(header_len..header_len.saturating_add(6))?;
            if base.len() < 6 {
                return None;
            }
            Some((u16::from_be_bytes([base[4], base[5]]), 0))
        }
        _ => None,
    }
}

fn class_for_protocol(protocol: u8) -> TrafficClass {
    match protocol {
        // TCP recovers itself; it tolerates the largest reorder budget.
        6 => TrafficClass::Bulk,
        // UDP carries latency-sensitive media; protect it first.
        17 => TrafficClass::Realtime,
        // ICMP echo and errors are operator signals, not bulk transfer.
        1 | 58 => TrafficClass::Interactive,
        _ => TrafficClass::Bulk,
    }
}

fn hash_flow(
    prefix: &[u8],
    src: &[u8],
    dst: &[u8],
    ports: Option<(u16, u16)>,
    ip_id: Option<u16>,
    fragmented: bool,
) -> FlowId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    let mut mix = |byte: u8| {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    };
    for byte in prefix {
        mix(*byte);
    }
    mix(u8::from(fragmented));
    for byte in src {
        mix(*byte);
    }
    for byte in dst {
        mix(*byte);
    }
    match ports {
        Some((a, b)) => {
            for byte in a.to_be_bytes().into_iter().chain(b.to_be_bytes()) {
                mix(byte);
            }
        }
        None => {
            mix(0xF0);
        }
    }
    match ip_id {
        Some(id) => {
            for byte in id.to_be_bytes() {
                mix(byte);
            }
        }
        None => {
            mix(0x0D);
        }
    }
    FlowId::new(hash)
}

trait Combine {
    fn combine(self, value: u32) -> Self;
}

impl Combine for FlowId {
    fn combine(self, value: u32) -> Self {
        let mut hash = self.get();
        for byte in value.to_be_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        FlowId::new(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp() -> Vec<u8> {
        // 20-byte IPv4 + 4-byte ports, no fragmentation.
        vec![
            0x45, 0x00, 0x00, 0x1C, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0,
            1, 10, 0, 0, 2, 0x1F, 0x90, 0x00, 0x50, 0xAA, 0xBB, 0xCC, 0xDD,
        ]
    }

    fn ipv4_udp() -> Vec<u8> {
        let mut packet = ipv4_tcp();
        packet[9] = 17;
        packet
    }

    fn ipv6_udp() -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = 17;
        packet[8..12].copy_from_slice(&[0x20, 0x01, 0x0D, 0xB8]);
        packet[24..28].copy_from_slice(&[0x20, 0x01, 0x0D, 0xB9]);
        packet[40..42].copy_from_slice(&1234u16.to_be_bytes());
        packet[42..44].copy_from_slice(&5678u16.to_be_bytes());
        packet
    }

    #[test]
    fn ipv4_protocols_map_to_stable_classes() {
        let tcp = classify_packet(&ipv4_tcp()).unwrap();
        assert_eq!(tcp.traffic_class, TrafficClass::Bulk);
        let udp = classify_packet(&ipv4_udp()).unwrap();
        assert_eq!(udp.traffic_class, TrafficClass::Realtime);
        assert_ne!(tcp.flow_id, udp.flow_id);
        // Deterministic: same bytes hash the same way.
        assert_eq!(classify_packet(&ipv4_tcp()).unwrap(), tcp);
    }

    #[test]
    fn ports_distinguish_flows_without_logging_addresses() {
        let mut a = ipv4_tcp();
        let mut b = ipv4_tcp();
        b[22..24].copy_from_slice(&9999u16.to_be_bytes());
        let fa = classify_packet(&a).unwrap();
        let fb = classify_packet(&b).unwrap();
        assert_ne!(fa.flow_id, fb.flow_id);
        a[15] = 9;
        assert_ne!(classify_packet(&a).unwrap().flow_id, fa.flow_id);
        let debug = format!("{:?}", Classifier::new().metrics());
        assert!(!debug.contains("10.0.0"));
    }

    #[test]
    fn ipv4_fragments_never_read_ports_and_stay_bulk() {
        // Non-initial fragment: offset 1, ports region overwritten with junk.
        let mut fragment = ipv4_tcp();
        fragment[6] = 0x20;
        fragment[7] = 0x01;
        for byte in fragment.iter_mut().skip(20) {
            *byte = 0xFF;
        }
        let classified = classify_packet(&fragment).unwrap();
        assert_eq!(classified.traffic_class, TrafficClass::Bulk);
        // Initial fragment with MF set is also conservative bulk.
        let mut initial = ipv4_tcp();
        initial[6] = 0x20;
        initial[7] = 0x00;
        assert_eq!(
            classify_packet(&initial).unwrap().traffic_class,
            TrafficClass::Bulk
        );
    }

    #[test]
    fn ipv6_udp_and_fragments_behave_strictly() {
        let udp = classify_packet(&ipv6_udp()).unwrap();
        assert_eq!(udp.traffic_class, TrafficClass::Realtime);
        let mut fragment = ipv6_udp();
        fragment[6] = 44;
        fragment.resize(48, 0);
        fragment[44..48].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let classified = classify_packet(&fragment).unwrap();
        assert_eq!(classified.traffic_class, TrafficClass::Bulk);
        assert_ne!(classified.flow_id, udp.flow_id);
    }

    #[test]
    fn truncated_and_non_ip_inputs_are_rejected_without_panic() {
        assert_eq!(classify_packet(&[]), Err(ClassifyError::Empty));
        assert_eq!(classify_packet(&[0x45]), Err(ClassifyError::Truncated));
        assert_eq!(classify_packet(&[0x70; 24]), Err(ClassifyError::NotIp));
        assert_eq!(classify_packet(&[0x44; 24]), Err(ClassifyError::InvalidHeader));
        // Fuzz sweep: no input length panics.
        let mut state = 0x1234_5678_9ABCu64;
        for len in 0..160 {
            let mut packet = vec![0u8; len];
            for byte in &mut packet {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = (state & 0xFF) as u8;
            }
            let _ = classify_packet(&packet);
        }
    }

    #[test]
    fn metrics_count_only_outcomes() {
        let mut classifier = Classifier::new();
        let _ = classifier.classify(&ipv4_tcp());
        let _ = classifier.classify(&[]);
        let _ = classifier.classify(&[0x70; 24]);
        let metrics = classifier.metrics();
        assert_eq!(metrics.classified, 1);
        assert_eq!(metrics.truncated_dropped, 1);
        assert_eq!(metrics.invalid_dropped, 1);
        let debug = format!("{metrics:?}");
        assert!(!debug.contains("10.0.0"));
    }

    #[test]
    fn ipv4_trailing_beyond_total_is_ignored() {
        // Declared total 28 with 12 trailing bytes that look like ports must
        // classify identically to the 28-byte datagram alone.
        let base = ipv4_tcp();
        assert_eq!(u16::from_be_bytes([base[2], base[3]]) as usize, base.len());
        let mut trailing = base.clone();
        trailing.extend_from_slice(&[0xFF, 0xEE, 0xDD, 0xCC, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(
            classify_packet(&trailing).unwrap(),
            classify_packet(&base).unwrap(),
            "trailing beyond IPv4 total length must not influence classification"
        );
        // Header-only datagram (total 20, no L4) with 4 trailing bytes that
        // mimic ports must hash as header-only, not as a ported flow.
        let mut header_only = base[..20].to_vec();
        header_only[2..4].copy_from_slice(&20u16.to_be_bytes());
        let header_class = classify_packet(&header_only).unwrap();
        let mut with_trailing = header_only.clone();
        with_trailing.extend_from_slice(&[0x1F, 0x90, 0x00, 0x50]);
        assert_eq!(
            classify_packet(&with_trailing).unwrap(),
            header_class,
            "L4 reads must stay inside the declared IPv4 total length"
        );
        assert_ne!(
            header_class,
            classify_packet(&base).unwrap(),
            "header-only flow differs from the ported flow"
        );
    }

    #[test]
    fn ipv6_trailing_beyond_payload_is_ignored() {
        let base = ipv6_udp();
        let mut trailing = base.clone();
        trailing.extend_from_slice(&[0xAA; 16]);
        assert_eq!(
            classify_packet(&trailing).unwrap(),
            classify_packet(&base).unwrap(),
            "trailing beyond IPv6 payload length must not influence classification"
        );
        // Zero-length UDP payload with trailing port-like bytes must hash as
        // portless (declared payload has no L4 bytes).
        let mut header_only = vec![0u8; 40];
        header_only[0] = 0x60;
        header_only[4..6].copy_from_slice(&0u16.to_be_bytes());
        header_only[6] = 17;
        header_only[8..12].copy_from_slice(&[0x20, 0x01, 0x0D, 0xB8]);
        header_only[24..28].copy_from_slice(&[0x20, 0x01, 0x0D, 0xB9]);
        let header_class = classify_packet(&header_only).unwrap();
        let mut with_trailing = header_only.clone();
        with_trailing.extend_from_slice(&[0x04, 0xD2, 0x16, 0x2E]);
        assert_eq!(
            classify_packet(&with_trailing).unwrap(),
            header_class,
            "L4 reads must stay inside the declared IPv6 payload length"
        );
        assert_ne!(
            header_class,
            classify_packet(&base).unwrap(),
            "portless IPv6 flow differs from the ported flow"
        );
    }

    #[test]
    fn ipv6_fragment_header_needs_declared_payload() {
        // Next header 44 with declared payload 0 but 8 trailing bytes that
        // look like a fragment header must be truncated, not a fragment:
        // the declared datagram has no room for the 8-byte frag header.
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&0u16.to_be_bytes());
        packet[6] = 44;
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(packet.len(), 48);
        assert_eq!(
            classify_packet(&packet),
            Err(ClassifyError::Truncated),
            "fragment identification must be inside the declared payload"
        );
    }
}
