//! WP-302: MTU dynamic reduction, blackhole, and no-ID/counter-advance netem tests.
//!
//! These tests exercise the interaction between [`sg_transport::mtu`] admission
//! and the deterministic netem harness. The key invariant under test is:
//!
//! **A payload rejected at the MTU admission gate MUST NOT advance the
//! sequencer's packet-ID counter or any delivery metric.**
//!
//! The netem harness supports mid-scenario MTU changes via
//! [`Netem::update_path_mtu`]. Tests use a trivial mock sequencer to track
//! whether `next_sequence` was called; the real sequencer lives in
//! `sg-multipath` and must not be imported here.

use bytes::Bytes;
use sg_core::v2::{FlowId, PacketId, PathId, SessionId, TrafficClass};
use sg_protocol::v2::{Direction, PayloadLimit, V2Envelope, V2Header, FIXED_HEADER_LEN};
use sg_transport::mtu::{
    self, DatagramMtu, MtuEvent, MtuMetrics, MtuRejectReason, PathMtuState,
    SAFE_MODE_MIN_DATAGRAM_MTU, SAFE_MODE_MIN_PAYLOAD_MTU,
};
use streamguard_netem::{
    DirectionalPathProfile, EventKind, FakeTun, GatewayConfig, Netem, NetemConfig,
    PathProfile, PostAdmissionBinding, QueueLimits, ScriptedGateway, SendDropReason,
    SendOutcome, UpdateMtuError,
};

const SESSION: SessionId = SessionId::from_bytes([0xA1; 16]);
const DEVICE: sg_core::v2::DeviceId = sg_core::v2::DeviceId::from_bytes([0xB2; 16]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binding(connection_id: u64, path_id: u16, direction: Direction) -> PostAdmissionBinding {
    PostAdmissionBinding {
        connection_id,
        session_id: SESSION,
        device_id: DEVICE,
        path_id: PathId::new(path_id),
        path_epoch: 7,
        key_epoch: 9,
        direction,
    }
}

fn datagram(binding: PostAdmissionBinding, payload: Bytes) -> Bytes {
    let payload_limit = PayloadLimit::new(payload.len());
    V2Envelope {
        header: V2Header {
            traffic_class: TrafficClass::Interactive,
            direction: binding.direction,
            session_id: binding.session_id,
            path_id: binding.path_id,
            path_epoch: binding.path_epoch,
            key_epoch: binding.key_epoch,
            flow_id: FlowId::new(1),
            packet_id: PacketId::new(2),
        },
        payload,
    }
    .encode(payload_limit)
    .unwrap()
}

fn reliable_profile(datagram_mtu: usize) -> PathProfile {
    PathProfile {
        client_to_gateway: DirectionalPathProfile::reliable(datagram_mtu),
        gateway_to_client: DirectionalPathProfile::reliable(datagram_mtu),
    }
}

fn gateway(bindings: &[PostAdmissionBinding], tun_limits: QueueLimits, datagram_mtu: usize) -> ScriptedGateway {
    let mut gw = ScriptedGateway::new(
        GatewayConfig::default(),
        FakeTun::new(tun_limits, tun_limits),
    );
    for binding in bindings {
        gw.bind_post_admission(*binding, datagram_mtu).unwrap();
    }
    gw
}

fn harness(seed: u64, bindings: &[PostAdmissionBinding], config: NetemConfig, datagram_mtu: usize) -> Netem {
    Netem::new(
        "wp-302-mtu",
        seed,
        config,
        gateway(bindings, QueueLimits::new(16, 4096), datagram_mtu),
    )
    .unwrap()
}

/// A trivial mock sequencer that tracks whether `next_sequence` was called.
/// Tests assert that MTU-rejected payloads never cause a call.
struct MockSequencer {
    next: u64,
    calls: u64,
}

impl MockSequencer {
    fn new(start: u64) -> Self {
        Self {
            next: start,
            calls: 0,
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.calls = self.calls.saturating_add(1);
        id
    }

    fn calls(&self) -> u64 {
        self.calls
    }

    fn current(&self) -> u64 {
        self.next
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn safe_mode_min_datagram_mtu_carries_safe_mode_payload() {
    // The SafeMode minimum whole datagram (1352) must exactly carry the
    // SafeMode payload MTU (1300).
    let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
    let ep = dm.effective_payload();
    assert_eq!(ep.get(), SAFE_MODE_MIN_PAYLOAD_MTU);
    assert_eq!(SAFE_MODE_MIN_DATAGRAM_MTU - FIXED_HEADER_LEN, SAFE_MODE_MIN_PAYLOAD_MTU);
}

#[test]
fn path_mtu_unknown_denies_admission_and_netem_send() {
    // A path in Unknown MTU state must not admit any payload, and the
    // netem harness must drop oversized datagrams.
    let b = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(100, &[b], NetemConfig::default(), FIXED_HEADER_LEN + 10);
    netem
        .add_path(b.path_id, reliable_profile(FIXED_HEADER_LEN + 10))
        .unwrap();

    // State starts Unknown; admission denied.
    let state = PathMtuState::Unknown;
    assert!(state.send_denied());
    assert!(mtu::check_payload(1, &state).is_err());

    // netem send still works (netem checks datagram length, not admission),
    // but a payload that fits the path MTU succeeds on the wire.
    let wire_ok = datagram(b, Bytes::from(vec![0u8; 10]));
    assert!(matches!(
        netem.send_payload(b, wire_ok, None),
        SendOutcome::Queued { .. }
    ));

    // A wire that exceeds the netem path MTU is dropped at the netem layer.
    let wire_big = datagram(b, Bytes::from(vec![0u8; 11]));
    assert!(matches!(
        netem.send_payload(b, wire_big, None),
        SendOutcome::Dropped(SendDropReason::MtuExceeded { .. })
    ));
}

#[test]
fn dynamic_mtu_reduction_rejects_payloads_that_exceeded_new_limit() {
    // Path starts at 1500 datagram MTU (1448 payload). Mid-scenario the
    // MTU is reduced to 1352 (1300 payload). Payloads that were valid
    // before are now rejected at the admission gate.
    let b = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(200, &[b], NetemConfig::default(), 1500);
    let initial_dm = DatagramMtu::new(1500).unwrap();
    netem
        .add_path(b.path_id, reliable_profile(initial_dm.get()))
        .unwrap();

    // Initial state: discover MTU.
    let (mut mtu_state, _) = PathMtuState::Unknown.discover(initial_dm);
    assert!(!mtu_state.send_denied());
    assert!(mtu::check_payload(1448, &mtu_state).is_ok());

    // Admit and send a 1448-byte payload on the netem wire.
    let wire1 = datagram(b, Bytes::from(vec![0u8; 1448]));
    assert!(matches!(
        netem.send_payload(b, wire1, None),
        SendOutcome::Queued { .. }
    ));
    netem.advance_to(0).unwrap();
    assert_eq!(
        netem.gateway_mut().tun_mut().pop_ingress(),
        Some(Bytes::from(vec![0u8; 1448]))
    );

    // Reduce MTU to 1352.
    let new_dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
    netem
        .update_path_mtu(b.path_id, Direction::ClientToGateway, new_dm.get())
        .unwrap();
    let (reduced, event) = mtu_state.reduce(new_dm);
    mtu_state = reduced;
    assert_eq!(
        event,
        MtuEvent::MtuReduced {
            previous: 1500,
            current: SAFE_MODE_MIN_DATAGRAM_MTU
        }
    );

    // 1448-byte payload now exceeds the reduced MTU (1300 effective).
    assert!(mtu::check_payload(1448, &mtu_state).is_err());
    match mtu::check_payload(1448, &mtu_state) {
        Err(MtuRejectReason::PayloadExceedsMtu {
            payload_len,
            effective_mtu,
        }) => {
            assert_eq!(payload_len, 1448);
            assert_eq!(effective_mtu, SAFE_MODE_MIN_PAYLOAD_MTU);
        }
        other => panic!("expected PayloadExceedsMtu, got {other:?}"),
    }

    // 1300-byte payload still fits.
    assert!(mtu::check_payload(SAFE_MODE_MIN_PAYLOAD_MTU, &mtu_state).is_ok());

    // netem rejects a 1448-byte wire datagram on the reduced path.
    let wire2 = datagram(b, Bytes::from(vec![0u8; 1448]));
    assert!(matches!(
        netem.send_payload(b, wire2, None),
        SendOutcome::Dropped(SendDropReason::MtuExceeded {
            datagram_len: 1500,
            mtu: 1352
        })
    ));
}

#[test]
fn mtu_blackhole_denies_all_sends_and_event_is_recorded() {
    let b = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(300, &[b], NetemConfig::default(), SAFE_MODE_MIN_DATAGRAM_MTU);
    netem
        .add_path(b.path_id, reliable_profile(SAFE_MODE_MIN_DATAGRAM_MTU))
        .unwrap();

    let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
    let (mut mtu_state, _) = PathMtuState::Unknown.discover(dm);
    let mut metrics = MtuMetrics::default();

    // Admit a small payload.
    assert!(mtu::admit_payload(100, &mtu_state, &mut metrics).is_ok());
    assert_eq!(metrics.sends_admitted, 1);

    // Transition to blackhole.
    let (bh, event) = mtu_state.blackhole();
    mtu_state = bh;
    assert_eq!(event, MtuEvent::MtuBlackHole);
    metrics.record_event(event);
    assert_eq!(metrics.blackholes_detected, 1);

    // Admission denied.
    assert!(mtu_state.send_denied());
    assert_eq!(
        mtu::check_payload(100, &mtu_state),
        Err(MtuRejectReason::PathMtuBlackHole)
    );
    assert!(mtu::admit_payload(100, &mtu_state, &mut metrics).is_err());
    assert_eq!(metrics.sends_rejected, 1);
}

#[test]
fn no_packet_id_or_counter_advance_on_mtu_rejection() {
    // Core WP-302 invariant: a payload rejected at the MTU admission gate
    // must NOT cause the sequencer's next_id to advance.
    let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
    let (mut mtu_state, _) = PathMtuState::Unknown.discover(dm);
    let mut seq = MockSequencer::new(0);
    let mut metrics = MtuMetrics::default();

    // Admit a valid payload: counter advances.
    let id_before = seq.current();
    let result = mtu::admit_payload(100, &mtu_state, &mut metrics);
    assert!(result.is_ok());
    let _id = seq.next_id();
    assert_eq!(seq.current(), id_before + 1);
    assert_eq!(seq.calls(), 1);

    // Reject an oversized payload: counter MUST NOT advance.
    let id_before = seq.current();
    let result = mtu::admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU + 1, &mtu_state, &mut metrics);
    assert!(result.is_err());
    // No next_id call; current unchanged.
    assert_eq!(seq.current(), id_before);
    assert_eq!(seq.calls(), 1);

    // Reject on Unknown: counter MUST NOT advance.
    let id_before = seq.current();
    let result = mtu::admit_payload(10, &PathMtuState::Unknown, &mut metrics);
    assert!(result.is_err());
    assert_eq!(seq.current(), id_before);
    assert_eq!(seq.calls(), 1);

    // Transition to blackhole, reject: counter MUST NOT advance.
    let (bh, _) = mtu_state.blackhole();
    mtu_state = bh;
    let id_before = seq.current();
    let result = mtu::admit_payload(10, &mtu_state, &mut metrics);
    assert!(result.is_err());
    assert_eq!(seq.current(), id_before);
    assert_eq!(seq.calls(), 1);
}

#[test]
fn mtu_reduction_in_netem_causes_send_drop_and_no_delivered_event() {
    // Full round-trip: discover → send OK → reduce → send dropped → no
    // PayloadDelivered event for the rejected send.
    let b = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(400, &[b], NetemConfig::default(), 1500);
    netem
        .add_path(b.path_id, reliable_profile(1500))
        .unwrap();

    // Phase 1: send a 1448-byte payload at MTU 1500 → delivered.
    let wire1 = datagram(b, Bytes::from(vec![0xAB; 1448]));
    assert!(matches!(
        netem.send_payload(b, wire1, None),
        SendOutcome::Queued { .. }
    ));
    netem.advance_to(0).unwrap();
    assert_eq!(
        netem.gateway_mut().tun_mut().pop_ingress(),
        Some(Bytes::from(vec![0xAB; 1448]))
    );

    // Phase 2: reduce MTU to 1352.
    netem
        .update_path_mtu(b.path_id, Direction::ClientToGateway, SAFE_MODE_MIN_DATAGRAM_MTU)
        .unwrap();

    // Phase 3: send a 1448-byte payload at MTU 1352 → dropped.
    let wire2 = datagram(b, Bytes::from(vec![0xCD; 1448]));
    let outcome = netem.send_payload(b, wire2, None);
    assert!(matches!(
        outcome,
        SendOutcome::Dropped(SendDropReason::MtuExceeded { .. })
    ));
    netem.advance_to(0).unwrap();

    // No payload was delivered for the second send.
    let delivered: Vec<_> = netem
        .events()
        .filter(|e| e.kind == EventKind::PayloadDelivered)
        .collect();
    assert_eq!(delivered.len(), 1, "only the first send was delivered");
    assert!(netem.gateway_mut().tun_mut().pop_ingress().is_none());
}

#[test]
fn mtu_recovery_from_blackhole_allows_sends_again() {
    let b = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(500, &[b], NetemConfig::default(), SAFE_MODE_MIN_DATAGRAM_MTU);
    netem
        .add_path(b.path_id, reliable_profile(SAFE_MODE_MIN_DATAGRAM_MTU))
        .unwrap();

    let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
    let (mut mtu_state, _) = PathMtuState::Unknown.discover(dm);
    let mut metrics = MtuMetrics::default();

    // Admit OK.
    assert!(mtu::admit_payload(100, &mtu_state, &mut metrics).is_ok());

    // Blackhole.
    let (bh, _) = mtu_state.blackhole();
    mtu_state = bh;
    assert!(mtu::check_payload(100, &mtu_state).is_err());

    // Recover.
    let (recovered, event) = mtu_state.recover(dm);
    mtu_state = recovered;
    assert_eq!(
        event,
        MtuEvent::MtuDiscovered {
            datagram_mtu: SAFE_MODE_MIN_DATAGRAM_MTU
        }
    );
    assert!(!mtu_state.send_denied());
    assert!(mtu::admit_payload(100, &mtu_state, &mut metrics).is_ok());
}

#[test]
fn dynamic_mtu_update_rejects_too_small_and_unknown_path() {
    let b = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(600, &[b], NetemConfig::default(), 1500);
    netem
        .add_path(b.path_id, reliable_profile(1500))
        .unwrap();

    // MTU below V2 header is rejected.
    assert_eq!(
        netem.update_path_mtu(b.path_id, Direction::ClientToGateway, FIXED_HEADER_LEN - 1),
        Err(UpdateMtuError::MtuTooSmall {
            mtu: FIXED_HEADER_LEN - 1,
            minimum: FIXED_HEADER_LEN,
        })
    );

    // Non-existent path is rejected.
    assert_eq!(
        netem.update_path_mtu(PathId::new(99), Direction::ClientToGateway, 1352),
        Err(UpdateMtuError::PathNotFound(PathId::new(99)))
    );
}

#[test]
fn mtu_metrics_accumulate_across_transitions() {
    let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
    let dm_small = DatagramMtu::new(1280).unwrap();
    let mut metrics = MtuMetrics::default();

    // Discover.
    let (state, event) = PathMtuState::Unknown.discover(dm);
    metrics.record_event(event);
    assert_eq!(metrics.mtu_reductions, 0);
    assert_eq!(metrics.blackholes_detected, 0);

    // Reduce.
    let (state, event) = state.reduce(dm_small);
    metrics.record_event(event);
    assert_eq!(metrics.mtu_reductions, 1);
    assert_eq!(metrics.blackholes_detected, 0);

    // Blackhole.
    let (state, event) = state.blackhole();
    metrics.record_event(event);
    assert_eq!(metrics.mtu_reductions, 1);
    assert_eq!(metrics.blackholes_detected, 1);

    // Recover.
    let (state, event) = state.recover(dm);
    metrics.record_event(event);
    assert_eq!(metrics.mtu_reductions, 1);
    assert_eq!(metrics.blackholes_detected, 1);

    // Reduce again.
    let (_state, event) = state.reduce(dm_small);
    metrics.record_event(event);
    assert_eq!(metrics.mtu_reductions, 2);
    assert_eq!(metrics.blackholes_detected, 1);
}

#[test]
fn netem_sends_that_fit_reduced_mtu_are_still_delivered() {
    // After a reduction, payloads within the new limit still succeed.
    let b = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(700, &[b], NetemConfig::default(), SAFE_MODE_MIN_DATAGRAM_MTU);
    netem
        .add_path(b.path_id, reliable_profile(1500))
        .unwrap();

    // Reduce to 1352.
    netem
        .update_path_mtu(b.path_id, Direction::ClientToGateway, SAFE_MODE_MIN_DATAGRAM_MTU)
        .unwrap();

    // 1300-byte payload fits in 1352 datagram (1300 payload + 52 header).
    let wire = datagram(b, Bytes::from(vec![0xEF; SAFE_MODE_MIN_PAYLOAD_MTU]));
    assert_eq!(wire.len(), SAFE_MODE_MIN_DATAGRAM_MTU);
    assert!(matches!(
        netem.send_payload(b, wire, None),
        SendOutcome::Queued { .. }
    ));
    netem.advance_to(0).unwrap();
    assert_eq!(
        netem.gateway_mut().tun_mut().pop_ingress(),
        Some(Bytes::from(vec![0xEF; SAFE_MODE_MIN_PAYLOAD_MTU]))
    );
}

#[test]
fn sequential_admit_reject_admit_does_not_leak_counter() {
    // Simulates the real engine pattern: admit, reject, admit. The
    // sequencer must only advance for the two admitted sends.
    let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
    let (state, _) = PathMtuState::Unknown.discover(dm);
    let mut seq = MockSequencer::new(100);
    let mut metrics = MtuMetrics::default();

    // 1st admit: id 100.
    assert!(mtu::admit_payload(500, &state, &mut metrics).is_ok());
    assert_eq!(seq.next_id(), 100);

    // Reject: id stays at 101.
    assert!(mtu::admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU + 1, &state, &mut metrics).is_err());
    assert_eq!(seq.current(), 101);
    assert_eq!(seq.calls(), 1);

    // 2nd admit: id 101.
    assert!(mtu::admit_payload(100, &state, &mut metrics).is_ok());
    assert_eq!(seq.next_id(), 101);
    assert_eq!(seq.current(), 102);
    assert_eq!(seq.calls(), 2);

    assert_eq!(metrics.sends_admitted, 2);
    assert_eq!(metrics.sends_rejected, 1);
}

#[test]
fn debug_output_never_leaks_payload_content() {
    let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
    let state = PathMtuState::Available {
        datagram_mtu: dm,
        effective: dm.effective_payload(),
    };
    let debug = format!("{state:?}");
    assert!(!debug.contains("payload content"));
    assert!(debug.contains("Available"));

    let metrics = MtuMetrics::default();
    let debug = format!("{metrics:?}");
    assert!(!debug.contains("0x")); // no hex payload bytes
}
