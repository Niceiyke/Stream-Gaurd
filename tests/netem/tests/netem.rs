use bytes::Bytes;
use sg_core::v2::{DeviceId, FlowId, PacketId, PathId, SessionId, TrafficClass};
use sg_protocol::v2::{control::{AdmissionTicket, ControlFrame, ControlMessage}, Direction, PayloadLimit, V2Envelope, V2Header, FIXED_HEADER_LEN};
use streamguard_netem::{AddPathError, ControlDropReason, DirectionalPathProfile, EventKind, FakeTun, GatewayBindError, GatewayConfig, GatewayDropReason, GatewayOutcome, Netem, NetemConfig, NetemCreateError, PathProfile, PostAdmissionBinding, QueueDropReason, QueueLimits, QueueOutcome, QueueResource, ScriptedGateway, SendDropReason, SendOutcome};

const SESSION: SessionId = SessionId::from_bytes([0xA1; 16]);
const DEVICE: DeviceId = DeviceId::from_bytes([0xB2; 16]);

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

fn gateway(bindings: &[PostAdmissionBinding], tun_limits: QueueLimits) -> ScriptedGateway {
    let mut gateway = ScriptedGateway::new(GatewayConfig::default(), FakeTun::new(tun_limits, tun_limits));
    for binding in bindings {
        gateway.bind_post_admission(*binding, 512).unwrap();
    }
    gateway
}

fn profile(profile: DirectionalPathProfile) -> PathProfile {
    PathProfile {
        client_to_gateway: profile,
        gateway_to_client: profile,
    }
}

fn harness(seed: u64, bindings: &[PostAdmissionBinding], config: NetemConfig) -> Netem {
    Netem::new("wp-102", seed, config, gateway(bindings, QueueLimits::new(16, 4096))).unwrap()
}

#[test]
fn seed_reproduces_metadata_event_log_and_diagnostic() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let path_profile = DirectionalPathProfile {
        latency_ms: 20,
        jitter_ms: 5,
        loss_ppm: 0,
        duplicate_ppm: 500_000,
        datagram_mtu: 512,
        connection_loss_at_ms: None,
    };
    let run = |seed| {
        let mut netem = harness(seed, &[binding], NetemConfig::default());
        netem.add_path(binding.path_id, profile(path_profile)).unwrap();
        for packet_id in 0..6 {
            let wire = datagram(binding, Bytes::from(vec![packet_id; 8]));
            assert!(matches!(netem.send_payload(binding, wire, None), SendOutcome::Queued { .. }));
        }
        let keys = netem.scenario().scheduled_keys().collect::<Vec<_>>();
        assert!(keys.windows(2).all(|pair| pair[0] <= pair[1]));
        netem.advance_to(100).unwrap();
        (netem.events().copied().collect::<Vec<_>>(), netem.reproducibility_diagnostic().clone())
    };

    let first = run(77);
    assert_eq!(first, run(77));
    assert_ne!(first.0, run(78).0);
    assert_eq!(first.1.scenario_name, "wp-102");
    assert_eq!(first.1.seed, 77);
}

#[test]
fn path_faults_are_independent_and_a_loss_does_not_block_b() {
    let a = binding(1, 1, Direction::ClientToGateway);
    let a_reverse = binding(3, 1, Direction::GatewayToClient);
    let b = binding(2, 2, Direction::ClientToGateway);
    let mut netem = harness(10, &[a, a_reverse, b], NetemConfig::default());
    netem.add_path(a.path_id, PathProfile {
        client_to_gateway: DirectionalPathProfile { loss_ppm: 1_000_000, ..DirectionalPathProfile::reliable(512) },
        gateway_to_client: DirectionalPathProfile::reliable(512),
    }).unwrap();
    netem.add_path(b.path_id, profile(DirectionalPathProfile::reliable(512))).unwrap();

    assert_eq!(netem.send_payload(a, datagram(a, Bytes::from_static(b"a")), None), SendOutcome::Dropped(SendDropReason::SimulatedLoss));
    assert!(matches!(netem.send_payload(a_reverse, datagram(a_reverse, Bytes::from_static(b"reverse")), None), SendOutcome::Queued { .. }));
    assert!(matches!(netem.send_payload(b, datagram(b, Bytes::from_static(b"b")), None), SendOutcome::Queued { .. }));
    netem.advance_to(0).unwrap();

    assert_eq!(netem.gateway_mut().tun_mut().pop_ingress(), Some(Bytes::from_static(b"reverse")));
    assert_eq!(netem.gateway_mut().tun_mut().pop_ingress(), Some(Bytes::from_static(b"b")));
    assert!(netem.events().any(|event| event.path_id == a.path_id && matches!(event.kind, EventKind::PayloadDropped(SendDropReason::SimulatedLoss))));
}

#[test]
fn full_wire_mtu_includes_the_v2_header_boundary() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let mtu = FIXED_HEADER_LEN + 5;
    let mut netem = harness(1, &[binding], NetemConfig::default());
    netem.add_path(binding.path_id, profile(DirectionalPathProfile::reliable(mtu))).unwrap();

    let exact = datagram(binding, Bytes::from_static(b"12345"));
    assert_eq!(exact.len(), mtu);
    assert!(matches!(netem.send_payload(binding, exact, None), SendOutcome::Queued { .. }));
    let over = datagram(binding, Bytes::from_static(b"123456"));
    assert_eq!(netem.send_payload(binding, over, None), SendOutcome::Dropped(SendDropReason::MtuExceeded { datagram_len: mtu + 1, mtu }));
}

#[test]
fn tun_and_path_queues_are_bounded_with_explicit_reasons() {
    let limits = QueueLimits::new(1, 3);
    let mut tun = FakeTun::new(limits, limits);
    assert_eq!(tun.push_ingress(Bytes::from_static(b"abc")), QueueOutcome::Queued);
    assert_eq!(tun.push_ingress(Bytes::from_static(b"x")), QueueOutcome::Dropped(QueueDropReason::CapacityExceeded { resource: QueueResource::Packets }));
    assert_eq!(tun.push_egress(Bytes::from_static(b"abcd")), QueueOutcome::Dropped(QueueDropReason::CapacityExceeded { resource: QueueResource::Bytes }));

    let binding = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(2, &[binding], NetemConfig { path_queue_limits: QueueLimits::new(1, 512), ..NetemConfig::default() });
    netem.add_path(binding.path_id, profile(DirectionalPathProfile { latency_ms: 10, ..DirectionalPathProfile::reliable(512) })).unwrap();
    assert!(matches!(netem.send_payload(binding, datagram(binding, Bytes::from_static(b"one")), None), SendOutcome::Queued { .. }));
    assert_eq!(netem.send_payload(binding, datagram(binding, Bytes::from_static(b"two")), None), SendOutcome::Dropped(SendDropReason::CapacityExceeded { resource: QueueResource::Packets }));
}

#[test]
fn deadlines_and_scheduled_path_loss_emit_events() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(3, &[binding], NetemConfig::default());
    netem.add_path(binding.path_id, profile(DirectionalPathProfile {
        latency_ms: 10,
        connection_loss_at_ms: Some(20),
        ..DirectionalPathProfile::reliable(512)
    })).unwrap();
    assert_eq!(netem.send_payload(binding, datagram(binding, Bytes::from_static(b"late")), Some(9)), SendOutcome::Dropped(SendDropReason::DeliveryDeadlineExceeded { delivery_at_ms: 10, deadline_ms: 9 }));
    assert!(matches!(netem.send_payload(binding, datagram(binding, Bytes::from_static(b"lost")), None), SendOutcome::Queued { delivery_at_ms: 10, .. }));
    netem.advance_to(20).unwrap();
    assert!(netem.events().any(|event| matches!(event.kind, EventKind::ConnectionLost)));
    assert!(netem.events().any(|event| matches!(event.kind, EventKind::PayloadDropped(SendDropReason::DeliveryDeadlineExceeded { .. }))));
}

#[test]
fn malformed_unbound_and_full_width_binding_mismatches_never_reach_tun() {
    let bound = binding(1, 1, Direction::ClientToGateway);
    let mut gateway = gateway(&[bound], QueueLimits::new(16, 4096));
    assert_eq!(gateway.receive_payload(bound, Bytes::from_static(b"bad")), GatewayOutcome::Dropped(GatewayDropReason::Malformed));
    let unbound = binding(99, 1, Direction::ClientToGateway);
    assert_eq!(gateway.receive_payload(unbound, datagram(unbound, Bytes::from_static(b"x"))), GatewayOutcome::Dropped(GatewayDropReason::UnboundConnection));
    let mut wrong_device = bound;
    wrong_device.device_id = DeviceId::from_bytes([0xB3; 16]);
    assert_eq!(gateway.receive_payload(wrong_device, datagram(bound, Bytes::from_static(b"x"))), GatewayOutcome::Dropped(GatewayDropReason::BindingMismatch));
    let mut wrong_session = bound;
    wrong_session.session_id = SessionId::from_bytes([0xA1, 0xA1, 0xA1, 0xA1, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]);
    assert_eq!(gateway.receive_payload(bound, datagram(wrong_session, Bytes::from_static(b"x"))), GatewayOutcome::Dropped(GatewayDropReason::HeaderBindingMismatch));
    assert_eq!(gateway.tun().metrics().ingress_packets, 0);
}

#[test]
fn reliable_control_ignores_payload_faults_until_explicit_connection_close() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(4, &[binding], NetemConfig::default());
    netem.add_path(binding.path_id, profile(DirectionalPathProfile {
        latency_ms: 5,
        jitter_ms: 20,
        loss_ppm: 1_000_000,
        duplicate_ppm: 1_000_000,
        datagram_mtu: FIXED_HEADER_LEN,
        connection_loss_at_ms: Some(10),
    })).unwrap();
    let frame = ControlFrame {
        transaction_id: 1,
        message: ControlMessage::PathHealth {
            session_id: SESSION,
            path_id: binding.path_id,
            path_epoch: 7,
            rtt_ms: 1,
            loss_ppm: 0,
        },
    };
    assert!(matches!(netem.send_control(binding, frame.clone()), SendOutcome::Queued { delivery_at_ms: 5, .. }));
    netem.advance_to(5).unwrap();
    assert_eq!(netem.gateway().received_control_frames(), 1);
    netem.advance_to(6).unwrap();
    assert!(matches!(netem.send_control(binding, frame), SendOutcome::Queued { .. }));
    netem.advance_to(11).unwrap();
    assert_eq!(netem.gateway().received_control_frames(), 1);
    assert!(netem.events().any(|event| matches!(event.kind, EventKind::ControlTerminated)));
}

#[test]
fn event_log_truncation_is_bounded_and_reported() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(5, &[binding], NetemConfig { event_log_capacity: 1, ..NetemConfig::default() });
    netem.add_path(binding.path_id, profile(DirectionalPathProfile::reliable(512))).unwrap();
    let _ = netem.send_payload(binding, datagram(binding, Bytes::from_static(b"x")), None);
    netem.advance_to(0).unwrap();
    assert_eq!(netem.events().len(), 1);
    assert!(netem.event_log_metrics().truncated >= 1);
    assert_eq!(netem.last_event_log_outcome(), streamguard_netem::EventLogOutcome::Truncated);
}

#[test]
fn jitter_is_clamped_and_drain_uses_scheduled_time_and_ordinal() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    for seed in 0..32 {
        let mut netem = harness(seed, &[binding], NetemConfig::default());
        netem.add_path(binding.path_id, profile(DirectionalPathProfile {
            jitter_ms: 100,
            ..DirectionalPathProfile::reliable(512)
        })).unwrap();
        netem.advance_to(100).unwrap();
        let SendOutcome::Queued { delivery_at_ms, .. } = netem.send_payload(binding, datagram(binding, Bytes::from_static(b"jitter")), None) else {
            panic!("payload must queue");
        };
        assert!(delivery_at_ms >= 100);
    }

    let mut netem = harness(9, &[binding], NetemConfig::default());
    netem.add_path(binding.path_id, profile(DirectionalPathProfile {
        latency_ms: 5,
        ..DirectionalPathProfile::reliable(512)
    })).unwrap();
    let _ = netem.send_payload(binding, datagram(binding, Bytes::from_static(b"one")), None);
    let _ = netem.send_payload(binding, datagram(binding, Bytes::from_static(b"two")), None);
    netem.advance_to(10).unwrap();
    let delivered = netem.events()
        .filter(|event| event.kind == EventKind::PayloadDelivered)
        .map(|event| (event.time_ms, event.ordinal))
        .collect::<Vec<_>>();
    assert_eq!(delivered, vec![(5, 0), (5, 1)]);
    assert_eq!(netem.clock().now_ms(), 10);
}

#[test]
fn gateway_rejects_inbound_wire_larger_than_its_configured_mtu() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let mut gateway = ScriptedGateway::new(GatewayConfig::default(), FakeTun::new(QueueLimits::new(4, 512), QueueLimits::new(4, 512)));
    gateway.bind_post_admission(binding, FIXED_HEADER_LEN + 1).unwrap();
    let wire = datagram(binding, Bytes::from_static(b"xx"));
    assert_eq!(gateway.receive_payload(binding, wire), GatewayOutcome::Dropped(GatewayDropReason::MtuExceeded {
        datagram_len: FIXED_HEADER_LEN + 2,
        mtu: FIXED_HEADER_LEN + 1,
    }));
    assert_eq!(gateway.tun().metrics().ingress_packets, 0);
}

#[test]
fn post_admission_control_rejects_invalid_messages_without_delivery() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let mut gateway = gateway(&[binding], QueueLimits::new(4, 512));
    let client_hello = ControlFrame {
        transaction_id: 1,
        message: ControlMessage::ClientHello {
            device_id: DEVICE,
            requested_gateway: "test".into(),
            ticket: AdmissionTicket::new("ticket".into()).unwrap(),
        },
    };
    assert_eq!(gateway.receive_control(binding, client_hello), GatewayOutcome::Dropped(GatewayDropReason::Control(ControlDropReason::ClientHelloNotAllowed)));
    assert_eq!(gateway.receive_control(binding, ControlFrame { transaction_id: 2, message: ControlMessage::Ack }), GatewayOutcome::Dropped(GatewayDropReason::Control(ControlDropReason::UncorrelatedReply)));
    let wrong_path = ControlFrame {
        transaction_id: 3,
        message: ControlMessage::PathHealth {
            session_id: SESSION,
            path_id: PathId::new(2),
            path_epoch: 7,
            rtt_ms: 1,
            loss_ppm: 0,
        },
    };
    assert_eq!(gateway.receive_control(binding, wrong_path.clone()), GatewayOutcome::Dropped(GatewayDropReason::Control(ControlDropReason::InvalidScope)));
    let stale_detach = ControlFrame {
        transaction_id: 4,
        message: ControlMessage::PathDetach {
            session_id: SESSION,
            path_id: binding.path_id,
            path_epoch: 8,
            reason: "stale".into(),
        },
    };
    assert_eq!(gateway.receive_control(binding, stale_detach), GatewayOutcome::Dropped(GatewayDropReason::Control(ControlDropReason::InvalidScope)));
    let wrong_attached = ControlFrame {
        transaction_id: 5,
        message: ControlMessage::PathAttached {
            session_id: SESSION,
            path_id: PathId::new(2),
            path_epoch: 7,
        },
    };
    assert_eq!(gateway.receive_control(binding, wrong_attached), GatewayOutcome::Dropped(GatewayDropReason::Control(ControlDropReason::InvalidDirection)));
    assert_eq!(gateway.received_control_frames(), 0);
    assert_eq!(gateway.tun().metrics().ingress_packets, 0);
    gateway.expect_control_reply(binding, 6).unwrap();
    assert_eq!(gateway.receive_control(binding, ControlFrame { transaction_id: 6, message: ControlMessage::Ack }), GatewayOutcome::DeliveredToTun);

    let mut netem = harness(11, &[binding], NetemConfig::default());
    netem.add_path(binding.path_id, profile(DirectionalPathProfile::reliable(512))).unwrap();
    assert!(matches!(netem.send_control(binding, wrong_path), SendOutcome::Queued { .. }));
    netem.advance_to(0).unwrap();
    assert_eq!(netem.gateway().received_control_frames(), 0);
    assert_eq!(netem.gateway().tun().metrics().ingress_packets, 0);
    assert!(netem.events().any(|event| event.kind == EventKind::GatewayDropped));
    assert!(!netem.events().any(|event| event.kind == EventKind::ControlDelivered));
}

#[test]
fn debug_output_redacts_queued_and_tun_payloads() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let marker = "netem-secret-marker";
    let mut netem = harness(12, &[binding], NetemConfig::default());
    netem.add_path(binding.path_id, profile(DirectionalPathProfile { latency_ms: 10, ..DirectionalPathProfile::reliable(512) })).unwrap();
    let _ = netem.send_payload(binding, datagram(binding, Bytes::from(marker.as_bytes().to_vec())), None);
    assert_eq!(netem.gateway_mut().tun_mut().push_egress(Bytes::from(marker.as_bytes().to_vec())), QueueOutcome::Queued);
    assert!(!format!("{netem:?}").contains(marker));
    assert!(!format!("{:?}", netem.scenario()).contains(marker));
    assert!(!format!("{:?}", netem.gateway()).contains(marker));
}

#[test]
fn scenario_name_paths_and_gateway_bindings_have_configured_bounds() {
    let bound = binding(1, 1, Direction::ClientToGateway);
    assert!(matches!(
        Netem::new("too-long", 1, NetemConfig { scenario_name_max_len: 3, ..NetemConfig::default() }, gateway(&[bound], QueueLimits::new(4, 512))),
        Err(NetemCreateError::ScenarioNameTooLong { length: 8, maximum: 3 })
    ));
    let mut netem = harness(13, &[bound], NetemConfig { path_capacity: 1, ..NetemConfig::default() });
    netem.add_path(bound.path_id, profile(DirectionalPathProfile::reliable(512))).unwrap();
    assert_eq!(netem.add_path(PathId::new(2), profile(DirectionalPathProfile::reliable(512))), Err(AddPathError::CapacityExceeded));
    assert_eq!(netem.metrics().path_capacity_rejections, 1);

    let mut gateway = ScriptedGateway::new(
        GatewayConfig { binding_capacity: 1, control_reply_capacity: 1 },
        FakeTun::new(QueueLimits::new(4, 512), QueueLimits::new(4, 512)),
    );
    gateway.bind_post_admission(bound, 512).unwrap();
    let second = binding(2, 2, Direction::ClientToGateway);
    assert_eq!(gateway.bind_post_admission(second, 512), Err(GatewayBindError::CapacityExceeded));
    assert_eq!(gateway.metrics().binding_capacity_rejections, 1);
}

#[test]
fn post_admission_path_and_policy_control_require_direction_and_expectations() {
    let client_to_gateway = binding(1, 1, Direction::ClientToGateway);
    let gateway_to_client = binding(2, 1, Direction::GatewayToClient);
    let path_attached = ControlFrame {
        transaction_id: 10,
        message: ControlMessage::PathAttached {
            session_id: SESSION,
            path_id: gateway_to_client.path_id,
            path_epoch: 7,
        },
    };
    let policy = ControlFrame {
        transaction_id: 11,
        message: ControlMessage::PolicyUpdate {
            session_id: SESSION,
            policy_epoch: 3,
            policy: Bytes::from_static(b"policy"),
        },
    };
    let mut gateway = gateway(&[client_to_gateway, gateway_to_client], QueueLimits::new(4, 512));
    assert_eq!(gateway.receive_control(gateway_to_client, path_attached.clone()), GatewayOutcome::Dropped(GatewayDropReason::Control(ControlDropReason::UncorrelatedPathAttached)));
    assert_eq!(gateway.receive_control(client_to_gateway, policy.clone()), GatewayOutcome::Dropped(GatewayDropReason::Control(ControlDropReason::InvalidDirection)));
    assert_eq!(gateway.receive_control(gateway_to_client, policy.clone()), GatewayOutcome::Dropped(GatewayDropReason::Control(ControlDropReason::UncorrelatedPolicyUpdate)));
    assert_eq!(gateway.received_control_frames(), 0);
    assert_eq!(gateway.tun().metrics().ingress_packets, 0);
    gateway.register_path_attach(gateway_to_client, 10, 7).unwrap();
    assert_eq!(gateway.receive_control(gateway_to_client, path_attached.clone()), GatewayOutcome::DeliveredToTun);
    gateway.expect_policy_update(gateway_to_client, 11, 3).unwrap();
    assert_eq!(gateway.receive_control(gateway_to_client, policy), GatewayOutcome::DeliveredToTun);

    let mut netem = harness(14, &[client_to_gateway, gateway_to_client], NetemConfig::default());
    netem.add_path(client_to_gateway.path_id, profile(DirectionalPathProfile::reliable(512))).unwrap();
    assert!(matches!(netem.send_control(gateway_to_client, path_attached), SendOutcome::Queued { .. }));
    netem.advance_to(0).unwrap();
    assert_eq!(netem.gateway().received_control_frames(), 0);
    assert_eq!(netem.gateway().tun().metrics().ingress_packets, 0);
    assert!(netem.events().any(|event| event.kind == EventKind::GatewayDropped));
    assert!(!netem.events().any(|event| event.kind == EventKind::ControlDelivered));
}

#[test]
fn adding_an_expired_path_close_is_immediate_and_clock_remains_monotonic() {
    let binding = binding(1, 1, Direction::ClientToGateway);
    let mut netem = harness(15, &[binding], NetemConfig::default());
    netem.advance_to(10).unwrap();
    netem.add_path(binding.path_id, profile(DirectionalPathProfile {
        connection_loss_at_ms: Some(5),
        ..DirectionalPathProfile::reliable(512)
    })).unwrap();
    assert_eq!(netem.clock().now_ms(), 10);
    assert!(netem.scenario().is_empty());
    assert!(netem.events().any(|event| event.time_ms == 10 && event.kind == EventKind::ConnectionLost));
    assert_eq!(netem.send_payload(binding, datagram(binding, Bytes::from_static(b"closed")), None), SendOutcome::Dropped(SendDropReason::ConnectionClosed));
    assert!(netem.advance_to(9).is_err());
    assert_eq!(netem.advance_by(1), Ok(()));
    assert_eq!(netem.clock().now_ms(), 11);
}

#[test]
fn lowest_healthy_path_is_an_observable_test_seam() {
    let first = binding(1, 1, Direction::ClientToGateway);
    let second = binding(2, 2, Direction::ClientToGateway);
    let mut netem = harness(16, &[first, second], NetemConfig::default());
    netem.add_path(second.path_id, profile(DirectionalPathProfile { latency_ms: 5, ..DirectionalPathProfile::reliable(512) })).unwrap();
    netem.add_path(first.path_id, profile(DirectionalPathProfile { latency_ms: 5, ..DirectionalPathProfile::reliable(512) })).unwrap();
    assert_eq!(netem.choose_lowest_healthy_path(Direction::ClientToGateway), Some(first.path_id));
    assert_eq!(
        netem.send_payload_on_lowest_healthy_path(
            &[second, first],
            Direction::ClientToGateway,
            datagram(first, Bytes::from_static(b"selected")),
            Some(5),
        ),
        SendOutcome::Queued {
            path_id: first.path_id,
            copies: 1,
            delivery_at_ms: 5,
        }
    );
    assert_eq!(
        netem.send_payload_on_lowest_healthy_path(
            &[second, first],
            Direction::ClientToGateway,
            datagram(first, Bytes::from_static(b"late")),
            Some(4),
        ),
        SendOutcome::Dropped(SendDropReason::DeliveryDeadlineExceeded {
            delivery_at_ms: 5,
            deadline_ms: 4,
        })
    );
    netem.advance_to(5).unwrap();
    assert!(netem.events().any(|event| event.path_id == first.path_id && event.kind == EventKind::PayloadDelivered));
    assert!(netem.events().any(|event| matches!(event.kind, EventKind::PayloadDropped(SendDropReason::DeliveryDeadlineExceeded { .. }))));
}
