//! Deterministic V2-only network simulation for packet-delivery tests.
//!
//! This crate models only traffic after authentication and admission. It does
//! not create credentials, tickets, sessions, production transports, or tasks.
//! Existing V1 real-Quinn loopback tests remain the current real transport
//! coverage. V2 QUIC datagram integration belongs with the V2 engine and
//! transport work, so this harness intentionally does not emulate a Quinn test.

use bytes::Bytes;
use sg_core::v2::{DeviceId, PathId, SessionId};
use sg_protocol::v2::{control::{ControlFrame, ControlMessage}, Direction, PayloadLimit, V2Envelope};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

pub const PPM_DENOMINATOR: u32 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLimits {
    pub packets: usize,
    pub bytes: usize,
}

impl QueueLimits {
    pub const fn new(packets: usize, bytes: usize) -> Self {
        Self { packets, bytes }
    }

    fn accepts(self, packets: usize, bytes: usize, additional_bytes: usize) -> Result<(), QueueDropReason> {
        if packets >= self.packets {
            return Err(QueueDropReason::CapacityExceeded {
                resource: QueueResource::Packets,
            });
        }
        if bytes.saturating_add(additional_bytes) > self.bytes {
            return Err(QueueDropReason::CapacityExceeded {
                resource: QueueResource::Bytes,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueResource {
    Packets,
    Bytes,
    Events,
    Paths,
    Bindings,
    ControlTransactions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueDropReason {
    CapacityExceeded { resource: QueueResource },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendDropReason {
    CapacityExceeded { resource: QueueResource },
    MtuExceeded { datagram_len: usize, mtu: usize },
    SimulatedLoss,
    DeliveryDeadlineExceeded { delivery_at_ms: u64, deadline_ms: u64 },
    ConnectionClosed,
}

impl From<QueueDropReason> for SendDropReason {
    fn from(reason: QueueDropReason) -> Self {
        match reason {
            QueueDropReason::CapacityExceeded { resource } => Self::CapacityExceeded { resource },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueOutcome {
    Queued,
    Dropped(QueueDropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Queued {
        path_id: PathId,
        copies: u8,
        delivery_at_ms: u64,
    },
    Dropped(SendDropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimClock {
    now_ms: u64,
}

impl SimClock {
    pub const fn new(now_ms: u64) -> Self {
        Self { now_ms }
    }

    pub const fn now_ms(self) -> u64 {
        self.now_ms
    }

    pub fn advance_to(&mut self, now_ms: u64) -> Result<(), ClockError> {
        if now_ms < self.now_ms {
            return Err(ClockError::CannotMoveBackwards {
                now_ms: self.now_ms,
                requested_ms: now_ms,
            });
        }
        self.now_ms = now_ms;
        Ok(())
    }

}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    CannotMoveBackwards { now_ms: u64, requested_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectionalPathProfile {
    pub latency_ms: u64,
    pub jitter_ms: u64,
    pub loss_ppm: u32,
    pub duplicate_ppm: u32,
    /// Full V2 datagram MTU, including the fixed 52-byte envelope header.
    pub datagram_mtu: usize,
    /// The connection closes at this simulated monotonic time.
    pub connection_loss_at_ms: Option<u64>,
}

impl DirectionalPathProfile {
    pub const fn reliable(datagram_mtu: usize) -> Self {
        Self {
            latency_ms: 0,
            jitter_ms: 0,
            loss_ppm: 0,
            duplicate_ppm: 0,
            datagram_mtu,
            connection_loss_at_ms: None,
        }
    }

    fn validate(self) -> Result<(), ProfileError> {
        if self.loss_ppm > PPM_DENOMINATOR {
            return Err(ProfileError::InvalidPpm(self.loss_ppm));
        }
        if self.duplicate_ppm > PPM_DENOMINATOR {
            return Err(ProfileError::InvalidPpm(self.duplicate_ppm));
        }
        if self.datagram_mtu < sg_protocol::v2::FIXED_HEADER_LEN {
            return Err(ProfileError::MtuSmallerThanHeader {
                mtu: self.datagram_mtu,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathProfile {
    pub client_to_gateway: DirectionalPathProfile,
    pub gateway_to_client: DirectionalPathProfile,
}

impl PathProfile {
    pub const fn for_direction(self, direction: Direction) -> DirectionalPathProfile {
        match direction {
            Direction::ClientToGateway => self.client_to_gateway,
            Direction::GatewayToClient => self.gateway_to_client,
        }
    }

    fn validate(self) -> Result<(), ProfileError> {
        self.client_to_gateway.validate()?;
        self.gateway_to_client.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    InvalidPpm(u32),
    MtuSmallerThanHeader { mtu: usize },
}

/// A test-only representation of a transport connection that has already been
/// admitted elsewhere. It is not an authentication claim and cannot mint one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostAdmissionBinding {
    pub connection_id: u64,
    pub session_id: SessionId,
    pub device_id: DeviceId,
    pub path_id: PathId,
    pub path_epoch: u64,
    pub key_epoch: u32,
    pub direction: Direction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayDropReason {
    Malformed,
    MtuExceeded { datagram_len: usize, mtu: usize },
    UnboundConnection,
    BindingMismatch,
    HeaderBindingMismatch,
    Control(ControlDropReason),
    Tun(QueueDropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlDropReason {
    ClientHelloNotAllowed,
    InvalidDirection,
    InvalidScope,
    UncorrelatedReply,
    UncorrelatedPathAttached,
    UncorrelatedPolicyUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayOutcome {
    DeliveredToTun,
    Dropped(GatewayDropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLogMetrics {
    pub recorded: u64,
    pub truncated: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLogOutcome {
    Recorded,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    PayloadQueued,
    ControlQueued,
    PayloadDropped(SendDropReason),
    PayloadDelivered,
    ControlDelivered,
    ControlTerminated,
    GatewayDropped,
    ConnectionLost,
}

/// Metadata only: events intentionally never contain packet or control bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub time_ms: u64,
    pub ordinal: u64,
    pub path_id: PathId,
    pub direction: Direction,
    pub kind: EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproducibilityDiagnostic {
    pub scenario_name: String,
    pub seed: u64,
}

#[derive(Debug)]
struct EventLog {
    capacity: usize,
    entries: VecDeque<Event>,
    metrics: EventLogMetrics,
    last_outcome: EventLogOutcome,
}

impl EventLog {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
            metrics: EventLogMetrics {
                recorded: 0,
                truncated: 0,
            },
            last_outcome: EventLogOutcome::Recorded,
        }
    }

    fn record(&mut self, event: Event) -> EventLogOutcome {
        if self.entries.len() == self.capacity {
            self.metrics.truncated = self.metrics.truncated.saturating_add(1);
            self.last_outcome = EventLogOutcome::Truncated;
            return self.last_outcome;
        }
        self.entries.push_back(event);
        self.metrics.recorded = self.metrics.recorded.saturating_add(1);
        self.last_outcome = EventLogOutcome::Recorded;
        self.last_outcome
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeTunMetrics {
    pub ingress_packets: usize,
    pub ingress_bytes: usize,
    pub egress_packets: usize,
    pub egress_bytes: usize,
    pub ingress_drops: u64,
    pub egress_drops: u64,
}

pub struct FakeTun {
    ingress_limits: QueueLimits,
    egress_limits: QueueLimits,
    ingress: VecDeque<Bytes>,
    egress: VecDeque<Bytes>,
    ingress_bytes: usize,
    egress_bytes: usize,
    ingress_drops: u64,
    egress_drops: u64,
}

impl fmt::Debug for FakeTun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeTun")
            .field("metrics", &self.metrics())
            .finish()
    }
}

impl FakeTun {
    pub fn new(ingress_limits: QueueLimits, egress_limits: QueueLimits) -> Self {
        Self {
            ingress_limits,
            egress_limits,
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
            ingress_bytes: 0,
            egress_bytes: 0,
            ingress_drops: 0,
            egress_drops: 0,
        }
    }

    pub fn push_ingress(&mut self, packet: Bytes) -> QueueOutcome {
        Self::push(
            &mut self.ingress,
            &mut self.ingress_bytes,
            &mut self.ingress_drops,
            self.ingress_limits,
            packet,
        )
    }

    pub fn push_egress(&mut self, packet: Bytes) -> QueueOutcome {
        Self::push(
            &mut self.egress,
            &mut self.egress_bytes,
            &mut self.egress_drops,
            self.egress_limits,
            packet,
        )
    }

    fn push(
        queue: &mut VecDeque<Bytes>,
        queued_bytes: &mut usize,
        drops: &mut u64,
        limits: QueueLimits,
        packet: Bytes,
    ) -> QueueOutcome {
        match limits.accepts(queue.len(), *queued_bytes, packet.len()) {
            Ok(()) => {
                *queued_bytes = queued_bytes.saturating_add(packet.len());
                queue.push_back(packet);
                QueueOutcome::Queued
            }
            Err(reason) => {
                *drops = drops.saturating_add(1);
                QueueOutcome::Dropped(reason)
            }
        }
    }

    pub fn pop_ingress(&mut self) -> Option<Bytes> {
        let packet = self.ingress.pop_front()?;
        self.ingress_bytes = self.ingress_bytes.saturating_sub(packet.len());
        Some(packet)
    }

    pub fn pop_egress(&mut self) -> Option<Bytes> {
        let packet = self.egress.pop_front()?;
        self.egress_bytes = self.egress_bytes.saturating_sub(packet.len());
        Some(packet)
    }

    pub fn metrics(&self) -> FakeTunMetrics {
        FakeTunMetrics {
            ingress_packets: self.ingress.len(),
            ingress_bytes: self.ingress_bytes,
            egress_packets: self.egress.len(),
            egress_bytes: self.egress_bytes,
            ingress_drops: self.ingress_drops,
            egress_drops: self.egress_drops,
        }
    }
}

pub struct ScriptedGateway {
    config: GatewayConfig,
    bindings: BTreeMap<u64, GatewayBinding>,
    pending_control_replies: BTreeMap<(u64, u64), ()>,
    pending_path_attaches: BTreeMap<(u64, u64), u64>,
    pending_policy_updates: BTreeMap<(u64, u64), u64>,
    tun: FakeTun,
    received_control_frames: usize,
    binding_capacity_rejections: u64,
    control_capacity_rejections: u64,
}

impl ScriptedGateway {
    pub fn new(config: GatewayConfig, tun: FakeTun) -> Self {
        Self {
            config,
            bindings: BTreeMap::new(),
            pending_control_replies: BTreeMap::new(),
            pending_path_attaches: BTreeMap::new(),
            pending_policy_updates: BTreeMap::new(),
            tun,
            received_control_frames: 0,
            binding_capacity_rejections: 0,
            control_capacity_rejections: 0,
        }
    }

    pub fn bind_post_admission(
        &mut self,
        binding: PostAdmissionBinding,
        datagram_mtu: usize,
    ) -> Result<(), GatewayBindError> {
        if binding.connection_id == 0
            || binding.path_epoch == 0
            || binding.key_epoch == 0
            || datagram_mtu < sg_protocol::v2::FIXED_HEADER_LEN
        {
            return Err(GatewayBindError::InvalidBinding);
        }
        if self.bindings.contains_key(&binding.connection_id) {
            return Err(GatewayBindError::DuplicateConnection);
        }
        if self.bindings.len() == self.config.binding_capacity {
            self.binding_capacity_rejections = self.binding_capacity_rejections.saturating_add(1);
            return Err(GatewayBindError::CapacityExceeded);
        }
        self.bindings.insert(
            binding.connection_id,
            GatewayBinding {
                binding,
                datagram_mtu,
            },
        );
        Ok(())
    }

    pub fn receive_payload(&mut self, peer: PostAdmissionBinding, datagram: Bytes) -> GatewayOutcome {
        let Some(expected) = self.bindings.get(&peer.connection_id) else {
            return GatewayOutcome::Dropped(GatewayDropReason::UnboundConnection);
        };
        if expected.binding != peer {
            return GatewayOutcome::Dropped(GatewayDropReason::BindingMismatch);
        }
        if datagram.len() > expected.datagram_mtu {
            return GatewayOutcome::Dropped(GatewayDropReason::MtuExceeded {
                datagram_len: datagram.len(),
                mtu: expected.datagram_mtu,
            });
        }
        let payload_limit = PayloadLimit::new(expected.datagram_mtu - sg_protocol::v2::FIXED_HEADER_LEN);
        let envelope = match V2Envelope::decode(datagram, payload_limit) {
            Ok(envelope) => envelope,
            Err(_) => return GatewayOutcome::Dropped(GatewayDropReason::Malformed),
        };
        if envelope.header.session_id != expected.binding.session_id
            || envelope.header.path_id != expected.binding.path_id
            || envelope.header.path_epoch != expected.binding.path_epoch
            || envelope.header.key_epoch != expected.binding.key_epoch
            || envelope.header.direction != expected.binding.direction
        {
            return GatewayOutcome::Dropped(GatewayDropReason::HeaderBindingMismatch);
        }
        match self.tun.push_ingress(envelope.payload) {
            QueueOutcome::Queued => GatewayOutcome::DeliveredToTun,
            QueueOutcome::Dropped(reason) => GatewayOutcome::Dropped(GatewayDropReason::Tun(reason)),
        }
    }

    pub fn receive_control(&mut self, peer: PostAdmissionBinding, frame: ControlFrame) -> GatewayOutcome {
        let Some(expected) = self.bindings.get(&peer.connection_id) else {
            return GatewayOutcome::Dropped(GatewayDropReason::UnboundConnection);
        };
        if expected.binding != peer {
            return GatewayOutcome::Dropped(GatewayDropReason::BindingMismatch);
        }
        let result = validate_control(
            &expected.binding,
            &frame,
            &mut self.pending_control_replies,
            &mut self.pending_path_attaches,
            &mut self.pending_policy_updates,
        );
        if let Err(reason) = result {
            return GatewayOutcome::Dropped(GatewayDropReason::Control(reason));
        }
        self.received_control_frames = self.received_control_frames.saturating_add(1);
        GatewayOutcome::DeliveredToTun
    }

    pub fn expect_control_reply(
        &mut self,
        peer: PostAdmissionBinding,
        transaction_id: u64,
    ) -> Result<(), ControlExpectationError> {
        if transaction_id == 0 || self.bindings.get(&peer.connection_id).is_none_or(|binding| binding.binding != peer) {
            return Err(ControlExpectationError::UnboundOrInvalid);
        }
        self.reserve_control_expectation()?;
        self.pending_control_replies.insert((peer.connection_id, transaction_id), ());
        Ok(())
    }

    /// Registers a prior client path attach for a simulated gateway-to-client
    /// `PathAttached` reply. This is a harness correlation seam, not admission.
    pub fn register_path_attach(
        &mut self,
        peer: PostAdmissionBinding,
        transaction_id: u64,
        path_epoch: u64,
    ) -> Result<(), ControlExpectationError> {
        if peer.direction != Direction::GatewayToClient
            || transaction_id == 0
            || path_epoch != peer.path_epoch
            || self.bindings.get(&peer.connection_id).is_none_or(|binding| binding.binding != peer)
        {
            return Err(ControlExpectationError::UnboundOrInvalid);
        }
        self.reserve_control_expectation()?;
        self.pending_path_attaches
            .insert((peer.connection_id, transaction_id), path_epoch);
        Ok(())
    }

    /// Registers a gateway policy transaction for a simulated gateway-to-client
    /// `PolicyUpdate`. This carries no policy bytes and only validates epoch.
    pub fn expect_policy_update(
        &mut self,
        peer: PostAdmissionBinding,
        transaction_id: u64,
        policy_epoch: u64,
    ) -> Result<(), ControlExpectationError> {
        if peer.direction != Direction::GatewayToClient
            || transaction_id == 0
            || policy_epoch == 0
            || self.bindings.get(&peer.connection_id).is_none_or(|binding| binding.binding != peer)
        {
            return Err(ControlExpectationError::UnboundOrInvalid);
        }
        self.reserve_control_expectation()?;
        self.pending_policy_updates
            .insert((peer.connection_id, transaction_id), policy_epoch);
        Ok(())
    }

    fn reserve_control_expectation(&mut self) -> Result<(), ControlExpectationError> {
        let pending = self.pending_control_replies.len()
            + self.pending_path_attaches.len()
            + self.pending_policy_updates.len();
        if pending == self.config.control_reply_capacity {
            self.control_capacity_rejections = self.control_capacity_rejections.saturating_add(1);
            return Err(ControlExpectationError::CapacityExceeded);
        }
        Ok(())
    }

    pub fn tun(&self) -> &FakeTun {
        &self.tun
    }

    pub fn tun_mut(&mut self) -> &mut FakeTun {
        &mut self.tun
    }

    pub const fn received_control_frames(&self) -> usize {
        self.received_control_frames
    }

    pub fn metrics(&self) -> GatewayMetrics {
        GatewayMetrics {
            bindings: self.bindings.len(),
            binding_capacity: self.config.binding_capacity,
            binding_capacity_rejections: self.binding_capacity_rejections,
            pending_control_replies: self.pending_control_replies.len()
                + self.pending_path_attaches.len()
                + self.pending_policy_updates.len(),
            control_capacity_rejections: self.control_capacity_rejections,
        }
    }
}

impl fmt::Debug for ScriptedGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptedGateway")
            .field("metrics", &self.metrics())
            .field("tun", &self.tun)
            .field("received_control_frames", &self.received_control_frames)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayConfig {
    pub binding_capacity: usize,
    pub control_reply_capacity: usize,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            binding_capacity: 128,
            control_reply_capacity: 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayMetrics {
    pub bindings: usize,
    pub binding_capacity: usize,
    pub binding_capacity_rejections: u64,
    pub pending_control_replies: usize,
    pub control_capacity_rejections: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct GatewayBinding {
    binding: PostAdmissionBinding,
    datagram_mtu: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlExpectationError {
    UnboundOrInvalid,
    CapacityExceeded,
}

fn validate_control(
    binding: &PostAdmissionBinding,
    frame: &ControlFrame,
    pending_replies: &mut BTreeMap<(u64, u64), ()>,
    pending_path_attaches: &mut BTreeMap<(u64, u64), u64>,
    pending_policy_updates: &mut BTreeMap<(u64, u64), u64>,
) -> Result<(), ControlDropReason> {
    match &frame.message {
        ControlMessage::ClientHello { .. } => Err(ControlDropReason::ClientHelloNotAllowed),
        ControlMessage::Ack | ControlMessage::Reject { .. } if binding.direction == Direction::ClientToGateway => pending_replies
                .remove(&(binding.connection_id, frame.transaction_id))
                .map(|_| ())
                .ok_or(ControlDropReason::UncorrelatedReply),
        ControlMessage::PathAttached { .. } if binding.direction != Direction::GatewayToClient => {
            Err(ControlDropReason::InvalidDirection)
        }
        ControlMessage::PathAttached {
            session_id,
            path_id,
            path_epoch,
        } if binding.direction == Direction::GatewayToClient
            && *session_id == binding.session_id
            && *path_id == binding.path_id
            && pending_path_attaches
                .get(&(binding.connection_id, frame.transaction_id))
                .is_some_and(|expected_epoch| *expected_epoch == *path_epoch) => {
                pending_path_attaches.remove(&(binding.connection_id, frame.transaction_id));
                Ok(())
            }
        ControlMessage::PathDetach {
            session_id,
            path_id,
            path_epoch,
            ..
        }
        | ControlMessage::PathHealth {
            session_id,
            path_id,
            path_epoch,
            ..
        } if binding.direction == Direction::ClientToGateway
            && *session_id == binding.session_id
            && *path_id == binding.path_id
            && *path_epoch == binding.path_epoch => Ok(()),
        ControlMessage::PathAttached { .. } => Err(ControlDropReason::UncorrelatedPathAttached),
        ControlMessage::PolicyUpdate { .. } if binding.direction != Direction::GatewayToClient => {
            Err(ControlDropReason::InvalidDirection)
        }
        ControlMessage::PolicyUpdate {
            session_id,
            policy_epoch,
            ..
        } if binding.direction == Direction::GatewayToClient
            && *session_id == binding.session_id
            && pending_policy_updates
                .get(&(binding.connection_id, frame.transaction_id))
                .is_some_and(|expected_epoch| *expected_epoch == *policy_epoch) => {
                pending_policy_updates.remove(&(binding.connection_id, frame.transaction_id));
                Ok(())
            }
        ControlMessage::PolicyUpdate { .. } => Err(ControlDropReason::UncorrelatedPolicyUpdate),
        ControlMessage::Close { session_id, .. }
            if binding.direction == Direction::ClientToGateway && *session_id == binding.session_id => Ok(()),
        ControlMessage::Ack | ControlMessage::Reject { .. } => Err(ControlDropReason::InvalidDirection),
        _ => Err(ControlDropReason::InvalidScope),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayBindError {
    InvalidBinding,
    DuplicateConnection,
    CapacityExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetemConfig {
    pub scenario_queue_limits: QueueLimits,
    pub path_queue_limits: QueueLimits,
    pub event_log_capacity: usize,
    pub path_capacity: usize,
    pub scenario_name_max_len: usize,
}

impl Default for NetemConfig {
    fn default() -> Self {
        Self {
            scenario_queue_limits: QueueLimits::new(1_024, 2 * 1024 * 1024),
            path_queue_limits: QueueLimits::new(128, 256 * 1024),
            event_log_capacity: 1_024,
            path_capacity: 64,
            scenario_name_max_len: 128,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ScheduledAction {
    Payload { binding: PostAdmissionBinding, datagram: Bytes },
    Control { binding: PostAdmissionBinding, frame: ControlFrame, byte_len: usize },
    Close { path_id: PathId, direction: Direction },
}

impl fmt::Debug for ScheduledAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Payload { binding, datagram } => formatter
                .debug_struct("Payload")
                .field("connection_id", &binding.connection_id)
                .field("path_id", &binding.path_id)
                .field("direction", &binding.direction)
                .field("datagram_len", &datagram.len())
                .finish(),
            Self::Control {
                binding, byte_len, ..
            } => formatter
                .debug_struct("Control")
                .field("connection_id", &binding.connection_id)
                .field("path_id", &binding.path_id)
                .field("direction", &binding.direction)
                .field("frame_len", byte_len)
                .finish(),
            Self::Close { path_id, direction } => formatter
                .debug_struct("Close")
                .field("path_id", path_id)
                .field("direction", direction)
                .finish(),
        }
    }
}

impl ScheduledAction {
    fn byte_len(&self) -> usize {
        match self {
            Self::Payload { datagram, .. } => datagram.len(),
            Self::Control { byte_len, .. } => *byte_len,
            Self::Close { .. } => 0,
        }
    }

    fn path_and_direction(&self) -> (PathId, Direction) {
        match self {
            Self::Payload { binding, .. } | Self::Control { binding, .. } => {
                (binding.path_id, binding.direction)
            }
            Self::Close { path_id, direction } => (*path_id, *direction),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ScheduledEvent {
    time_ms: u64,
    ordinal: u64,
    action: ScheduledAction,
}

impl fmt::Debug for ScheduledEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScheduledEvent")
            .field("time_ms", &self.time_ms)
            .field("ordinal", &self.ordinal)
            .field("action", &self.action)
            .finish()
    }
}

pub struct Scenario {
    queue_limits: QueueLimits,
    queued_bytes: usize,
    next_ordinal: u64,
    events: VecDeque<ScheduledEvent>,
}

impl fmt::Debug for Scenario {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Scenario")
            .field("queue_limits", &self.queue_limits)
            .field("queued_bytes", &self.queued_bytes)
            .field("next_ordinal", &self.next_ordinal)
            .field("events", &self.events)
            .finish()
    }
}

impl Scenario {
    pub fn new(queue_limits: QueueLimits) -> Self {
        Self {
            queue_limits,
            queued_bytes: 0,
            next_ordinal: 0,
            events: VecDeque::new(),
        }
    }

    fn schedule(&mut self, time_ms: u64, action: ScheduledAction) -> Result<u64, QueueDropReason> {
        self.can_schedule(1, action.byte_len())?;
        let ordinal = self.next_ordinal;
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        let event = ScheduledEvent {
            time_ms,
            ordinal,
            action,
        };
        let position = self
            .events
            .iter()
            .position(|existing| (existing.time_ms, existing.ordinal) > (time_ms, ordinal))
            .unwrap_or(self.events.len());
        self.queued_bytes = self.queued_bytes.saturating_add(event.action.byte_len());
        self.events.insert(position, event);
        Ok(ordinal)
    }

    fn pop_due(&mut self, now_ms: u64) -> Option<ScheduledEvent> {
        if self.events.front().is_none_or(|event| event.time_ms > now_ms) {
            return None;
        }
        let event = self.events.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(event.action.byte_len());
        Some(event)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn scheduled_keys(&self) -> impl ExactSizeIterator<Item = (u64, u64)> + '_ {
        self.events.iter().map(|event| (event.time_ms, event.ordinal))
    }

    fn can_schedule(&self, count: usize, byte_len: usize) -> Result<(), QueueDropReason> {
        if self.events.len().saturating_add(count) > self.queue_limits.packets {
            return Err(QueueDropReason::CapacityExceeded {
                resource: QueueResource::Packets,
            });
        }
        if self.queued_bytes.saturating_add(byte_len) > self.queue_limits.bytes {
            return Err(QueueDropReason::CapacityExceeded {
                resource: QueueResource::Bytes,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PathDirectionState {
    prng: DeterministicPrng,
    queued_packets: usize,
    queued_bytes: usize,
    closed: bool,
    last_control_delivery_ms: u64,
}

impl PathDirectionState {
    fn new(seed: u64) -> Self {
        Self {
            prng: DeterministicPrng::new(seed),
            queued_packets: 0,
            queued_bytes: 0,
            closed: false,
            last_control_delivery_ms: 0,
        }
    }
}

#[derive(Debug)]
struct SimPath {
    profile: PathProfile,
    client_to_gateway: PathDirectionState,
    gateway_to_client: PathDirectionState,
}

impl SimPath {
    fn state(&self, direction: Direction) -> &PathDirectionState {
        match direction {
            Direction::ClientToGateway => &self.client_to_gateway,
            Direction::GatewayToClient => &self.gateway_to_client,
        }
    }

    fn state_mut(&mut self, direction: Direction) -> &mut PathDirectionState {
        match direction {
            Direction::ClientToGateway => &mut self.client_to_gateway,
            Direction::GatewayToClient => &mut self.gateway_to_client,
        }
    }
}

/// A deterministic V2 test harness. Call [`Self::advance_to`] manually to
/// process scheduled events; the harness does not run an executor.
pub struct Netem {
    clock: SimClock,
    scenario: Scenario,
    config: NetemConfig,
    paths: BTreeMap<u16, SimPath>,
    gateway: ScriptedGateway,
    diagnostic: ReproducibilityDiagnostic,
    log: EventLog,
    path_capacity_rejections: u64,
}

impl Netem {
    pub fn new(
        scenario_name: &str,
        seed: u64,
        config: NetemConfig,
        gateway: ScriptedGateway,
    ) -> Result<Self, NetemCreateError> {
        if scenario_name.len() > config.scenario_name_max_len {
            return Err(NetemCreateError::ScenarioNameTooLong {
                length: scenario_name.len(),
                maximum: config.scenario_name_max_len,
            });
        }
        Ok(Self {
            clock: SimClock::new(0),
            scenario: Scenario::new(config.scenario_queue_limits),
            log: EventLog::new(config.event_log_capacity),
            config,
            paths: BTreeMap::new(),
            gateway,
            diagnostic: ReproducibilityDiagnostic {
                scenario_name: scenario_name.to_owned(),
                seed,
            },
            path_capacity_rejections: 0,
        })
    }

    pub fn add_path(&mut self, path_id: PathId, profile: PathProfile) -> Result<(), AddPathError> {
        profile.validate().map_err(AddPathError::Profile)?;
        if self.paths.contains_key(&path_id.get()) {
            return Err(AddPathError::DuplicatePath(path_id));
        }
        if self.paths.len() == self.config.path_capacity {
            self.path_capacity_rejections = self.path_capacity_rejections.saturating_add(1);
            return Err(AddPathError::CapacityExceeded);
        }
        let close_count = [Direction::ClientToGateway, Direction::GatewayToClient]
            .iter()
            .filter(|direction| profile.for_direction(**direction).connection_loss_at_ms.is_some())
            .count();
        self.scenario
            .can_schedule(close_count, 0)
            .map_err(AddPathError::Capacity)?;
        let client_seed = derive_seed(self.diagnostic.seed, path_id, Direction::ClientToGateway);
        let gateway_seed = derive_seed(self.diagnostic.seed, path_id, Direction::GatewayToClient);
        self.paths.insert(
            path_id.get(),
            SimPath {
                profile,
                client_to_gateway: PathDirectionState::new(client_seed),
                gateway_to_client: PathDirectionState::new(gateway_seed),
            },
        );
        for direction in [Direction::ClientToGateway, Direction::GatewayToClient] {
            if let Some(time_ms) = profile.for_direction(direction).connection_loss_at_ms {
                let close_at_ms = time_ms.max(self.clock.now_ms());
                self.scenario
                    .schedule(close_at_ms, ScheduledAction::Close { path_id, direction })
                    .map_err(AddPathError::Capacity)?;
            }
        }
        self.drain_due_at_current_time().map_err(AddPathError::Clock)?;
        Ok(())
    }

    /// Picks the lowest attached, non-failed path for deterministic harness
    /// tests only. This is not the V2 scheduler planned for WP-602.
    pub fn choose_lowest_healthy_path(&self, direction: Direction) -> Option<PathId> {
        self.paths
            .iter()
            .find(|(_, path)| !path.state(direction).closed)
            .map(|(path_id, _)| PathId::new(*path_id))
    }

    /// Sends through [`Self::choose_lowest_healthy_path`] using a supplied,
    /// already post-admission binding. This is a deterministic test seam only.
    pub fn send_payload_on_lowest_healthy_path(
        &mut self,
        bindings: &[PostAdmissionBinding],
        direction: Direction,
        datagram: Bytes,
        deadline_ms: Option<u64>,
    ) -> SendOutcome {
        let Some(path_id) = self.choose_lowest_healthy_path(direction) else {
            return SendOutcome::Dropped(SendDropReason::ConnectionClosed);
        };
        let Some(binding) = bindings
            .iter()
            .copied()
            .find(|binding| binding.path_id == path_id && binding.direction == direction)
        else {
            return SendOutcome::Dropped(SendDropReason::ConnectionClosed);
        };
        self.send_payload(binding, datagram, deadline_ms)
    }

    pub fn send_payload(
        &mut self,
        binding: PostAdmissionBinding,
        datagram: Bytes,
        deadline_ms: Option<u64>,
    ) -> SendOutcome {
        let now_ms = self.clock.now_ms();
        let Some(path) = self.paths.get_mut(&binding.path_id.get()) else {
            return SendOutcome::Dropped(SendDropReason::ConnectionClosed);
        };
        let profile = path.profile.for_direction(binding.direction);
        let state = path.state_mut(binding.direction);
        if state.closed || profile.connection_loss_at_ms.is_some_and(|loss_at| now_ms >= loss_at) {
            return self.drop(binding, SendDropReason::ConnectionClosed);
        }
        if datagram.len() > profile.datagram_mtu {
            return self.drop(
                binding,
                SendDropReason::MtuExceeded {
                    datagram_len: datagram.len(),
                    mtu: profile.datagram_mtu,
                },
            );
        }
        if state.prng.chance(profile.loss_ppm) {
            return self.drop(binding, SendDropReason::SimulatedLoss);
        }
        let copies = if state.prng.chance(profile.duplicate_ppm) { 2 } else { 1 };
        let delivery_at_ms = jittered_delivery(now_ms, profile, &mut state.prng);
        if deadline_ms.is_some_and(|deadline| delivery_at_ms > deadline) {
            return self.drop(
                binding,
                SendDropReason::DeliveryDeadlineExceeded {
                    delivery_at_ms,
                    deadline_ms: deadline_ms.unwrap_or_default(),
                },
            );
        }
        let total_bytes = datagram.len().saturating_mul(copies as usize);
        if let Err(reason) = self
            .config
            .path_queue_limits
            .accepts(state.queued_packets, state.queued_bytes, total_bytes)
        {
            return self.drop(binding, reason.into());
        }
        if let Err(reason) = self.scenario.can_schedule(copies as usize, total_bytes) {
            return self.drop(binding, reason.into());
        }
        let mut ordinals = Vec::with_capacity(copies as usize);
        for _ in 0..copies {
            let ordinal = match self.scenario.schedule(
                delivery_at_ms,
                ScheduledAction::Payload {
                    binding,
                    datagram: datagram.clone(),
                },
            ) {
                Ok(ordinal) => ordinal,
                Err(reason) => return self.drop(binding, reason.into()),
            };
            state.queued_packets = state.queued_packets.saturating_add(1);
            state.queued_bytes = state.queued_bytes.saturating_add(datagram.len());
            ordinals.push(ordinal);
        }
        for ordinal in ordinals {
            self.record(
                delivery_at_ms,
                ordinal,
                binding.path_id,
                binding.direction,
                EventKind::PayloadQueued,
            );
        }
        SendOutcome::Queued {
            path_id: binding.path_id,
            copies,
            delivery_at_ms,
        }
    }

    /// Schedules one reliable ordered control frame. Payload loss, duplication,
    /// jitter, and datagram MTU do not affect control delivery; a path close does.
    pub fn send_control(&mut self, binding: PostAdmissionBinding, frame: ControlFrame) -> SendOutcome {
        let now_ms = self.clock.now_ms();
        let Some(path) = self.paths.get_mut(&binding.path_id.get()) else {
            return SendOutcome::Dropped(SendDropReason::ConnectionClosed);
        };
        let profile = path.profile.for_direction(binding.direction);
        let state = path.state_mut(binding.direction);
        if state.closed || profile.connection_loss_at_ms.is_some_and(|loss_at| now_ms >= loss_at) {
            return self.drop(binding, SendDropReason::ConnectionClosed);
        }
        let byte_len = match frame.encode(Default::default()) {
            Ok(frame) => frame.len(),
            Err(_) => return self.drop(binding, SendDropReason::CapacityExceeded { resource: QueueResource::Bytes }),
        };
        if let Err(reason) = self
            .config
            .path_queue_limits
            .accepts(state.queued_packets, state.queued_bytes, byte_len)
        {
            return self.drop(binding, reason.into());
        }
        let delivery_at_ms = now_ms
            .saturating_add(profile.latency_ms)
            .max(state.last_control_delivery_ms);
        let ordinal = match self.scenario.schedule(
            delivery_at_ms,
            ScheduledAction::Control {
                binding,
                frame,
                byte_len,
            },
        ) {
            Ok(ordinal) => ordinal,
            Err(reason) => return self.drop(binding, reason.into()),
        };
        state.queued_packets = state.queued_packets.saturating_add(1);
        state.queued_bytes = state.queued_bytes.saturating_add(byte_len);
        state.last_control_delivery_ms = delivery_at_ms;
        self.record(
            delivery_at_ms,
            ordinal,
            binding.path_id,
            binding.direction,
            EventKind::ControlQueued,
        );
        SendOutcome::Queued {
            path_id: binding.path_id,
            copies: 1,
            delivery_at_ms,
        }
    }

    pub fn advance_to(&mut self, now_ms: u64) -> Result<(), ClockError> {
        if now_ms < self.clock.now_ms() {
            return Err(ClockError::CannotMoveBackwards {
                now_ms: self.clock.now_ms(),
                requested_ms: now_ms,
            });
        }
        while let Some(event) = self.scenario.pop_due(now_ms) {
            self.clock.advance_to(event.time_ms)?;
            self.process(event);
        }
        self.clock.advance_to(now_ms)?;
        Ok(())
    }

    pub fn advance_by(&mut self, elapsed_ms: u64) -> Result<(), ClockError> {
        let target_ms = self.clock.now_ms().saturating_add(elapsed_ms);
        self.advance_to(target_ms)
    }

    fn drain_due_at_current_time(&mut self) -> Result<(), ClockError> {
        while let Some(event) = self.scenario.pop_due(self.clock.now_ms()) {
            self.clock.advance_to(event.time_ms)?;
            self.process(event);
        }
        Ok(())
    }

    fn process(&mut self, event: ScheduledEvent) {
        let time_ms = event.time_ms;
        let ordinal = event.ordinal;
        let (path_id, direction) = event.action.path_and_direction();
        match event.action {
            ScheduledAction::Close { .. } => {
                if let Some(path) = self.paths.get_mut(&path_id.get()) {
                    path.state_mut(direction).closed = true;
                }
                self.record(time_ms, ordinal, path_id, direction, EventKind::ConnectionLost);
            }
            ScheduledAction::Payload { binding, datagram } => {
                self.release_path_queue(path_id, direction, datagram.len());
                if self.path_closed(path_id, direction) {
                    self.record(
                        time_ms,
                        ordinal,
                        path_id,
                        direction,
                        EventKind::PayloadDropped(SendDropReason::ConnectionClosed),
                    );
                    return;
                }
                match self.gateway.receive_payload(binding, datagram) {
                    GatewayOutcome::DeliveredToTun => self.record(time_ms, ordinal, path_id, direction, EventKind::PayloadDelivered),
                    GatewayOutcome::Dropped(_) => self.record(time_ms, ordinal, path_id, direction, EventKind::GatewayDropped),
                };
            }
            ScheduledAction::Control {
                binding,
                frame,
                byte_len,
            } => {
                self.release_path_queue(path_id, direction, byte_len);
                if self.path_closed(path_id, direction) {
                    self.record(time_ms, ordinal, path_id, direction, EventKind::ControlTerminated);
                    return;
                }
                match self.gateway.receive_control(binding, frame) {
                    GatewayOutcome::DeliveredToTun => self.record(time_ms, ordinal, path_id, direction, EventKind::ControlDelivered),
                    GatewayOutcome::Dropped(_) => self.record(time_ms, ordinal, path_id, direction, EventKind::GatewayDropped),
                };
            }
        }
    }

    fn release_path_queue(&mut self, path_id: PathId, direction: Direction, byte_len: usize) {
        if let Some(path) = self.paths.get_mut(&path_id.get()) {
            let state = path.state_mut(direction);
            state.queued_packets = state.queued_packets.saturating_sub(1);
            state.queued_bytes = state.queued_bytes.saturating_sub(byte_len);
        }
    }

    fn path_closed(&self, path_id: PathId, direction: Direction) -> bool {
        self.paths
            .get(&path_id.get())
            .is_none_or(|path| path.state(direction).closed)
    }

    fn drop(&mut self, binding: PostAdmissionBinding, reason: SendDropReason) -> SendOutcome {
        self.record(
            self.clock.now_ms(),
            self.scenario.next_ordinal,
            binding.path_id,
            binding.direction,
            EventKind::PayloadDropped(reason),
        );
        SendOutcome::Dropped(reason)
    }

    fn record(
        &mut self,
        time_ms: u64,
        ordinal: u64,
        path_id: PathId,
        direction: Direction,
        kind: EventKind,
    ) -> EventLogOutcome {
        self.log.record(Event {
            time_ms,
            ordinal,
            path_id,
            direction,
            kind,
        })
    }

    pub const fn clock(&self) -> SimClock {
        self.clock
    }

    pub fn scenario(&self) -> &Scenario {
        &self.scenario
    }

    pub fn gateway(&self) -> &ScriptedGateway {
        &self.gateway
    }

    pub fn gateway_mut(&mut self) -> &mut ScriptedGateway {
        &mut self.gateway
    }

    pub fn events(&self) -> impl ExactSizeIterator<Item = &Event> {
        self.log.entries.iter()
    }

    pub const fn event_log_metrics(&self) -> EventLogMetrics {
        self.log.metrics
    }

    pub const fn last_event_log_outcome(&self) -> EventLogOutcome {
        self.log.last_outcome
    }

    pub fn metrics(&self) -> NetemMetrics {
        NetemMetrics {
            paths: self.paths.len(),
            path_capacity: self.config.path_capacity,
            path_capacity_rejections: self.path_capacity_rejections,
        }
    }

    pub fn reproducibility_diagnostic(&self) -> &ReproducibilityDiagnostic {
        &self.diagnostic
    }
}

impl fmt::Debug for Netem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Netem")
            .field("clock", &self.clock)
            .field("scenario", &self.scenario)
            .field("metrics", &self.metrics())
            .field("gateway", &self.gateway)
            .field("diagnostic", &self.diagnostic)
            .field("event_log_metrics", &self.log.metrics)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetemMetrics {
    pub paths: usize,
    pub path_capacity: usize,
    pub path_capacity_rejections: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetemCreateError {
    ScenarioNameTooLong { length: usize, maximum: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddPathError {
    Profile(ProfileError),
    DuplicatePath(PathId),
    Capacity(QueueDropReason),
    CapacityExceeded,
    Clock(ClockError),
}

#[derive(Debug)]
struct DeterministicPrng {
    state: u64,
}

impl DeterministicPrng {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut state = self.state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.state = state;
        state
    }

    fn chance(&mut self, ppm: u32) -> bool {
        if ppm == 0 {
            return false;
        }
        if ppm == PPM_DENOMINATOR {
            return true;
        }
        self.next_u64() % u64::from(PPM_DENOMINATOR) < u64::from(ppm)
    }

    fn jitter(&mut self, maximum_ms: u64) -> i64 {
        if maximum_ms == 0 {
            return 0;
        }
    let span = maximum_ms.saturating_mul(2).saturating_add(1);
    (self.next_u64() % span) as i64 - maximum_ms as i64
}
}

fn derive_seed(seed: u64, path_id: PathId, direction: Direction) -> u64 {
    let direction_tag = match direction {
        Direction::ClientToGateway => 0xC1E1_0001,
        Direction::GatewayToClient => 0x6A7E_0002,
    };
    let mut value = seed ^ (u64::from(path_id.get()) << 32) ^ direction_tag;
    value ^= value >> 30;
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn jittered_delivery(now_ms: u64, profile: DirectionalPathProfile, prng: &mut DeterministicPrng) -> u64 {
    let base = now_ms.saturating_add(profile.latency_ms);
    let jitter = prng.jitter(profile.jitter_ms);
    let delivery_at_ms = if jitter.is_negative() {
        base.saturating_sub(jitter.unsigned_abs())
    } else {
        base.saturating_add(jitter as u64)
    };
    delivery_at_ms.max(now_ms)
}
