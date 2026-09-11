//! V2-only checked path MTU, effective payload calculation, and whole-datagram
//! send admission (WP-302: checked whole MTU, no fallback, atomic pipeline).
//!
//! This module is strictly V2-only: it depends on the 52-byte V2 fixed header
//! and is never shared with V1 code. The core contract is:
//!
//! - [`DatagramMtu`] wraps the full QUIC datagram size including the fixed
//!   header and is validated at construction time.
//! - [`EffectivePayloadMtu`] is derived as `DatagramMtu - FIXED_HEADER_LEN`
//!   and represents the maximum application payload that fits in one datagram.
//!   The primary construction path is [`DatagramMtu::effective_payload`];
//!   [`EffectivePayloadMtu::new`] exists for engine construction from a
//!   validated TUN config value and carries a debug assertion.
//! - [`PathMtuState`] models the engine-level policy lifecycle: Unknown →
//!   Available → Reduced → BlackHole, with explicit typed transitions.
//!   [`PathMtuState::reduce`] only ever **lowers** the MTU; an equal or larger
//!   value is a typed no-op ([`MtuEvent::ReduceIgnored`]) that never replaces
//!   the current limit.
//! - [`MtuAdmission`] is the engine-owned admission gate. It validates a
//!   payload (or an already-encoded whole datagram) **before** packet-ID
//!   preview and before the transport send, so a rejected packet never
//!   previews an ID or advances a delivery counter. Engines construct the gate
//!   from the actual TUN config ([`MtuAdmission::with_tun_payload_mtu`])
//!   rather than relying on a V1-style implicit default. There is no
//!   admit-then-commit helper on the gate: callers that encode and send must
//!   use [`CheckedDatagramSender::send_checked`], which previews then commits
//!   only after a successful transport enqueue.
//! - [`MtuAdmission::sync_from_transport`] keeps the gate consistent with the
//!   transport's current advertised MTU on every send: the checked sender
//!   queries the transport's [`DatagramSender::current_datagram_mtu`] and
//!   syncs the gate before admission, so a stale cached limit cannot cause a
//!   send that exceeds the transport's actual bound.
//! - [`PacketIdSequencer`] is the engine-owned packet-ID counter for one send
//!   direction. It exposes no advancing method: [`PacketIdSequencer::next_value`]
//!   is a pure peek (`&self`), while preview and commit are private to this
//!   module. [`CheckedDatagramSender::send_checked`] takes `&mut` to the
//!   sequencer, fails fast with [`CheckedSendError::PacketIdExhausted`] when
//!   the sequencer is exhausted (before any gate mutation, preview, or
//!   transport enqueue), otherwise previews a single-use [`PacketReservation`]
//!   (non-advancing), hands it to the envelope builder, validates the built
//!   envelope carries the reserved ID (a substituted ID is rejected without
//!   commit), and commits only after the transport enqueue succeeds. Public
//!   callers own the sequencer but cannot advance it except through a
//!   successful checked send. IDs never wrap: issuing `u64::MAX` terminates
//!   the sequencer and the sender MUST rotate the key epoch (a new
//!   [`PacketIdSequencer`] under a new key epoch) to continue; there is
//!   deliberately no reset/unexhaust method.
//! - [`DatagramSender`] + [`CheckedDatagramSender`] are the V2-only sender
//!   interface. [`CheckedDatagramSender::send_checked`] is the **atomic
//!   pipeline**: query transport MTU → sync gate → admit payload → **preview**
//!   a reservation (pure peek, never advances) → build envelope from the
//!   reservation → validate the envelope ID → encode → transport send → **commit**
//!   the reservation **only after** the transport enqueue succeeds. A failed
//!   build validation, encode, or transport rejection leaves the sequencer
//!   uncommitted, so the sequencer/delivery counters never advance for a
//!   packet that was never enqueued. There is no way to bypass this with a
//!   pre-built ID or pre-built envelope. Raw transport send requires a
//!   [`CheckedSendPermit`] that only the checked sender can construct, so a
//!   public [`DatagramSender`] handle cannot bypass admission.
//! - **No fallback**: an unknown, disabled, or not-yet-negotiated datagram
//!   limit is `None` and propagates as admission-denied. Unlike V1
//!   `PathTransport::send` (which keeps `unwrap_or(1200)`), V2 never
//!   synthesizes a 1200-byte limit.
//!
//! Safe Mode defaults:
//! - [`SAFE_MODE_MIN_DATAGRAM_MTU`] = 1352 (whole datagram including header).
//! - [`SAFE_MODE_MIN_PAYLOAD_MTU`] = 1300 (= 1352 − 52).
//!
//! # Bounds and time
//!
//! Every metric and counter uses saturating arithmetic. Metrics never contain
//! packet payloads, session IDs, IP addresses, or port numbers.
//!
//! # Observability
//!
//! [`MtuMetrics`] separates gate attempts (`sends_admitted`) from successful
//! transport enqueues (`sends_enqueued`): a failed encode or a transport
//! rejection increments `encode_failures`/`transport_failures` and never
//! increments `sends_enqueued`. [`MtuEvent`] captures state
//! transitions for the engine policy log without retaining packet content.

use bytes::Bytes;
use sg_core::v2::PacketId;
use sg_protocol::v2::{FIXED_HEADER_LEN, PayloadLimit, V2Envelope, V2EnvelopeError};
use thiserror::Error;

use crate::async_trait;

// ---------------------------------------------------------------------------
// Safe Mode constants
// ---------------------------------------------------------------------------

/// Minimum whole-datagram MTU for Safe Mode. This is the QUIC datagram size
/// including the 52-byte V2 fixed header. Chosen to carry the IPv6 minimum
/// (1280) plus a 72-byte safety margin for encapsulation overhead observed on
/// real paths; this value must not be lowered without re-validating on the
/// target link layer.
pub const SAFE_MODE_MIN_DATAGRAM_MTU: usize = 1352;

/// Minimum effective payload MTU for Safe Mode (1352 − 52 = 1300). This is
/// the TUN MTU advertised to the OS before path discovery completes.
pub const SAFE_MODE_MIN_PAYLOAD_MTU: usize = 1300;

/// Maximum datagram MTU. This is the practical upper bound for a single QUIC
/// datagram on any supported path; values above this are rejected at
/// construction rather than silently truncating.
pub const MAX_DATAGRAM_MTU: usize = 65_535;

// ---------------------------------------------------------------------------
// Checked types
// ---------------------------------------------------------------------------

/// A validated V2 datagram MTU (the full datagram including the 52-byte fixed
/// header). Values below [`FIXED_HEADER_LEN`] or above [`MAX_DATAGRAM_MTU`]
/// are rejected at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramMtu(usize);

/// A validated maximum payload that fits in one V2 datagram. Derived as
/// `DatagramMtu − FIXED_HEADER_LEN` (therefore always ≥ 0 and always converts
/// back to a valid datagram MTU).
///
/// Construction is private: the only checked way to obtain a value is
/// [`DatagramMtu::effective_payload`], so a value can never be created that
/// reverses into an invalid datagram MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectivePayloadMtu(usize);

/// Why a [`DatagramMtu`] could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DatagramMtuError {
    /// The value is below the minimum datagram size (must hold the V2 header).
    #[error("datagram MTU {value} is below the minimum {minimum}")]
    BelowMinimum { value: usize, minimum: usize },
    /// The value exceeds the practical upper bound.
    #[error("datagram MTU {value} exceeds the maximum {maximum}")]
    AboveMaximum { value: usize, maximum: usize },
}

impl DatagramMtu {
    /// Creates a validated datagram MTU. Rejects values outside
    /// `[FIXED_HEADER_LEN, MAX_DATAGRAM_MTU]`.
    pub const fn new(value: usize) -> Result<Self, DatagramMtuError> {
        if value < FIXED_HEADER_LEN {
            return Err(DatagramMtuError::BelowMinimum {
                value,
                minimum: FIXED_HEADER_LEN,
            });
        }
        if value > MAX_DATAGRAM_MTU {
            return Err(DatagramMtuError::AboveMaximum {
                value,
                maximum: MAX_DATAGRAM_MTU,
            });
        }
        Ok(Self(value))
    }

    /// The whole-datagram MTU in bytes.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }

    /// The effective payload MTU derived from this datagram MTU.
    #[must_use]
    pub const fn effective_payload(self) -> EffectivePayloadMtu {
        // SAFETY: `new` guarantees self.0 >= FIXED_HEADER_LEN, so the
        // subtraction cannot underflow.
        EffectivePayloadMtu(self.0 - FIXED_HEADER_LEN)
    }
}

impl EffectivePayloadMtu {
    /// Creates an effective payload MTU from a validated TUN config value.
    ///
    /// This constructor exists for engine construction from the actual
    /// [`sg_tun::TunConfig::mtu`] (the safe-mode default is 1300). The debug
    /// assertion guards against a value that reverses into an invalid datagram
    /// MTU; production paths should prefer [`DatagramMtu::effective_payload`].
    #[must_use]
    pub fn new(payload_bytes: usize) -> Self {
        debug_assert!(
            payload_bytes + FIXED_HEADER_LEN <= MAX_DATAGRAM_MTU,
            "EffectivePayloadMtu must correspond to a valid DatagramMtu"
        );
        Self(payload_bytes)
    }

    /// The maximum payload bytes that fit in one datagram.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Derives the corresponding datagram MTU.
    ///
    /// No unchecked constructor exists: every value is derived from a
    /// validated [`DatagramMtu`], so `self.0 + FIXED_HEADER_LEN` is always in
    /// `[FIXED_HEADER_LEN, MAX_DATAGRAM_MTU]`. The debug assertion guards
    /// against a future regression that broadens construction.
    #[must_use]
    pub const fn datagram_mtu(self) -> DatagramMtu {
        debug_assert!(
            self.0 + FIXED_HEADER_LEN <= MAX_DATAGRAM_MTU,
            "EffectivePayloadMtu must be derived from a validated DatagramMtu"
        );
        DatagramMtu(self.0 + FIXED_HEADER_LEN)
    }
}

// ---------------------------------------------------------------------------
// Engine-level path MTU state
// ---------------------------------------------------------------------------

/// Per-path MTU state for the engine policy layer. Models the lifecycle
/// without carrying packet data or sequencing state.
///
/// Transitions:
/// ```text
/// Unknown → Available   (path discovery returns a concrete MTU)
/// Available → Reduced   (PMTUD detected a smaller MTU; never larger)
/// Available → BlackHole  (all sends fail, no recovery signal)
/// Reduced → BlackHole   (further degradation)
/// BlackHole → Available  (path re-discovery succeeds)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMtuState {
    /// MTU not yet discovered; send admission is denied.
    Unknown,
    /// MTU known; sends admitted up to [`EffectivePayloadMtu`].
    Available {
        datagram_mtu: DatagramMtu,
        effective: EffectivePayloadMtu,
    },
    /// MTU reduced from a previous value; still usable but the path is
    /// degraded. The `previous` field records the last-known-good MTU so
    /// the health engine can decide whether to re-probe.
    Reduced {
        datagram_mtu: DatagramMtu,
        effective: EffectivePayloadMtu,
        previous: DatagramMtu,
    },
    /// Complete MTU black hole: every send would exceed the path MTU or
    /// no MTU is known. Send admission is denied until re-discovery.
    BlackHole,
}

impl PathMtuState {
    /// The effective payload MTU if the path is sendable, or `None` for
    /// Unknown/BlackHole.
    #[must_use]
    pub const fn effective_payload(&self) -> Option<EffectivePayloadMtu> {
        match self {
            Self::Available { effective, .. } | Self::Reduced { effective, .. } => Some(*effective),
            Self::Unknown | Self::BlackHole => None,
        }
    }

    /// The whole-datagram MTU if known, or `None`.
    #[must_use]
    pub const fn datagram_mtu(&self) -> Option<DatagramMtu> {
        match self {
            Self::Available { datagram_mtu, .. } | Self::Reduced { datagram_mtu, .. } => {
                Some(*datagram_mtu)
            }
            Self::Unknown | Self::BlackHole => None,
        }
    }

    /// True when send admission should be denied (Unknown or BlackHole).
    #[must_use]
    pub const fn send_denied(&self) -> bool {
        matches!(self, Self::Unknown | Self::BlackHole)
    }

    /// Transitions Unknown → Available with a discovered MTU.
    ///
    /// Returns the new state and an [`MtuEvent`] for the policy log.
    pub fn discover(self, mtu: DatagramMtu) -> (Self, MtuEvent) {
        let effective = mtu.effective_payload();
        let event = MtuEvent::MtuDiscovered {
            datagram_mtu: mtu.get(),
        };
        (
            Self::Available {
                datagram_mtu: mtu,
                effective,
            },
            event,
        )
    }

    /// Transitions Available/Reduced → Reduced **only when the new MTU is
    /// strictly smaller**. An equal or larger value never replaces the current
    /// limit: it returns the unchanged state plus [`MtuEvent::ReduceIgnored`]
    /// (a typed no-op), so a stale PMTUD report cannot raise the limit.
    ///
    /// Returns the new state and an [`MtuEvent`] for the policy log.
    pub fn reduce(self, new_mtu: DatagramMtu) -> (Self, MtuEvent) {
        let previous = match self {
            Self::Available { datagram_mtu, .. } | Self::Reduced { datagram_mtu, .. } => {
                datagram_mtu
            }
            Self::Unknown | Self::BlackHole => return (self, MtuEvent::NoOp),
        };
        if new_mtu.get() >= previous.get() {
            return (
                self,
                MtuEvent::ReduceIgnored {
                    requested: new_mtu.get(),
                    current: previous.get(),
                },
            );
        }
        let effective = new_mtu.effective_payload();
        let event = MtuEvent::MtuReduced {
            previous: previous.get(),
            current: new_mtu.get(),
        };
        (
            Self::Reduced {
                datagram_mtu: new_mtu,
                effective,
                previous,
            },
            event,
        )
    }

    /// Transitions Available/Reduced → BlackHole when all sends fail.
    ///
    /// Returns the new state and an [`MtuEvent`] for the policy log.
    pub fn blackhole(self) -> (Self, MtuEvent) {
        if self.send_denied() {
            return (self, MtuEvent::NoOp);
        }
        (
            Self::BlackHole,
            MtuEvent::MtuBlackHole,
        )
    }

    /// Recovers from BlackHole → Available with a re-discovered MTU.
    ///
    /// Returns the new state and an [`MtuEvent`] for the policy log.
    pub fn recover(self, mtu: DatagramMtu) -> (Self, MtuEvent) {
        if !matches!(self, Self::BlackHole) {
            return (self, MtuEvent::NoOp);
        }
        self.discover(mtu)
    }
}

// ---------------------------------------------------------------------------
// Send admission gate
// ---------------------------------------------------------------------------

/// Why a send was rejected at the MTU admission gate. The packet ID and
/// delivery counter must NOT be advanced when any of these is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MtuRejectReason {
    /// The envelope payload is empty; such a datagram can never be encoded.
    #[error("V2 datagram payload must not be empty")]
    EmptyPayload,
    /// Payload exceeds the effective payload MTU for the selected path.
    #[error("payload of {payload_len} bytes exceeds the effective payload MTU {effective_mtu}")]
    PayloadExceedsMtu {
        payload_len: usize,
        effective_mtu: usize,
    },
    /// The whole datagram (fixed header + payload) exceeds the path datagram MTU.
    #[error("whole V2 datagram of {datagram_len} bytes exceeds the path datagram MTU {datagram_mtu}")]
    DatagramExceedsMtu {
        datagram_len: usize,
        datagram_mtu: usize,
    },
    /// A whole datagram shorter than the V2 fixed header is not a valid V2 datagram.
    #[error("whole V2 datagram of {datagram_len} bytes is shorter than the {minimum} byte fixed header")]
    DatagramBelowHeader {
        datagram_len: usize,
        minimum: usize,
    },
    /// Path MTU is unknown (path discovery not yet complete).
    #[error("path MTU is unknown; discovery is incomplete")]
    PathMtuUnknown,
    /// Path is in BlackHole state; no MTU is usable.
    #[error("path MTU is in blackhole state")]
    PathMtuBlackHole,
}

/// Validates a payload length against the current [`PathMtuState`] without
/// touching the sequencer, packet-ID counter, or transport. Returns `Ok(())`
/// when the payload fits, or [`MtuRejectReason`] when it must be dropped.
///
/// This gate MUST be called **before** any packet-ID preview or commit (the
/// checked pipeline calls it internally before previewing from
/// [`PacketIdSequencer`]) so a rejected packet never advances delivery
/// counters.
pub fn check_payload(
    payload_len: usize,
    state: &PathMtuState,
) -> Result<EffectivePayloadMtu, MtuRejectReason> {
    if payload_len == 0 {
        return Err(MtuRejectReason::EmptyPayload);
    }
    match state {
        PathMtuState::Unknown => Err(MtuRejectReason::PathMtuUnknown),
        PathMtuState::BlackHole => Err(MtuRejectReason::PathMtuBlackHole),
        PathMtuState::Available { effective, .. }
        | PathMtuState::Reduced { effective, .. } => {
            if payload_len > effective.get() {
                Err(MtuRejectReason::PayloadExceedsMtu {
                    payload_len,
                    effective_mtu: effective.get(),
                })
            } else {
                Ok(*effective)
            }
        }
    }
}

/// Validates a whole-datagram length (fixed header + payload) against the
/// current [`PathMtuState`]. This is the exact check a V2 datagram sender must
/// perform **before** encoding and transport send: the advertised path limit
/// is a whole-datagram bound, and no 1200-byte fallback exists.
///
/// Callers that have a payload (not yet a datagram) should prefer
/// [`check_payload`]; the two agree whenever `datagram_len ==
/// FIXED_HEADER_LEN + payload_len` and the datagram MTU is at least the
/// safe-mode minimum.
pub fn check_datagram(
    datagram_len: usize,
    state: &PathMtuState,
) -> Result<DatagramMtu, MtuRejectReason> {
    if datagram_len < FIXED_HEADER_LEN {
        return Err(MtuRejectReason::DatagramBelowHeader {
            datagram_len,
            minimum: FIXED_HEADER_LEN,
        });
    }
    match state {
        PathMtuState::Unknown => Err(MtuRejectReason::PathMtuUnknown),
        PathMtuState::BlackHole => Err(MtuRejectReason::PathMtuBlackHole),
        PathMtuState::Available { datagram_mtu, .. }
        | PathMtuState::Reduced { datagram_mtu, .. } => {
            if datagram_len > datagram_mtu.get() {
                Err(MtuRejectReason::DatagramExceedsMtu {
                    datagram_len,
                    datagram_mtu: datagram_mtu.get(),
                })
            } else {
                Ok(*datagram_mtu)
            }
        }
    }
}

/// Structured MTU admission result including the effective payload MTU when
/// admitted, for callers that need the value downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionResult {
    /// The effective payload MTU the path is currently advertising.
    pub effective_mtu: EffectivePayloadMtu,
}

/// Validates a payload length and returns the effective MTU on success.
/// This is the checked entry point that engines and test harnesses use.
///
/// A rejection result carries [`MtuRejectReason`] and means the caller MUST
/// NOT advance any packet-ID, sequence, or delivery counter.
pub fn admit_payload(
    payload_len: usize,
    state: &PathMtuState,
    metrics: &mut MtuMetrics,
) -> Result<AdmissionResult, MtuRejectReason> {
    match check_payload(payload_len, state) {
        Ok(effective) => {
            metrics.sends_admitted = metrics.sends_admitted.saturating_add(1);
            Ok(AdmissionResult { effective_mtu: effective })
        }
        Err(reason) => {
            metrics.sends_rejected = metrics.sends_rejected.saturating_add(1);
            Err(reason)
        }
    }
}

/// Structured whole-datagram admission result, for callers that need the
/// advertised datagram MTU downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramAdmissionResult {
    /// The whole-datagram MTU the path is currently advertising.
    pub datagram_mtu: DatagramMtu,
}

/// Validates a whole-datagram length and returns the advertised datagram MTU
/// on success. A rejection means the caller MUST NOT transport the datagram
/// and MUST NOT advance any packet-ID, sequence, or delivery counter.
pub fn admit_datagram(
    datagram_len: usize,
    state: &PathMtuState,
    metrics: &mut MtuMetrics,
) -> Result<DatagramAdmissionResult, MtuRejectReason> {
    match check_datagram(datagram_len, state) {
        Ok(datagram_mtu) => {
            metrics.sends_admitted = metrics.sends_admitted.saturating_add(1);
            Ok(DatagramAdmissionResult { datagram_mtu })
        }
        Err(reason) => {
            metrics.sends_rejected = metrics.sends_rejected.saturating_add(1);
            Err(reason)
        }
    }
}

/// Engine-owned MTU admission gate (WP-302).
///
/// Owns the per-path [`PathMtuState`], the admission [`MtuMetrics`], and the
/// conservative TUN payload MTU the path must be able to carry to stay
/// eligible as an active path. All transitions and admissions route through
/// this one structure so the engine can answer "may I sequence this packet?"
/// and "may this path remain active?" from one authoritative source.
///
/// The default is the Safe Mode policy: MTU `Unknown` (sends denied) and a
/// TUN payload requirement of [`SAFE_MODE_MIN_PAYLOAD_MTU`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuAdmission {
    state: PathMtuState,
    metrics: MtuMetrics,
    tun_payload_mtu: EffectivePayloadMtu,
}

impl Default for MtuAdmission {
    fn default() -> Self {
        let tun_payload_mtu = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU)
            .expect("safe-mode minimum datagram MTU is valid by construction")
            .effective_payload();
        Self {
            state: PathMtuState::Unknown,
            metrics: MtuMetrics::default(),
            tun_payload_mtu,
        }
    }
}

impl MtuAdmission {
    /// Creates an admission gate from the actual TUN adapter MTU (the payload
    /// size the OS will generate, e.g. 1300 for safe-mode). This is the
    /// constructor V2 engines use instead of [`MtuAdmission::default`]: it
    /// wires the gate to the real advertised config rather than relying on a
    /// V1-style implicit value.
    ///
    /// The state starts `Unknown` (sends denied) until the path supervisor
    /// drives a discovery event.
    ///
    /// # Errors
    ///
    /// Returns [`DatagramMtuError`] if the corresponding datagram MTU
    /// (`tun_payload_mtu + FIXED_HEADER_LEN`) is outside the valid range.
    pub fn with_tun_payload_mtu(tun_payload_mtu: usize) -> Result<Self, DatagramMtuError> {
        // Validate that the corresponding datagram MTU is in range.
        let _ = DatagramMtu::new(tun_payload_mtu + FIXED_HEADER_LEN)?;
        Ok(Self {
            state: PathMtuState::Unknown,
            metrics: MtuMetrics::default(),
            tun_payload_mtu: EffectivePayloadMtu::new(tun_payload_mtu),
        })
    }

    /// The current per-path MTU state.
    #[must_use]
    pub const fn state(&self) -> PathMtuState {
        self.state
    }

    /// The admission counters owned by the gate.
    #[must_use]
    pub const fn metrics(&self) -> MtuMetrics {
        self.metrics
    }

    /// The conservative TUN payload MTU the path must keep carrying to stay
    /// eligible as an active path.
    #[must_use]
    pub const fn tun_payload_mtu(&self) -> EffectivePayloadMtu {
        self.tun_payload_mtu
    }

    /// True while the current path can still carry a full TUN-sized payload.
    /// Flipping to false is the typed signal the path supervisor keys path
    /// failover (or degraded mode) on after an MTU reduction.
    #[must_use]
    pub fn can_carry_tun_payload(&self) -> bool {
        self.state
            .effective_payload()
            .is_some_and(|effective| effective.get() >= self.tun_payload_mtu.get())
    }

    /// Records a discovered MTU and returns the policy event.
    pub fn discover(&mut self, mtu: DatagramMtu) -> MtuEvent {
        let (state, event) = self.state.discover(mtu);
        self.state = state;
        self.metrics.record_event(event);
        event
    }

    /// Records an MTU reduction report. Only strictly smaller values replace
    /// the current limit; equal/larger reports yield `ReduceIgnored`.
    pub fn reduce(&mut self, new_mtu: DatagramMtu) -> MtuEvent {
        let (state, event) = self.state.reduce(new_mtu);
        self.state = state;
        self.metrics.record_event(event);
        event
    }

    /// Records a blackhole detection.
    pub fn blackhole(&mut self) -> MtuEvent {
        let (state, event) = self.state.blackhole();
        self.state = state;
        self.metrics.record_event(event);
        event
    }

    /// Records MTU recovery after a blackhole.
    pub fn recover(&mut self, mtu: DatagramMtu) -> MtuEvent {
        let (state, event) = self.state.recover(mtu);
        self.state = state;
        self.metrics.record_event(event);
        event
    }

    /// Synchronizes the admission gate with the transport's current advertised
    /// MTU. The checked sender calls this on **every** send after querying
    /// [`DatagramSender::current_datagram_mtu`], ensuring the gate is never
    /// stale relative to the actual transport bound.
    ///
    /// Transition rules:
    /// - `Unknown` → `Available` (discover the transport's limit).
    /// - `Available`/`Reduced` with a strictly smaller transport MTU → `Reduced`.
    /// - `Available`/`Reduced` with an equal or larger transport MTU → no-op.
    /// - `BlackHole` → no-op (recovery requires an explicit [`recover`] call).
    ///
    /// Returns the policy event for the engine log.
    pub fn sync_from_transport(&mut self, transport_mtu: DatagramMtu) -> MtuEvent {
        match self.state {
            PathMtuState::Unknown => self.discover(transport_mtu),
            PathMtuState::Available { datagram_mtu, .. }
            | PathMtuState::Reduced { datagram_mtu, .. } => {
                if transport_mtu.get() < datagram_mtu.get() {
                    self.reduce(transport_mtu)
                } else {
                    MtuEvent::NoOp
                }
            }
            PathMtuState::BlackHole => MtuEvent::NoOp,
        }
    }

    /// Records a rejection for a transport that advertised **no** datagram
    /// limit (absent, disabled, or not yet negotiated). No fallback is
    /// applied; the caller must not allocate a packet ID or advance any
    /// counter. Counts in the `sends_rejected` bucket.
    pub fn reject_absent_transport_limit(&mut self) -> MtuRejectReason {
        self.metrics.sends_rejected = self.metrics.sends_rejected.saturating_add(1);
        MtuRejectReason::PathMtuUnknown
    }

    /// Admits a payload length at the gate. On success returns the effective
    /// payload MTU; on rejection the caller MUST NOT advance any packet-ID,
    /// sequence, or delivery counter.
    pub fn admit_payload(
        &mut self,
        payload_len: usize,
    ) -> Result<AdmissionResult, MtuRejectReason> {
        admit_payload(payload_len, &self.state, &mut self.metrics)
    }

    /// Admits a whole datagram length (fixed header + payload). This is the
    /// exact check the V2 sender runs before encoding and transport send.
    pub fn admit_datagram(
        &mut self,
        datagram_len: usize,
    ) -> Result<DatagramAdmissionResult, MtuRejectReason> {
        admit_datagram(datagram_len, &self.state, &mut self.metrics)
    }

    /// Single-accounting funnel for a V2 sender: validates that a payload is
    /// non-empty and that its whole datagram (`FIXED_HEADER_LEN + payload_len`)
    /// fits the current path limit, counting the gate attempt exactly once as
    /// admitted (`sends_admitted`) or rejected (`sends_rejected`). Returns the
    /// effective payload MTU for encoding on success.
    ///
    /// Gate admission is an attempt, not a delivery: only a successful
    /// transport enqueue increments `sends_enqueued` (via
    /// [`CheckedDatagramSender::send_checked`]). Encode and transport
    /// failures increment `encode_failures`/`transport_failures` and never
    /// increment `sends_enqueued`.
    pub fn admit_envelope(
        &mut self,
        payload_len: usize,
        datagram_len: usize,
    ) -> Result<EffectivePayloadMtu, MtuRejectReason> {
        if payload_len == 0 {
            self.metrics.sends_rejected = self.metrics.sends_rejected.saturating_add(1);
            return Err(MtuRejectReason::EmptyPayload);
        }
        admit_datagram(datagram_len, &self.state, &mut self.metrics)
            .map(|result| result.datagram_mtu.effective_payload())
    }

    /// Records a successful transport enqueue after admission. Only
    /// [`CheckedDatagramSender::send_checked`] calls this, on the success
    /// path after the transport accepted the datagram.
    fn record_enqueue_success(&mut self) {
        self.metrics.sends_enqueued = self.metrics.sends_enqueued.saturating_add(1);
    }

    /// Records an encode failure after admission. The previewed packet ID is
    /// never committed and `sends_enqueued` is never incremented.
    fn record_encode_failure(&mut self) {
        self.metrics.encode_failures = self.metrics.encode_failures.saturating_add(1);
    }

    /// Records a transport rejection after admission. The previewed packet ID
    /// is never committed and `sends_enqueued` is never incremented.
    fn record_transport_failure(&mut self) {
        self.metrics.transport_failures = self.metrics.transport_failures.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// Engine-owned packet-ID sequencer and single-use reservation (WP-302)
// ---------------------------------------------------------------------------
//
// The preview-closure design this replaces trusted callers to peek without
// advancing: a caller-supplied `preview` closure could increment its own
// counter (advancing on a send that later fails) or return an ID unrelated to
// the committed one. The sequencer below closes that forge vector at the type
// level: the counter lives in one engine-owned struct with no public advancing
// method, preview/commit are private to this module, and the built envelope is
// validated against the reservation before encode.

/// Why a packet ID could not be reserved from [`PacketIdSequencer`].
///
/// The only variant today is terminal exhaustion: the `u64` packet-ID space
/// for this send direction under this key epoch is consumed. There is
/// deliberately no wrap, no saturating reuse, and no reset: the sender MUST
/// rotate the key epoch (a new [`PacketIdSequencer`] under a new key epoch,
/// which the receiver treats as a new delivery key) to continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PacketIdError {
    /// The sequencer already issued `u64::MAX`. No further ID may be issued
    /// under the same key epoch.
    #[error("V2 packet-ID space exhausted at u64::MAX; rotate key epoch to continue")]
    Exhausted,
}

/// Engine-owned V2 packet-ID counter for one send direction (WP-302).
///
/// Each V2 engine owns exactly one instance (first packet ID `0`) and hands
/// `&mut` to [`CheckedDatagramSender::send_checked`] for every send. The
/// counter advances only inside that pipeline, after the transport accepted
/// the datagram. There is deliberately no public advancing method:
///
/// - [`PacketIdSequencer::next_value`] is a pure peek (`&self`); calling it
///   any number of times never advances the counter, so observability and
///   tests cannot advance the preview.
/// - [`PacketIdSequencer::is_exhausted`] is a pure exhaustion probe
///   (`&self`); once true it stays true for the life of this instance.
/// - Preview ([`PacketIdSequencer::preview`]) and commit
///   ([`PacketIdSequencer::commit`]) are private to `sg-transport::mtu`: only
///   the checked send pipeline can preview the next ID or commit it. External
///   crates own an instance but cannot advance it except through a successful
///   checked send.
///
/// IDs never wrap within a key epoch, mirroring the receiver contract
/// (`sg-multipath::v2`: delivering `u64::MAX` terminates the key and every
/// later arrival for the same key is dropped as exhausted). Issuing
/// `u64::MAX` terminates this sequencer: [`PacketIdSequencer::commit`] sets
/// the exhausted flag and keeps `next` at `u64::MAX` so
/// [`PacketIdSequencer::next_value`] keeps reporting the last issued ID.
/// Every later [`CheckedDatagramSender::send_checked`] fails fast with
/// [`CheckedSendError::PacketIdExhausted`] before any gate mutation, preview,
/// or transport enqueue, and the ID is never reused. Recovery requires a new
/// instance under a rotated key epoch; there is deliberately no
/// reset/unexhaust method.
///
/// Per-flow sequencers (WP-301/WP-601) extend this type; for WP-302 one
/// sequencer per send direction is the authoritative counter.
#[derive(Debug)]
pub struct PacketIdSequencer {
    next: u64,
    exhausted: bool,
}

impl PacketIdSequencer {
    /// Creates a sequencer starting at `start`. V2 engines start at `0`: the
    /// first packet ID in a send direction is `0`.
    #[must_use]
    pub const fn new(start: u64) -> Self {
        Self {
            next: start,
            exhausted: false,
        }
    }

    /// Non-advancing peek at the next packet ID value. Pure read (`&self`);
    /// repeated calls return the same value until the checked pipeline
    /// commits a send. Once exhausted the value stays at `u64::MAX` (the last
    /// issued ID); no further ID will ever be issued from this instance.
    #[must_use]
    pub const fn next_value(&self) -> u64 {
        self.next
    }

    /// True once `u64::MAX` has been issued from this instance. Terminal:
    /// once true it never returns to false. The sender MUST rotate the key
    /// epoch and construct a new sequencer to continue sending.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Non-advancing preview for the checked pipeline. Returns a single-use
    /// [`PacketReservation`] for the current head without advancing the
    /// counter, or [`PacketIdError::Exhausted`] when this instance already
    /// issued `u64::MAX`. Private: only [`CheckedDatagramSender::send_checked`]
    /// (same module) may preview.
    fn preview(&self) -> Result<PacketReservation, PacketIdError> {
        if self.exhausted {
            return Err(PacketIdError::Exhausted);
        }
        Ok(PacketReservation {
            id: PacketId::new(self.next),
        })
    }

    /// Commits a previewed reservation after a successful transport enqueue.
    /// Private: only [`CheckedDatagramSender::send_checked`] may commit, and
    /// only on the success path. Validates the reservation still matches the
    /// head (it always does: the pipeline holds `&mut` across preview to
    /// commit, so no other send can interleave) and advances exactly once.
    /// A stale reservation never skips or rewinds the counter. Committing the
    /// `u64::MAX` reservation terminates the sequencer instead of wrapping or
    /// saturating: the exhausted flag is set and `next` stays at `u64::MAX`
    /// so the ID is never reused.
    fn commit(&mut self, reservation: PacketReservation) {
        debug_assert_eq!(
            reservation.id.get(),
            self.next,
            "commit must match the previewed head"
        );
        if self.exhausted || reservation.id.get() != self.next {
            return;
        }
        if self.next == u64::MAX {
            self.exhausted = true;
        } else {
            // Guarded by the `u64::MAX` check above, so this cannot overflow.
            self.next += 1;
        }
    }
}

/// Single-use packet-ID reservation handed to the envelope builder.
///
/// Public so it can appear in the [`CheckedDatagramSender::send_checked`]
/// builder signature, but non-forgeable: the field is private and there is no
/// public constructor, so the only instance a caller ever sees is the one the
/// checked pipeline previewed for this send. The pipeline validates the built
/// envelope carries [`PacketReservation::id`] and rejects (without commit) any
/// envelope that substitutes a different ID.
#[derive(Debug)]
pub struct PacketReservation {
    id: PacketId,
}

impl PacketReservation {
    /// The reserved packet ID the built envelope must carry.
    #[must_use]
    pub const fn id(&self) -> PacketId {
        self.id
    }
}

// ---------------------------------------------------------------------------
// V2-only datagram sender interface (checked, no fallback)
// ---------------------------------------------------------------------------
//
// `DatagramSender` is the V2-only seam a QUIC path (and any synthesized test
// path) implements. `CheckedDatagramSender` wraps it with the admission gate
// so no caller can bypass whole-MTU validation, and there is no 1200-byte
// fallback anywhere in the chain. Raw transport send requires a
// [`CheckedSendPermit`] that only the checked sender can construct.

/// Capability token proving a raw datagram send goes through
/// [`CheckedDatagramSender::send_checked`].
///
/// The type is public so it can appear in the public [`DatagramSender`]
/// signature, but its constructor is crate-private and its field is private,
/// so code outside `sg-transport` cannot construct or forge it. A public
/// [`V2QuicDatagramSender`](crate::quic::V2QuicDatagramSender) handle therefore
/// exposes no bypass: querying [`DatagramSender::current_datagram_mtu`] is
/// public, but transmitting requires a permit only the checked sender owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedSendPermit(());

impl CheckedSendPermit {
    /// Creates the single permit owned by the checked send pipeline.
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// Transport-level error from a V2 datagram send attempt. Carries no payload
/// content, only lengths and a stable classification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DatagramSendError {
    /// The transport advertised no concrete datagram limit. V2 applies **no
    /// fallback**: the caller must treat the path as not sendable.
    #[error("V2 transport advertised no datagram limit; no fallback is configured")]
    NoDatagramLimit,
    /// The transport refused the whole datagram because it exceeds the limit
    /// it is currently advertising.
    #[error("V2 datagram of {datagram_len} bytes exceeds the transport datagram limit {limit}")]
    TooLarge { datagram_len: usize, limit: usize },
    /// The transport rejected the datagram for a classified transient reason
    /// (disabled by peer, blocked by congestion, connection lost). The caller
    /// may retry deliberately; the sender never retries silently.
    #[error("V2 datagram was rejected by the transport: {0}")]
    Rejected(String),
}

/// V2-only raw datagram transport seam.
///
/// Implementations must report their **whole-datagram** limit via
/// [`DatagramSender::current_datagram_mtu`] and must never synthesize a limit
/// when datagrams are disabled or not yet negotiated (`None` propagates).
/// Transmitting requires a [`CheckedSendPermit`]: only
/// [`CheckedDatagramSender::send_checked`] can construct one, so no public
/// caller can bypass admission.
#[async_trait]
pub trait DatagramSender: Send + Sync {
    /// Transmits one already-validated V2 datagram (fixed header + payload).
    /// The datagram length has already passed [`MtuAdmission::admit_datagram`].
    /// Callers must supply the [`CheckedSendPermit`] owned by the checked
    /// send pipeline; there is no public constructor for it.
    async fn send_datagram(
        &self,
        datagram: Bytes,
        permit: CheckedSendPermit,
    ) -> Result<(), DatagramSendError>;

    /// The whole-datagram limit currently advertised by the transport, or
    /// `None` when no datagram limit is available. **No fallback is applied**:
    /// `None` means admission stays denied until the transport supplies a
    /// concrete limit.
    fn current_datagram_mtu(&self) -> Option<DatagramMtu>;
}

/// Error from [`CheckedDatagramSender`]. `PacketIdExhausted` means the
/// sequencer already issued `u64::MAX` and the send was denied **before**
/// any gate mutation, preview, or transport enqueue; `Rejected` means the
/// packet was stopped at the admission gate **before** any preview or counter
/// commit; `BuildMismatch` means the gate passed and an ID was previewed, but
/// the caller-built envelope substituted a different ID — the previewed ID is
/// never committed; `Encode` means the gate passed and an ID was previewed
/// but **never committed**; `Transport` means the gate passed, an ID was
/// previewed, and the underlying transport refused the datagram — again, the
/// previewed ID is never committed. Only `Ok(PacketId)` advances the
/// sequencer/counters.
#[derive(Debug, Error)]
pub enum CheckedSendError {
    /// The packet-ID space is exhausted (`u64::MAX` already issued). Returned
    /// before any gate mutation, preview, or transport enqueue; the ID is
    /// never reused. The sender MUST rotate the key epoch and construct a new
    /// [`PacketIdSequencer`] to continue.
    #[error(transparent)]
    PacketIdExhausted(#[from] PacketIdError),
    /// The datagram was rejected at the MTU admission gate.
    #[error("V2 datagram rejected at the MTU admission gate: {0}")]
    Rejected(MtuRejectReason),
    /// The caller-built envelope did not carry the previewed reservation ID.
    /// The previewed ID is never committed and nothing is enqueued; counted
    /// in the `encode_failures` bucket (admitted, previewed, never enqueued).
    #[error("V2 envelope substituted packet ID {found:?} for the previewed reservation {expected:?}")]
    BuildMismatch {
        /// The ID the checked pipeline previewed for this send.
        expected: PacketId,
        /// The ID the caller-built envelope actually carried.
        found: PacketId,
    },
    /// The admitted datagram failed V2 envelope encoding (protocol invariant).
    #[error("V2 envelope encoding failed: {0}")]
    Encode(V2EnvelopeError),
    /// The admission gate passed and the transport refused the send.
    #[error(transparent)]
    Transport(#[from] DatagramSendError),
}

/// V2-only checked datagram sender: owns the [`MtuAdmission`] gate and an
/// inner [`DatagramSender`].
///
/// `send` validates the **whole datagram** (52-byte fixed header + payload)
/// against the current path MTU before encoding and before any transport
/// invocation. There is no fallback: an `Unknown`/`BlackHole`/unsupported
/// path rejects the send, and a transport `TooLarge`/`NoDatagramLimit`
/// propagates to the caller typed (`[`CheckedSendError::Transport`]`).
///
/// Metric split: gate passes increment `sends_admitted` (attempted); only a
/// successful transport enqueue increments `sends_enqueued`. Encode failures
/// increment `encode_failures` and transport rejections increment
/// `transport_failures`; neither ever increments `sends_enqueued`.
///
/// `&mut self` deliberately: the uplink loop owns this sender exclusively and
/// the admission counters are only mutated by the loop that owns it — no async
/// lock is ever held across the transport send.
pub struct CheckedDatagramSender<S: DatagramSender> {
    inner: S,
    admission: MtuAdmission,
}

impl<S: DatagramSender> CheckedDatagramSender<S> {
    /// Wraps a transport with an engine-owned admission gate. The gate starts
    /// in `Unknown` (sends denied) until `admission_mut().discover(...)` runs.
    #[must_use]
    pub fn new(inner: S, admission: MtuAdmission) -> Self {
        Self { inner, admission }
    }

    /// Read access to the admission gate.
    #[must_use]
    pub const fn admission(&self) -> &MtuAdmission {
        &self.admission
    }

    /// Mutable access to the admission gate (transitions and metrics).
    pub fn admission_mut(&mut self) -> &mut MtuAdmission {
        &mut self.admission
    }

    /// Atomic V2 send pipeline: exhaustion guard → query transport MTU → sync
    /// gate → admit payload → **preview** a reservation → build envelope from
    /// the reservation → validate the envelope ID → encode → transport send →
    /// **commit** the reservation (only after transport enqueue succeeds).
    ///
    /// This is the **only** way to send a V2 datagram through the checked
    /// sender. There is no pre-built-envelope or pre-built-ID bypass.
    ///
    /// The packet ID is engine-owned, never caller-supplied: the pipeline
    /// fails fast with [`CheckedSendError::PacketIdExhausted`] when the
    /// sequencer already issued `u64::MAX` (before any gate mutation, preview,
    /// or transport enqueue), otherwise previews a single-use
    /// [`PacketReservation`] from `sequencer` (a pure peek that never advances)
    /// after the admission gate passes, lends it to `build_envelope` by
    /// reference, and commits it only after the transport accepted the
    /// datagram. Consequences, all enforced by the types rather than by caller
    /// discipline:
    ///
    /// - An exhausted sequencer never mutates gate state, never previews, and
    ///   never enqueues; the ID is never reused. The sender MUST rotate the
    ///   key epoch and construct a new [`PacketIdSequencer`] to continue.
    /// - A rejected send (absent transport limit, gate rejection) never
    ///   previews, so the sequencer is untouched.
    /// - `build_envelope` receives the reservation and must stamp
    ///   [`PacketReservation::id`] on the envelope. An envelope carrying any
    ///   other ID fails with [`CheckedSendError::BuildMismatch`]: the
    ///   previewed ID is never committed and nothing is enqueued.
    /// - An encode failure or transport rejection/too-large never commits, so
    ///   those paths cannot advance ID or delivery state.
    /// - Public callers cannot advance the sequencer: preview and commit are
    ///   private to `sg-transport::mtu`, and [`PacketIdSequencer`] exposes no
    ///   other advancing method. The caller's scheduler data plane observes
    ///   the counter via [`PacketIdSequencer::next_value`] and exhaustion via
    ///   [`PacketIdSequencer::is_exhausted`] (WP-301/WP-601).
    ///
    /// Pipeline order on every path:
    ///
    /// 0. Fail fast on [`PacketIdSequencer::is_exhausted`] with
    ///    [`CheckedSendError::PacketIdExhausted`]: no gate mutation, no
    ///    preview, no transport call, no commit. (The fallible preview in
    ///    step 3 re-checks defensively; the `&mut` pipeline cannot interleave
    ///    another send, so the early guard and the preview always agree.)
    /// 1. Query [`DatagramSender::current_datagram_mtu`] and sync the gate
    ///    ([`MtuAdmission::sync_from_transport`]); an absent limit denies the
    ///    send with no preview and no commit.
    /// 2. Admit the payload through the single accounting funnel
    ///    ([`MtuAdmission::admit_envelope`]).
    /// 3. Preview a [`PacketReservation`] from `sequencer` (no advance;
    ///    fallible on exhaustion).
    /// 4. Build the envelope via `build_envelope(&reservation)`.
    /// 5. Validate the envelope carries the reserved ID.
    /// 6. Encode the envelope ([`V2Envelope::encode`]).
    /// 7. Send the encoded datagram through the transport.
    /// 8. Commit the reservation via the sequencer — the ONLY point where
    ///    the sequencer/counters advance. Committing `u64::MAX` terminates
    ///    the sequencer instead of wrapping or reusing.
    ///
    /// A rejection at any step returns a typed [`CheckedSendError`] without
    /// committing. The returned `Ok(PacketId)` confirms the ID that was
    /// previewed, enqueued, and committed.
    pub async fn send_checked<F>(
        &mut self,
        payload_len: usize,
        sequencer: &mut PacketIdSequencer,
        build_envelope: F,
    ) -> Result<PacketId, CheckedSendError>
    where
        F: FnOnce(&PacketReservation) -> V2Envelope,
    {
        // Step 0: fail fast on exhaustion before any gate mutation, preview,
        // or transport call. The ID is never reused; the caller must rotate
        // the key epoch and construct a new sequencer to continue.
        if sequencer.is_exhausted() {
            return Err(CheckedSendError::PacketIdExhausted(PacketIdError::Exhausted));
        }
        // Step 1: query the transport MTU on every send and sync the gate. An
        // absent limit (datagrams disabled or mid-negotiation) denies the send
        // here — no soft fallback — and never previews or commits.
        let Some(transport_mtu) = self.inner.current_datagram_mtu() else {
            let reason = self.admission.reject_absent_transport_limit();
            return Err(CheckedSendError::Rejected(reason));
        };
        let _event = self.admission.sync_from_transport(transport_mtu);

        // Step 2: admit payload (single accounting bucket for both
        // payload-length and whole-datagram checks).
        let datagram_len = FIXED_HEADER_LEN.saturating_add(payload_len);
        let effective = self
            .admission
            .admit_envelope(payload_len, datagram_len)
            .map_err(CheckedSendError::Rejected)?;

        // Step 3: PREVIEW a single-use reservation from the engine-owned
        // sequencer. Private and non-advancing: the counter still reads the
        // same head after this call. Fallible on exhaustion (defensive: the
        // `&mut` pipeline cannot interleave another send, so this agrees with
        // the step-0 guard).
        let reservation = sequencer.preview()?;
        let packet_id = reservation.id();

        // Step 4: build the envelope from the reservation. The builder must
        // stamp the reserved ID; anything else is a contract violation.
        let envelope = build_envelope(&reservation);

        // Step 5: non-forgeability gate. A substituted ID is rejected before
        // encode and before any transport work; the previewed ID is never
        // committed. Counted with encode failures: admitted, previewed, never
        // enqueued.
        if envelope.header.packet_id != packet_id {
            self.admission.record_encode_failure();
            return Err(CheckedSendError::BuildMismatch {
                expected: packet_id,
                found: envelope.header.packet_id,
            });
        }

        // Step 6: encode envelope against the effective payload MTU. On encode
        // failure the previewed ID is never committed and `sends_enqueued`
        // is never incremented — only `encode_failures`.
        let datagram = match envelope.encode(PayloadLimit::new(effective.get())) {
            Ok(datagram) => datagram,
            Err(error) => {
                self.admission.record_encode_failure();
                return Err(CheckedSendError::Encode(error));
            }
        };

        // Step 7: transport send (permit proves the checked pipeline owns this
        // call). On rejection/too-large the previewed ID is never committed
        // and `sends_enqueued` is never incremented — only
        // `transport_failures`.
        if let Err(error) = self.inner.send_datagram(datagram, CheckedSendPermit::new()).await {
            self.admission.record_transport_failure();
            return Err(CheckedSendError::Transport(error));
        }

        // Step 8: COMMIT — the only point the sequencer advances, and the
        // only point `sends_enqueued` increments.
        self.admission.record_enqueue_success();
        sequencer.commit(reservation);

        Ok(packet_id)
    }
}

// ---------------------------------------------------------------------------
// Events and metrics
// ---------------------------------------------------------------------------

/// MTU-related state transitions for the engine policy log. Carries no
/// packet content, session IDs, or addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuEvent {
    /// Initial MTU discovered on a path.
    MtuDiscovered { datagram_mtu: usize },
    /// MTU reduced from `previous` to `current` (PMTUD black hole probe).
    MtuReduced { previous: usize, current: usize },
    /// A reduction was reported but ignored because it is not strictly
    /// smaller (`requested >= current`). The path limit is unchanged.
    ReduceIgnored { requested: usize, current: usize },
    /// Complete MTU black hole: path sends must be suspended.
    MtuBlackHole,
    /// No state change (e.g., reduce called on Unknown).
    NoOp,
}

/// Aggregate MTU admission and state-transition outcomes. Counts only; no
/// packet content, session identity, or addresses.
///
/// `sends_admitted` counts gate passes (attempts, before encode/send);
/// `sends_enqueued` counts successful transport enqueues. A failed encode or
/// a transport rejection increments `encode_failures`/`transport_failures`
/// and never increments `sends_enqueued`, so `sends_enqueued` is the only
/// successful-send counter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MtuMetrics {
    /// Gate passes (attempted sends, before encode and transport send).
    pub sends_admitted: u64,
    /// Successful transport enqueues (only incremented after the transport
    /// accepted the datagram in `send_checked`).
    pub sends_enqueued: u64,
    /// Datagrams rejected at the admission gate (before any counter advance).
    pub sends_rejected: u64,
    /// Admitted sends that failed V2 envelope encoding (previewed ID never
    /// committed, never enqueued).
    pub encode_failures: u64,
    /// Admitted sends that the transport refused (previewed ID never
    /// committed, never enqueued).
    pub transport_failures: u64,
    /// MTU reductions detected (Available/Reduced → Reduced).
    pub mtu_reductions: u64,
    /// Complete blackholes detected (Available/Reduced → BlackHole).
    pub blackholes_detected: u64,
}

impl MtuMetrics {
    /// Records an [`MtuEvent`] into the aggregate metrics. Ignored reductions
    /// are not counted as reductions.
    pub fn record_event(&mut self, event: MtuEvent) {
        match event {
            MtuEvent::MtuReduced { .. } => {
                self.mtu_reductions = self.mtu_reductions.saturating_add(1);
            }
            MtuEvent::MtuBlackHole => {
                self.blackholes_detected = self.blackholes_detected.saturating_add(1);
            }
            MtuEvent::MtuDiscovered { .. }
            | MtuEvent::ReduceIgnored { .. }
            | MtuEvent::NoOp => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sg_core::v2::{FlowId, PacketId, PathId, SessionId, TrafficClass};
    use sg_protocol::v2::{Direction, V2EnvelopeError, V2Header};
    use std::sync::{Arc, Mutex};

    /// A transport double that records every admitted send length and can be
    /// scripted to report a changing datagram limit (per-send querying) or to
    /// refuse the send.
    struct FakeDatagramSender {
        attempts: Arc<Mutex<Vec<usize>>>,
        /// The current advertised limit; wrapped so tests can change it
        /// between sends to exercise per-send transport MTU querying.
        current: Arc<Mutex<Option<DatagramMtu>>>,
        refuse: bool,
    }

    #[async_trait]
    impl DatagramSender for FakeDatagramSender {
        async fn send_datagram(
            &self,
            datagram: Bytes,
            _permit: CheckedSendPermit,
        ) -> Result<(), DatagramSendError> {
            self.attempts.lock().unwrap().push(datagram.len());
            if self.refuse {
                let limit = self.current.lock().unwrap().map(|mtu| mtu.get()).unwrap_or(0);
                return Err(DatagramSendError::TooLarge {
                    datagram_len: datagram.len(),
                    limit,
                });
            }
            Ok(())
        }

        fn current_datagram_mtu(&self) -> Option<DatagramMtu> {
            *self.current.lock().unwrap()
        }
    }

    // ----- DatagramMtu and EffectivePayloadMtu construction -----

    #[test]
    fn datagram_mtu_rejects_below_header_and_above_max() {
        assert!(DatagramMtu::new(FIXED_HEADER_LEN - 1).is_err());
        assert!(DatagramMtu::new(0).is_err());
        assert!(DatagramMtu::new(MAX_DATAGRAM_MTU + 1).is_err());
        assert!(DatagramMtu::new(FIXED_HEADER_LEN).is_ok());
        assert!(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).is_ok());
        assert!(DatagramMtu::new(MAX_DATAGRAM_MTU).is_ok());
    }

    #[test]
    fn effective_payload_derives_from_datagram_mtu() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let ep = dm.effective_payload();
        assert_eq!(ep.get(), SAFE_MODE_MIN_PAYLOAD_MTU);
        assert_eq!(ep.datagram_mtu(), dm);
    }

    #[test]
    fn minimum_datagram_mtu_yields_zero_payload() {
        let dm = DatagramMtu::new(FIXED_HEADER_LEN).unwrap();
        let ep = dm.effective_payload();
        assert_eq!(ep.get(), 0);
        assert_eq!(ep.datagram_mtu(), dm);
    }

    #[test]
    fn maximum_datagram_mtu_round_trips_through_effective_payload() {
        let dm = DatagramMtu::new(MAX_DATAGRAM_MTU).unwrap();
        let ep = dm.effective_payload();
        assert_eq!(ep.get(), MAX_DATAGRAM_MTU - FIXED_HEADER_LEN);
        assert_eq!(ep.datagram_mtu(), dm);
    }

    #[test]
    fn effective_payload_new_constructs_from_raw_tun_value() {
        // Engine construction from the actual TUN config (safe-mode 1300).
        let ep = EffectivePayloadMtu::new(SAFE_MODE_MIN_PAYLOAD_MTU);
        assert_eq!(ep.get(), SAFE_MODE_MIN_PAYLOAD_MTU);
        assert_eq!(ep.datagram_mtu().get(), SAFE_MODE_MIN_DATAGRAM_MTU);
    }

    #[test]
    fn mtu_admission_with_tun_payload_mtu_wires_actual_tun_config() {
        let admission = MtuAdmission::with_tun_payload_mtu(SAFE_MODE_MIN_PAYLOAD_MTU).unwrap();
        // State starts Unknown (sends denied) but the TUN payload requirement
        // is the actual configured value, not a V1-style implicit constant.
        assert_eq!(admission.state(), PathMtuState::Unknown);
        assert_eq!(admission.tun_payload_mtu().get(), SAFE_MODE_MIN_PAYLOAD_MTU);
        assert!(!admission.can_carry_tun_payload());

        // A larger TUN config carries a larger requirement.
        let admission = MtuAdmission::with_tun_payload_mtu(1_500).unwrap();
        assert_eq!(admission.tun_payload_mtu().get(), 1_500);
        assert_eq!(
            admission.tun_payload_mtu().datagram_mtu(),
            DatagramMtu::new(1_500 + FIXED_HEADER_LEN).unwrap()
        );

        // Invalid values (reversing into an out-of-range datagram MTU) fail.
        assert!(MtuAdmission::with_tun_payload_mtu(MAX_DATAGRAM_MTU - FIXED_HEADER_LEN + 1).is_err());
    }

    // ----- sync_from_transport (per-send transport MTU query) -----

    #[test]
    fn sync_from_transport_discovers_unknown_and_never_raises() {
        // Unknown gates discover on first sync.
        let mut admission = MtuAdmission::default();
        let event = admission.sync_from_transport(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert_eq!(event, MtuEvent::MtuDiscovered { datagram_mtu: SAFE_MODE_MIN_DATAGRAM_MTU });
        assert_eq!(admission.state().datagram_mtu().unwrap().get(), SAFE_MODE_MIN_DATAGRAM_MTU);

        // A smaller transport limit lowers the gate (real reduction).
        let event = admission.sync_from_transport(DatagramMtu::new(1280).unwrap());
        assert_eq!(event, MtuEvent::MtuReduced { previous: SAFE_MODE_MIN_DATAGRAM_MTU, current: 1280 });

        // An equal or larger stale report never raises the limit.
        let equal = admission.sync_from_transport(DatagramMtu::new(1280).unwrap());
        assert_eq!(equal, MtuEvent::NoOp);
        let larger = admission.sync_from_transport(DatagramMtu::new(1_500).unwrap());
        assert_eq!(larger, MtuEvent::NoOp);
        assert_eq!(admission.state().datagram_mtu().unwrap().get(), 1280);

        // BlackHole never syncs upward or changes without an explicit recover.
        admission.blackhole();
        let event = admission.sync_from_transport(DatagramMtu::new(1_500).unwrap());
        assert_eq!(event, MtuEvent::NoOp);
        assert_eq!(admission.state(), PathMtuState::BlackHole);
    }

    // ----- PathMtuState transitions -----

    #[test]
    fn unknown_state_denies_sends_and_discovers() {
        let state = PathMtuState::Unknown;
        assert!(state.send_denied());
        assert!(state.effective_payload().is_none());
        assert!(state.datagram_mtu().is_none());

        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (new_state, event) = state.discover(dm);
        assert_eq!(event, MtuEvent::MtuDiscovered { datagram_mtu: SAFE_MODE_MIN_DATAGRAM_MTU });
        assert!(!new_state.send_denied());
        assert_eq!(new_state.effective_payload(), Some(dm.effective_payload()));
        assert_eq!(new_state.datagram_mtu(), Some(dm));
    }

    #[test]
    fn available_reduces_and_records_previous() {
        let dm1 = DatagramMtu::new(1500).unwrap();
        let dm2 = DatagramMtu::new(1352).unwrap();
        let (available, _) = PathMtuState::Unknown.discover(dm1);

        let (reduced, event) = available.reduce(dm2);
        assert_eq!(event, MtuEvent::MtuReduced { previous: 1500, current: 1352 });
        match reduced {
            PathMtuState::Reduced { datagram_mtu, effective, previous } => {
                assert_eq!(datagram_mtu, dm2);
                assert_eq!(effective, dm2.effective_payload());
                assert_eq!(previous, dm1);
            }
            other => panic!("expected Reduced, got {other:?}"),
        }
        assert!(!reduced.send_denied());
    }

    #[test]
    fn reduce_never_raises_and_reports_ignored_noop() {
        let dm1 = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (available, _) = PathMtuState::Unknown.discover(dm1);

        // Equal value: typed no-op, state untouched.
        let (state, event) = available.reduce(dm1);
        assert_eq!(
            event,
            MtuEvent::ReduceIgnored {
                requested: SAFE_MODE_MIN_DATAGRAM_MTU,
                current: SAFE_MODE_MIN_DATAGRAM_MTU,
            }
        );
        assert_eq!(state, available, "equal reduction must not replace the state");

        // Larger value: typed no-op, state untouched.
        let larger = DatagramMtu::new(1500).unwrap();
        let (state, event) = available.reduce(larger);
        assert_eq!(
            event,
            MtuEvent::ReduceIgnored {
                requested: 1500,
                current: SAFE_MODE_MIN_DATAGRAM_MTU,
            }
        );
        assert_eq!(state, available, "larger reduction must not raise the limit");

        // Chained reduction still only lowers what it records as previous.
        let smaller = DatagramMtu::new(1280).unwrap();
        let (state, event) = available.reduce(smaller);
        assert_eq!(event, MtuEvent::MtuReduced { previous: 1352, current: 1280 });
        assert!(matches!(
            state,
            PathMtuState::Reduced { datagram_mtu, .. } if datagram_mtu == smaller
        ));
    }

    #[test]
    fn blackhole_denies_sends_and_recovers() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (available, _) = PathMtuState::Unknown.discover(dm);
        let (bh, event) = available.blackhole();
        assert_eq!(event, MtuEvent::MtuBlackHole);
        assert!(bh.send_denied());
        assert!(bh.effective_payload().is_none());

        let (recovered, event) = bh.recover(dm);
        assert_eq!(event, MtuEvent::MtuDiscovered { datagram_mtu: SAFE_MODE_MIN_DATAGRAM_MTU });
        assert!(!recovered.send_denied());
        assert_eq!(recovered.effective_payload(), Some(dm.effective_payload()));
    }

    #[test]
    fn reduce_on_unknown_or_blackhole_is_noop() {
        let (state1, event1) = PathMtuState::Unknown.reduce(DatagramMtu::new(1352).unwrap());
        assert_eq!(event1, MtuEvent::NoOp);
        assert_eq!(state1, PathMtuState::Unknown);

        let (bh, _) = PathMtuState::Unknown.discover(DatagramMtu::new(1352).unwrap());
        let (bh, _) = bh.blackhole();
        let (state2, event2) = bh.reduce(DatagramMtu::new(1280).unwrap());
        assert_eq!(event2, MtuEvent::NoOp);
        assert_eq!(state2, PathMtuState::BlackHole);
    }

    #[test]
    fn recover_from_non_blackhole_is_noop() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (available, _) = PathMtuState::Unknown.discover(dm);
        let (state, event) = available.recover(DatagramMtu::new(1500).unwrap());
        assert_eq!(event, MtuEvent::NoOp);
        assert_eq!(state, available);
    }

    // ----- check_payload / check_datagram / admit_* -----

    #[test]
    fn check_payload_admits_within_limit_and_rejects_over_or_empty() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (state, _) = PathMtuState::Unknown.discover(dm);
        let ep = dm.effective_payload();

        assert_eq!(check_payload(ep.get(), &state), Ok(ep));
        assert_eq!(check_payload(1, &state), Ok(ep));
        // An empty payload can never be encoded; reject before counter commit.
        assert_eq!(check_payload(0, &state), Err(MtuRejectReason::EmptyPayload));
        assert!(matches!(
            check_payload(ep.get() + 1, &state),
            Err(MtuRejectReason::PayloadExceedsMtu { .. })
        ));
    }

    #[test]
    fn check_payload_rejects_unknown_and_blackhole() {
        assert_eq!(check_payload(10, &PathMtuState::Unknown), Err(MtuRejectReason::PathMtuUnknown));
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (bh, _) = PathMtuState::Unknown.discover(dm);
        let (bh, _) = bh.blackhole();
        assert_eq!(check_payload(10, &bh), Err(MtuRejectReason::PathMtuBlackHole));
    }

    #[test]
    fn check_datagram_validates_whole_datagram_bounds() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (state, _) = PathMtuState::Unknown.discover(dm);

        // Exactly at the whole-datagram limit: admitted.
        assert_eq!(check_datagram(dm.get(), &state), Ok(dm));
        // One byte over: whole-datagram rejection with both lengths reported.
        assert_eq!(
            check_datagram(dm.get() + 1, &state),
            Err(MtuRejectReason::DatagramExceedsMtu {
                datagram_len: SAFE_MODE_MIN_DATAGRAM_MTU + 1,
                datagram_mtu: SAFE_MODE_MIN_DATAGRAM_MTU,
            })
        );
        // A whole datagram (or length claim) below the fixed header is not a
        // valid V2 datagram at all.
        assert_eq!(
            check_datagram(FIXED_HEADER_LEN - 1, &state),
            Err(MtuRejectReason::DatagramBelowHeader {
                datagram_len: FIXED_HEADER_LEN - 1,
                minimum: FIXED_HEADER_LEN,
            })
        );
        // Unknown/BlackHole deny as strongly as payload admission.
        assert_eq!(check_datagram(1352, &PathMtuState::Unknown), Err(MtuRejectReason::PathMtuUnknown));
        let (bh, _) = PathMtuState::Unknown.discover(dm);
        let (bh, _) = bh.blackhole();
        assert_eq!(check_datagram(1352, &bh), Err(MtuRejectReason::PathMtuBlackHole));
    }

    #[test]
    fn admit_payload_and_datagram_count_metrics_and_preserve_reject_reason() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (state, _) = PathMtuState::Unknown.discover(dm);
        let mut metrics = MtuMetrics::default();

        assert!(admit_payload(dm.effective_payload().get(), &state, &mut metrics).is_ok());
        assert_eq!(metrics.sends_admitted, 1);
        assert_eq!(metrics.sends_rejected, 0);
        // Direct gate admission never enqueues: only the checked send pipeline
        // records `sends_enqueued` after a successful transport send.
        assert_eq!(metrics.sends_enqueued, 0);
        assert_eq!(metrics.encode_failures, 0);
        assert_eq!(metrics.transport_failures, 0);

        assert!(admit_payload(dm.effective_payload().get() + 1, &state, &mut metrics).is_err());
        assert_eq!(metrics.sends_admitted, 1);
        assert_eq!(metrics.sends_rejected, 1);

        // Whole-datagram admission is an independent, equally-counted gate.
        assert!(admit_datagram(dm.get(), &state, &mut metrics).is_ok());
        assert!(admit_datagram(dm.get() + 1, &state, &mut metrics).is_err());
        assert_eq!(metrics.sends_admitted, 2);
        assert_eq!(metrics.sends_rejected, 2);
        assert_eq!(metrics.sends_enqueued, 0, "gate admission alone never enqueues");

        assert!(admit_payload(0, &state, &mut metrics).is_err());
        assert_eq!(metrics.sends_rejected, 3);
    }

    // ----- MtuAdmission engine gate -----

    #[test]
    fn mtu_admission_default_denies_until_discovery() {
        let mut admission = MtuAdmission::default();
        assert_eq!(admission.state(), PathMtuState::Unknown);
        assert_eq!(admission.tun_payload_mtu().get(), SAFE_MODE_MIN_PAYLOAD_MTU);
        assert!(!admission.can_carry_tun_payload());

        // The gate never allocates packet IDs: sequencing belongs to the
        // checked send pipeline (preview/commit). A rejection records only a
        // gate rejection — never an attempt or an enqueue.
        assert_eq!(
            admission.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU),
            Err(MtuRejectReason::PathMtuUnknown)
        );
        assert_eq!(admission.metrics().sends_rejected, 1);
        assert_eq!(admission.metrics().sends_admitted, 0);
        assert_eq!(admission.metrics().sends_enqueued, 0);
    }

    #[test]
    fn mtu_admission_admits_safe_mode_payload_at_gate_without_enqueue() {
        let mut admission = MtuAdmission::default();
        let event = admission.discover(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert_eq!(event, MtuEvent::MtuDiscovered { datagram_mtu: SAFE_MODE_MIN_DATAGRAM_MTU });
        assert!(admission.can_carry_tun_payload());

        // 1300-byte payload inside a 1352-byte datagram: admitted at the gate.
        // Gate admission is an attempt, not a delivery: `sends_enqueued`
        // advances only in `send_checked` after a successful transport send.
        assert!(admission.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU).is_ok());
        assert_eq!(admission.metrics().sends_admitted, 1);
        assert_eq!(admission.metrics().sends_enqueued, 0);

        let event = admission.discover(DatagramMtu::new(1352).unwrap());
        assert_eq!(event, MtuEvent::MtuDiscovered { datagram_mtu: 1352 });
        assert!(admission.can_carry_tun_payload());
        assert!(admission.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU).is_ok());
        assert_eq!(admission.metrics().sends_admitted, 2);
        assert_eq!(admission.metrics().sends_enqueued, 0);
    }

    #[test]
    fn mtu_admission_rejection_records_only_in_rejected_bucket() {
        let mut admission = MtuAdmission::default();
        admission.discover(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());

        // Oversized payload: rejected, counters move only in the rejected
        // bucket — never admitted or enqueued.
        assert!(matches!(
            admission.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU + 1),
            Err(MtuRejectReason::PayloadExceedsMtu { .. })
        ));
        assert_eq!(admission.metrics().sends_admitted, 0);
        assert_eq!(admission.metrics().sends_enqueued, 0);
        assert_eq!(admission.metrics().sends_rejected, 1);

        // Empty payload: rejected, no admission.
        assert_eq!(admission.admit_payload(0), Err(MtuRejectReason::EmptyPayload));
        assert_eq!(admission.metrics().sends_rejected, 2);

        // Blackhole: rejected, no admission.
        admission.blackhole();
        assert_eq!(admission.admit_payload(10), Err(MtuRejectReason::PathMtuBlackHole));
        assert_eq!(admission.metrics().sends_rejected, 3);
        assert_eq!(admission.metrics().sends_admitted, 0, "no gate pass may have been recorded");
        assert_eq!(admission.metrics().sends_enqueued, 0, "no enqueue may have been recorded");
    }

    #[test]
    fn mtu_admission_reduction_degrades_then_fails_path_below_tun_payload() {
        let mut admission = MtuAdmission::default();
        admission.discover(DatagramMtu::new(1500).unwrap());
        assert!(admission.can_carry_tun_payload());
        assert!(admission.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU).is_ok());

        // Degrade to 1352: still carries a full TUN payload (1300) -> degraded but usable.
        admission.reduce(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert!(admission.can_carry_tun_payload());
        assert!(admission.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU).is_ok());
        assert_eq!(
            admission.metrics().mtu_reductions,
            1,
            "first reduction is real (1500 -> 1352)"
        );

        // Degrade below the TUN payload: path can no longer carry full TUN
        // packets -> the supervisor must fail over (typed, observable signal).
        admission.reduce(DatagramMtu::new(1280).unwrap());
        assert!(!admission.can_carry_tun_payload(), "a 1248-byte payload MTU cannot carry 1300-byte TUN frames");
        assert_eq!(
            admission.metrics().mtu_reductions,
            2,
            "1280 is strictly lower than 1352, so the second reduction is real"
        );

        // A TUN-sized payload is now rejected at the gate; the engine must
        // select another path (WP-501) or drop into degraded mode. The gate
        // never allocates packet IDs, so there is no ID to leak.
        assert!(matches!(
            admission.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU),
            Err(MtuRejectReason::PayloadExceedsMtu { .. })
        ));
        assert_eq!(admission.metrics().sends_enqueued, 0);
    }

    #[test]
    fn mtu_admission_reduce_never_raises_and_metrics_ignore_it() {
        let mut admission = MtuAdmission::default();
        admission.discover(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert_eq!(admission.metrics().mtu_reductions, 0);

        // A stale larger report must not raise the limit.
        let event = admission.reduce(DatagramMtu::new(1500).unwrap());
        assert_eq!(
            event,
            MtuEvent::ReduceIgnored {
                requested: 1500,
                current: SAFE_MODE_MIN_DATAGRAM_MTU
            }
        );
        // An equal report is also ignored.
        let event = admission.reduce(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert_eq!(
            event,
            MtuEvent::ReduceIgnored {
                requested: SAFE_MODE_MIN_DATAGRAM_MTU,
                current: SAFE_MODE_MIN_DATAGRAM_MTU
            }
        );

        // State and usable limits are untouched.
        assert_eq!(
            admission.state().datagram_mtu(),
            Some(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap())
        );
        assert!(admission.can_carry_tun_payload());
        assert!(admission.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU).is_ok());
        assert_eq!(
            admission.metrics().mtu_reductions,
            0,
            "ignored reduce reports must never count as reductions"
        );
    }

    #[test]
    fn mtu_admission_blackhole_and_recover_round_trip() {
        let mut admission = MtuAdmission::default();
        admission.discover(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert_eq!(admission.blackhole(), MtuEvent::MtuBlackHole);
        assert!(!admission.can_carry_tun_payload());
        assert_eq!(admission.metrics().blackholes_detected, 1);

        admission.recover(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert!(admission.can_carry_tun_payload());
        // Blackhole followed by discovery is not a reduction.
        assert_eq!(admission.metrics().mtu_reductions, 0);
    }

    // ----- PacketIdSequencer (non-forgeable preview/commit) -----

    #[test]
    fn packet_sequencer_peeks_never_advance_and_commit_advances_once() {
        // The engine-owned sequencer exposes no advancing method: repeated
        // peeks (shared reads and private previews) never move the head, and
        // one commit advances exactly once. White-box: this test module shares
        // the parent module, so it may exercise the private preview/commit
        // pair directly; external crates can only advance via `send_checked`.
        let mut sequencer = PacketIdSequencer::new(5);
        assert!(!sequencer.is_exhausted());
        assert_eq!(sequencer.next_value(), 5);
        assert_eq!(sequencer.next_value(), 5, "repeated peeks never advance");
        assert_eq!(sequencer.preview().expect("not exhausted").id(), PacketId::new(5));
        assert_eq!(
            sequencer.preview().expect("not exhausted").id(),
            PacketId::new(5),
            "repeated previews never advance"
        );
        assert_eq!(sequencer.next_value(), 5);
        sequencer.commit(sequencer.preview().expect("not exhausted"));
        assert_eq!(sequencer.next_value(), 6, "one commit advances exactly once");
        assert!(!sequencer.is_exhausted());
        assert_eq!(sequencer.preview().expect("not exhausted").id(), PacketId::new(6));
    }

    #[test]
    fn packet_sequencer_commits_advance_sequentially() {
        // Sequential preview→commit pairs advance the head one step at a
        // time. Each commit matches the previewed head (the checked pipeline
        // holds `&mut` across preview→commit, so no other send can
        // interleave); the release guard in `commit` additionally ensures a
        // stale reservation could never skip or rewind the counter.
        let mut sequencer = PacketIdSequencer::new(9);
        assert!(!sequencer.is_exhausted());
        sequencer.commit(sequencer.preview().expect("not exhausted"));
        assert_eq!(sequencer.next_value(), 10);
        sequencer.commit(sequencer.preview().expect("not exhausted"));
        assert_eq!(sequencer.next_value(), 11);
        assert_eq!(sequencer.preview().expect("not exhausted").id(), PacketId::new(11));
        assert_eq!(sequencer.next_value(), 11, "trailing preview leaves the head untouched");
        assert!(!sequencer.is_exhausted());
    }

    #[test]
    fn packet_sequencer_exhaustion_is_terminal_and_never_reuses() {
        // Issuing `u64::MAX` terminates the sequencer: no wrap to zero, no
        // saturating reuse of `MAX`. The receiver contract
        // (`sg-multipath::v2`) drops every later arrival for the same key as
        // exhausted, so the sender must stop under this key epoch.
        let mut sequencer = PacketIdSequencer::new(u64::MAX - 1);
        assert!(!sequencer.is_exhausted());

        sequencer.commit(sequencer.preview().expect("MAX-1 is issuable"));
        assert_eq!(sequencer.next_value(), u64::MAX);
        assert!(!sequencer.is_exhausted(), "MAX itself is still issuable once");

        sequencer.commit(sequencer.preview().expect("MAX is issuable once"));
        assert_eq!(sequencer.next_value(), u64::MAX, "head stays at MAX; never wraps to 0");
        assert!(sequencer.is_exhausted(), "issuing MAX terminates the sequencer");

        // Every later preview fails with the typed exhaustion error; the head
        // never moves and the ID is never reused.
        assert_eq!(sequencer.preview(), Err(PacketIdError::Exhausted));
        assert_eq!(sequencer.preview(), Err(PacketIdError::Exhausted), "exhaustion is sticky");
        assert_eq!(sequencer.next_value(), u64::MAX);
        assert!(sequencer.is_exhausted());
    }

    #[test]
    fn packet_sequencer_starting_at_max_issues_once_then_exhausts() {
        // A sequencer constructed directly at `MAX` (e.g. a restored counter
        // at the boundary) may issue that one ID and then must stop.
        let mut sequencer = PacketIdSequencer::new(u64::MAX);
        assert!(!sequencer.is_exhausted(), "construction alone never exhausts");
        assert_eq!(sequencer.next_value(), u64::MAX);
        assert_eq!(
            sequencer.preview().expect("MAX issuable once").id(),
            PacketId::new(u64::MAX)
        );
        sequencer.commit(sequencer.preview().expect("MAX issuable once"));
        assert!(sequencer.is_exhausted());
        assert_eq!(sequencer.next_value(), u64::MAX);
        assert_eq!(sequencer.preview(), Err(PacketIdError::Exhausted));
    }

    #[test]
    fn packet_sequencer_has_no_reset_and_stale_commit_never_revives() {
        // There is deliberately no reset/unexhaust API: the only recovery is a
        // new instance under a rotated key epoch. A stale commit against an
        // exhausted sequencer must not revive it, skip, rewind, or reuse.
        let mut sequencer = PacketIdSequencer::new(u64::MAX);
        sequencer.commit(sequencer.preview().expect("MAX issuable once"));
        assert!(sequencer.is_exhausted());
        // A forged stale reservation for an old ID cannot rewind the head
        // (commit validates the head; `PacketReservation` has no public
        // constructor, so this path is only reachable via a held reservation).
        // The head stays at MAX and exhaustion stays sticky.
        assert_eq!(sequencer.next_value(), u64::MAX);
        assert_eq!(sequencer.preview(), Err(PacketIdError::Exhausted));
        assert!(sequencer.is_exhausted());
    }

    // ----- CheckedDatagramSender (atomic pipeline, checked whole MTU) -----

    /// Builds a V2 envelope stamping the reserved ID. The payload is captured;
    /// the packet ID comes from the pipeline's reservation, so a prebuilt-ID
    /// bypass is impossible without tripping the build-mismatch gate.
    fn envelope_builder(payload: Bytes) -> impl FnOnce(&PacketReservation) -> V2Envelope {
        move |reservation| V2Envelope {
            header: V2Header {
                traffic_class: TrafficClass::Bulk,
                direction: Direction::ClientToGateway,
                session_id: SessionId::from_bytes([7; 16]),
                path_id: PathId::new(1),
                path_epoch: 1,
                key_epoch: 1,
                flow_id: FlowId::new(1),
                packet_id: reservation.id(),
            },
            payload,
        }
    }

    #[tokio::test]
    async fn checked_sender_admits_full_datagrams_before_transport() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(40);

        // A payload that fills the whole datagram exactly (1300 + 52 = 1352).
        // Preview → reservation for 40, build → envelope with 40, encode,
        // send, commit → head at 41.
        let sent_id = sender
            .send_checked(
                SAFE_MODE_MIN_PAYLOAD_MTU,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; SAFE_MODE_MIN_PAYLOAD_MTU])),
            )
            .await
            .expect("within-limit send admitted");
        assert_eq!(sent_id, PacketId::new(40), "pipeline returns the previewed/committed ID");
        assert_eq!(sequencer.next_value(), 41, "commit advanced the counter by exactly 1");
        assert_eq!(*attempts.lock().unwrap(), vec![SAFE_MODE_MIN_DATAGRAM_MTU]);
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 1);
        assert_eq!(sender.admission().metrics().sends_rejected, 0);
        assert_eq!(sender.admission().metrics().encode_failures, 0);
        assert_eq!(sender.admission().metrics().transport_failures, 0);

        // One payload byte over -> rejected at the gate, transport never
        // called, and the sequencer is never previewed past its head.
        let mut rejected_sequencer = PacketIdSequencer::new(41);
        match sender
            .send_checked(
                SAFE_MODE_MIN_PAYLOAD_MTU + 1,
                &mut rejected_sequencer,
                envelope_builder(Bytes::from(vec![0xAB; SAFE_MODE_MIN_PAYLOAD_MTU + 1])),
            )
            .await
            .unwrap_err()
        {
            CheckedSendError::Rejected(MtuRejectReason::DatagramExceedsMtu {
                datagram_len,
                datagram_mtu,
            }) => {
                assert_eq!(datagram_len, SAFE_MODE_MIN_DATAGRAM_MTU + 1);
                assert_eq!(datagram_mtu, SAFE_MODE_MIN_DATAGRAM_MTU);
            }
            other => panic!("expected whole-datagram rejection, got {other:?}"),
        }
        assert_eq!(rejected_sequencer.next_value(), 41, "rejected payload leaves the sequencer untouched");
        assert_eq!(sequencer.next_value(), 41, "prior commit is unaffected by the later rejection");
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![SAFE_MODE_MIN_DATAGRAM_MTU],
            "transport must not be invoked for a rejected datagram"
        );
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 1);
        assert_eq!(sender.admission().metrics().sends_rejected, 1);
        assert_eq!(sender.admission().metrics().encode_failures, 0);
        assert_eq!(sender.admission().metrics().transport_failures, 0);
    }

    #[tokio::test]
    async fn checked_sender_rejects_empty_payloads_before_transport() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(0);

        let error = sender
            .send_checked(
                0,
                &mut sequencer,
                envelope_builder(Bytes::new()),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CheckedSendError::Rejected(MtuRejectReason::EmptyPayload)));
        assert_eq!(sequencer.next_value(), 0, "empty payload leaves the sequencer untouched");
        assert!(attempts.lock().unwrap().is_empty(), "no transport call for an empty payload");
        assert_eq!(sender.admission().metrics().sends_admitted, 0);
        assert_eq!(sender.admission().metrics().sends_enqueued, 0);
        assert_eq!(sender.admission().metrics().sends_rejected, 1);
    }

    #[tokio::test]
    async fn checked_sender_blocks_unknown_and_reports_no_fallback() {
        // Transport reports no datagram limit (datagrams disabled or mid
        // negotiation). The V2 gate must deny, not synthesize 1200.
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(None)),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(0);

        let error = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CheckedSendError::Rejected(MtuRejectReason::PathMtuUnknown)));
        assert_eq!(sequencer.next_value(), 0, "absent transport limit leaves the sequencer untouched");
        assert!(attempts.lock().unwrap().is_empty(), "no fallback send may occur");
        assert_eq!(sender.admission().metrics().sends_rejected, 1);
        assert_eq!(sender.admission().metrics().sends_admitted, 0);
        assert_eq!(sender.admission().metrics().sends_enqueued, 0);
    }

    #[tokio::test]
    async fn checked_sender_transport_reject_does_not_commit_packet_id() {
        // WP-302 ID commit blocker: admission passes and a reservation is
        // previewed, but the transport refuses — the sequencer must NOT
        // advance for an undelivered packet.
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: true,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(7);

        let error = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .unwrap_err();

        assert_eq!(sequencer.next_value(), 7, "counter unchanged — no commit on transport reject");

        match error {
            CheckedSendError::Transport(DatagramSendError::TooLarge {
                datagram_len,
                limit,
            }) => {
                assert_eq!(datagram_len, FIXED_HEADER_LEN + 64);
                assert_eq!(limit, SAFE_MODE_MIN_DATAGRAM_MTU);
            }
            other => panic!("expected transport TooLarge, got {other:?}"),
        }
        // Gate passed (attempted), but the transport refused: attempted
        // increments, enqueued never does — only the classified transport
        // failure bucket does.
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 0);
        assert_eq!(sender.admission().metrics().sends_rejected, 0);
        assert_eq!(sender.admission().metrics().encode_failures, 0);
        assert_eq!(sender.admission().metrics().transport_failures, 1);
    }

    #[tokio::test]
    async fn checked_sender_encode_failure_does_not_commit_packet_id() {
        // WP-302 ID commit blocker: admission passes and a reservation is
        // previewed, but `build_envelope` returns a payload larger than the
        // admitted limit, so `V2Envelope::encode` fails with
        // PayloadExceedsLimit. The previewed reservation is never committed.
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(20);

        // Payload length is within the gate (64 bytes < 1300 effective), so
        // admission succeeds and a reservation is previewed. But the envelope
        // payload is 1301 bytes (1 byte over effective MTU), so encode rejects.
        let oversized_builder = |reservation: &PacketReservation| V2Envelope {
            header: V2Header {
                traffic_class: TrafficClass::Bulk,
                direction: Direction::ClientToGateway,
                session_id: SessionId::from_bytes([7; 16]),
                path_id: PathId::new(1),
                path_epoch: 1,
                key_epoch: 1,
                flow_id: FlowId::new(1),
                packet_id: reservation.id(),
            },
            payload: Bytes::from(vec![0xAB; SAFE_MODE_MIN_PAYLOAD_MTU + 1]),
        };

        let error = sender
            .send_checked(64, &mut sequencer, oversized_builder)
            .await
            .unwrap_err();

        assert_eq!(sequencer.next_value(), 20, "counter unchanged — no commit on encode failure");
        match error {
            CheckedSendError::Encode(V2EnvelopeError::PayloadExceedsLimit { length, limit }) => {
                assert_eq!(length, SAFE_MODE_MIN_PAYLOAD_MTU + 1);
                assert_eq!(limit, SAFE_MODE_MIN_PAYLOAD_MTU);
            }
            other => panic!("expected Encode(PayloadExceedsLimit), got {other:?}"),
        }
        // Transport was never invoked (encode failed before send). Gate passed
        // (attempted), but nothing was enqueued: only the encode-failure
        // bucket increments.
        assert!(attempts.lock().unwrap().is_empty());
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 0);
        assert_eq!(sender.admission().metrics().sends_rejected, 0);
        assert_eq!(sender.admission().metrics().encode_failures, 1);
        assert_eq!(sender.admission().metrics().transport_failures, 0);
    }

    #[tokio::test]
    async fn checked_sender_rejects_forged_envelope_id_without_commit() {
        // Non-forgeability gate: the builder ignores the reservation and
        // stamps an unrelated packet ID. The pipeline must reject with
        // `BuildMismatch` before encode/transport, leaving the sequencer
        // untouched and recording only a build failure (never an enqueue).
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(33);

        let forged_builder = |_reservation: &PacketReservation| V2Envelope {
            header: V2Header {
                traffic_class: TrafficClass::Bulk,
                direction: Direction::ClientToGateway,
                session_id: SessionId::from_bytes([7; 16]),
                path_id: PathId::new(1),
                path_epoch: 1,
                key_epoch: 1,
                flow_id: FlowId::new(1),
                packet_id: PacketId::new(999),
            },
            payload: Bytes::from(vec![0xAB; 64]),
        };

        let error = sender
            .send_checked(64, &mut sequencer, forged_builder)
            .await
            .unwrap_err();
        match error {
            CheckedSendError::BuildMismatch { expected, found } => {
                assert_eq!(expected, PacketId::new(33));
                assert_eq!(found, PacketId::new(999));
            }
            other => panic!("expected BuildMismatch, got {other:?}"),
        }
        assert_eq!(sequencer.next_value(), 33, "forged envelope never commits the reservation");
        assert!(attempts.lock().unwrap().is_empty(), "forged envelope never reaches the transport");
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 0);
        assert_eq!(sender.admission().metrics().sends_rejected, 0);
        assert_eq!(sender.admission().metrics().encode_failures, 1);
        assert_eq!(sender.admission().metrics().transport_failures, 0);

        // The next honest send still uses the uncommitted head.
        let sent_id = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .expect("honest send after a forgery attempt");
        assert_eq!(sent_id, PacketId::new(33));
        assert_eq!(sequencer.next_value(), 34);
        assert_eq!(sender.admission().metrics().sends_enqueued, 1);
    }

    #[tokio::test]
    async fn checked_sender_commit_only_after_successful_transport_enqueue() {
        // Full positive pipeline: preview → build → validate → encode →
        // send → commit. This test proves the sequencer advances exactly once
        // per successful send and only after the datagram reached the
        // transport.
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(0);

        // Full payload send: reservation for 0, build, encode (1352 bytes),
        // send → Ok, commit → head at 1.
        let sent_id = sender
            .send_checked(
                SAFE_MODE_MIN_PAYLOAD_MTU,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xCD; SAFE_MODE_MIN_PAYLOAD_MTU])),
            )
            .await
            .expect("successful send");
        assert_eq!(sent_id, PacketId::new(0), "returned ID matches the previewed value");
        assert_eq!(sequencer.next_value(), 1, "counter advanced by exactly 1");
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 1);
        assert_eq!(sender.admission().metrics().sends_rejected, 0);

        // Second send: reservation for 1, commit → head at 2.
        let sent_id2 = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xEF; 64])),
            )
            .await
            .expect("second successful send");
        assert_eq!(sent_id2, PacketId::new(1), "second ID is sequential after commit");
        assert_eq!(sequencer.next_value(), 2, "counter at 2 after two commits");
        assert_eq!(sender.admission().metrics().sends_admitted, 2);
        assert_eq!(sender.admission().metrics().sends_enqueued, 2);
        assert_eq!(sender.admission().metrics().sends_rejected, 0);
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![SAFE_MODE_MIN_DATAGRAM_MTU, FIXED_HEADER_LEN + 64],
            "two distinct datagrams sent to the transport"
        );
    }

    #[tokio::test]
    async fn checked_sender_queries_transport_mtu_each_send() {
        // The transport begins at the safe-mode limit and the gate starts
        // Unknown. The first send discovers from the transport (per-send
        // query), so no explicit `discover` call is needed.
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let current = Arc::new(Mutex::new(Some(dm)));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::clone(&current),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(0);

        let sent_id = sender
            .send_checked(
                SAFE_MODE_MIN_PAYLOAD_MTU,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; SAFE_MODE_MIN_PAYLOAD_MTU])),
            )
            .await
            .expect("first send admitted at safe-mode limit");
        assert_eq!(sent_id, PacketId::new(0), "first previewed ID is committed");
        assert_eq!(sequencer.next_value(), 1);
        assert_eq!(sender.admission().state().datagram_mtu().unwrap().get(), SAFE_MODE_MIN_DATAGRAM_MTU);
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 1);

        // The transport lowers its advertised limit below the safe-mode
        // payload. The NEXT send is rejected at the gate: the sequencer is
        // untouched and the gate records the reduction.
        *current.lock().unwrap() = Some(DatagramMtu::new(1_280).unwrap());
        let mut reduced_sequencer = PacketIdSequencer::new(1);
        let error = sender
            .send_checked(
                SAFE_MODE_MIN_PAYLOAD_MTU,
                &mut reduced_sequencer,
                envelope_builder(Bytes::from(vec![0xAB; SAFE_MODE_MIN_PAYLOAD_MTU])),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CheckedSendError::Rejected(MtuRejectReason::DatagramExceedsMtu { .. })
        ));
        assert_eq!(reduced_sequencer.next_value(), 1, "reduced live limit leaves the sequencer untouched");
        assert_eq!(sender.admission().metrics().mtu_reductions, 1);
        assert!(!sender.admission().can_carry_tun_payload());
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![SAFE_MODE_MIN_DATAGRAM_MTU],
            "the over-limit second datagram must never reach the transport"
        );

        // A small payload still fits the reduced limit and re-syncs a no-op.
        let sent_id3 = sender
            .send_checked(
                64,
                &mut reduced_sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .expect("small payload still admitted after reduction");
        assert_eq!(sent_id3, PacketId::new(1), "previewed ID committed after reduced-limit send");
        assert_eq!(reduced_sequencer.next_value(), 2);
        assert_eq!(sender.admission().metrics().mtu_reductions, 1, "re-sync is a no-op");
        assert_eq!(sender.admission().metrics().sends_admitted, 2);
        assert_eq!(sender.admission().metrics().sends_enqueued, 2);
        assert_eq!(sender.admission().metrics().sends_rejected, 1);
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![SAFE_MODE_MIN_DATAGRAM_MTU, FIXED_HEADER_LEN + 64],
            "only the 64-byte datagram is sent; whole datagram is 52+64=116"
        );
    }

    #[tokio::test]
    async fn checked_sender_absent_transport_limit_denies_even_after_prior_discovery() {
        // The transport granted a limit, then datagrams become unavailable
        // (None). The pipeline must deny (no fallback) without previewing or
        // committing an ID.
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let current = Arc::new(Mutex::new(None::<DatagramMtu>));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::clone(&current),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(0);

        // Transport advertises a limit while datagrams are available.
        current.lock().unwrap().replace(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        let sent_id = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .expect("admissible while the transport advertises a limit");
        assert_eq!(sent_id, PacketId::new(0));
        assert_eq!(sequencer.next_value(), 1);

        // Transport stops advertising a limit: the very next send is denied
        // without a fallback and without touching the sequencer.
        current.lock().unwrap().take();
        let mut denied_sequencer = PacketIdSequencer::new(1);
        let error = sender
            .send_checked(
                64,
                &mut denied_sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .unwrap_err();
        assert_eq!(denied_sequencer.next_value(), 1, "absent live limit leaves the sequencer untouched");
        assert!(matches!(error, CheckedSendError::Rejected(MtuRejectReason::PathMtuUnknown)));
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 1);
        assert_eq!(sender.admission().metrics().sends_rejected, 1);
    }

    #[tokio::test]
    async fn send_checked_splits_attempted_vs_enqueued_counts() {
        // Blocker 1: gate passes (attempted) and successful enqueues are
        // counted separately. Failed encode/send increments only its
        // classified failure bucket and never `sends_enqueued`.
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let current = Arc::new(Mutex::new(Some(dm)));
        // Scripted refusal flag so the third send fails at the transport while
        // the first succeeds. The fake reads the flag per call.
        let refuse = Arc::new(Mutex::new(false));
        struct ScriptedSender {
            attempts: Arc<Mutex<Vec<usize>>>,
            current: Arc<Mutex<Option<DatagramMtu>>>,
            refuse: Arc<Mutex<bool>>,
        }
        #[async_trait]
        impl DatagramSender for ScriptedSender {
            async fn send_datagram(
                &self,
                datagram: Bytes,
                _permit: CheckedSendPermit,
            ) -> Result<(), DatagramSendError> {
                self.attempts.lock().unwrap().push(datagram.len());
                if *self.refuse.lock().unwrap() {
                    let limit = self.current.lock().unwrap().map(|mtu| mtu.get()).unwrap_or(0);
                    return Err(DatagramSendError::TooLarge {
                        datagram_len: datagram.len(),
                        limit,
                    });
                }
                Ok(())
            }
            fn current_datagram_mtu(&self) -> Option<DatagramMtu> {
                *self.current.lock().unwrap()
            }
        }
        let fake = ScriptedSender {
            attempts: Arc::clone(&attempts),
            current: Arc::clone(&current),
            refuse: Arc::clone(&refuse),
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(0);

        // 1. Success: admitted + enqueued + commit.
        sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .expect("first send succeeds");
        assert_eq!(sequencer.next_value(), 1);

        // 2. Encode failure: admitted, previewed, never committed, never
        // enqueued — only `encode_failures`.
        let oversized = |reservation: &PacketReservation| V2Envelope {
            header: V2Header {
                traffic_class: TrafficClass::Bulk,
                direction: Direction::ClientToGateway,
                session_id: SessionId::from_bytes([7; 16]),
                path_id: PathId::new(1),
                path_epoch: 1,
                key_epoch: 1,
                flow_id: FlowId::new(1),
                packet_id: reservation.id(),
            },
            payload: Bytes::from(vec![0xAB; SAFE_MODE_MIN_PAYLOAD_MTU + 1]),
        };
        let error = sender
            .send_checked(64, &mut sequencer, oversized)
            .await
            .unwrap_err();
        assert!(matches!(error, CheckedSendError::Encode(_)));
        assert_eq!(sequencer.next_value(), 1, "encode failure never commits");

        // 3. Transport failure: admitted, previewed, never committed, never
        // enqueued — only `transport_failures`.
        *refuse.lock().unwrap() = true;
        let error = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CheckedSendError::Transport(_)));
        assert_eq!(sequencer.next_value(), 1, "transport failure never commits");
        *refuse.lock().unwrap() = false;

        // 4. Gate rejection: never previewed, never committed, never
        // admitted or enqueued — only `sends_rejected`.
        let mut rejected_sequencer = PacketIdSequencer::new(1);
        let error = sender
            .send_checked(
                SAFE_MODE_MIN_PAYLOAD_MTU + 1,
                &mut rejected_sequencer,
                envelope_builder(Bytes::from(vec![0xAB; SAFE_MODE_MIN_PAYLOAD_MTU + 1])),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CheckedSendError::Rejected(_)));
        assert_eq!(rejected_sequencer.next_value(), 1);

        let metrics = sender.admission().metrics();
        assert_eq!(metrics.sends_admitted, 3, "success + encode fail + transport fail");
        assert_eq!(metrics.sends_enqueued, 1, "only the successful send enqueued");
        assert_eq!(metrics.encode_failures, 1);
        assert_eq!(metrics.transport_failures, 1);
        assert_eq!(metrics.sends_rejected, 1, "only the gate rejection");
        assert_eq!(
            metrics.sends_admitted + metrics.sends_rejected,
            4,
            "every send_checked call lands in exactly one gate bucket"
        );
    }

    #[tokio::test]
    async fn checked_sender_issues_max_once_then_requires_epoch_rotate() {
        // Boundary pipeline: a sequencer at `MAX - 1` issues `MAX - 1` and
        // `MAX` exactly once each, then terminates. The third send fails with
        // the typed exhaustion error before any transport enqueue, and the ID
        // is never reused. Recovery requires a new sequencer under a rotated
        // key epoch (mirroring the receiver: a new `ReceiveKey`).
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(u64::MAX - 1);

        let first = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .expect("MAX-1 issuable");
        assert_eq!(first, PacketId::new(u64::MAX - 1));
        assert_eq!(sequencer.next_value(), u64::MAX);
        assert!(!sequencer.is_exhausted());

        let second = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .expect("MAX issuable once");
        assert_eq!(second, PacketId::new(u64::MAX));
        assert_eq!(sequencer.next_value(), u64::MAX);
        assert!(sequencer.is_exhausted(), "issuing MAX terminates the sequencer");

        let metrics_before = sender.admission().metrics();
        let attempts_before = attempts.lock().unwrap().len();
        let error = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, CheckedSendError::PacketIdExhausted(PacketIdError::Exhausted)),
            "third send fails with typed exhaustion, got {error:?}"
        );
        assert_eq!(sequencer.next_value(), u64::MAX, "exhausted head never reuses");
        assert!(sequencer.is_exhausted(), "exhaustion is sticky");
        assert_eq!(
            attempts.lock().unwrap().len(),
            attempts_before,
            "exhausted send never reaches the transport"
        );
        assert_eq!(
            sender.admission().metrics(),
            metrics_before,
            "exhausted send mutates no gate counters"
        );

        // Epoch rotate: a new sequencer under a new key epoch starts fresh.
        // The new instance issues from zero; the old exhausted instance stays
        // terminal and can never be revived.
        let mut rotated = PacketIdSequencer::new(0);
        assert!(!rotated.is_exhausted());
        let rotated_id = sender
            .send_checked(
                64,
                &mut rotated,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .expect("rotated epoch sends from zero");
        assert_eq!(rotated_id, PacketId::new(0));
        assert_eq!(rotated.next_value(), 1);
        assert!(sequencer.is_exhausted(), "old instance stays terminal after rotate");
    }

    #[tokio::test]
    async fn checked_sender_exhausted_returns_typed_error_before_transport() {
        // An already-exhausted sequencer fails fast: no transport call, no
        // gate counter mutation, no preview/commit. The error takes
        // precedence even over an otherwise gate-rejectable payload, because
        // the exhaustion guard runs before admission.
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: false,
        };
        let mut sender = CheckedDatagramSender::new(fake, MtuAdmission::default());
        let mut sequencer = PacketIdSequencer::new(u64::MAX);
        // Drive to exhausted via one successful MAX send.
        sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .expect("MAX issuable once");
        assert!(sequencer.is_exhausted());
        let metrics_after_max = sender.admission().metrics();
        let attempts_after_max = attempts.lock().unwrap().len();
        assert_eq!(attempts_after_max, 1);

        // A valid-size payload on an exhausted sequencer: typed exhaustion,
        // not admission, and no new transport call.
        let error = sender
            .send_checked(
                64,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; 64])),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CheckedSendError::PacketIdExhausted(PacketIdError::Exhausted)
        ));
        assert_eq!(sequencer.next_value(), u64::MAX);
        assert_eq!(
            attempts.lock().unwrap().len(),
            attempts_after_max,
            "exhausted send never enqueues"
        );
        assert_eq!(
            sender.admission().metrics(),
            metrics_after_max,
            "exhausted send leaves gate counters untouched"
        );

        // Even a gate-rejectable (oversized) payload reports exhaustion first:
        // the sequencer guard runs before admission so no ID could be previewed.
        let error = sender
            .send_checked(
                SAFE_MODE_MIN_PAYLOAD_MTU + 1,
                &mut sequencer,
                envelope_builder(Bytes::from(vec![0xAB; SAFE_MODE_MIN_PAYLOAD_MTU + 1])),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CheckedSendError::PacketIdExhausted(PacketIdError::Exhausted)
        ));
        assert_eq!(
            sender.admission().metrics(),
            metrics_after_max,
            "exhaustion precedes admission accounting"
        );
    }

    #[tokio::test]
    async fn raw_send_requires_checked_permit() {
        // Blocker 2: raw transport send cannot be invoked without the
        // crate-private permit that only `send_checked` constructs. Inside
        // this crate the permit is available; outside `sg-transport` the
        // constructor is invisible, so a public `V2QuicDatagramSender` handle
        // exposes no bypass.
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let attempts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDatagramSender {
            attempts: Arc::clone(&attempts),
            current: Arc::new(Mutex::new(Some(dm))),
            refuse: false,
        };
        fake.send_datagram(Bytes::from(vec![0xAB; 64]), CheckedSendPermit::new())
            .await
            .expect("raw send with the checked permit succeeds inside the crate");
        assert_eq!(*attempts.lock().unwrap(), vec![64]);
    }

    // ----- Metrics recording -----

    #[test]
    fn metrics_record_event_increments_correctly() {
        let mut metrics = MtuMetrics::default();
        metrics.record_event(MtuEvent::MtuDiscovered { datagram_mtu: 1352 });
        assert_eq!(metrics.mtu_reductions, 0);
        assert_eq!(metrics.blackholes_detected, 0);

        metrics.record_event(MtuEvent::MtuReduced { previous: 1500, current: 1352 });
        assert_eq!(metrics.mtu_reductions, 1);
        assert_eq!(metrics.blackholes_detected, 0);

        // The typed ignored-reduction event is deliberately not a reduction.
        metrics.record_event(MtuEvent::ReduceIgnored { requested: 1500, current: 1352 });
        assert_eq!(metrics.mtu_reductions, 1);
        assert_eq!(metrics.blackholes_detected, 0);

        metrics.record_event(MtuEvent::MtuBlackHole);
        assert_eq!(metrics.mtu_reductions, 1);
        assert_eq!(metrics.blackholes_detected, 1);

        metrics.record_event(MtuEvent::NoOp);
        assert_eq!(metrics.mtu_reductions, 1);
        assert_eq!(metrics.blackholes_detected, 1);
    }

    // ----- Safe mode constants consistency -----

    #[test]
    fn safe_mode_consts_are_consistent() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        assert_eq!(dm.effective_payload().get(), SAFE_MODE_MIN_PAYLOAD_MTU);
        assert_eq!(
            SAFE_MODE_MIN_DATAGRAM_MTU - FIXED_HEADER_LEN,
            SAFE_MODE_MIN_PAYLOAD_MTU,
        );
    }

    // ----- Debug never leaks payload content -----

    #[test]
    fn debug_never_leaks_payload_content() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let state = PathMtuState::Available {
            datagram_mtu: dm,
            effective: dm.effective_payload(),
        };
        let debug = format!("{state:?}");
        assert!(debug.contains("Available"));
        assert!(!debug.contains("payload"));

        let metrics = MtuMetrics::default();
        let debug = format!("{metrics:?}");
        assert!(!debug.contains("0x")); // no hex payload bytes
    }

    // ----- Fuzz: arbitrary payload/datagram lengths never panic -----

    #[test]
    fn admission_never_panics_for_any_length() {
        let dm = DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap();
        let (state, _) = PathMtuState::Unknown.discover(dm);
        let interesting = [
            0, 1, 51, 52, 53, 64, 1024, 1299, 1300, 1301, 1351, 1352, 1353, 1500, 65534, 65535,
        ];
        for len in interesting {
            let _ = check_payload(len, &state);
            let _ = check_datagram(len, &state);
        }
        for len in interesting {
            let _ = check_payload(len, &PathMtuState::Unknown);
            let _ = check_datagram(len, &PathMtuState::Unknown);
        }
        let (bh, _) = PathMtuState::Unknown.discover(dm);
        let (bh, _) = bh.blackhole();
        for len in interesting {
            let _ = check_payload(len, &bh);
            let _ = check_datagram(len, &bh);
        }

        let mut admission = MtuAdmission::default();
        admission.discover(dm);
        // The gate never allocates packet IDs (no ID helper exists): gate
        // checks for every length must not panic and must land in exactly one
        // of the admitted/rejected buckets.
        let admitted_before = admission.metrics().sends_admitted;
        let rejected_before = admission.metrics().sends_rejected;
        for len in interesting {
            let _ = admission.admit_payload(len);
        }
        let admitted = admission.metrics().sends_admitted - admitted_before;
        let rejected = admission.metrics().sends_rejected - rejected_before;
        assert_eq!(
            admitted + rejected,
            interesting.len() as u64,
            "every gate check lands in exactly one bucket"
        );
        assert_eq!(admission.metrics().sends_enqueued, 0, "gate checks never enqueue");
    }
}