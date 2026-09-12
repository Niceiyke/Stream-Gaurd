//! Minimal V2 gateway engine supervisor (REBUILD WP-300/WP-302/WP-400).
//!
//! Owns one [`DriverTun`] (the exclusive blocking TUN owner) and mirrors its
//! durable terminal failure into a typed engine state. Since WP-302 the engine
//! also owns the V2 MTU admission gate ([`MtuAdmission`], derived at
//! construction from the driver's actual advertised TUN config) so the future
//! downlink can validate a payload **before** packet-ID/counter commit, plus the
//! engine-owned packet-ID sequencer ([`PacketIdSequencer`]) whose counter the
//! checked send pipeline previews (never advancing) and commits (only after a
//! successful transport enqueue). Since WP-400 the engine also owns the sole
//! client→gateway uplink ingress ([`V2GatewayEngine::ingest_uplink`]): every
//! uplink datagram is first bound to its authenticated transport connection
//! via the authoritative [`V2SessionManager::validate_ingress`] (session, path,
//! path/key epochs, direction, expiry, health, and session idle renewal), and
//! only then source-validated against the bounded [`AddressPool`] via
//! [`UplinkForwarder`], renewing that Active lease to `now + lease_ttl`
//! through the bounded owner wall time (authenticated activity renewal; only
//! validated ingress renews, failures fail closed with no forward), and sealed
//! through [`V2ForwardingSink`] behind the [`V2TunNatEgress`] contract, which
//! accepts solely [`ValidatedUplink`] (never raw `Bytes` plus a caller-supplied
//! session). There is intentionally no V2 packet, flow-table, NAT, or scheduler
//! wiring beyond that sealed handoff: WP-401/402 own the flow table and host
//! wiring behind the same sealed contract. V1 gateway code (`tunnel.rs`) and
//! the V2 admission listener are untouched: the listener mints the
//! [`AuthenticatedConnection`] capability the ingress requires, and no caller
//! can bypass it with a raw session ID.
//!
//! Autonomous terminal notification (WP-300 final blocker): the driver publishes
//! a single coalescing `watch` bool on its first failure (`send_replace`, so a
//! fault that races `spawn` is still visible to a late subscriber). The engine
//! subscribes at [`V2GatewayEngine::new`] and supervises exactly one Tokio task
//! that awaits the signal and flips `Running -> Terminal`. No polling loop and
//! no `observe` call is required; reads (`state`, `is_terminal`, `failure`)
//! also perform a prompt sync from the driver's durable failure so a caller
//! without a runtime still observes `Terminal` on its next read.
//!
//! Bounds: exactly one driver (one worker thread, one backend), one watch value,
//! at most one supervisor task, bounded driver queues owned by `DriverTun`, no
//! additional collections, channels, or tasks. Shutdown is explicit (`shutdown`
//! consumes the engine, aborts/joins the supervisor task, then joins the worker
//! off the runtime); dropping a live engine without `shutdown` is a programming
//! bug and surfaces as a durable `JoinRequired` terminal failure on every cloned
//! sender.

use sg_protocol::v2::V2Envelope;
use sg_transport::mtu::{
    AdmissionResult, DatagramMtu, MtuAdmission, MtuEvent, MtuMetrics, MtuRejectReason,
    PacketIdSequencer, PathMtuState,
};
use sg_tun::driver::{DriverError, DriverFailure, DriverMetrics, DriverSender, DriverTun};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::task::JoinHandle;

use super::address_pool::{AddressPool, AddressPoolError};
use super::forwarding::{
    ForwardError, ForwardedUplink, ForwarderSnapshot, SinkSnapshot, UplinkForwarder,
    V2ForwardingSink, V2TunNatEgress,
};
use super::persistence::PoolTime;
use super::session_manager::{
    AuthenticatedConnection, V2SessionManager, V2SessionManagerError,
};

/// Typed supervisor state for the V2 gateway engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2GatewayEngineState {
    /// Driver is owned and no terminal failure has been observed.
    Running,
    /// The driver recorded a durable terminal failure (read, write, or
    /// `JoinRequired`). First fault wins, matching [`DriverTun`].
    Terminal(DriverFailure),
    /// The engine was shut down cleanly with no recorded failure.
    Closed,
}

/// Typed uplink-ingress failure for the sole validated ingress
/// ([`V2GatewayEngine::ingest_uplink`]). `NotAttached` means the address pool
/// or the session manager has not been attached yet (fail closed);
/// `BindingRejected` carries the authoritative [`V2SessionManagerError`] from
/// transport binding validation (unknown connection, binding mismatch, stale
/// key epoch, wrong direction, expiry/idle); `Rejected` carries the sealed
/// [`ForwardError`] from source validation (parse vs spoof drops are counted
/// in the forwarder snapshot); `LeaseRejected` carries the
/// [`AddressPoolError`] from authenticated activity renewal (expired, unknown,
/// or store failure fails closed with no forward). Binding is always checked
/// before source validation, and renewal happens only after both succeed, so a
/// datagram that fails the transport bind or source check never extends a
/// lease. Never logs packet contents.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum UplinkIngestError {
    #[error("v2 uplink ingress has no attached address pool or session manager")]
    NotAttached,
    #[error("v2 uplink transport binding was rejected")]
    BindingRejected(#[from] V2SessionManagerError),
    #[error("v2 uplink packet was rejected")]
    Rejected(#[from] ForwardError),
    #[error("v2 uplink lease renewal was rejected")]
    LeaseRejected(#[from] AddressPoolError),
}

/// Minimal supervisor owning one V2 blocking TUN driver, the V2 MTU
/// admission gate, and the sole validated uplink ingress (WP-400).
pub struct V2GatewayEngine {
    driver: Option<DriverTun>,
    state: Arc<Mutex<V2GatewayEngineState>>,
    watcher: Option<JoinHandle<()>>,
    /// Engine-owned V2 MTU admission gate, derived from the driver's
    /// advertised TUN config (WP-302).
    mtu: MtuAdmission,
    /// Engine-owned V2 packet-ID sequencer for the gateway→client send
    /// direction (WP-302 preview-closure blocker). The first packet ID is 0;
    /// the counter advances only inside
    /// [`CheckedDatagramSender::send_checked`](sg_transport::mtu::CheckedDatagramSender::send_checked)
    /// after a successful transport enqueue. There is no other advancing
    /// path: handing `&mut` to the checked pipeline is the only way to move
    /// the head.
    sequencer: PacketIdSequencer,
    /// Sealed uplink source validator (WP-400). `None` until
    /// [`V2GatewayEngine::attach_uplink`] installs the bounded pool lease
    /// bind; [`V2GatewayEngine::ingest_uplink`] fails closed while detached.
    uplink_forwarder: Option<Arc<UplinkForwarder>>,
    /// Authoritative transport binding validator (WP-400 final blocker).
    /// `None` until [`V2GatewayEngine::attach_session_manager`] installs the
    /// shared session map; [`V2GatewayEngine::ingest_uplink`] fails closed
    /// while detached so no datagram can bypass
    /// [`V2SessionManager::validate_ingress`].
    sessions: Option<Arc<V2SessionManager>>,
    /// Sealed uplink egress sink (WP-400). Only
    /// [`V2GatewayEngine::ingest_uplink`] may submit to it in production:
    /// it accepts solely `ValidatedUplink` (via [`V2TunNatEgress`]), never
    /// raw `Bytes` plus a session, so spoofed sources can never reach the
    /// TUN/NAT handoff. Bounded atomics only.
    uplink_sink: V2ForwardingSink,
}

fn lock_state(state: &Arc<Mutex<V2GatewayEngineState>>) -> std::sync::MutexGuard<'_, V2GatewayEngineState> {
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl V2GatewayEngine {
    /// Takes ownership of an already-spawned driver and starts supervising it.
    ///
    /// Subscribes to the driver's coalescing terminal signal and, when a Tokio
    /// runtime is present, spawns exactly one supervised task that awaits the
    /// signal and flips `Running -> Terminal`. Outside a runtime no task is
    /// spawned (no panic); reads still sync promptly from the driver's durable
    /// failure on their next call.
    #[must_use]
    pub fn new(driver: DriverTun) -> Self {
        let state = Arc::new(Mutex::new(V2GatewayEngineState::Running));
        // Fast-path sync: a failure that raced `spawn` (published via
        // `send_replace` before we subscribed) is already visible here.
        if let Some(failure) = driver.failure() {
            *lock_state(&state) = V2GatewayEngineState::Terminal(failure);
        }
        let watcher = tokio::runtime::Handle::try_current().ok().map(|_| {
            let sender = driver.sender();
            let mut terminal = driver.subscribe_terminal();
            let state_clone = Arc::clone(&state);
            tokio::spawn(async move {
                // Coalescing wait: returns immediately for a late subscriber
                // after a failure, otherwise parks until the worker publishes.
                // A closed channel (all senders dropped) ends the watch without
                // transitioning; shutdown handles the clean-close path.
                let signalled = terminal.wait_for(|ready| *ready).await.is_ok();
                if !signalled {
                    return;
                }
                if let Some(failure) = sender.failure() {
                    let mut guard = lock_state(&state_clone);
                    if matches!(*guard, V2GatewayEngineState::Running) {
                        tracing::warn!(kind = ?failure.kind(), "v2 gateway engine entering terminal state");
                        *guard = V2GatewayEngineState::Terminal(failure);
                    }
                }
            })
        });
        let mtu = Self::mtu_admission_from_driver(&driver);
        Self {
            driver: Some(driver),
            state,
            watcher,
            mtu,
            sequencer: PacketIdSequencer::new(0),
            uplink_forwarder: None,
            sessions: None,
            uplink_sink: V2ForwardingSink::new(),
        }
    }

    /// Attaches the bounded address-pool lease bind for the sole uplink
    /// ingress (WP-400). Creates the sealed [`UplinkForwarder`] over `pool`
    /// with `maximum_packet_bytes` (validated as `1280..=65535`, matching the
    /// forwarder contract) and installs it; the engine-owned
    /// [`V2ForwardingSink`] is reused so egress counters survive re-attach.
    /// Idempotent: re-attaching replaces the forwarder. Production wiring
    /// calls this once after admission-pool startup and before serving
    /// datagrams; [`V2GatewayEngine::ingest_uplink`] fails closed until then.
    pub fn attach_uplink(
        &mut self,
        pool: Arc<AddressPool>,
        maximum_packet_bytes: usize,
    ) -> Result<(), ForwardError> {
        let forwarder = UplinkForwarder::new(pool, maximum_packet_bytes)?;
        self.uplink_forwarder = Some(Arc::new(forwarder));
        Ok(())
    }

    /// Attaches the authoritative session map for transport binding validation
    /// (WP-400 final blocker). The manager must be the same instance the V2
    /// admission listener commits sessions and path bindings into, so the
    /// capability passed to [`V2GatewayEngine::ingest_uplink`] always resolves
    /// against live admission state. Idempotent: re-attaching replaces the
    /// handle. Production wiring calls this before serving datagrams;
    /// [`V2GatewayEngine::ingest_uplink`] fails closed until both the pool
    /// and the session map are attached.
    pub fn attach_session_manager(&mut self, sessions: Arc<V2SessionManager>) {
        self.sessions = Some(sessions);
    }

    /// Sole client→gateway uplink ingress (WP-400).
    ///
    /// The caller presents the listener-minted [`AuthenticatedConnection`]
    /// capability for the QUIC connection the datagram arrived on, the decoded
    /// [`V2Envelope`] for that datagram, and the deterministic `now_ms`. The
    /// engine first binds the envelope to the authenticated connection via
    /// [`V2SessionManager::validate_ingress`] (session, path, path/key epochs,
    /// direction, expiry, health, and session idle renewal), and only then
    /// validates the envelope payload's IP source against the bound session's
    /// committed Active lease ([`UplinkForwarder::validate`]), renews that
    /// Active lease to `now + lease_ttl` (authenticated activity renewal), and
    /// seals the packet through the engine-owned [`V2ForwardingSink`] behind
    /// the [`V2TunNatEgress`] contract (`emit_validated`), which accepts solely
    /// the sealed type. Any failure drops the packet before any TUN/NAT
    /// handoff: binding failures never touch pool counters, source failures
    /// count in the forwarder snapshot (parse vs spoof) and never renew,
    /// renewal failures (`Expired`/`Unknown`/`Store`) fail closed with no
    /// forward and no sink emit. There is no raw-`SessionId` overload by
    /// construction, so a caller cannot bypass the transport bind. Never logs
    /// packet contents.
    ///
    /// Test/legacy entry point: `now_ms` supplies both clock domains
    /// (`PoolTime::from_monotonic`). Production must use
    /// [`V2GatewayEngine::ingest_uplink_at_time`] with a real wall clock so
    /// durable lease renewal survives a restart.
    ///
    /// The returned [`ForwardedUplink`] is the only packet the future
    /// TUN/NAT egress (WP-401/WP-402) may write to the host stack. The raw
    /// [`DriverSender::send`] path remains for WP-300 driver supervision
    /// tests and must never carry client uplink in production.
    #[allow(dead_code)] // Production datagram loop arrives in WP-401; tests are the sole caller today.
    pub(crate) fn ingest_uplink(
        &self,
        connection: AuthenticatedConnection,
        envelope: &V2Envelope,
        now_ms: u64,
    ) -> Result<ForwardedUplink, UplinkIngestError> {
        let sessions = self.sessions.as_ref().ok_or(UplinkIngestError::NotAttached)?;
        let forwarder = self.uplink_forwarder.as_ref().ok_or(UplinkIngestError::NotAttached)?;
        let pool = forwarder.pool();
        let bound = sessions
            .validate_ingress(connection, envelope, now_ms)
            .map_err(UplinkIngestError::BindingRejected)?;
        let validated = forwarder
            .validate(bound.session_id, envelope.payload.clone())
            .map_err(UplinkIngestError::Rejected)?;
        // Authenticated activity renewal: only validated ingress (binding +
        // source both succeed) extends the Active lease. Failures fail closed
        // with no forward and no sink emit; spoofed sources never reach here.
        pool.renew_at_time(bound.session_id, PoolTime::from_monotonic(now_ms))
            .map_err(UplinkIngestError::LeaseRejected)?;
        Ok(self.uplink_sink.emit_validated(validated))
    }

    /// Wall-aware validated ingress with authenticated activity renewal (V2
    /// Safe Mode renewal policy).
    ///
    /// Identical to [`V2GatewayEngine::ingest_uplink`] except the renewal uses
    /// the gateway's wall time (`PoolTime`) through the bounded owner queue,
    /// so durable leases persist a wall expiry that survives a restart.
    /// `now.monotonic_ms` drives binding/idle checks; `now.wall_ms` drives the
    /// durable journal. Renewal failures fail closed with no forward. Never
    /// logs packet contents.
    #[allow(dead_code)] // Production datagram loop arrives in WP-401; renewal tests are the caller today.
    pub(crate) async fn ingest_uplink_at_time(
        &self,
        connection: AuthenticatedConnection,
        envelope: &V2Envelope,
        now: PoolTime,
    ) -> Result<ForwardedUplink, UplinkIngestError> {
        let sessions = self.sessions.as_ref().ok_or(UplinkIngestError::NotAttached)?;
        let forwarder = self.uplink_forwarder.as_ref().ok_or(UplinkIngestError::NotAttached)?;
        let pool = Arc::clone(forwarder.pool());
        let bound = sessions
            .validate_ingress(connection, envelope, now.monotonic_ms)
            .map_err(UplinkIngestError::BindingRejected)?;
        let validated = forwarder
            .validate(bound.session_id, envelope.payload.clone())
            .map_err(UplinkIngestError::Rejected)?;
        pool.renew_at_time_async(bound.session_id, now)
            .await
            .map_err(UplinkIngestError::LeaseRejected)?;
        Ok(self.uplink_sink.emit_validated(validated))
    }

    /// True once [`V2GatewayEngine::attach_uplink`] has installed the lease
    /// bind. `false` means [`V2GatewayEngine::ingest_uplink`] fails closed.
    #[must_use]
    pub fn uplink_attached(&self) -> bool {
        self.uplink_forwarder.is_some()
    }

    /// True once [`V2GatewayEngine::attach_session_manager`] has installed the
    /// authoritative session map. `false` means
    /// [`V2GatewayEngine::ingest_uplink`] fails closed.
    #[must_use]
    pub fn sessions_attached(&self) -> bool {
        self.sessions.is_some()
    }

    /// True once both the address pool and the session map are attached and
    /// [`V2GatewayEngine::ingest_uplink`] can validate datagrams.
    #[must_use]
    pub fn ingress_ready(&self) -> bool {
        self.uplink_forwarder.is_some() && self.sessions.is_some()
    }

    /// Snapshot of the attached uplink validator, if any. Counts validated,
    /// parse-dropped, and spoof-dropped uplinks with no payload data.
    #[must_use]
    pub fn uplink_forwarder_snapshot(&self) -> Option<ForwarderSnapshot> {
        self.uplink_forwarder.as_ref().map(|forwarder| forwarder.snapshot())
    }

    /// Snapshot of the sealed uplink egress sink. `forwarded` advances only
    /// for source-validated packets; spoofed sources never reach it.
    #[must_use]
    pub fn uplink_sink_snapshot(&self) -> SinkSnapshot {
        self.uplink_sink.snapshot()
    }

    /// Sealed-sink egress snapshot via the [`V2TunNatEgress`] contract. This
    /// is the observability seam the future TUN/NAT egress (WP-401/WP-402)
    /// reads; it reports the same counters as
    /// [`V2GatewayEngine::uplink_sink_snapshot`].
    #[must_use]
    pub fn uplink_egress_snapshot(&self) -> SinkSnapshot {
        V2TunNatEgress::egress_snapshot(&self.uplink_sink)
    }

    /// Builds the admission gate from the driver's **actual advertised TUN
    /// config** (`backend.mtu()`, the safe-mode 1300 in production). The gate
    /// is never a V1-style implicit constant: it reflects the real adapter
    /// config the OS will generate packets at.
    ///
    /// A backend that reports an out-of-range MTU falls back to the safe-mode
    /// default (1300) with a warning; the engine stays usable and the anomaly
    /// is observable, never a crash.
    fn mtu_admission_from_driver(driver: &DriverTun) -> MtuAdmission {
        let backend_mtu = driver.backend_mtu() as usize;
        match MtuAdmission::with_tun_payload_mtu(backend_mtu) {
            Ok(admission) => admission,
            Err(error) => {
                tracing::warn!(backend_mtu, %error, "v2 TUN backend MTU out of range; falling back to safe-mode default");
                MtuAdmission::default()
            }
        }
    }

    /// Syncs a driver failure that arrived without the watcher (no runtime, or
    /// a race between publish and task wakeup) into `Running -> Terminal`.
    /// Idempotent: `Terminal` and `Closed` never change here. Takes no async
    /// lock and holds the state lock only for the short transition.
    fn sync_state(&self) {
        let is_running = matches!(*lock_state(&self.state), V2GatewayEngineState::Running);
        if !is_running {
            return;
        }
        if let Some(failure) = self.driver.as_ref().and_then(|driver| driver.failure()) {
            let mut guard = lock_state(&self.state);
            if matches!(*guard, V2GatewayEngineState::Running) {
                tracing::warn!(kind = ?failure.kind(), "v2 gateway engine entering terminal state");
                *guard = V2GatewayEngineState::Terminal(failure);
            }
        }
    }

    /// Current supervisor state. `Terminal` is sticky: once observed it never
    /// returns to `Running`. Transitions autonomously via the supervisor task
    /// (or via prompt sync on read when no runtime is present); no `observe`
    /// polling call is required.
    #[must_use]
    pub fn state(&self) -> V2GatewayEngineState {
        self.sync_state();
        lock_state(&self.state).clone()
    }

    /// True once a durable terminal failure has been observed.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.sync_state();
        matches!(*lock_state(&self.state), V2GatewayEngineState::Terminal(_))
    }

    /// The durable terminal failure, if the supervisor has entered `Terminal`.
    #[must_use]
    pub fn failure(&self) -> Option<DriverFailure> {
        self.sync_state();
        if let V2GatewayEngineState::Terminal(failure) = &*lock_state(&self.state) {
            Some(failure.clone())
        } else {
            None
        }
    }

    /// Event-driven wait for the terminal outcome. Returns `Some(failure)` once
    /// the supervisor is `Terminal` (fast-path when already terminal, otherwise
    /// awaits the driver's coalescing signal without polling). Returns `None`
    /// when the engine was shut down cleanly (driver gone with no failure, or
    /// the watch channel closed). Never polls; bound callers with a timeout.
    pub async fn await_terminal(&self) -> Option<DriverFailure> {
        if let Some(failure) = self.failure() {
            return Some(failure);
        }
        let mut terminal = self.driver.as_ref().map(|driver| driver.subscribe_terminal())?;
        // Immediate for a late subscriber after a failure; parks otherwise.
        let _ = terminal.wait_for(|ready| *ready).await.ok()?;
        self.failure()
    }

    /// Cloneable egress sender sharing the owned driver's queues, if the
    /// driver is still owned (before `shutdown`).
    #[must_use]
    pub fn sender(&self) -> Option<DriverSender> {
        self.driver.as_ref().map(|driver| driver.sender())
    }

    /// Live driver counters and queue depths, if the driver is still owned.
    #[must_use]
    pub fn metrics(&self) -> Option<DriverMetrics> {
        self.driver.as_ref().map(|driver| driver.metrics())
    }

    /// Name reported by the backend at spawn time, if still owned.
    #[must_use]
    pub fn backend_name(&self) -> Option<String> {
        self.driver.as_ref().map(|driver| driver.backend_name().to_owned())
    }

    /// MTU reported by the backend at spawn time, if still owned.
    #[must_use]
    pub fn backend_mtu(&self) -> Option<u32> {
        self.driver.as_ref().map(|driver| driver.backend_mtu())
    }

    /// Snapshot of the engine-owned MTU admission gate (state + counters).
    /// Starts in `Unknown` with the safe-mode TUN payload policy; the path
    /// supervisor drives it with the `on_mtu_*` methods (WP-302).
    #[must_use]
    pub fn mtu_admission(&self) -> MtuAdmission {
        self.mtu
    }

    /// Current per-path MTU state (`Unknown` until the first discovery).
    #[must_use]
    pub fn mtu_state(&self) -> PathMtuState {
        self.mtu.state()
    }

    /// MTU admission counters owned by the gate.
    #[must_use]
    pub fn mtu_metrics(&self) -> MtuMetrics {
        self.mtu.metrics()
    }

    /// True while the current path can still carry a full TUN-sized payload.
    /// Flipping to false after an MTU reduction is the typed failover signal
    /// for the path supervisor (WP-302, WP-501).
    #[must_use]
    pub fn can_carry_tun_payload(&self) -> bool {
        self.mtu.can_carry_tun_payload()
    }

    /// Admits a payload length at the engine-owned MTU gate. A rejection means
    /// the caller MUST NOT sequence, deliver, or count the packet (WP-302).
    /// Sequencing belongs to the checked send pipeline
    /// (`CheckedDatagramSender::send_checked` with the engine-owned
    /// [`PacketIdSequencer`]); this gate never allocates or commits a packet ID.
    pub fn admit_payload(&mut self, payload_len: usize) -> Result<AdmissionResult, MtuRejectReason> {
        self.mtu.admit_payload(payload_len)
    }

    /// Non-advancing peek at the next V2 packet ID for the gateway→client
    /// send direction. Pure read: repeated calls return the same value until
    /// the checked send pipeline commits a send. Public callers cannot
    /// advance the preview through this seam.
    #[must_use]
    pub fn packet_next_value(&self) -> u64 {
        self.sequencer.next_value()
    }

    /// Exclusive access to the engine-owned packet-ID sequencer for the
    /// checked send pipeline
    /// ([`CheckedDatagramSender::send_checked`](sg_transport::mtu::CheckedDatagramSender::send_checked)).
    /// The pipeline previews (never advancing) and commits (only after a
    /// successful transport enqueue); preview and commit are private to
    /// `sg-transport`, so this handle offers no other advancing path.
    pub fn packet_sequencer_mut(&mut self) -> &mut PacketIdSequencer {
        &mut self.sequencer
    }

    /// Records path MTU discovery on the selected path.
    pub fn on_mtu_discovered(&mut self, mtu: DatagramMtu) -> MtuEvent {
        self.mtu.discover(mtu)
    }

    /// Records a path MTU reduction report. Only strictly smaller values
    /// replace the limit; equal/larger reports yield
    /// [`MtuEvent::ReduceIgnored`] and never raise the path MTU.
    pub fn on_mtu_reduced(&mut self, new_mtu: DatagramMtu) -> MtuEvent {
        self.mtu.reduce(new_mtu)
    }

    /// Records a complete MTU black hole on the selected path.
    pub fn on_mtu_blackhole(&mut self) -> MtuEvent {
        self.mtu.blackhole()
    }

    /// Records MTU recovery (re-discovery) after a black hole.
    pub fn on_mtu_recovered(&mut self, mtu: DatagramMtu) -> MtuEvent {
        self.mtu.recover(mtu)
    }

    /// Asks the owned driver worker to exit (flag + interrupt event, prompt
    /// wakeup). Idempotent and non-blocking; use [`V2GatewayEngine::shutdown`]
    /// to join. A missing driver (after `shutdown`) is a no-op.
    pub fn request_shutdown(&self) {
        if let Some(driver) = self.driver.as_ref() {
            driver.shutdown();
        }
    }

    /// Signals shutdown, abandons the supervisor task, joins the blocking
    /// worker off the async runtime, and reports the terminal outcome. A
    /// recorded [`DriverFailure`] yields `Terminal`; a clean join yields
    /// `Closed`. `Err(JoinFailed)` means the worker panicked and must be
    /// treated as fatal.
    pub async fn shutdown(mut self) -> Result<V2GatewayEngineState, DriverError> {
        // Explicit cancellation for the single supervised task; never blocks.
        if let Some(watcher) = self.watcher.take() {
            watcher.abort();
            let _ = watcher.await;
        }
        let Some(driver) = self.driver.take() else {
            return Ok(lock_state(&self.state).clone());
        };
        match driver.close_async().await {
            Ok(None) => {
                let mut guard = lock_state(&self.state);
                // Preserve a `Terminal` that raced shutdown (watcher or sync
                // already flipped); only a still-`Running` engine closes clean.
                if matches!(*guard, V2GatewayEngineState::Running) {
                    *guard = V2GatewayEngineState::Closed;
                }
                Ok(guard.clone())
            }
            Ok(Some(failure)) => {
                let mut guard = lock_state(&self.state);
                // First fault wins: keep an existing `Terminal` (watcher may
                // have stored the same failure just before shutdown).
                if matches!(*guard, V2GatewayEngineState::Running) {
                    tracing::warn!(kind = ?failure.kind(), "v2 gateway engine shut down with terminal failure");
                    *guard = V2GatewayEngineState::Terminal(failure);
                }
                Ok(guard.clone())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for V2GatewayEngine {
    fn drop(&mut self) {
        // Explicit-shutdown ownership: abort the single supervisor task without
        // blocking (it holds only a sender clone and state, so abort drops
        // promptly). A live driver here means the engine was dropped without
        // `shutdown`; the inner `DriverTun` Drop then records durable
        // `JoinRequired` visible via every cloned sender.
        if let Some(watcher) = self.watcher.take() {
            watcher.abort();
        }
        if self.driver.is_some() {
            tracing::error!("v2 gateway engine dropped without shutdown; JoinRequired expected");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sg_tun::driver::{DriverConfig, FailureKind, InterruptTrigger, TunInterrupt};
    use sg_transport::mtu::{SAFE_MODE_MIN_DATAGRAM_MTU, SAFE_MODE_MIN_PAYLOAD_MTU};
    use std::io;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct StubInner {
        fail_read: bool,
        fail_write: bool,
        interrupt_requested: bool,
        interrupt_triggers: usize,
        entered_read: usize,
    }

    struct StubBackend {
        state: Arc<(Mutex<StubInner>, Condvar)>,
        mtu: u32,
    }

    struct StubInterrupt {
        state: Arc<(Mutex<StubInner>, Condvar)>,
    }

    impl InterruptTrigger for StubInterrupt {
        fn trigger(&self) {
            let (lock, cvar) = &*self.state;
            if let Ok(mut guard) = lock.lock() {
                guard.interrupt_requested = true;
                guard.interrupt_triggers = guard.interrupt_triggers.saturating_add(1);
            }
            cvar.notify_all();
        }
    }

    #[derive(Clone)]
    struct StubHandle {
        state: Arc<(Mutex<StubInner>, Condvar)>,
    }

    fn stub_pair() -> (StubBackend, StubHandle) {
        stub_pair_with_mtu(1_300)
    }

    fn stub_pair_with_mtu(mtu: u32) -> (StubBackend, StubHandle) {
        let state = Arc::new((
            Mutex::new(StubInner {
                fail_read: false,
                fail_write: false,
                interrupt_requested: false,
                interrupt_triggers: 0,
                entered_read: 0,
            }),
            Condvar::new(),
        ));
        (
            StubBackend { state: Arc::clone(&state), mtu },
            StubHandle { state },
        )
    }

    impl TunInterrupt for StubBackend {
        fn read_interruptible(&mut self, _buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.entered_read = guard.entered_read.saturating_add(1);
            cvar.notify_all();
            let deadline = Instant::now() + timeout;
            loop {
                if guard.fail_read {
                    guard.fail_read = false;
                    return Err(io::Error::new(io::ErrorKind::ConnectionReset, "stub read error"));
                }
                if guard.interrupt_requested {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "stub interrupt"));
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "stub no packet"));
                }
                let (next, _) = cvar
                    .wait_timeout(guard, deadline - now)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard = next;
            }
        }

        fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
            let (lock, _) = &*self.state;
            let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if guard.fail_write {
                guard.fail_write = false;
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stub write error"));
            }
            Ok(packet.len())
        }

        fn mtu(&self) -> u32 {
            self.mtu
        }

        fn name(&self) -> &str {
            "stub-tun"
        }

        fn interrupt_trigger(&self) -> Option<Arc<dyn InterruptTrigger>> {
            Some(Arc::new(StubInterrupt { state: Arc::clone(&self.state) }))
        }
    }

    impl StubHandle {
        fn fail_next_read(&self) {
            self.state.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).fail_read = true;
            self.state.1.notify_all();
        }

        fn fail_next_write(&self) {
            self.state.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).fail_write = true;
        }

        fn interrupt_triggers(&self) -> usize {
            self.state.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).interrupt_triggers
        }

        fn wait_entered_read(&self, count: usize) -> usize {
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let start = Instant::now();
            loop {
                if guard.entered_read >= count {
                    return guard.entered_read;
                }
                if start.elapsed() >= TEST_TIMEOUT {
                    return guard.entered_read;
                }
                let remaining = TEST_TIMEOUT - start.elapsed();
                let (next, _) = cvar
                    .wait_timeout(guard, remaining)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard = next;
            }
        }
    }

    fn engine_config() -> DriverConfig {
        DriverConfig {
            poll_interval: Duration::from_millis(1),
            ..DriverConfig::default()
        }
    }

    #[tokio::test]
    async fn new_engine_is_running_and_reports_backend() {
        let (backend, handle) = stub_pair();
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert_eq!(engine.state(), V2GatewayEngineState::Running);
        assert!(!engine.is_terminal());
        assert!(engine.failure().is_none());
        // Event-driven fast-path: no terminal is pending, so a bounded wait
        // must time out instead of resolving.
        assert!(tokio::time::timeout(Duration::from_millis(20), engine.await_terminal()).await.is_err());
        assert_eq!(engine.backend_name().as_deref(), Some("stub-tun"));
        assert_eq!(engine.backend_mtu(), Some(1_300));
        assert!(engine.metrics().is_some());
        assert!(engine.sender().is_some());
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn terminal_read_failure_transitions_automatically_without_polling() {
        let (backend, handle) = stub_pair();
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        handle.fail_next_read();
        // Autonomous: the supervisor task flips `Running -> Terminal` via the
        // driver's coalescing watch signal. No `observe` polling call exists;
        // the test only awaits the event-driven signal with a hard deadline.
        let failure = tokio::time::timeout(TEST_TIMEOUT, engine.await_terminal())
            .await
            .expect("terminal notification deadline")
            .expect("terminal failure present");
        assert_eq!(failure.kind(), FailureKind::Read);
        // The shared state already reflects `Terminal` (watcher push, with
        // prompt sync as the backstop for scheduling races).
        assert!(engine.is_terminal());
        assert_eq!(engine.failure().unwrap().kind(), FailureKind::Read);
        assert!(matches!(engine.state(), V2GatewayEngineState::Terminal(_)));
        let state = engine.shutdown().await.unwrap();
        assert!(matches!(state, V2GatewayEngineState::Terminal(_)));
        assert!(handle.interrupt_triggers() >= 1);
    }

    #[tokio::test]
    async fn terminal_write_failure_transitions_automatically_without_polling() {
        let (backend, handle) = stub_pair();
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        // Deterministic: arm the next backend write to fail, then enqueue one
        // downlink packet. The worker drains egress on its next pass and
        // records a durable `Write` failure; the supervisor task flips
        // `Running -> Terminal` via the coalescing watch signal.
        handle.fail_next_write();
        engine
            .sender()
            .unwrap()
            .send(sg_core::v2::TrafficClass::Bulk, bytes::Bytes::from(vec![0x45; 16]))
            .unwrap();
        let failure = tokio::time::timeout(TEST_TIMEOUT, engine.await_terminal())
            .await
            .expect("terminal notification deadline")
            .expect("terminal failure present");
        assert_eq!(failure.kind(), FailureKind::Write);
        assert!(engine.is_terminal());
        assert_eq!(engine.failure().unwrap().kind(), FailureKind::Write);
        assert!(matches!(engine.state(), V2GatewayEngineState::Terminal(_)));
        let state = engine.shutdown().await.unwrap();
        assert!(matches!(state, V2GatewayEngineState::Terminal(_)));
        assert!(handle.interrupt_triggers() >= 1);
    }

    #[tokio::test]
    async fn terminal_state_is_sticky_and_survives_shutdown() {
        let (backend, handle) = stub_pair();
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        handle.fail_next_read();
        let first = tokio::time::timeout(TEST_TIMEOUT, engine.await_terminal())
            .await
            .expect("terminal notification deadline")
            .expect("terminal failure present");
        assert_eq!(first.kind(), FailureKind::Read);
        // A second event-driven wait resolves immediately (sticky, coalesced).
        let second = tokio::time::timeout(TEST_TIMEOUT, engine.await_terminal())
            .await
            .expect("sticky terminal deadline")
            .expect("terminal failure present");
        assert_eq!(second.kind(), FailureKind::Read);
        assert!(engine.is_terminal());
        let state = engine.shutdown().await.unwrap();
        assert!(matches!(state, V2GatewayEngineState::Terminal(_)));
    }

    #[tokio::test]
    async fn clean_shutdown_closes_after_blocked_read() {
        let (backend, handle) = stub_pair();
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn shutdown_reports_terminal_failure() {
        let (backend, handle) = stub_pair();
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        handle.fail_next_read();
        // No polling: await the autonomous signal, then shut down; the
        // terminal outcome must survive the join.
        let failure = tokio::time::timeout(TEST_TIMEOUT, engine.await_terminal())
            .await
            .expect("terminal notification deadline")
            .expect("terminal failure present");
        assert_eq!(failure.kind(), FailureKind::Read);
        let state = engine.shutdown().await.unwrap();
        assert!(matches!(state, V2GatewayEngineState::Terminal(_)));
        assert!(handle.interrupt_triggers() >= 1);
    }

    #[tokio::test]
    async fn drop_without_shutdown_surfaces_join_required() {
        let (backend, handle) = stub_pair();
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        let sender = engine.sender().unwrap();
        drop(engine);
        // The detached driver records `JoinRequired` (and publishes the
        // terminal signal); the cloned sender observes it event-driven.
        let failure = tokio::time::timeout(TEST_TIMEOUT, sender.await_terminal())
            .await
            .expect("join-required notification deadline");
        assert_eq!(failure.kind(), FailureKind::JoinRequired);
        assert!(handle.interrupt_triggers() >= 1);
    }

    #[tokio::test]
    async fn engine_mtu_admits_safe_mode_payload_at_safe_mode_datagram() {
        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        // The gate starts Unknown: nothing is admissible until discovery.
        assert_eq!(engine.mtu_state(), PathMtuState::Unknown);
        assert!(!engine.can_carry_tun_payload());

        let event =
            engine.on_mtu_discovered(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert_eq!(event, MtuEvent::MtuDiscovered { datagram_mtu: SAFE_MODE_MIN_DATAGRAM_MTU });
        assert!(engine.can_carry_tun_payload());

        // A 1300-byte payload in a 1352-byte datagram: admitted at the gate.
        // The gate never allocates a packet ID or records an enqueue: IDs and
        // `sends_enqueued` advance only in the checked send pipeline
        // (`CheckedDatagramSender::send_checked` preview/commit).
        assert!(engine.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU).is_ok());
        assert_eq!(engine.mtu_metrics().sends_admitted, 1);
        assert_eq!(engine.mtu_metrics().sends_enqueued, 0);
        assert_eq!(engine.mtu_metrics().sends_rejected, 0);
        assert_eq!(engine.mtu_metrics().encode_failures, 0);
        assert_eq!(engine.mtu_metrics().transport_failures, 0);
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_mtu_rejection_counts_only_in_rejected_bucket() {
        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        engine.on_mtu_discovered(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());

        // Oversized at the safe-mode payload: rejected with the typed reason.
        // The gate allocates no packet ID (there is no ID helper here) and
        // records only a gate rejection — never an enqueue.
        assert!(matches!(
            engine.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU + 1),
            Err(MtuRejectReason::PayloadExceedsMtu { .. })
        ));
        assert_eq!(engine.mtu_metrics().sends_admitted, 0);
        assert_eq!(engine.mtu_metrics().sends_enqueued, 0);
        assert_eq!(engine.mtu_metrics().sends_rejected, 1);

        // A black-holed path rejects even tiny payloads the same way.
        engine.on_mtu_blackhole();
        assert_eq!(
            engine.admit_payload(1),
            Err(MtuRejectReason::PathMtuBlackHole)
        );
        assert_eq!(engine.mtu_metrics().sends_admitted, 0);
        assert_eq!(engine.mtu_metrics().sends_enqueued, 0);
        assert_eq!(engine.mtu_metrics().sends_rejected, 2);

        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_mtu_reduction_degrades_then_fails_over_below_tun_payload() {
        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        engine.on_mtu_discovered(DatagramMtu::new(1_500).unwrap());
        assert!(engine.can_carry_tun_payload());
        assert!(engine.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU).is_ok());

        // 1352 still carries the 1300-byte TUN payload: degraded but usable.
        engine.on_mtu_reduced(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert!(engine.can_carry_tun_payload());
        assert!(engine.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU).is_ok());
        assert_eq!(engine.mtu_metrics().mtu_reductions, 1);

        // Below the TUN payload the typed failover signal flips; a TUN-sized
        // payload is rejected at the gate (WP-501 consumes this). The gate
        // never allocates packet IDs, so there is no ID to leak.
        engine.on_mtu_reduced(DatagramMtu::new(1_280).unwrap());
        assert!(!engine.can_carry_tun_payload());
        assert_eq!(engine.mtu_metrics().mtu_reductions, 2);
        assert!(matches!(
            engine.admit_payload(SAFE_MODE_MIN_PAYLOAD_MTU),
            Err(MtuRejectReason::PayloadExceedsMtu { .. })
        ));
        assert_eq!(engine.mtu_metrics().sends_enqueued, 0);

        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_mtu_reduce_never_raises_the_limit() {
        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        engine.on_mtu_discovered(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert_eq!(engine.mtu_metrics().mtu_reductions, 0);

        let raised = engine.on_mtu_reduced(DatagramMtu::new(1_500).unwrap());
        assert_eq!(
            raised,
            MtuEvent::ReduceIgnored { requested: 1_500, current: SAFE_MODE_MIN_DATAGRAM_MTU }
        );
        let equal = engine.on_mtu_reduced(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert_eq!(
            equal,
            MtuEvent::ReduceIgnored {
                requested: SAFE_MODE_MIN_DATAGRAM_MTU,
                current: SAFE_MODE_MIN_DATAGRAM_MTU,
            }
        );
        // State provably unchanged, so the counters never advanced.
        assert_eq!(
            engine.mtu_state(),
            PathMtuState::Available {
                datagram_mtu: DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap(),
                effective: DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap().effective_payload(),
            }
        );
        assert!(engine.can_carry_tun_payload());
        assert_eq!(engine.mtu_metrics().mtu_reductions, 0);

        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_mtu_gate_derives_from_actual_advertised_tun_config() {
        // WP-302 final blocker: the admission gate is built from the driver's
        // **actual advertised TUN config**, never a V1-style implicit constant.
        let (backend, handle) = stub_pair_with_mtu(1_500);
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert_eq!(engine.backend_mtu(), Some(1_500));
        assert_eq!(engine.mtu_admission().tun_payload_mtu().get(), 1_500);
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);

        // The safe-mode default MTU (1300) wires the safe-mode requirement.
        let (backend, handle) = stub_pair();
        let engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert_eq!(engine.mtu_admission().tun_payload_mtu().get(), SAFE_MODE_MIN_PAYLOAD_MTU);
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_packet_sequencer_starts_at_zero_and_peeks_without_advancing() {
        // WP-302 preview-closure blocker: the engine owns the packet-ID
        // sequencer, the first ID is 0, and every public peek leaves the head
        // untouched — public callers cannot advance the preview. The only
        // advancing path is the checked send pipeline (tested in
        // `sg-transport::mtu`), which the future downlink drives through
        // `packet_sequencer_mut`.
        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert_eq!(engine.packet_next_value(), 0);
        assert_eq!(engine.packet_next_value(), 0, "repeated peeks never advance");
        assert_eq!(engine.packet_sequencer_mut().next_value(), 0);
        assert_eq!(engine.packet_next_value(), 0, "exclusive handle still peeks without advancing");
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    fn uplink_pool() -> Arc<crate::v2::address_pool::AddressPool> {
        use crate::v2::address_pool::{AddressPool, AddressPoolConfig};
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
        Arc::new(AddressPool::new(config).unwrap())
    }

    fn uplink_ipv4_packet(src: [u8; 4]) -> bytes::Bytes {
        use crate::v2::forwarding::test_ipv4_packet;
        test_ipv4_packet(src, [8, 8, 8, 8])
    }

    fn uplink_sessions(pool: &Arc<crate::v2::address_pool::AddressPool>) -> Arc<crate::v2::session_manager::V2SessionManager> {
        use crate::v2::session_manager::{V2SessionManager, V2SessionManagerConfig};
        Arc::new(
            V2SessionManager::with_cleanup(
                V2SessionManagerConfig {
                    maximum_sessions: 4,
                    idle_ttl_ms: 60_000,
                    maximum_paths_per_session: 4,
                    maximum_pending_attaches: 4,
                    pending_attach_ttl_ms: 5_000,
                    maximum_path_epoch_history: 16,
                    maximum_path_tombstones: 4,
                    path_tombstone_ttl_ms: 5_000,
                },
                vec![Arc::clone(pool) as Arc<dyn crate::v2::session_manager::SessionCleanup>],
            )
            .unwrap(),
        )
    }

    struct UplinkFixture {
        pool: Arc<crate::v2::address_pool::AddressPool>,
        sessions: Arc<crate::v2::session_manager::V2SessionManager>,
        connection: crate::v2::session_manager::AuthenticatedConnection,
        path: sg_session::v2::PathBinding,
        lease: crate::v2::address_pool::AssignedAddresses,
        session: sg_core::v2::SessionId,
    }

    fn uplink_fixture() -> UplinkFixture {
        use sg_auth::ticket::OrganizationId;
        use sg_core::v2::{DeviceId, SessionId};
        let pool = uplink_pool();
        let sessions = uplink_sessions(&pool);
        let session = SessionId::from_bytes([21; 16]);
        let device = DeviceId::from_bytes([22; 16]);
        let org = OrganizationId::from_bytes([23; 16]);
        let now = 1_000;
        let reservation = sessions.reserve_admission(session, device, org, now + 60_000, now).unwrap();
        sessions.commit_admission(reservation, now).unwrap();
        let lease = pool.reserve(session, device, now).unwrap();
        pool.commit(session, now).unwrap();
        let connection = sessions.bind_authenticated_connection(session, now).unwrap();
        let attach = sessions.reserve_attach(connection, 7, 9, now).unwrap();
        let path = sessions.commit_attach(attach).unwrap();
        UplinkFixture { pool, sessions, connection, path, lease, session }
    }

    fn uplink_envelope(fixture: &UplinkFixture, payload: bytes::Bytes) -> sg_protocol::v2::V2Envelope {
        use sg_core::v2::{FlowId, PacketId, TrafficClass};
        use sg_protocol::v2::{Direction, V2Envelope, V2Header};
        V2Envelope {
            header: V2Header {
                traffic_class: TrafficClass::Interactive,
                direction: Direction::ClientToGateway,
                session_id: fixture.session,
                path_id: fixture.path.path_id,
                path_epoch: fixture.path.path_epoch,
                key_epoch: fixture.path.key_epoch,
                flow_id: FlowId::new(1),
                packet_id: PacketId::new(1),
            },
            payload,
        }
    }

    #[tokio::test]
    async fn uplink_ingest_requires_both_attachments_then_validates_and_seals() {
        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert!(!engine.uplink_attached());
        assert!(!engine.sessions_attached());
        assert!(!engine.ingress_ready());
        assert!(engine.uplink_forwarder_snapshot().is_none());
        let fixture = uplink_fixture();
        let envelope = uplink_envelope(&fixture, uplink_ipv4_packet(fixture.lease.ipv4));
        // Neither attachment: fail closed without touching any counters.
        assert!(
            matches!(
                engine.ingest_uplink(fixture.connection, &envelope, 1_000),
                Err(UplinkIngestError::NotAttached)
            ),
            "ingest without attachments must fail closed"
        );
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 0);
        assert!(engine.attach_uplink(uplink_pool(), 64).is_err(), "forwarder bound rejects undersized maxima");
        assert!(!engine.uplink_attached());
        // Pool attached but session map missing: still fail closed.
        engine.attach_uplink(Arc::clone(&fixture.pool), 1_500).unwrap();
        assert!(engine.uplink_attached());
        assert!(!engine.sessions_attached());
        assert!(!engine.ingress_ready());
        assert!(
            matches!(
                engine.ingest_uplink(fixture.connection, &envelope, 1_000),
                Err(UplinkIngestError::NotAttached)
            ),
            "ingest without the session map must fail closed"
        );
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 0);
        // Session map attached with no lease for an unknown envelope session:
        // binding succeeds only for the fixture session; use a fresh envelope
        // bound to an unknown session to prove the pool check still fails
        // closed after the binding gate. Here the binding gate itself rejects
        // first (unknown connection binding), which is the correct order.
        engine.attach_session_manager(Arc::clone(&fixture.sessions));
        assert!(engine.sessions_attached());
        assert!(engine.ingress_ready());
        // Valid ingress now forwards.
        let forwarded = engine.ingest_uplink(fixture.connection, &envelope, 1_000).expect("bound leased source must ingest");
        assert_eq!(forwarded.session_id(), fixture.session);
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1);
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn uplink_binding_is_checked_before_source_validation() {
        // Transport binding (session/path/key epochs, direction, connection)
        // is validated before any pool source check: a stale epoch or wrong
        // direction never touches forwarder counters, and a bound-but-spoofed
        // source fails only at the forwarder.
        use crate::v2::forwarding::ForwardError;
        use crate::v2::session_manager::V2SessionManagerError;
        use sg_protocol::v2::Direction;
        let fixture = uplink_fixture();
        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        engine.attach_uplink(Arc::clone(&fixture.pool), 1_500).unwrap();
        engine.attach_session_manager(Arc::clone(&fixture.sessions));

        // Valid envelope forwards.
        let valid = uplink_envelope(&fixture, uplink_ipv4_packet(fixture.lease.ipv4));
        let valid_len = valid.payload.len();
        let forwarded = engine.ingest_uplink(fixture.connection, &valid, 1_000).expect("valid must ingest");
        assert_eq!(forwarded.session_id(), fixture.session);
        assert_eq!(forwarded.packet_len(), valid_len);
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1);
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().validated, 1);

        // Stale path epoch: binding rejects before source validation.
        let mut stale_path = valid.clone();
        stale_path.header.path_epoch = fixture.path.path_epoch.saturating_add(100);
        assert!(matches!(
            engine.ingest_uplink(fixture.connection, &stale_path, 1_000),
            Err(UplinkIngestError::BindingRejected(V2SessionManagerError::BindingMismatch))
        ));
        // Stale key epoch.
        let mut stale_key = valid.clone();
        stale_key.header.key_epoch = fixture.path.key_epoch.saturating_add(1);
        assert!(matches!(
            engine.ingest_uplink(fixture.connection, &stale_key, 1_000),
            Err(UplinkIngestError::BindingRejected(V2SessionManagerError::StaleKeyEpoch))
        ));
        // Wrong direction.
        let mut wrong_direction = valid.clone();
        wrong_direction.header.direction = Direction::GatewayToClient;
        assert!(matches!(
            engine.ingest_uplink(fixture.connection, &wrong_direction, 1_000),
            Err(UplinkIngestError::BindingRejected(V2SessionManagerError::InvalidDirection))
        ));
        // None of the three binding failures may touch the forwarder.
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().validated, 1);
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().spoof_dropped, 0);
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().parse_dropped, 0);
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1);

        // Bound envelope with a spoofed IP source: binding passes, forwarder
        // rejects, sink never advances.
        let spoofed = uplink_envelope(&fixture, uplink_ipv4_packet([10, 64, 0, 99]));
        assert!(matches!(
            engine.ingest_uplink(fixture.connection, &spoofed, 1_000),
            Err(UplinkIngestError::Rejected(ForwardError::SourceMismatch))
        ));
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1);
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().validated, 1);
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().spoof_dropped, 1);
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn uplink_spoof_never_reaches_sealed_sink_or_tun_nat_egress() {
        // Sole-ingress proof: `ingest_uplink` binds the envelope to its
        // authenticated connection first, then validates the source, and only
        // then emits through the sealed sink behind `V2TunNatEgress`. Binding
        // failures and spoofed/malformed packets never advance the sink or
        // egress counters, so nothing unauthenticated can reach the TUN/NAT
        // handoff. There is no raw-`SessionId` overload to bypass the bind.
        use crate::v2::forwarding::ForwardError;
        use crate::v2::session_manager::V2SessionManagerError;
        use sg_auth::ticket::OrganizationId;
        use sg_core::v2::{DeviceId, SessionId};
        let fixture = uplink_fixture();
        // Second session with a distinct lease, also admitted and attached,
        // so cross-session spoof has a real lease to steal.
        let other_session = SessionId::from_bytes([23; 16]);
        let other_device = DeviceId::from_bytes([24; 16]);
        let now = 1_000;
        let other_reservation = fixture
            .sessions
            .reserve_admission(other_session, other_device, OrganizationId::from_bytes([25; 16]), now + 60_000, now)
            .unwrap();
        fixture.sessions.commit_admission(other_reservation, now).unwrap();
        let other_lease = fixture.pool.reserve(other_session, other_device, now).unwrap();
        fixture.pool.commit(other_session, now).unwrap();
        let other_connection = fixture.sessions.bind_authenticated_connection(other_session, now).unwrap();
        let other_attach = fixture.sessions.reserve_attach(other_connection, 11, 13, now).unwrap();
        let _other_path = fixture.sessions.commit_attach(other_attach).unwrap();

        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        engine.attach_uplink(Arc::clone(&fixture.pool), 1_500).unwrap();
        engine.attach_session_manager(Arc::clone(&fixture.sessions));

        let valid = uplink_envelope(&fixture, uplink_ipv4_packet(fixture.lease.ipv4));
        let valid_len = valid.payload.len();
        let forwarded = engine.ingest_uplink(fixture.connection, &valid, now).expect("leased source must ingest");
        assert_eq!(forwarded.session_id(), fixture.session);
        assert_eq!(forwarded.packet_len(), valid_len);
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1);
        assert_eq!(engine.uplink_sink_snapshot().bytes_forwarded, valid_len as u64);
        assert_eq!(engine.uplink_egress_snapshot(), engine.uplink_sink_snapshot());
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().validated, 1);

        // Cross-session IPv4 spoof: binding passes for the fixture session,
        // source belongs to the other lease.
        let cross_spoof = uplink_envelope(&fixture, uplink_ipv4_packet(other_lease.ipv4));
        assert!(matches!(
            engine.ingest_uplink(fixture.connection, &cross_spoof, now),
            Err(UplinkIngestError::Rejected(ForwardError::SourceMismatch))
        ));
        // Gateway-address spoof.
        let gateway_spoof = uplink_envelope(&fixture, uplink_ipv4_packet([10, 64, 0, 1]));
        assert!(matches!(
            engine.ingest_uplink(fixture.connection, &gateway_spoof, now),
            Err(UplinkIngestError::Rejected(ForwardError::SourceMismatch))
        ));
        // Unknown connection: a second capability for the same session with
        // no path binding cannot ingest, even with a correctly leased source.
        let unbound = fixture.sessions.bind_authenticated_connection(fixture.session, now).unwrap();
        assert!(matches!(
            engine.ingest_uplink(unbound, &valid, now),
            Err(UplinkIngestError::BindingRejected(V2SessionManagerError::UnknownConnection))
        ));
        // Malformed IP payload (truncated): binding passes, forwarder
        // parse-drops before any egress.
        let malformed = uplink_envelope(&fixture, bytes::Bytes::from(vec![0x45; 8]));
        assert!(matches!(
            engine.ingest_uplink(fixture.connection, &malformed, now),
            Err(UplinkIngestError::Rejected(_))
        ));
        // None of the four rejections may reach the sealed sink or the
        // TUN/NAT egress contract: the count stays at the single valid packet.
        // The unbound-connection failure never touches the forwarder.
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1, "spoof must never reach the sink");
        assert_eq!(engine.uplink_egress_snapshot().forwarded, 1);
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().validated, 1);
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().spoof_dropped, 2);
        assert_eq!(engine.uplink_forwarder_snapshot().unwrap().parse_dropped, 1);
        // The sealed egress type carries the session/source/packet the host
        // stack must write; its Debug never includes payload contents.
        let debug = format!("{forwarded:?}");
        assert!(debug.contains("packet_len"));
        assert!(!debug.contains("8, 8, 8, 8"));
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn uplink_validated_ingress_renews_lease_idle_expiry_closes_no_forward() {
        // Authenticated activity renewal policy: every validated ingress
        // (binding + source both succeed) renews the Active lease to
        // `now + lease_ttl`; failures fail closed with no forward and no sink
        // emit. Active renewal prevents expiry; idle (no valid ingress) lets
        // the lease expire and closes the session. No sleeps: all time is an
        // explicit `now_ms` argument and every sweep is a direct call.
        use crate::v2::address_pool::{AddressPool, AddressPoolConfig};
        use crate::v2::session_manager::{SessionCleanup, V2SessionManager, V2SessionManagerConfig};
        use sg_auth::ticket::OrganizationId;
        use sg_core::v2::{DeviceId, SessionId};

        let pool_config = AddressPoolConfig::new(
            [10, 64, 0, 0],
            24,
            [10, 64, 0, 1],
            vec![],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            48,
            4,
            5_000,
            10_000,
            4,
        )
        .unwrap();
        let pool = Arc::new(AddressPool::new(pool_config).unwrap());
        let sessions = Arc::new(
            V2SessionManager::with_cleanup(
                V2SessionManagerConfig {
                    maximum_sessions: 4,
                    idle_ttl_ms: 60_000,
                    maximum_paths_per_session: 4,
                    maximum_pending_attaches: 4,
                    pending_attach_ttl_ms: 5_000,
                    maximum_path_epoch_history: 16,
                    maximum_path_tombstones: 4,
                    path_tombstone_ttl_ms: 5_000,
                },
                vec![Arc::clone(&pool) as Arc<dyn SessionCleanup>],
            )
            .unwrap(),
        );
        let session = SessionId::from_bytes([41; 16]);
        let device = DeviceId::from_bytes([42; 16]);
        // Far-future ticket expiry so only lease/idle TTLs drive this test.
        let reservation = sessions
            .reserve_admission(session, device, OrganizationId::from_bytes([43; 16]), 1_000_000, 1_000)
            .unwrap();
        sessions.commit_admission(reservation, 1_000).unwrap();
        let lease = pool.reserve(session, device, 1_000).unwrap();
        pool.commit(session, 1_000).unwrap();
        let connection = sessions.bind_authenticated_connection(session, 1_000).unwrap();
        let attach = sessions.reserve_attach(connection, 7, 9, 1_000).unwrap();
        let path = sessions.commit_attach(attach).unwrap();

        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        engine.attach_uplink(Arc::clone(&pool), 1_500).unwrap();
        engine.attach_session_manager(Arc::clone(&sessions));

        let envelope_at = |_now_ms: u64| {
            use sg_core::v2::{FlowId, PacketId, TrafficClass};
            use sg_protocol::v2::{Direction, V2Envelope, V2Header};
            V2Envelope {
                header: V2Header {
                    traffic_class: TrafficClass::Interactive,
                    direction: Direction::ClientToGateway,
                    session_id: session,
                    path_id: path.path_id,
                    path_epoch: path.path_epoch,
                    key_epoch: path.key_epoch,
                    flow_id: FlowId::new(1),
                    packet_id: PacketId::new(1),
                },
                payload: uplink_ipv4_packet(lease.ipv4),
            }
        };

        // Active renewal at 5_000 (before the 11_000 lease expiry) extends the
        // lease to 15_000 and proves liveness.
        let forwarded = engine.ingest_uplink(connection, &envelope_at(5_000), 5_000).expect("valid ingress must renew and forward");
        assert_eq!(forwarded.session_id(), session);
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1);
        assert_eq!(pool.snapshot().renewals, 1);
        // Original expiry passes without expiring: renewal prevented it.
        assert!(pool.sweep(11_000).is_empty(), "renewed lease must survive its original expiry");
        assert!(pool.lookup_active(session).is_some());
        assert_eq!(sessions.snapshot().sessions, 1);

        // Spoofed sources never renew: a cross-session source at 6_000 fails
        // closed with no forward and no renewal (renewal count stays 1).
        let spoofed = {
            use sg_protocol::v2::V2Envelope;
            V2Envelope {
                header: envelope_at(6_000).header,
                payload: uplink_ipv4_packet([10, 64, 0, 99]),
            }
        };
        assert!(matches!(
            engine.ingest_uplink(connection, &spoofed, 6_000),
            Err(UplinkIngestError::Rejected(_))
        ));
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1, "spoof must never reach the sink");
        assert_eq!(pool.snapshot().renewals, 1, "spoof must never renew the lease");

        // Second valid ingress at 12_000 extends the lease to 22_000.
        engine.ingest_uplink(connection, &envelope_at(12_000), 12_000).unwrap();
        assert_eq!(pool.snapshot().renewals, 2);
        assert!(pool.sweep(20_000).is_empty(), "second renewal must survive past the first renewed expiry");
        assert!(pool.lookup_active(session).is_some());

        // Idle past the renewed lease: no valid ingress between 12_000 and
        // 35_000, so the pool sweep expires the lease and the caller closes
        // the session (mirroring the listener accept/control-tick order).
        // Session idle (60 s from 12_000) has not yet fired; the lease is the
        // limiter here, proving renewal was what kept it alive.
        let expired = pool.sweep(35_000);
        assert_eq!(expired, vec![session], "idle lease must expire after activity stops");
        for expired_session in expired {
            let _ = sessions.close(expired_session);
        }
        assert!(pool.lookup_active(session).is_none());
        assert_eq!(sessions.snapshot().sessions, 0);

        // After expiry the ingress fails closed with no forward: the session
        // is gone (binding rejects) and the sink never advances.
        assert!(matches!(
            engine.ingest_uplink(connection, &envelope_at(35_001), 35_001),
            Err(UplinkIngestError::BindingRejected(_))
        ));
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 2, "expired ingress must not forward");
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn uplink_at_time_renews_through_bounded_owner_wall_time() {
        // Wall-aware renewal: `ingest_uplink_at_time` drives the monotonic
        // expiry from `now.monotonic_ms` and the durable expiry from
        // `now.wall_ms` through the bounded owner queue. For the ephemeral
        // pool used here the wall domain is accepted and ignored for memory
        // expiry; production durable pools persist the wall expiry (covered by
        // `address_pool` wall tests). Failures still fail closed with no
        // forward. No sleeps: explicit `PoolTime` arguments only.
        use crate::v2::address_pool::{AddressPool, AddressPoolConfig};
        use crate::v2::persistence::PoolTime;
        use crate::v2::session_manager::{SessionCleanup, V2SessionManager, V2SessionManagerConfig};
        use sg_auth::ticket::OrganizationId;
        use sg_core::v2::{DeviceId, SessionId};

        let pool = Arc::new(
            AddressPool::new(
                AddressPoolConfig::new(
                    [10, 64, 0, 0],
                    24,
                    [10, 64, 0, 1],
                    vec![],
                    [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    48,
                    4,
                    5_000,
                    10_000,
                    4,
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let sessions = Arc::new(
            V2SessionManager::with_cleanup(
                V2SessionManagerConfig {
                    maximum_sessions: 4,
                    idle_ttl_ms: 60_000,
                    maximum_paths_per_session: 4,
                    maximum_pending_attaches: 4,
                    pending_attach_ttl_ms: 5_000,
                    maximum_path_epoch_history: 16,
                    maximum_path_tombstones: 4,
                    path_tombstone_ttl_ms: 5_000,
                },
                vec![Arc::clone(&pool) as Arc<dyn SessionCleanup>],
            )
            .unwrap(),
        );
        let session = SessionId::from_bytes([51; 16]);
        let device = DeviceId::from_bytes([52; 16]);
        let reservation = sessions
            .reserve_admission(session, device, OrganizationId::from_bytes([53; 16]), 1_000_000, 1_000)
            .unwrap();
        sessions.commit_admission(reservation, 1_000).unwrap();
        let lease = pool.reserve(session, device, 1_000).unwrap();
        pool.commit(session, 1_000).unwrap();
        let connection = sessions.bind_authenticated_connection(session, 1_000).unwrap();
        let attach = sessions.reserve_attach(connection, 7, 9, 1_000).unwrap();
        let path = sessions.commit_attach(attach).unwrap();

        let (backend, handle) = stub_pair();
        let mut engine = V2GatewayEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        engine.attach_uplink(Arc::clone(&pool), 1_500).unwrap();
        engine.attach_session_manager(Arc::clone(&sessions));

        let envelope = {
            use sg_core::v2::{FlowId, PacketId, TrafficClass};
            use sg_protocol::v2::{Direction, V2Envelope, V2Header};
            V2Envelope {
                header: V2Header {
                    traffic_class: TrafficClass::Interactive,
                    direction: Direction::ClientToGateway,
                    session_id: session,
                    path_id: path.path_id,
                    path_epoch: path.path_epoch,
                    key_epoch: path.key_epoch,
                    flow_id: FlowId::new(1),
                    packet_id: PacketId::new(1),
                },
                payload: uplink_ipv4_packet(lease.ipv4),
            }
        };
        // Monotonic 5_000 renews memory expiry to 15_000; wall 9_000_000 is
        // accepted through the bounded owner path (ephemeral ignores it for
        // memory, durable would persist wall + ttl).
        let now = PoolTime::new(5_000, 9_000_000);
        let forwarded = engine.ingest_uplink_at_time(connection, &envelope, now).await.expect("wall-aware ingress must renew and forward");
        assert_eq!(forwarded.session_id(), session);
        assert_eq!(pool.snapshot().renewals, 1);
        assert!(pool.sweep(11_000).is_empty(), "wall-aware renewal must prevent monotonic expiry");
        // Expired wall-aware ingress fails closed with no forward.
        let expired_now = PoolTime::new(35_000, 9_030_000);
        let expired = pool.sweep(expired_now.monotonic_ms);
        assert_eq!(expired, vec![session]);
        for expired_session in expired {
            let _ = sessions.close(expired_session);
        }
        assert!(matches!(
            engine.ingest_uplink_at_time(connection, &envelope, expired_now).await,
            Err(UplinkIngestError::BindingRejected(_))
        ));
        assert_eq!(engine.uplink_sink_snapshot().forwarded, 1, "expired wall-aware ingress must not forward");
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2GatewayEngineState::Closed);
    }

    #[tokio::test]
    async fn uplink_tun_nat_egress_contract_only_accepts_validated_uplinks() {
        // Compile-time + runtime proof that the TUN/NAT handoff cannot take
        // raw bytes: `V2TunNatEgress::emit_validated` requires the sealed
        // `ValidatedUplink` (constructible only via `validate`), and a spoof
        // that fails validation never yields one, so `emit_validated` is
        // unreachable for it.
        use crate::v2::forwarding::{UplinkForwarder, V2ForwardingSink, V2TunNatEgress};
        use sg_core::v2::DeviceId;
        let pool = uplink_pool();
        let session = sg_core::v2::SessionId::from_bytes([31; 16]);
        let lease = pool.reserve(session, DeviceId::from_bytes([32; 16]), 1_000).unwrap();
        pool.commit(session, 1_000).unwrap();
        let forwarder = UplinkForwarder::new(Arc::clone(&pool), 1_500).unwrap();
        let sink = V2ForwardingSink::new();
        let sink_trait: &dyn V2TunNatEgress = &sink;
        let validated = forwarder.validate(session, uplink_ipv4_packet(lease.ipv4)).unwrap();
        let forwarded = sink_trait.emit_validated(validated);
        assert_eq!(forwarded.session_id(), session);
        assert_eq!(sink_trait.egress_snapshot().forwarded, 1);
        // A spoofed source never becomes `ValidatedUplink`, so the trait
        // method is unreachable for it: validation fails first.
        assert!(forwarder.validate(session, uplink_ipv4_packet([10, 64, 0, 99])).is_err());
        assert_eq!(sink_trait.egress_snapshot().forwarded, 1, "failed validation must not reach the egress");
    }
}
