//! Minimal V2 client engine supervisor (REBUILD WP-300/WP-302).
//!
//! Owns one [`DriverTun`] (the exclusive blocking TUN owner) and mirrors its
//! durable terminal failure into a typed engine state. Since WP-302 the engine
//! also owns the V2 MTU admission gate ([`MtuAdmission`], derived at
//! construction from the driver's actual advertised TUN config) so the future
//! uplink can validate a payload **before** packet-ID/counter commit, plus the
//! engine-owned packet-ID sequencer ([`PacketIdSequencer`]) whose counter the
//! checked send pipeline previews (never advancing) and commits (only after a
//! successful transport enqueue). There is intentionally no V2 packet, scheduler, QUIC send, or
//! TUN-traffic wiring here yet: sequencing and forwarding arrive in later work
//! packets (WP-301/WP-302 send path, WP-600+). V1 client code (`client.rs`,
//! `status.rs`, `ipc.rs`) is untouched.
//!
//! Autonomous terminal notification (WP-300 final blocker): the driver publishes
//! a single coalescing `watch` bool on its first failure (`send_replace`, so a
//! fault that races `spawn` is still visible to a late subscriber). The engine
//! subscribes at [`V2ClientEngine::new`] and supervises exactly one Tokio task
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

use sg_transport::mtu::{
    AdmissionResult, DatagramMtu, MtuAdmission, MtuEvent, MtuMetrics, MtuRejectReason,
    PacketIdSequencer, PathMtuState,
};
use sg_tun::driver::{DriverError, DriverFailure, DriverMetrics, DriverSender, DriverTun};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

/// Typed supervisor state for the V2 client engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2ClientEngineState {
    /// Driver is owned and no terminal failure has been observed.
    Running,
    /// The driver recorded a durable terminal failure (read, write, or
    /// `JoinRequired`). First fault wins, matching [`DriverTun`].
    Terminal(DriverFailure),
    /// The engine was shut down cleanly with no recorded failure.
    Closed,
}

/// Minimal supervisor owning one V2 blocking TUN driver and the V2 MTU
/// admission gate.
pub struct V2ClientEngine {
    driver: Option<DriverTun>,
    state: Arc<Mutex<V2ClientEngineState>>,
    watcher: Option<JoinHandle<()>>,
    /// Engine-owned V2 MTU admission gate, derived from the driver's
    /// advertised TUN config (WP-302).
    mtu: MtuAdmission,
    /// Engine-owned V2 packet-ID sequencer for the client→gateway send
    /// direction (WP-302 preview-closure blocker). The first packet ID is 0;
    /// the counter advances only inside
    /// [`CheckedDatagramSender::send_checked`](sg_transport::mtu::CheckedDatagramSender::send_checked)
    /// after a successful transport enqueue. There is no other advancing
    /// path: handing `&mut` to the checked pipeline is the only way to move
    /// the head. IDs never wrap: issuing `u64::MAX` terminates the sequencer
    /// and the sender MUST rotate the key epoch to continue.
    sequencer: PacketIdSequencer,
}

fn lock_state(state: &Arc<Mutex<V2ClientEngineState>>) -> std::sync::MutexGuard<'_, V2ClientEngineState> {
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl V2ClientEngine {
    /// Takes ownership of an already-spawned driver and starts supervising it.
    ///
    /// Subscribes to the driver's coalescing terminal signal and, when a Tokio
    /// runtime is present, spawns exactly one supervised task that awaits the
    /// signal and flips `Running -> Terminal`. Outside a runtime no task is
    /// spawned (no panic); reads still sync promptly from the driver's durable
    /// failure on their next call.
    #[must_use]
    pub fn new(driver: DriverTun) -> Self {
        let state = Arc::new(Mutex::new(V2ClientEngineState::Running));
        // Fast-path sync: a failure that raced `spawn` (published via
        // `send_replace` before we subscribed) is already visible here.
        if let Some(failure) = driver.failure() {
            *lock_state(&state) = V2ClientEngineState::Terminal(failure);
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
                    if matches!(*guard, V2ClientEngineState::Running) {
                        tracing::warn!(kind = ?failure.kind(), "v2 client engine entering terminal state");
                        *guard = V2ClientEngineState::Terminal(failure);
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
        }
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
        let is_running = matches!(*lock_state(&self.state), V2ClientEngineState::Running);
        if !is_running {
            return;
        }
        if let Some(failure) = self.driver.as_ref().and_then(|driver| driver.failure()) {
            let mut guard = lock_state(&self.state);
            if matches!(*guard, V2ClientEngineState::Running) {
                tracing::warn!(kind = ?failure.kind(), "v2 client engine entering terminal state");
                *guard = V2ClientEngineState::Terminal(failure);
            }
        }
    }

    /// Current supervisor state. `Terminal` is sticky: once observed it never
    /// returns to `Running`. Transitions autonomously via the supervisor task
    /// (or via prompt sync on read when no runtime is present); no `observe`
    /// polling call is required.
    #[must_use]
    pub fn state(&self) -> V2ClientEngineState {
        self.sync_state();
        lock_state(&self.state).clone()
    }

    /// True once a durable terminal failure has been observed.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.sync_state();
        matches!(*lock_state(&self.state), V2ClientEngineState::Terminal(_))
    }

    /// The durable terminal failure, if the supervisor has entered `Terminal`.
    #[must_use]
    pub fn failure(&self) -> Option<DriverFailure> {
        self.sync_state();
        if let V2ClientEngineState::Terminal(failure) = &*lock_state(&self.state) {
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

    /// Non-advancing peek at the next V2 packet ID for the client→gateway
    /// send direction. Pure read: repeated calls return the same value until
    /// the checked send pipeline commits a send. Public callers cannot
    /// advance the preview through this seam. Once exhausted the value stays
    /// at `u64::MAX` (the last issued ID); see [`Self::packet_id_exhausted`].
    #[must_use]
    pub fn packet_next_value(&self) -> u64 {
        self.sequencer.next_value()
    }

    /// True once the engine-owned sequencer issued `u64::MAX`. Terminal: the
    /// checked send pipeline fails fast with a typed exhaustion error before
    /// any enqueue, the ID is never reused, and recovery requires rotating
    /// the key epoch with a new sequencer.
    #[must_use]
    pub fn packet_id_exhausted(&self) -> bool {
        self.sequencer.is_exhausted()
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
    /// wakeup). Idempotent and non-blocking; use [`V2ClientEngine::shutdown`]
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
    pub async fn shutdown(mut self) -> Result<V2ClientEngineState, DriverError> {
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
                if matches!(*guard, V2ClientEngineState::Running) {
                    *guard = V2ClientEngineState::Closed;
                }
                Ok(guard.clone())
            }
            Ok(Some(failure)) => {
                let mut guard = lock_state(&self.state);
                // First fault wins: keep an existing `Terminal` (watcher may
                // have stored the same failure just before shutdown).
                if matches!(*guard, V2ClientEngineState::Running) {
                    tracing::warn!(kind = ?failure.kind(), "v2 client engine shut down with terminal failure");
                    *guard = V2ClientEngineState::Terminal(failure);
                }
                Ok(guard.clone())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for V2ClientEngine {
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
            tracing::error!("v2 client engine dropped without shutdown; JoinRequired expected");
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
        let engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert_eq!(engine.state(), V2ClientEngineState::Running);
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
        assert_eq!(state, V2ClientEngineState::Closed);
    }

    #[tokio::test]
    async fn terminal_read_failure_transitions_automatically_without_polling() {
        let (backend, handle) = stub_pair();
        let engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        assert!(matches!(engine.state(), V2ClientEngineState::Terminal(_)));
        let state = engine.shutdown().await.unwrap();
        assert!(matches!(state, V2ClientEngineState::Terminal(_)));
        assert!(handle.interrupt_triggers() >= 1);
    }

    #[tokio::test]
    async fn terminal_write_failure_transitions_automatically_without_polling() {
        let (backend, handle) = stub_pair();
        let engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        assert!(matches!(engine.state(), V2ClientEngineState::Terminal(_)));
        let state = engine.shutdown().await.unwrap();
        assert!(matches!(state, V2ClientEngineState::Terminal(_)));
        assert!(handle.interrupt_triggers() >= 1);
    }

    #[tokio::test]
    async fn terminal_state_is_sticky_and_survives_shutdown() {
        let (backend, handle) = stub_pair();
        let engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        assert!(matches!(state, V2ClientEngineState::Terminal(_)));
    }

    #[tokio::test]
    async fn clean_shutdown_closes_and_fires_interrupt() {
        let (backend, handle) = stub_pair();
        let engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2ClientEngineState::Closed);
        assert!(handle.interrupt_triggers() >= 1);
    }

    #[tokio::test]
    async fn shutdown_reports_terminal_failure() {
        let (backend, handle) = stub_pair();
        let engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        assert!(matches!(state, V2ClientEngineState::Terminal(_)));
        assert!(handle.interrupt_triggers() >= 1);
    }

    #[tokio::test]
    async fn drop_without_shutdown_surfaces_join_required() {
        let (backend, handle) = stub_pair();
        let engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        let mut engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        assert_eq!(state, V2ClientEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_mtu_rejection_counts_only_in_rejected_bucket() {
        let (backend, handle) = stub_pair();
        let mut engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        assert_eq!(state, V2ClientEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_mtu_reduction_degrades_then_fails_over_below_tun_payload() {
        let (backend, handle) = stub_pair();
        let mut engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        assert_eq!(state, V2ClientEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_mtu_reduce_never_raises_the_limit() {
        let (backend, handle) = stub_pair();
        let mut engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
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
        assert_eq!(state, V2ClientEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_mtu_gate_derives_from_actual_advertised_tun_config() {
        // WP-302 final blocker: the admission gate is built from the driver's
        // **actual advertised TUN config**, never a V1-style implicit constant.
        // A 1500-byte TUN config creates a 1500-byte payload requirement, so
        // the safe-mode 1352 datagram limit cannot carry a full TUN payload.
        let (backend, handle) = stub_pair_with_mtu(1_500);
        let mut engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert_eq!(engine.backend_mtu(), Some(1_500));
        assert_eq!(engine.mtu_admission().tun_payload_mtu().get(), 1_500);

        engine.on_mtu_discovered(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        // 1300 effective < the 1500-byte configured TUN payload: the path
        // cannot carry a full TUN frame and the typed failover signal flips.
        assert!(!engine.can_carry_tun_payload());
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2ClientEngineState::Closed);

        // The safe-mode default MTU (1300) still carries its own frame: with
        // the production config the gate is exactly safe-mode behavior.
        let (backend, handle) = stub_pair();
        let mut engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert_eq!(engine.mtu_admission().tun_payload_mtu().get(), SAFE_MODE_MIN_PAYLOAD_MTU);
        engine.on_mtu_discovered(DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).unwrap());
        assert!(engine.can_carry_tun_payload());
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2ClientEngineState::Closed);
    }

    #[tokio::test]
    async fn engine_packet_sequencer_starts_at_zero_and_peeks_without_advancing() {
        // WP-302 preview-closure blocker: the engine owns the packet-ID
        // sequencer, the first ID is 0, and every public peek leaves the head
        // untouched — public callers cannot advance the preview. The only
        // advancing path is the checked send pipeline (tested in
        // `sg-transport::mtu`), which the future uplink drives through
        // `packet_sequencer_mut`.
        let (backend, handle) = stub_pair();
        let mut engine = V2ClientEngine::new(DriverTun::spawn(backend, engine_config()).unwrap());
        assert_eq!(handle.wait_entered_read(1), 1);
        assert_eq!(engine.packet_next_value(), 0);
        assert_eq!(engine.packet_next_value(), 0, "repeated peeks never advance");
        assert_eq!(engine.packet_sequencer_mut().next_value(), 0);
        assert_eq!(engine.packet_next_value(), 0, "exclusive handle still peeks without advancing");
        let state = engine.shutdown().await.unwrap();
        assert_eq!(state, V2ClientEngineState::Closed);
    }
}
