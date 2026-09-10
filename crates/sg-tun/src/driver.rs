//! V2 blocking TUN driver (REBUILD WP-300).
//!
//! V1 drives its `Tun` trait from Tokio tasks behind an async mutex. Real
//! platform adapters block on read, so a blocked uplink read can stall the
//! downlink write path and shutdown can hang inside a Tokio task. This module
//! is the V2 replacement for that boundary only; the V1 `Tun` trait, the
//! `LoopbackTun` dev adapter, and both V1 engines are untouched.
//!
//! Design (WP-300 requirements 1-5):
//!
//! ```text
//! Dedicated blocking TUN owner (one std thread, owns `B: TunInterrupt`)
//!   OS -> bounded raw ingress queue -> async scheduler (`recv`)
//!   async scheduler (`send`) -> bounded per-class egress queues -> OS write
//! ```
//!
//! - The worker thread exclusively owns the backend. No other thread touches
//!   it after `DriverTun::spawn`.
//! - Ingress is a single raw FIFO queue. The OS provides no traffic-class
//!   tag, so per approved V2 architecture no classifier runs on this path:
//!   ingress is bounded by packet count (channel capacity) plus total bytes
//!   (explicit gauge), overflow drops the newest arriving packet and counts
//!   the reason, and the worker never blocks the OS read path on a full
//!   queue. There is intentionally no per-class ingress queue or metric.
//! - Egress is bounded per traffic class (`Realtime`, `Interactive`, `Bulk`).
//!   `Control` is rejected: control-plane traffic must use the reliable QUIC
//!   control stream, never the TUN data path (V2 wire invariant).
//! - Egress classes drain in fixed scheduled order
//!   `Realtime -> Interactive -> Bulk`, one packet per non-empty class per
//!   pass, so a flooded class cannot starve the others and the order is
//!   exact/deterministic when the queues are pre-filled (no timing claim).
//! - The first read/write fault poisons the driver durably: the failure is
//!   stored once, every later `send`/`recv` reports it, and `close` hands it
//!   to the supervising engine state machine. The same publish also flips a
//!   single coalescing `watch::Sender<bool>` terminal signal (`send_replace`)
//!   so V2 supervisors transition autonomously without polling: `await` the
//!   signal via `subscribe_terminal`/`await_terminal` instead of looping on
//!   `failure()`.
//! - Ownership must be closed explicitly. `close` (blocking) and
//!   `close_async` (Tokio-friendly, joins via `spawn_blocking`) consume the
//!   owner, signal shutdown, join the worker, and report the terminal
//!   failure or `JoinFailed`. Dropping a live `DriverTun` without `close`
//!   is a programming bug: `Drop` records a durable `JoinRequired` fatal
//!   visible via every cloned `DriverSender`, signals shutdown, and detaches
//!   the thread (which wakes promptly via the interrupt event). V2 engines
//!   must treat `JoinRequired` as fatal and must always `close`/`close_async`.
//! - `shutdown` sets the flag and fires the backend interrupt handle, so the
//!   interruptible timed read returns `Interrupted` promptly and `close` joins
//!   without waiting out `poll_interval`. Native backends use
//!   tun-rs 2.8.9 `interruptible` (`recv_intr_timeout`: `poll()` on Linux,
//!   `WaitForMultipleObjects` on Windows) for this bound; fakes reproduce it
//!   with a condvar + deadline plus an explicit interrupt trigger.

use bytes::Bytes;
use sg_core::v2::TrafficClass;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, watch};

/// Largest IP packet the worker will ever buffer (IPv4/IPv6 maximum).
pub const MAX_IP_PACKET_BYTES: usize = 65_535;

/// Number of V2 data-plane egress classes. `TrafficClass::Control` is never
/// queued; see [`DriverError::ControlRejected`].
pub const EGRESS_CLASSES: usize = 3;

/// Index of each data-plane class in per-class bound/metric arrays.
const REALTIME_INDEX: usize = 0;
const INTERACTIVE_INDEX: usize = 1;
const BULK_INDEX: usize = 2;

/// A blocking TUN backend owned exclusively by one driver worker thread.
///
/// The contract is deliberately narrow so fakes can reproduce every fault
/// deterministically:
/// - `read_interruptible` waits up to `timeout` for one OS packet, then
///   returns `Err` with kind `WouldBlock`/`TimedOut` when no packet arrived.
///   Any other `Err`, or `Ok(0)`, is a terminal driver failure.
/// - `write` must persist the whole packet and return its length. A short
///   count or `Ok(0)` is a terminal partial/zero I/O failure.
/// - All methods run on the worker thread only. `Send` lets the backend move
///   into that thread; no method is ever called concurrently.
/// - `interrupt_trigger` returns a shareable handle that unblocks a parked
///   `read_interruptible` promptly (tun-rs `InterruptEvent::trigger`,
///   mapping to `Interrupted`). The driver calls it on every shutdown path
///   so `close` joins without waiting out a full `poll_interval`.
pub trait TunInterrupt: Send {
    fn read_interruptible(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize>;
    fn write(&mut self, packet: &[u8]) -> io::Result<usize>;
    fn mtu(&self) -> u32;
    fn name(&self) -> &str;
    /// Shareable shutdown wakeup for a parked read. The default (`None`)
    /// keeps the `poll_interval` timeout bound; native backends return a
    /// trigger bound to their interrupt event. Called only before the backend
    /// moves into the worker thread.
    fn interrupt_trigger(&self) -> Option<std::sync::Arc<dyn InterruptTrigger>> {
        None
    }
}

/// Shareable shutdown wakeup for a parked blocking read.
///
/// The handle is captured at `DriverTun::spawn` time (before the backend moves
/// into the worker thread) and stored in the shared state. Every shutdown path
/// (`shutdown`, `close`, `close_async`, `Drop`) fires it best-effort after
/// setting the shutdown flag, so a worker parked in `read_interruptible`
/// observes `Interrupted` promptly instead of sleeping out `poll_interval`.
/// Triggering is idempotent and never records a terminal failure.
pub trait InterruptTrigger: Send + Sync {
    fn trigger(&self);
}

/// Static bounds for one driver instance. Every queue has a packet-count and
/// a byte bound; every bound is validated by [`DriverConfig::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverConfig {
    /// Largest TUN packet accepted in either direction.
    pub max_packet_bytes: usize,
    /// Ingress (OS -> scheduler) packet capacity.
    pub ingress_max_packets: usize,
    /// Ingress (OS -> scheduler) byte capacity.
    pub ingress_max_bytes: usize,
    /// Egress (scheduler -> OS) packet capacity per class.
    pub egress_max_packets_realtime: usize,
    /// Egress (scheduler -> OS) packet capacity per class.
    pub egress_max_packets_interactive: usize,
    /// Egress (scheduler -> OS) packet capacity per class.
    pub egress_max_packets_bulk: usize,
    /// Egress (scheduler -> OS) byte capacity per class.
    pub egress_max_bytes_realtime: usize,
    /// Egress (scheduler -> OS) byte capacity per class.
    pub egress_max_bytes_interactive: usize,
    /// Egress (scheduler -> OS) byte capacity per class.
    pub egress_max_bytes_bulk: usize,
    /// Timeslice for one backend read. Bounds duplex latency (an egress
    /// packet waits at most this long while a read is blocked) and shutdown
    /// latency (`close` joins within about one slice plus one write).
    pub poll_interval: Duration,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            max_packet_bytes: 9_000,
            ingress_max_packets: 256,
            ingress_max_bytes: 512 * 1_024,
            egress_max_packets_realtime: 128,
            egress_max_packets_interactive: 128,
            egress_max_packets_bulk: 256,
            egress_max_bytes_realtime: 192 * 1_024,
            egress_max_bytes_interactive: 192 * 1_024,
            egress_max_bytes_bulk: 512 * 1_024,
            poll_interval: Duration::from_millis(5),
        }
    }
}

impl DriverConfig {
    /// Packet capacity for one data-plane class.
    #[must_use]
    pub const fn egress_max_packets(self, class: TrafficClass) -> Option<usize> {
        match class {
            TrafficClass::Realtime => Some(self.egress_max_packets_realtime),
            TrafficClass::Interactive => Some(self.egress_max_packets_interactive),
            TrafficClass::Bulk => Some(self.egress_max_packets_bulk),
            TrafficClass::Control => None,
        }
    }

    /// Byte capacity for one data-plane class.
    #[must_use]
    pub const fn egress_max_bytes(self, class: TrafficClass) -> Option<usize> {
        match class {
            TrafficClass::Realtime => Some(self.egress_max_bytes_realtime),
            TrafficClass::Interactive => Some(self.egress_max_bytes_interactive),
            TrafficClass::Bulk => Some(self.egress_max_bytes_bulk),
            TrafficClass::Control => None,
        }
    }

    fn validate(self) -> Result<(), DriverError> {
        if self.max_packet_bytes == 0 || self.max_packet_bytes > MAX_IP_PACKET_BYTES {
            return Err(DriverError::InvalidConfig(format!(
                "max_packet_bytes {} is outside 1..={MAX_IP_PACKET_BYTES}",
                self.max_packet_bytes
            )));
        }
        let packet_bounds = [
            ("ingress_max_packets", self.ingress_max_packets),
            ("egress_max_packets_realtime", self.egress_max_packets_realtime),
            ("egress_max_packets_interactive", self.egress_max_packets_interactive),
            ("egress_max_packets_bulk", self.egress_max_packets_bulk),
        ];
        for (name, bound) in packet_bounds {
            if bound == 0 {
                return Err(DriverError::InvalidConfig(format!("{name} must be nonzero")));
            }
        }
        let byte_bounds = [
            ("ingress_max_bytes", self.ingress_max_bytes),
            ("egress_max_bytes_realtime", self.egress_max_bytes_realtime),
            ("egress_max_bytes_interactive", self.egress_max_bytes_interactive),
            ("egress_max_bytes_bulk", self.egress_max_bytes_bulk),
        ];
        for (name, bound) in byte_bounds {
            if bound < self.max_packet_bytes {
                return Err(DriverError::InvalidConfig(format!(
                    "{name} {bound} cannot hold one {0}-byte packet",
                    self.max_packet_bytes
                )));
            }
        }
        if self.poll_interval < Duration::from_micros(100) || self.poll_interval > Duration::from_secs(5) {
            return Err(DriverError::InvalidConfig(format!(
                "poll_interval {:?} is outside 100us..=5s",
                self.poll_interval
            )));
        }
        Ok(())
    }
}

/// Which side of the blocking boundary failed first. The message carries the
/// OS error text only, never packet payloads. `JoinRequired` is an ownership
/// fatal: the `DriverTun` owner was dropped without `close`/`close_async`,
/// so the worker was detached instead of joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Read,
    Write,
    JoinRequired,
}

/// The durable terminal failure recorded by the worker. First fault wins;
/// later faults only bump their counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverFailure {
    kind: FailureKind,
    message: String,
}

impl DriverFailure {
    #[must_use]
    pub const fn kind(&self) -> FailureKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("V2 TUN driver configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("V2 TUN packet is empty")]
    EmptyPacket,
    #[error("V2 TUN packet length {length} exceeds limit {limit}")]
    Oversize { length: usize, limit: usize },
    #[error("V2 TUN control traffic must use the reliable control stream")]
    ControlRejected,
    #[error("V2 TUN egress {class:?} packet queue is full")]
    EgressPacketLimit { class: TrafficClass },
    #[error("V2 TUN egress {class:?} byte queue is full")]
    EgressByteLimit { class: TrafficClass },
    #[error("V2 TUN driver is terminal after {kind:?}: {message}")]
    Terminal { kind: FailureKind, message: String },
    #[error("V2 TUN driver is closed")]
    Closed,
    #[error("V2 TUN driver worker failed to join")]
    JoinFailed,
}

/// Point-in-time counters for one driver. Queue depths are live gauges;
/// every other field is a monotonic counter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverMetrics {
    pub ingress_received: u64,
    pub ingress_delivered: u64,
    pub ingress_dropped_packet_limit: u64,
    pub ingress_dropped_byte_limit: u64,
    pub ingress_dropped_oversize: u64,
    pub ingress_queue_packets: usize,
    pub ingress_queue_bytes: usize,
    pub egress_enqueued_realtime: u64,
    pub egress_enqueued_interactive: u64,
    pub egress_enqueued_bulk: u64,
    pub egress_written_realtime: u64,
    pub egress_written_interactive: u64,
    pub egress_written_bulk: u64,
    pub egress_dropped_packet_realtime: u64,
    pub egress_dropped_packet_interactive: u64,
    pub egress_dropped_packet_bulk: u64,
    pub egress_dropped_byte_realtime: u64,
    pub egress_dropped_byte_interactive: u64,
    pub egress_dropped_byte_bulk: u64,
    pub egress_dropped_oversize: u64,
    pub egress_empty_rejected: u64,
    pub egress_control_rejected: u64,
    pub egress_queue_packets_realtime: usize,
    pub egress_queue_packets_interactive: usize,
    pub egress_queue_packets_bulk: usize,
    pub egress_queue_bytes_realtime: usize,
    pub egress_queue_bytes_interactive: usize,
    pub egress_queue_bytes_bulk: usize,
    pub read_errors: u64,
    pub write_errors: u64,
    pub zero_reads: u64,
    pub zero_writes: u64,
    pub partial_writes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

struct SharedMetrics {
    ingress_received: AtomicU64,
    ingress_delivered: AtomicU64,
    ingress_dropped_packet_limit: AtomicU64,
    ingress_dropped_byte_limit: AtomicU64,
    ingress_dropped_oversize: AtomicU64,
    ingress_queued_packets: AtomicUsize,
    ingress_queued_bytes: AtomicUsize,
    egress_enqueued: [AtomicU64; EGRESS_CLASSES],
    egress_written: [AtomicU64; EGRESS_CLASSES],
    egress_dropped_packet: [AtomicU64; EGRESS_CLASSES],
    egress_dropped_byte: [AtomicU64; EGRESS_CLASSES],
    egress_dropped_oversize: AtomicU64,
    egress_empty_rejected: AtomicU64,
    egress_control_rejected: AtomicU64,
    egress_queued_packets: [AtomicUsize; EGRESS_CLASSES],
    egress_queued_bytes: [AtomicUsize; EGRESS_CLASSES],
    read_errors: AtomicU64,
    write_errors: AtomicU64,
    zero_reads: AtomicU64,
    zero_writes: AtomicU64,
    partial_writes: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
}

impl SharedMetrics {
    fn new() -> Self {
        Self {
            ingress_received: AtomicU64::new(0),
            ingress_delivered: AtomicU64::new(0),
            ingress_dropped_packet_limit: AtomicU64::new(0),
            ingress_dropped_byte_limit: AtomicU64::new(0),
            ingress_dropped_oversize: AtomicU64::new(0),
            ingress_queued_packets: AtomicUsize::new(0),
            ingress_queued_bytes: AtomicUsize::new(0),
            egress_enqueued: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            egress_written: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            egress_dropped_packet: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            egress_dropped_byte: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            egress_dropped_oversize: AtomicU64::new(0),
            egress_empty_rejected: AtomicU64::new(0),
            egress_control_rejected: AtomicU64::new(0),
            egress_queued_packets: [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)],
            egress_queued_bytes: [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)],
            read_errors: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            zero_reads: AtomicU64::new(0),
            zero_writes: AtomicU64::new(0),
            partial_writes: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> DriverMetrics {
        let load = AtomicU64::load;
        let load_size = AtomicUsize::load;
        DriverMetrics {
            ingress_received: load(&self.ingress_received, Ordering::Relaxed),
            ingress_delivered: load(&self.ingress_delivered, Ordering::Relaxed),
            ingress_dropped_packet_limit: load(&self.ingress_dropped_packet_limit, Ordering::Relaxed),
            ingress_dropped_byte_limit: load(&self.ingress_dropped_byte_limit, Ordering::Relaxed),
            ingress_dropped_oversize: load(&self.ingress_dropped_oversize, Ordering::Relaxed),
            ingress_queue_packets: load_size(&self.ingress_queued_packets, Ordering::Relaxed),
            ingress_queue_bytes: load_size(&self.ingress_queued_bytes, Ordering::Relaxed),
            egress_enqueued_realtime: load(&self.egress_enqueued[REALTIME_INDEX], Ordering::Relaxed),
            egress_enqueued_interactive: load(&self.egress_enqueued[INTERACTIVE_INDEX], Ordering::Relaxed),
            egress_enqueued_bulk: load(&self.egress_enqueued[BULK_INDEX], Ordering::Relaxed),
            egress_written_realtime: load(&self.egress_written[REALTIME_INDEX], Ordering::Relaxed),
            egress_written_interactive: load(&self.egress_written[INTERACTIVE_INDEX], Ordering::Relaxed),
            egress_written_bulk: load(&self.egress_written[BULK_INDEX], Ordering::Relaxed),
            egress_dropped_packet_realtime: load(&self.egress_dropped_packet[REALTIME_INDEX], Ordering::Relaxed),
            egress_dropped_packet_interactive: load(&self.egress_dropped_packet[INTERACTIVE_INDEX], Ordering::Relaxed),
            egress_dropped_packet_bulk: load(&self.egress_dropped_packet[BULK_INDEX], Ordering::Relaxed),
            egress_dropped_byte_realtime: load(&self.egress_dropped_byte[REALTIME_INDEX], Ordering::Relaxed),
            egress_dropped_byte_interactive: load(&self.egress_dropped_byte[INTERACTIVE_INDEX], Ordering::Relaxed),
            egress_dropped_byte_bulk: load(&self.egress_dropped_byte[BULK_INDEX], Ordering::Relaxed),
            egress_dropped_oversize: load(&self.egress_dropped_oversize, Ordering::Relaxed),
            egress_empty_rejected: load(&self.egress_empty_rejected, Ordering::Relaxed),
            egress_control_rejected: load(&self.egress_control_rejected, Ordering::Relaxed),
            egress_queue_packets_realtime: load_size(&self.egress_queued_packets[REALTIME_INDEX], Ordering::Relaxed),
            egress_queue_packets_interactive: load_size(&self.egress_queued_packets[INTERACTIVE_INDEX], Ordering::Relaxed),
            egress_queue_packets_bulk: load_size(&self.egress_queued_packets[BULK_INDEX], Ordering::Relaxed),
            egress_queue_bytes_realtime: load_size(&self.egress_queued_bytes[REALTIME_INDEX], Ordering::Relaxed),
            egress_queue_bytes_interactive: load_size(&self.egress_queued_bytes[INTERACTIVE_INDEX], Ordering::Relaxed),
            egress_queue_bytes_bulk: load_size(&self.egress_queued_bytes[BULK_INDEX], Ordering::Relaxed),
            read_errors: load(&self.read_errors, Ordering::Relaxed),
            write_errors: load(&self.write_errors, Ordering::Relaxed),
            zero_reads: load(&self.zero_reads, Ordering::Relaxed),
            zero_writes: load(&self.zero_writes, Ordering::Relaxed),
            partial_writes: load(&self.partial_writes, Ordering::Relaxed),
            bytes_read: load(&self.bytes_read, Ordering::Relaxed),
            bytes_written: load(&self.bytes_written, Ordering::Relaxed),
        }
    }
}

#[must_use]
const fn class_index(class: TrafficClass) -> Option<usize> {
    match class {
        TrafficClass::Realtime => Some(REALTIME_INDEX),
        TrafficClass::Interactive => Some(INTERACTIVE_INDEX),
        TrafficClass::Bulk => Some(BULK_INDEX),
        TrafficClass::Control => None,
    }
}

struct Shared {
    config: DriverConfig,
    metrics: SharedMetrics,
    shutdown: AtomicBool,
    failure: Mutex<Option<DriverFailure>>,
    egress_tx: [mpsc::Sender<Bytes>; EGRESS_CLASSES],
    interrupt: Option<Arc<dyn InterruptTrigger>>,
    /// Autonomous terminal notification (WP-300 final blocker).
    ///
    /// Single `bool` watch value (`false` = running, `true` = terminal).
    /// Bounded (one value) and coalescing: every terminal failure maps to the
    /// same `true`, so repeated faults never grow a queue. The worker publishes
    /// via `send_replace` (stored even with zero receivers, so a failure that
    /// races `spawn` is still visible to a late subscriber); supervisors await
    /// via `wait_for(|ready| *ready)` which returns immediately for late
    /// joiners. No task, no channel beyond this one value, no data-path use.
    terminal: watch::Sender<bool>,
}

/// Sets the shutdown flag and fires the backend interrupt event best-effort
/// so a worker parked in `read_interruptible` wakes promptly with
/// `Interrupted` (a clean wakeup, never a terminal fault) instead of waiting
/// out `poll_interval`. Idempotent; trigger errors are intentionally ignored
/// because shutdown itself is the signal.
fn signal_shutdown(shared: &Shared) {
    shared.shutdown.store(true, Ordering::SeqCst);
    if let Some(trigger) = shared.interrupt.as_ref() {
        trigger.trigger();
    }
}

fn read_failure(shared: &Shared) -> Option<DriverFailure> {
    match shared.failure.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn set_failure(shared: &Shared, kind: FailureKind, message: String) {
    let is_first = match shared.failure.lock() {
        Ok(mut guard) => {
            if guard.is_none() {
                tracing::warn!(?kind, "v2 TUN driver entering durable terminal failure");
                *guard = Some(DriverFailure { kind, message });
                true
            } else {
                false
            }
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            if guard.is_none() {
                tracing::warn!(?kind, "v2 TUN driver entering durable terminal failure");
                *guard = Some(DriverFailure { kind, message });
                true
            } else {
                false
            }
        }
    };
    // Publish outside the failure lock: `send_replace` stores `true` even with
    // zero receivers (unlike `send`), so a fault that races `spawn` is still
    // visible to a late subscriber, and repeated faults coalesce to one value.
    if is_first {
        shared.terminal.send_replace(true);
    }
}

fn terminal_error(failure: &DriverFailure) -> DriverError {
    DriverError::Terminal {
        kind: failure.kind,
        message: failure.message.clone(),
    }
}

/// Cloneable sender half of a driver. `Send` + `Sync` so every scheduler
/// task can enqueue downlink packets without touching the ingress receiver.
#[derive(Clone)]
pub struct DriverSender {
    shared: Arc<Shared>,
}

impl DriverSender {
    /// Non-blocking enqueue with deterministic drop: oversize/empty/control
    /// packets are rejected before queuing, then the per-class byte bound,
    /// then the per-class packet bound. Every outcome bumps a metric.
    pub fn send(&self, class: TrafficClass, packet: Bytes) -> Result<(), DriverError> {
        if let Some(failure) = read_failure(&self.shared) {
            return Err(terminal_error(&failure));
        }
        if self.shared.shutdown.load(Ordering::SeqCst) {
            return Err(DriverError::Closed);
        }
        let Some(index) = class_index(class) else {
            self.shared
                .metrics
                .egress_control_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(DriverError::ControlRejected);
        };
        if packet.is_empty() {
            self.shared
                .metrics
                .egress_empty_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(DriverError::EmptyPacket);
        }
        let config = self.shared.config;
        if packet.len() > config.max_packet_bytes {
            self.shared
                .metrics
                .egress_dropped_oversize
                .fetch_add(1, Ordering::Relaxed);
            return Err(DriverError::Oversize {
                length: packet.len(),
                limit: config.max_packet_bytes,
            });
        }
        let byte_limit = config.egress_max_bytes(class).unwrap_or(usize::MAX);
        // Reserve queue gauges before `try_send`: the worker's dequeue
        // decrement is sequenced after its `try_recv`, which synchronizes
        // with this `try_send`, so the reservation must already be visible.
        // A rejected send rolls its reservation back immediately.
        let length = packet.len();
        let previous_bytes = self.shared.metrics.egress_queued_bytes[index].fetch_add(length, Ordering::Relaxed);
        if previous_bytes.saturating_add(length) > byte_limit {
            self.shared.metrics.egress_queued_bytes[index].fetch_sub(length, Ordering::Relaxed);
            self.shared.metrics.egress_dropped_byte[index].fetch_add(1, Ordering::Relaxed);
            return Err(DriverError::EgressByteLimit { class });
        }
        self.shared.metrics.egress_queued_packets[index].fetch_add(1, Ordering::Relaxed);
        match self.shared.egress_tx[index].try_send(packet) {
            Ok(()) => {
                self.shared.metrics.egress_enqueued[index].fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.shared.metrics.egress_queued_bytes[index].fetch_sub(length, Ordering::Relaxed);
                self.shared.metrics.egress_queued_packets[index].fetch_sub(1, Ordering::Relaxed);
                self.shared.metrics.egress_dropped_packet[index].fetch_add(1, Ordering::Relaxed);
                Err(DriverError::EgressPacketLimit { class })
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.shared.metrics.egress_queued_bytes[index].fetch_sub(length, Ordering::Relaxed);
                self.shared.metrics.egress_queued_packets[index].fetch_sub(1, Ordering::Relaxed);
                Err(DriverError::Closed)
            }
        }
    }

    /// Live counters and queue depths. Never blocks and takes no lock.
    #[must_use]
    pub fn metrics(&self) -> DriverMetrics {
        self.shared.metrics.snapshot()
    }

    /// The durable terminal failure, if the worker has recorded one.
    #[must_use]
    pub fn failure(&self) -> Option<DriverFailure> {
        read_failure(&self.shared)
    }

    /// Subscribes to the autonomous terminal signal. The returned receiver
    /// observes the single coalescing `bool` (`true` = terminal); `wait_for`
    /// returns immediately for a late subscriber after a failure, so a fault
    /// that races `spawn` is never missed. One receiver per supervisor task;
    /// receivers are bounded (watch holds one value) and dropped on shutdown.
    #[must_use]
    pub fn subscribe_terminal(&self) -> watch::Receiver<bool> {
        self.shared.terminal.subscribe()
    }

    /// Sync fast-path for the terminal signal (`true` once the first failure
    /// was published). Never blocks; combines with [`DriverSender::failure`]
    /// for prompt reads without awaiting.
    #[must_use]
    pub fn is_terminal_signalled(&self) -> bool {
        *self.shared.terminal.borrow()
    }

    /// Event-driven wait for the durable terminal failure. Checks the stored
    /// failure first (late-join fast path), then awaits the coalescing watch
    /// signal; after the signal the failure must be present (first fault
    /// wins). Hangs on a clean shutdown (no failure is ever published); callers
    /// race this against shutdown with a timeout. Never polls.
    pub async fn await_terminal(&self) -> DriverFailure {
        if let Some(failure) = read_failure(&self.shared) {
            return failure;
        }
        let mut receiver = self.shared.terminal.subscribe();
        // `wait_for` returns immediately if `true` was already published via
        // `send_replace` (late subscriber), otherwise parks until the worker
        // publishes. A closed channel means every sender was dropped, which
        // cannot happen while `self` holds `Shared`; treat it as a recheck.
        let _ = receiver.wait_for(|ready| *ready).await;
        loop {
            if let Some(failure) = read_failure(&self.shared) {
                return failure;
            }
            // Signal was `true` but the failure lock has not yet settled
            // (publish happens just after the lock release); re-await instead
            // of spinning. The value stays `true`, so this returns promptly
            // once the lock is visible.
            let _ = receiver.changed().await;
        }
    }

    /// Ask the worker to exit. Idempotent; use `close` on the owner to join.
    /// Sets the shutdown flag and fires the backend interrupt event so a
    /// parked read wakes promptly with `Interrupted`.
    pub fn shutdown(&self) {
        signal_shutdown(&self.shared);
    }
}

/// Owner of one V2 blocking TUN driver.
///
/// Holds the ingress receiver and the worker join handle. `send` is also
/// available here for single-owner use; clone [`DriverTun::sender`] to share
/// the egress path across tasks.
///
/// Ownership contract: the owner must be closed explicitly with [`DriverTun::close`]
/// (blocking threads) or [`DriverTun::close_async`] (Tokio tasks). Both consume
/// the owner, signal shutdown, join the worker, and report the durable terminal
/// failure. Dropping a live owner without closing records a durable
/// `JoinRequired` fatal visible via every cloned [`DriverSender`] and detaches
/// the worker; V2 engines must treat that as fatal and must never rely on `Drop`
/// to join.
pub struct DriverTun {
    shared: Arc<Shared>,
    ingress_rx: Option<mpsc::Receiver<Bytes>>,
    worker: Option<JoinHandle<()>>,
    backend_name: String,
    backend_mtu: u32,
}

impl DriverTun {
    /// Spawns the exclusive blocking owner for `backend` and returns the
    /// async-side handle. Validates `config` before the thread starts.
    /// Captures the backend interrupt handle (if any) before the backend moves
    /// into the worker thread so every shutdown path can unblock a parked read.
    pub fn spawn<B: TunInterrupt + 'static>(mut backend: B, config: DriverConfig) -> Result<Self, DriverError> {
        config.validate()?;
        let backend_name = backend.name().to_owned();
        let backend_mtu = backend.mtu();
        let interrupt = backend.interrupt_trigger();
        let (ingress_tx, ingress_rx) = mpsc::channel::<Bytes>(config.ingress_max_packets);
        let (realtime_tx, realtime_rx) = mpsc::channel::<Bytes>(config.egress_max_packets_realtime);
        let (interactive_tx, interactive_rx) = mpsc::channel::<Bytes>(config.egress_max_packets_interactive);
        let (bulk_tx, bulk_rx) = mpsc::channel::<Bytes>(config.egress_max_packets_bulk);
        // Single coalescing terminal value; `send_replace` keeps it visible to
        // late subscribers even when no supervisor has subscribed yet.
        let (terminal, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            config,
            metrics: SharedMetrics::new(),
            shutdown: AtomicBool::new(false),
            failure: Mutex::new(None),
            egress_tx: [realtime_tx, interactive_tx, bulk_tx],
            interrupt,
            terminal,
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("sg-tun-v2-driver".into())
            .spawn(move || {
                worker_loop(&mut backend, &worker_shared, &ingress_tx, [realtime_rx, interactive_rx, bulk_rx]);
            })
            .map_err(|error| DriverError::InvalidConfig(format!("failed to spawn TUN driver thread: {error}")))?;
        Ok(Self {
            shared,
            ingress_rx: Some(ingress_rx),
            worker: Some(worker),
            backend_name,
            backend_mtu,
        })
    }

    /// A cloneable sender half sharing this driver's egress queues.
    #[must_use]
    pub fn sender(&self) -> DriverSender {
        DriverSender {
            shared: Arc::clone(&self.shared),
        }
    }

    /// See [`DriverSender::send`].
    pub fn send(&self, class: TrafficClass, packet: Bytes) -> Result<(), DriverError> {
        self.sender().send(class, packet)
    }

    /// Non-blocking ingress poll. `Ok(None)` means the queue is currently
    /// empty; `Err(Terminal)` wins over queued packets once poisoned.
    pub fn try_recv(&mut self) -> Result<Option<Bytes>, DriverError> {
        if let Some(failure) = read_failure(&self.shared) {
            return Err(terminal_error(&failure));
        }
        let Some(rx) = self.ingress_rx.as_mut() else {
            return Err(DriverError::Closed);
        };
        match rx.try_recv() {
            Ok(packet) => {
                self.shared.metrics.ingress_queued_packets.fetch_sub(1, Ordering::Relaxed);
                self.shared
                    .metrics
                    .ingress_queued_bytes
                    .fetch_sub(packet.len(), Ordering::Relaxed);
                Ok(Some(packet))
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                if let Some(failure) = read_failure(&self.shared) {
                    Err(terminal_error(&failure))
                } else {
                    Err(DriverError::Closed)
                }
            }
        }
    }

    /// Async ingress receive. Returns `Ok(None)` only when the worker exited
    /// cleanly (shutdown) and the queue drained; a recorded fault reports
    /// `Err(Terminal)` instead.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, DriverError> {
        if let Some(failure) = read_failure(&self.shared) {
            return Err(terminal_error(&failure));
        }
        let Some(rx) = self.ingress_rx.as_mut() else {
            return Err(DriverError::Closed);
        };
        match rx.recv().await {
            Some(packet) => {
                self.shared.metrics.ingress_queued_packets.fetch_sub(1, Ordering::Relaxed);
                self.shared
                    .metrics
                    .ingress_queued_bytes
                    .fetch_sub(packet.len(), Ordering::Relaxed);
                Ok(Some(packet))
            }
            None => {
                if let Some(failure) = read_failure(&self.shared) {
                    Err(terminal_error(&failure))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Live counters and queue depths. Never blocks and takes no lock.
    #[must_use]
    pub fn metrics(&self) -> DriverMetrics {
        self.shared.metrics.snapshot()
    }

    /// The durable terminal failure, if the worker has recorded one.
    #[must_use]
    pub fn failure(&self) -> Option<DriverFailure> {
        read_failure(&self.shared)
    }

    /// Subscribes to the autonomous terminal signal; see
    /// [`DriverSender::subscribe_terminal`]. Late subscribers observe an
    /// already-published `true` immediately via `wait_for`.
    #[must_use]
    pub fn subscribe_terminal(&self) -> watch::Receiver<bool> {
        self.shared.terminal.subscribe()
    }

    /// Sync fast-path for the terminal signal; see
    /// [`DriverSender::is_terminal_signalled`].
    #[must_use]
    pub fn is_terminal_signalled(&self) -> bool {
        *self.shared.terminal.borrow()
    }

    /// Event-driven wait for the durable terminal failure; see
    /// [`DriverSender::await_terminal`].
    pub async fn await_terminal(&self) -> DriverFailure {
        self.sender().await_terminal().await
    }

    /// Name reported by the backend at spawn time.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }

    /// MTU reported by the backend at spawn time.
    #[must_use]
    pub const fn backend_mtu(&self) -> u32 {
        self.backend_mtu
    }

    /// Ask the worker to exit. Idempotent and non-blocking; the interrupt event
    /// wakes a parked read promptly, so the worker observes shutdown without
    /// waiting out `poll_interval`. Call [`DriverTun::close`] or
    /// [`DriverTun::close_async`] to join; `shutdown` alone never joins.
    pub fn shutdown(&self) {
        signal_shutdown(&self.shared);
    }

    /// Signal shutdown, join the worker on the calling (blocking) thread, and
    /// report the outcome. Returns the recorded terminal failure (if any) so
    /// the supervising engine can react; `Err(JoinFailed)` means the worker
    /// panicked. Unsent egress and undrained ingress are discarded with
    /// shutdown. Never call from a Tokio async context; use `close_async`.
    pub fn close(mut self) -> Result<Option<DriverFailure>, DriverError> {
        signal_shutdown(&self.shared);
        let Some(worker) = self.worker.take() else {
            return Err(DriverError::Closed);
        };
        match worker.join() {
            Ok(()) => Ok(read_failure(&self.shared)),
            Err(_) => Err(DriverError::JoinFailed),
        }
    }

    /// Async ownership close for Tokio contexts. Signals shutdown, then joins
    /// the blocking worker on a `spawn_blocking` thread so the async runtime
    /// is never blocked. Returns the same outcome as [`DriverTun::close`].
    pub async fn close_async(mut self) -> Result<Option<DriverFailure>, DriverError> {
        signal_shutdown(&self.shared);
        let Some(worker) = self.worker.take() else {
            return Err(DriverError::Closed);
        };
        let shared = Arc::clone(&self.shared);
        // `self` still owns `shared` + `ingress_rx`; dropping it after the
        // take sees `worker: None` so `Drop` stays silent. Join off-runtime.
        let joined = tokio::task::spawn_blocking(move || worker.join())
            .await
            .map_err(|_| DriverError::JoinFailed)?;
        match joined {
            Ok(()) => Ok(read_failure(&shared)),
            Err(_) => Err(DriverError::JoinFailed),
        }
    }
}

impl Drop for DriverTun {
    fn drop(&mut self) {
        // Explicit-close ownership: a live worker here means the owner was
        // dropped without `close`/`close_async`. Never block in Drop; record
        // the durable `JoinRequired` fatal so every cloned sender observes it,
        // signal shutdown (flag + interrupt event), and detach. The detached
        // thread wakes promptly via the interrupt and exits, but the
        // supervisor must treat this as a fatal programming bug, not a clean
        // shutdown.
        if self.worker.is_some() {
            set_failure(
                &self.shared,
                FailureKind::JoinRequired,
                "driver owner dropped without close; worker detached, join required".into(),
            );
            signal_shutdown(&self.shared);
            let _detached: Option<JoinHandle<()>> = self.worker.take();
            tracing::error!("v2 TUN driver dropped without close; JoinRequired recorded");
        }
    }
}

fn worker_loop<B: TunInterrupt>(
    backend: &mut B,
    shared: &Shared,
    ingress_tx: &mpsc::Sender<Bytes>,
    mut egress_rx: [mpsc::Receiver<Bytes>; EGRESS_CLASSES],
) {
    let config = shared.config;
    let mut buffer = vec![0u8; MAX_IP_PACKET_BYTES];
    loop {
        if shared.shutdown.load(Ordering::SeqCst) {
            break;
        }
        if read_failure(shared).is_some() {
            break;
        }
        // Deterministic scheduled fairness: fixed class order
        // `Realtime -> Interactive -> Bulk`, one packet per non-empty class
        // per pass. No rotation, no timing claim: when the test pre-fills the
        // queues while the worker is parked in `read_interruptible`, the next
        // pass emits exactly this order. A flooded class still cannot starve
        // the others because each pass takes at most one packet per class.
        for (index, queue) in egress_rx.iter_mut().enumerate() {
            if shared.shutdown.load(Ordering::SeqCst) || read_failure(shared).is_some() {
                break;
            }
            let packet = match queue.try_recv() {
                Ok(packet) => packet,
                Err(mpsc::error::TryRecvError::Empty) => continue,
                Err(mpsc::error::TryRecvError::Disconnected) => continue,
            };
            shared.metrics.egress_queued_packets[index].fetch_sub(1, Ordering::Relaxed);
            shared.metrics.egress_queued_bytes[index].fetch_sub(packet.len(), Ordering::Relaxed);
            let expected = packet.len();
            match backend.write(&packet) {
                Ok(written) if written == expected => {
                    shared.metrics.egress_written[index].fetch_add(1, Ordering::Relaxed);
                    shared.metrics.bytes_written.fetch_add(written as u64, Ordering::Relaxed);
                }
                Ok(0) => {
                    shared.metrics.zero_writes.fetch_add(1, Ordering::Relaxed);
                    shared.metrics.write_errors.fetch_add(1, Ordering::Relaxed);
                    set_failure(shared, FailureKind::Write, "backend wrote zero bytes".into());
                    break;
                }
                Ok(written) => {
                    shared.metrics.partial_writes.fetch_add(1, Ordering::Relaxed);
                    shared.metrics.write_errors.fetch_add(1, Ordering::Relaxed);
                    set_failure(
                        shared,
                        FailureKind::Write,
                        format!("backend partial write {written}/{expected}"),
                    );
                    break;
                }
                Err(error) => {
                    shared.metrics.write_errors.fetch_add(1, Ordering::Relaxed);
                    set_failure(shared, FailureKind::Write, error.to_string());
                    break;
                }
            }
        }
        if shared.shutdown.load(Ordering::SeqCst) || read_failure(shared).is_some() {
            break;
        }
        match backend.read_interruptible(&mut buffer, config.poll_interval) {
            Ok(0) => {
                shared.metrics.zero_reads.fetch_add(1, Ordering::Relaxed);
                shared.metrics.read_errors.fetch_add(1, Ordering::Relaxed);
                set_failure(shared, FailureKind::Read, "backend returned zero bytes".into());
                break;
            }
            Ok(length) => {
                shared.metrics.ingress_received.fetch_add(1, Ordering::Relaxed);
                if length > config.max_packet_bytes {
                    shared.metrics.ingress_dropped_oversize.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // Reserve ingress gauges before `try_send` for the same
                // visibility reason as the egress path: the handle's receive
                // decrement runs after a `recv` synchronized with this send.
                let previous_bytes = shared.metrics.ingress_queued_bytes.fetch_add(length, Ordering::Relaxed);
                if previous_bytes.saturating_add(length) > config.ingress_max_bytes {
                    shared.metrics.ingress_queued_bytes.fetch_sub(length, Ordering::Relaxed);
                    shared.metrics.ingress_dropped_byte_limit.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                shared.metrics.ingress_queued_packets.fetch_add(1, Ordering::Relaxed);
                let packet = Bytes::copy_from_slice(&buffer[..length]);
                match ingress_tx.try_send(packet) {
                    Ok(()) => {
                        shared.metrics.ingress_delivered.fetch_add(1, Ordering::Relaxed);
                        shared.metrics.bytes_read.fetch_add(length as u64, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        shared.metrics.ingress_queued_bytes.fetch_sub(length, Ordering::Relaxed);
                        shared.metrics.ingress_queued_packets.fetch_sub(1, Ordering::Relaxed);
                        shared.metrics.ingress_dropped_packet_limit.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        shared.metrics.ingress_queued_bytes.fetch_sub(length, Ordering::Relaxed);
                        shared.metrics.ingress_queued_packets.fetch_sub(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut => {
                continue;
            }
            // `Interrupted` is the tun-rs `interruptible` shutdown signal
            // (`InterruptEvent::trigger`). Treat it as a clean wakeup: the
            // loop re-checks `shutdown`/terminal state on the next pass
            // instead of poisoning the driver.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(error) => {
                shared.metrics.read_errors.fetch_add(1, Ordering::Relaxed);
                set_failure(shared, FailureKind::Read, error.to_string());
                break;
            }
        }
    }
    tracing::debug!("v2 TUN driver worker exited");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Condvar, Mutex};
    use std::time::Instant;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct FakeInner {
        ingress: VecDeque<Bytes>,
        writes: Vec<Bytes>,
        read_error: Option<io::ErrorKind>,
        read_zero: bool,
        /// When true, the next `read_interruptible` returns `Interrupted`
        /// once (the tun-rs shutdown wakeup) instead of data or timeout.
        read_interrupted_once: bool,
        /// Persistent shutdown interrupt set by the driver's interrupt handle.
        /// Mirrors a triggered tun-rs `InterruptEvent` (stays triggered until
        /// the backend is dropped): every subsequent read returns `Interrupted`
        /// so a parked worker wakes promptly on `shutdown`/`close`/`Drop`.
        interrupt_requested: bool,
        /// How many times the interrupt handle fired. Lets tests assert the
        /// shutdown path actually triggered instead of relying on timeouts.
        interrupt_triggers: usize,
        write_error: Option<io::ErrorKind>,
        write_partial: bool,
        write_zero: bool,
        /// How many times the worker has entered `read_interruptible`.
        /// Incremented under the same mutex before any ingress/error check,
        /// so tests can wait (via the shared condvar) until the worker is
        /// parked in its timed read before pre-filling queues. This makes
        /// egress schedule assertions exact instead of timing-dependent.
        entered_read: usize,
    }

    /// Deterministic scriptable backend. The worker owns the `FakeTun`; the
    /// test drives the shared state through the cloned `FakeHandle`, so reads
    /// can stay blocked while writes are observed via the condvar. Every
    /// entry into `read_interruptible` bumps `entered_read` and notifies,
    /// giving tests a barrier for "worker is parked in read".
    struct FakeTun {
        state: Arc<(Mutex<FakeInner>, Condvar)>,
    }

    #[derive(Clone)]
    struct FakeHandle {
        state: Arc<(Mutex<FakeInner>, Condvar)>,
    }

    fn fake_pair() -> (FakeTun, FakeHandle) {
        let state = Arc::new((
            Mutex::new(FakeInner {
                ingress: VecDeque::new(),
                writes: Vec::new(),
                read_error: None,
                read_zero: false,
                read_interrupted_once: false,
                interrupt_requested: false,
                interrupt_triggers: 0,
                write_error: None,
                write_partial: false,
                write_zero: false,
                entered_read: 0,
            }),
            Condvar::new(),
        ));
        (FakeTun { state: Arc::clone(&state) }, FakeHandle { state })
    }

    /// Test interrupt handle: mirrors `InterruptEvent::trigger` by latching
    /// `interrupt_requested` and waking the condvar so a parked
    /// `read_interruptible` returns `Interrupted` promptly.
    struct FakeInterrupt {
        state: Arc<(Mutex<FakeInner>, Condvar)>,
    }

    impl InterruptTrigger for FakeInterrupt {
        fn trigger(&self) {
            let (lock, cvar) = &*self.state;
            if let Ok(mut guard) = lock.lock() {
                guard.interrupt_requested = true;
                guard.interrupt_triggers = guard.interrupt_triggers.saturating_add(1);
            }
            cvar.notify_all();
        }
    }

    impl TunInterrupt for FakeTun {
        fn read_interruptible(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            // Barrier: record entry before checking any condition so the test
            // can observe "worker parked in read" deterministically.
            guard.entered_read = guard.entered_read.saturating_add(1);
            cvar.notify_all();
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(kind) = guard.read_error.take() {
                    return Err(io::Error::new(kind, "fake read error"));
                }
                if guard.read_zero {
                    guard.read_zero = false;
                    return Ok(0);
                }
                // tun-rs `InterruptEvent` wakeup: a clean signal, never a
                // terminal fault. The worker treats it as a wakeup and
                // re-checks shutdown/state.
                if guard.read_interrupted_once {
                    guard.read_interrupted_once = false;
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "fake interrupted"));
                }
                // Driver shutdown interrupt (latched by `FakeInterrupt` via
                // `interrupt_trigger`): persistent like a triggered event so
                // every parked read wakes promptly on shutdown/close/drop.
                if guard.interrupt_requested {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "fake interrupt"));
                }
                if let Some(packet) = guard.ingress.pop_front() {
                    if packet.len() > buf.len() {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "fake packet larger than buffer"));
                    }
                    buf[..packet.len()].copy_from_slice(&packet);
                    return Ok(packet.len());
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "fake no packet"));
                }
                let (next, _) = cvar
                    .wait_timeout(guard, deadline - now)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard = next;
            }
        }

        fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.writes.push(Bytes::copy_from_slice(packet));
            cvar.notify_all();
            if let Some(kind) = guard.write_error.take() {
                return Err(io::Error::new(kind, "fake write error"));
            }
            if guard.write_zero {
                guard.write_zero = false;
                return Ok(0);
            }
            if guard.write_partial {
                guard.write_partial = false;
                return Ok(packet.len().saturating_sub(1));
            }
            Ok(packet.len())
        }

        fn mtu(&self) -> u32 {
            1_500
        }

        fn name(&self) -> &str {
            "fake-tun"
        }

        fn interrupt_trigger(&self) -> Option<Arc<dyn InterruptTrigger>> {
            Some(Arc::new(FakeInterrupt { state: Arc::clone(&self.state) }))
        }
    }

    impl FakeHandle {
        fn lock(&self) -> std::sync::MutexGuard<'_, FakeInner> {
            self.state.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn push_ingress(&self, packet: Bytes) {
            self.lock().ingress.push_back(packet);
            self.state.1.notify_all();
        }

        fn set_read_error(&self, kind: io::ErrorKind) {
            self.lock().read_error = Some(kind);
            self.state.1.notify_all();
        }

        fn set_read_zero(&self) {
            self.lock().read_zero = true;
            self.state.1.notify_all();
        }

        fn set_read_interrupted_once(&self) {
            self.lock().read_interrupted_once = true;
            self.state.1.notify_all();
        }

        fn set_write_error(&self, kind: io::ErrorKind) {
            self.lock().write_error = Some(kind);
        }

        fn set_write_partial(&self) {
            self.lock().write_partial = true;
        }

        fn set_write_zero(&self) {
            self.lock().write_zero = true;
        }

        fn writes(&self) -> Vec<Bytes> {
            self.lock().writes.clone()
        }

        fn entered_read(&self) -> usize {
            self.lock().entered_read
        }

        fn interrupt_triggers(&self) -> usize {
            self.lock().interrupt_triggers
        }

        /// Barrier wait: returns once the worker has entered
        /// `read_interruptible` at least `count` times or the deadline
        /// passes. The worker notifies on every entry, so this needs no
        /// sleep-polling; the timeout is only a failure deadline.
        fn wait_entered_read(&self, count: usize, timeout: Duration) -> usize {
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let start = Instant::now();
            loop {
                if guard.entered_read >= count {
                    return guard.entered_read;
                }
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return guard.entered_read;
                }
                let (next, _) = cvar
                    .wait_timeout(guard, timeout - elapsed)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard = next;
            }
        }

        /// Event-driven wait: returns once `count` writes land or the
        /// deadline passes. No sleep-polling; the worker notifies per write.
        fn wait_writes(&self, count: usize, timeout: Duration) -> Vec<Bytes> {
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let start = Instant::now();
            loop {
                if guard.writes.len() >= count {
                    return guard.writes.clone();
                }
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return guard.writes.clone();
                }
                let (next, _) = cvar
                    .wait_timeout(guard, timeout - elapsed)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard = next;
            }
        }
    }

    fn test_config() -> DriverConfig {
        DriverConfig {
            poll_interval: Duration::from_millis(1),
            ..DriverConfig::default()
        }
    }

    /// Event-driven wait for a driver condition with a hard deadline.
    /// Yields instead of sleeping; returns false only on timeout.
    fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while !condition() {
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    #[test]
    fn invalid_bounds_are_rejected_before_the_thread_starts() {
        let (backend, _fake) = fake_pair();
        let mut bad = test_config();
        bad.ingress_max_packets = 0;
        assert!(matches!(
            DriverTun::spawn(backend, bad),
            Err(DriverError::InvalidConfig(_))
        ));

        let (backend, _fake) = fake_pair();
        let mut bad = test_config();
        bad.max_packet_bytes = 0;
        assert!(matches!(
            DriverTun::spawn(backend, bad),
            Err(DriverError::InvalidConfig(_))
        ));

        let (backend, _fake) = fake_pair();
        let mut bad = test_config();
        bad.egress_max_bytes_bulk = bad.max_packet_bytes - 1;
        assert!(matches!(
            DriverTun::spawn(backend, bad),
            Err(DriverError::InvalidConfig(_))
        ));

        let (backend, _fake) = fake_pair();
        let mut bad = test_config();
        bad.poll_interval = Duration::ZERO;
        assert!(matches!(
            DriverTun::spawn(backend, bad),
            Err(DriverError::InvalidConfig(_))
        ));
    }

    #[test]
    fn blocked_read_does_not_prevent_downlink_write() {
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        assert_eq!(driver.backend_name(), "fake-tun");
        assert_eq!(driver.backend_mtu(), 1_500);
        // Deterministic barrier: the worker is parked in its timed read
        // before the egress packet is enqueued, so the test proves a blocked
        // read does not prevent the downlink write without a timing guess.
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);

        // No ingress is ever injected: the worker stays inside its timed
        // read while this egress packet must still reach the backend.
        let payload = Bytes::from(vec![0x45; 64]);
        driver.send(TrafficClass::Bulk, payload.clone()).unwrap();
        let writes = fake.wait_writes(1, TEST_TIMEOUT);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0], payload);

        assert!(wait_for(TEST_TIMEOUT, || driver.metrics().egress_written_bulk == 1));
        let metrics = driver.metrics();
        assert_eq!(metrics.egress_enqueued_bulk, 1);
        assert_eq!(metrics.egress_written_bulk, 1);
        assert_eq!(metrics.bytes_written, 64);
        assert!(driver.failure().is_none());
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn shutdown_while_read_is_blocked_joins_without_hanging() {
        let (backend, _fake) = fake_pair();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        driver.shutdown();
        driver.shutdown();
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn read_error_is_a_durable_terminal_failure() {
        let (backend, fake) = fake_pair();
        fake.set_read_error(io::ErrorKind::ConnectionReset);
        let mut driver = DriverTun::spawn(backend, test_config()).unwrap();
        assert!(wait_for(TEST_TIMEOUT, || driver.failure().is_some()));

        let failure = driver.failure().unwrap();
        assert_eq!(failure.kind(), FailureKind::Read);
        assert_eq!(driver.metrics().read_errors, 1);

        // Durable: later data-path calls report the same terminal state.
        assert!(matches!(
            driver.send(TrafficClass::Bulk, Bytes::from_static(b"late")),
            Err(DriverError::Terminal { kind: FailureKind::Read, .. })
        ));
        assert!(matches!(
            driver.try_recv(),
            Err(DriverError::Terminal { kind: FailureKind::Read, .. })
        ));
        assert_eq!(driver.close().unwrap().unwrap().kind(), FailureKind::Read);
    }

    #[test]
    fn zero_length_read_is_a_terminal_failure() {
        let (backend, fake) = fake_pair();
        fake.set_read_zero();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        assert!(wait_for(TEST_TIMEOUT, || driver.failure().is_some()));
        let metrics = driver.metrics();
        assert_eq!(metrics.zero_reads, 1);
        assert_eq!(metrics.read_errors, 1);
        assert_eq!(driver.close().unwrap().unwrap().kind(), FailureKind::Read);
    }

    #[test]
    fn partial_write_is_a_terminal_failure() {
        let (backend, fake) = fake_pair();
        fake.set_write_partial();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        driver.send(TrafficClass::Bulk, Bytes::from(vec![0x45; 8])).unwrap();
        assert!(wait_for(TEST_TIMEOUT, || driver.failure().is_some()));

        let metrics = driver.metrics();
        assert_eq!(metrics.partial_writes, 1);
        assert_eq!(metrics.write_errors, 1);
        assert!(matches!(
            driver.send(TrafficClass::Bulk, Bytes::from_static(b"late")),
            Err(DriverError::Terminal { kind: FailureKind::Write, .. })
        ));
        assert_eq!(driver.close().unwrap().unwrap().kind(), FailureKind::Write);
    }

    #[test]
    fn zero_write_is_a_terminal_failure() {
        let (backend, fake) = fake_pair();
        fake.set_write_zero();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        driver.send(TrafficClass::Interactive, Bytes::from(vec![0x46; 8])).unwrap();
        assert!(wait_for(TEST_TIMEOUT, || driver.failure().is_some()));

        let metrics = driver.metrics();
        assert_eq!(metrics.zero_writes, 1);
        assert_eq!(metrics.write_errors, 1);
        assert_eq!(driver.close().unwrap().unwrap().kind(), FailureKind::Write);
    }

    #[test]
    fn write_error_is_a_terminal_failure() {
        let (backend, fake) = fake_pair();
        fake.set_write_error(io::ErrorKind::BrokenPipe);
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        driver.send(TrafficClass::Realtime, Bytes::from(vec![0x47; 8])).unwrap();
        assert!(wait_for(TEST_TIMEOUT, || driver.failure().is_some()));
        assert_eq!(driver.metrics().write_errors, 1);
        assert_eq!(driver.close().unwrap().unwrap().kind(), FailureKind::Write);
    }

    #[test]
    fn ingress_packet_limit_drops_deterministically() {
        let config = DriverConfig {
            ingress_max_packets: 2,
            ingress_max_bytes: 1_000_000,
            poll_interval: Duration::from_millis(1),
            ..DriverConfig::default()
        };
        let (backend, fake) = fake_pair();
        let mut driver = DriverTun::spawn(backend, config).unwrap();
        // The test never drains during injection, so the first two packets
        // fill the queue and the remaining three must drop on the count bound.
        for marker in 0..5u8 {
            fake.push_ingress(Bytes::from(vec![marker; 100]));
        }
        assert!(wait_for(TEST_TIMEOUT, || driver.metrics().ingress_received == 5));

        let metrics = driver.metrics();
        assert_eq!(metrics.ingress_received, 5);
        assert_eq!(metrics.ingress_delivered, 2);
        assert_eq!(metrics.ingress_dropped_packet_limit, 3);
        assert_eq!(metrics.ingress_dropped_byte_limit, 0);

        let first = driver.try_recv().unwrap().unwrap();
        let second = driver.try_recv().unwrap().unwrap();
        assert_eq!(first.len(), 100);
        assert_eq!(second.len(), 100);
        assert_eq!(first[0], 0);
        assert_eq!(second[0], 1);
        assert!(matches!(driver.try_recv(), Ok(None)));
        assert_eq!(driver.metrics().ingress_queue_packets, 0);
        assert_eq!(driver.metrics().ingress_queue_bytes, 0);
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn ingress_byte_limit_drops_deterministically() {
        let config = DriverConfig {
            max_packet_bytes: 100,
            ingress_max_packets: 64,
            ingress_max_bytes: 250,
            poll_interval: Duration::from_millis(1),
            ..DriverConfig::default()
        };
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, config).unwrap();
        for _ in 0..5 {
            fake.push_ingress(Bytes::from(vec![0x45; 100]));
        }
        assert!(wait_for(TEST_TIMEOUT, || driver.metrics().ingress_received == 5));

        // 200 of 250 bytes fit; every further 100-byte packet exceeds the
        // byte bound while the queue stays undrained.
        let metrics = driver.metrics();
        assert_eq!(metrics.ingress_received, 5);
        assert_eq!(metrics.ingress_delivered, 2);
        assert_eq!(metrics.ingress_dropped_byte_limit, 3);
        assert_eq!(metrics.ingress_dropped_packet_limit, 0);
        assert_eq!(metrics.ingress_queue_bytes, 200);
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn oversize_and_empty_packets_are_rejected_on_both_directions() {
        let config = DriverConfig {
            max_packet_bytes: 100,
            poll_interval: Duration::from_millis(1),
            ..DriverConfig::default()
        };
        let (backend, fake) = fake_pair();
        let mut driver = DriverTun::spawn(backend, config).unwrap();

        let big = Bytes::from(vec![0x45; 200]);
        assert!(matches!(
            driver.send(TrafficClass::Bulk, big),
            Err(DriverError::Oversize { length: 200, limit: 100 })
        ));
        assert!(matches!(
            driver.send(TrafficClass::Bulk, Bytes::new()),
            Err(DriverError::EmptyPacket)
        ));
        let metrics = driver.metrics();
        assert_eq!(metrics.egress_dropped_oversize, 1);
        assert_eq!(metrics.egress_empty_rejected, 1);
        // Rejected before queuing: the backend never sees a write.
        assert!(fake.writes().is_empty());

        fake.push_ingress(Bytes::from(vec![0x46; 200]));
        assert!(wait_for(TEST_TIMEOUT, || driver.metrics().ingress_received == 1));
        let metrics = driver.metrics();
        assert_eq!(metrics.ingress_delivered, 0);
        assert_eq!(metrics.ingress_dropped_oversize, 1);
        assert!(matches!(driver.try_recv(), Ok(None)));
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn control_traffic_is_rejected_before_queuing() {
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        assert!(matches!(
            driver.send(TrafficClass::Control, Bytes::from_static(b"ctrl")),
            Err(DriverError::ControlRejected)
        ));
        let metrics = driver.metrics();
        assert_eq!(metrics.egress_control_rejected, 1);
        assert_eq!(metrics.egress_enqueued_realtime, 0);
        assert_eq!(metrics.egress_enqueued_interactive, 0);
        assert_eq!(metrics.egress_enqueued_bulk, 0);
        assert!(fake.writes().is_empty());
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn per_class_egress_limits_isolate_and_all_classes_deliver() {
        // Deterministic schedule: the worker is parked in its timed read
        // (barrier via `entered_read`) while all three queues are pre-filled,
        // so the next pass emits the fixed scheduled order exactly.
        let config = DriverConfig {
            egress_max_packets_realtime: 1,
            egress_max_packets_interactive: 1,
            egress_max_packets_bulk: 1,
            poll_interval: Duration::from_millis(50),
            ..DriverConfig::default()
        };
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, config).unwrap();
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);

        let realtime = Bytes::from(vec![0x01; 8]);
        let interactive = Bytes::from(vec![0x02; 8]);
        let bulk = Bytes::from(vec![0x03; 8]);
        driver.send(TrafficClass::Bulk, bulk.clone()).unwrap();
        // A saturated Bulk queue rejects further Bulk packets but still
        // admits the other classes: quotas are isolated, not shared.
        assert!(matches!(
            driver.send(TrafficClass::Bulk, bulk.clone()),
            Err(DriverError::EgressPacketLimit { class: TrafficClass::Bulk })
        ));
        driver.send(TrafficClass::Realtime, realtime.clone()).unwrap();
        driver.send(TrafficClass::Interactive, interactive.clone()).unwrap();
        assert!(matches!(
            driver.send(TrafficClass::Realtime, realtime.clone()),
            Err(DriverError::EgressPacketLimit { class: TrafficClass::Realtime })
        ));

        // Exact scheduled order, no sorting and no timing claim: the queues
        // were full before the next pass started.
        let writes = fake.wait_writes(3, TEST_TIMEOUT);
        assert_eq!(writes, vec![realtime, interactive, bulk]);

        // `wait_writes` wakes on the backend push, which precedes the
        // worker's `egress_written` increment: wait for the counters
        // event-driven instead of asserting a racing snapshot.
        assert!(wait_for(TEST_TIMEOUT, || {
            let metrics = driver.metrics();
            metrics.egress_written_realtime == 1
                && metrics.egress_written_interactive == 1
                && metrics.egress_written_bulk == 1
        }));

        let metrics = driver.metrics();
        assert_eq!(metrics.egress_written_realtime, 1);
        assert_eq!(metrics.egress_written_interactive, 1);
        assert_eq!(metrics.egress_written_bulk, 1);
        assert_eq!(metrics.egress_dropped_packet_realtime, 1);
        assert_eq!(metrics.egress_dropped_packet_bulk, 1);
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn bulk_flood_does_not_starve_other_classes() {
        // Same barrier: pre-fill while parked, then assert the exact
        // interleaving. Fixed schedule `Realtime -> Interactive -> Bulk`
        // takes one packet per non-empty class per pass.
        let config = DriverConfig {
            poll_interval: Duration::from_millis(50),
            ..DriverConfig::default()
        };
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, config).unwrap();
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);
        for _ in 0..8 {
            driver.send(TrafficClass::Bulk, Bytes::from(vec![0x03; 16])).unwrap();
        }
        driver.send(TrafficClass::Realtime, Bytes::from(vec![0x01; 16])).unwrap();
        driver.send(TrafficClass::Realtime, Bytes::from(vec![0x01; 16])).unwrap();

        let writes = fake.wait_writes(10, TEST_TIMEOUT);
        assert_eq!(writes.len(), 10);
        let markers: Vec<u8> = writes.iter().map(|packet| packet[0]).collect();
        assert_eq!(
            markers,
            vec![0x01, 0x03, 0x01, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03],
            "fixed schedule must interleave Realtime first without starving Bulk"
        );

        assert!(wait_for(TEST_TIMEOUT, || {
            let metrics = driver.metrics();
            metrics.egress_written_realtime == 2 && metrics.egress_written_bulk == 8
        }));
        let metrics = driver.metrics();
        assert_eq!(metrics.egress_written_realtime, 2);
        assert_eq!(metrics.egress_written_bulk, 8);
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn egress_byte_limit_drops_deterministically_per_class() {
        let config = DriverConfig {
            egress_max_bytes_bulk: 100,
            max_packet_bytes: 100,
            poll_interval: Duration::from_millis(1),
            ..DriverConfig::default()
        };
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, config).unwrap();
        // 60 + 60 = 120 > 100, so the second Bulk packet drops on bytes
        // while Realtime keeps its own independent byte budget.
        driver.send(TrafficClass::Bulk, Bytes::from(vec![0x03; 60])).unwrap();
        assert!(matches!(
            driver.send(TrafficClass::Bulk, Bytes::from(vec![0x03; 60])),
            Err(DriverError::EgressByteLimit { class: TrafficClass::Bulk })
        ));
        driver.send(TrafficClass::Realtime, Bytes::from(vec![0x01; 60])).unwrap();

        let writes = fake.wait_writes(2, TEST_TIMEOUT);
        assert_eq!(writes.len(), 2);
        assert!(wait_for(TEST_TIMEOUT, || {
            let metrics = driver.metrics();
            metrics.egress_written_bulk == 1 && metrics.egress_written_realtime == 1
        }));
        let metrics = driver.metrics();
        assert_eq!(metrics.egress_dropped_byte_bulk, 1);
        assert_eq!(metrics.egress_dropped_byte_realtime, 0);
        assert!(driver.close().unwrap().is_none());
    }

    #[tokio::test]
    async fn async_recv_delivers_ingress_packets() {
        let (backend, fake) = fake_pair();
        let mut driver = DriverTun::spawn(backend, test_config()).unwrap();
        let payload = Bytes::from(vec![0x47; 32]);
        fake.push_ingress(payload.clone());
        let received = tokio::time::timeout(TEST_TIMEOUT, driver.recv())
            .await
            .expect("ingress recv deadline")
            .unwrap()
            .unwrap();
        assert_eq!(received, payload);
        assert_eq!(driver.metrics().ingress_queue_packets, 0);
        assert!(driver.close().unwrap().is_none());
    }

    #[tokio::test]
    async fn async_recv_reports_terminal_failure_instead_of_hanging() {
        let (backend, fake) = fake_pair();
        fake.set_read_error(io::ErrorKind::ConnectionAborted);
        let mut driver = DriverTun::spawn(backend, test_config()).unwrap();
        let outcome = tokio::time::timeout(TEST_TIMEOUT, driver.recv())
            .await
            .expect("terminal recv deadline");
        assert!(matches!(
            outcome,
            Err(DriverError::Terminal { kind: FailureKind::Read, .. })
        ));
        assert!(driver.close().unwrap().is_some());
    }

    #[test]
    fn ingress_is_single_raw_fifo_without_classification() {
        // Approved V2 architecture: the OS delivers raw IP packets with no
        // traffic-class tag, so the driver keeps exactly one raw ingress FIFO.
        // Overflow drops the newest arriving packet (count bound here); there
        // is no per-class ingress queue, bound, or metric by design.
        let config = DriverConfig {
            ingress_max_packets: 2,
            ingress_max_bytes: 1_000_000,
            poll_interval: Duration::from_millis(50),
            ..DriverConfig::default()
        };
        let (backend, fake) = fake_pair();
        let mut driver = DriverTun::spawn(backend, config).unwrap();
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);
        for marker in 0..5u8 {
            fake.push_ingress(Bytes::from(vec![marker; 32]));
        }
        assert!(wait_for(TEST_TIMEOUT, || driver.metrics().ingress_received == 5));

        let metrics = driver.metrics();
        assert_eq!(metrics.ingress_received, 5);
        assert_eq!(metrics.ingress_delivered, 2);
        assert_eq!(metrics.ingress_dropped_packet_limit, 3);
        // FIFO: the first two arrivals survive, the three newest drop.
        let first = driver.try_recv().unwrap().unwrap();
        let second = driver.try_recv().unwrap().unwrap();
        assert_eq!((first[0], second[0]), (0, 1));
        assert!(matches!(driver.try_recv(), Ok(None)));
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn interrupted_read_is_a_clean_wakeup_not_a_terminal_failure() {
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);
        // One tun-rs `InterruptEvent` wakeup must not poison the driver.
        fake.set_read_interrupted_once();
        assert!(wait_for(TEST_TIMEOUT, || fake.entered_read() >= 2));
        assert!(driver.failure().is_none());

        // The driver still forwards data after the wakeup.
        driver.send(TrafficClass::Bulk, Bytes::from(vec![0x45; 16])).unwrap();
        let writes = fake.wait_writes(1, TEST_TIMEOUT);
        assert_eq!(writes.len(), 1);
        assert!(driver.close().unwrap().is_none());
    }

    #[test]
    fn drop_without_close_records_durable_join_required() {
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        let sender = driver.sender();
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);
        // Explicit-close ownership violated: drop without `close`.
        drop(driver);
        assert!(wait_for(TEST_TIMEOUT, || sender.failure().is_some()));

        let failure = sender.failure().unwrap();
        assert_eq!(failure.kind(), FailureKind::JoinRequired);
        assert!(matches!(
            sender.send(TrafficClass::Bulk, Bytes::from_static(b"late")),
            Err(DriverError::Terminal { kind: FailureKind::JoinRequired, .. })
        ));
        // The detached worker was signalled and exits on its next poll slice;
        // the supervisor must treat `JoinRequired` as fatal, never as clean.
    }

    #[tokio::test]
    async fn close_async_joins_and_reports_terminal_failure() {
        // Clean path: `close_async` joins without blocking the runtime.
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        driver.send(TrafficClass::Realtime, Bytes::from(vec![0x01; 8])).unwrap();
        assert_eq!(fake.wait_writes(1, TEST_TIMEOUT).len(), 1);
        assert!(driver.close_async().await.unwrap().is_none());

        // Failure path: a poisoned driver still joins and hands the failure
        // to the supervisor through the async close.
        let (backend, fake) = fake_pair();
        fake.set_read_error(io::ErrorKind::ConnectionReset);
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        assert!(wait_for(TEST_TIMEOUT, || driver.failure().is_some()));
        let outcome = driver.close_async().await.unwrap().unwrap();
        assert_eq!(outcome.kind(), FailureKind::Read);
    }

    #[test]
    fn shutdown_fires_the_interrupt_handle_and_joins_promptly() {
        // Long poll slice: without an actual trigger, `close` would wait out
        // the full slice. With the interrupt handle it must join promptly.
        let config = DriverConfig {
            poll_interval: Duration::from_secs(5),
            ..DriverConfig::default()
        };
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, config).unwrap();
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);

        // `shutdown` alone must fire the interrupt (best-effort wakeup).
        driver.shutdown();
        assert!(wait_for(TEST_TIMEOUT, || fake.interrupt_triggers() >= 1));
        assert!(driver.failure().is_none());

        // `close` fires it again and joins far ahead of the 5s slice.
        let start = Instant::now();
        assert!(driver.close().unwrap().is_none());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "close must join via the interrupt, not the poll timeout"
        );
        assert!(fake.interrupt_triggers() >= 2);
    }

    #[test]
    fn drop_without_close_fires_the_interrupt_handle() {
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        let sender = driver.sender();
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);
        drop(driver);
        assert!(wait_for(TEST_TIMEOUT, || sender.failure().is_some()));
        assert_eq!(sender.failure().unwrap().kind(), FailureKind::JoinRequired);
        // The detached worker was woken via the interrupt, not left parked
        // until its next poll slice.
        assert!(wait_for(TEST_TIMEOUT, || fake.interrupt_triggers() >= 1));
    }

    #[tokio::test]
    async fn terminal_signal_fires_on_read_fault_and_late_subscribers_see_it() {
        let (backend, fake) = fake_pair();
        fake.set_read_error(io::ErrorKind::ConnectionReset);
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        // Event-driven: no `wait_for(failure().is_some())` polling. The watch
        // signal resolves, then the stored failure is returned.
        let failure = tokio::time::timeout(TEST_TIMEOUT, driver.await_terminal())
            .await
            .expect("terminal signal deadline");
        assert_eq!(failure.kind(), FailureKind::Read);
        assert!(driver.is_terminal_signalled());
        assert!(driver.sender().is_terminal_signalled());

        // Coalescing: a late subscriber observes the same stored `true`
        // immediately instead of hanging.
        let mut late = driver.subscribe_terminal();
        let observed = tokio::time::timeout(TEST_TIMEOUT, late.wait_for(|ready| *ready))
            .await
            .expect("late terminal subscriber deadline")
            .expect("terminal watch stays open while the driver is owned");
        assert!(*observed);
        assert_eq!(driver.close().unwrap().unwrap().kind(), FailureKind::Read);
    }

    #[tokio::test]
    async fn clean_shutdown_never_signals_terminal() {
        let (backend, fake) = fake_pair();
        let driver = DriverTun::spawn(backend, test_config()).unwrap();
        assert_eq!(fake.wait_entered_read(1, TEST_TIMEOUT), 1);
        let sender = driver.sender();
        let late_before_close = sender.subscribe_terminal();
        assert!(!*late_before_close.borrow());
        assert!(driver.close_async().await.unwrap().is_none());
        // No terminal was ever published; the shared signal stays `false`
        // (observed via the sender clone that outlives the closed owner).
        assert!(!sender.is_terminal_signalled());
        assert!(sender.failure().is_none());
    }
}
