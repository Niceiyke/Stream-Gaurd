//! Production V2 gateway setup: autonomous expiry ownership (REBUILD WP-400).
//!
//! Owns the shared [`AddressPool`], the authoritative [`V2SessionManager`],
//! one monotonic [`Clock`] domain, and both supervised sweeps
//! ([`SupervisedSessionSweep`] plus [`SupervisedPoolSweep`] with autonomous
//! session close). This is the production entry point that guarantees expiry
//! without listener traffic: after construction both sweep tasks run on their
//! capacity-1 tick channels, and after [`V2GatewaySetup::stop`] both tasks
//! are joined. Dropping the setup aborts both tasks via the owned sweeps.
//!
//! The listener keeps its opportunistic per-accept/per-control sweeps as a
//! fast path (free capacity before admission), but production must hold this
//! setup alongside the listener: build the [`AdmissionHandler`] from
//! [`V2GatewaySetup::sessions`], build [`V2AdmissionListenerSetup`] from
//! [`V2GatewaySetup::pool`] plus that handler, and keep the setup alive for
//! the listener lifetime. An expired lease then closes its session
//! autonomously even with no new admission or control traffic.
//!
//! This module never touches V1 `main.rs` or `tunnel.rs`.
//!
//! Bounds: exactly two supervised tasks (one session ticker plus one session
//! sweep, one pool ticker plus one pool sweep), one shared clock, no
//! additional collections, channels, or tasks. Pool I/O runs on the bounded
//! blocking pool inside [`SupervisedPoolSweep`]; no lock crosses an await.

use std::sync::Arc;

use super::address_pool::{AddressPool, PoolSweepConfig, PoolSweepMetrics, SupervisedPoolSweep};
use super::session_manager::{
    Clock, MonotonicClock, SessionSweepConfig, SupervisedSessionSweep, SweepMetrics,
    V2SessionManager,
};

/// Final metrics from [`V2GatewaySetup::stop`], one snapshot per owned sweep.
#[derive(Debug)]
pub struct V2GatewaySetupMetrics {
    /// Session-sweep outcome (sweeps completed, sessions reaped, queue drops).
    pub session: SweepMetrics,
    /// Pool-sweep outcome (sweeps completed, leases expired, sessions closed).
    pub pool: PoolSweepMetrics,
}

/// Production owner for V2 gateway expiry. Constructed with the shared pool
/// and session manager so the listener, engine, and sweeps resolve against
/// one address and session map.
pub struct V2GatewaySetup {
    pool: Arc<AddressPool>,
    sessions: Arc<V2SessionManager>,
    clock: Arc<dyn Clock>,
    session_sweep: SupervisedSessionSweep,
    pool_sweep: SupervisedPoolSweep,
}

impl V2GatewaySetup {
    /// Starts autonomous expiry with a fresh production [`MonotonicClock`].
    ///
    /// Spawns the session sweep (`session_config` ticker) and the pool sweep
    /// with autonomous session close (`pool_config` ticker) on the shared
    /// clock. Must be called inside a Tokio runtime (both sweeps spawn
    /// ticker plus worker tasks). The caller owns the returned setup;
    /// dropping it aborts both sweep tasks; call [`stop`](Self::stop) to join.
    #[must_use]
    pub fn start(
        pool: Arc<AddressPool>,
        sessions: Arc<V2SessionManager>,
        session_config: SessionSweepConfig,
        pool_config: PoolSweepConfig,
    ) -> Self {
        let clock: Arc<MonotonicClock> = Arc::new(MonotonicClock::new());
        Self::start_with_clock(pool, sessions, session_config, pool_config, clock)
    }

    /// Starts autonomous expiry on an injected clock domain.
    ///
    /// Production passes a [`MonotonicClock`]; tests pass a controllable
    /// [`Clock`] and advance it while the production tickers fire. Both
    /// sweeps share the same `clock` value so TTL state uses one monotonic
    /// domain. The pool sweep is always spawned with sessions attached, so
    /// expired leases close their sessions autonomously (idempotent).
    pub fn start_with_clock<C>(
        pool: Arc<AddressPool>,
        sessions: Arc<V2SessionManager>,
        session_config: SessionSweepConfig,
        pool_config: PoolSweepConfig,
        clock: Arc<C>,
    ) -> Self
    where
        C: Clock + 'static,
    {
        let clock_dyn: Arc<dyn Clock> = clock;
        let session_sweep = SupervisedSessionSweep::spawn(
            Arc::clone(&sessions),
            session_config,
            Arc::clone(&clock_dyn),
        );
        let pool_sweep = SupervisedPoolSweep::spawn_with_sessions(
            Arc::clone(&pool),
            Arc::clone(&sessions),
            pool_config,
            Arc::clone(&clock_dyn),
        );
        Self {
            pool,
            sessions,
            clock: clock_dyn,
            session_sweep,
            pool_sweep,
        }
    }

    /// Deterministic test constructor: both sweeps run without production
    /// tickers and advance only via the returned manual trigger handles, each
    /// of which awaits a completion ack (no sleeps, no polling). Tests advance
    /// both clocks together and tick the pool sweep (which expires leases and
    /// closes sessions autonomously) then the session sweep, mirroring the
    /// production expiry order. The setup clock domain is the session clock;
    /// both test clocks must be advanced together to keep one monotonic domain.
    #[cfg(test)]
    pub fn start_with_manual(
        pool: Arc<AddressPool>,
        sessions: Arc<V2SessionManager>,
        session_config: SessionSweepConfig,
        pool_config: PoolSweepConfig,
        session_clock: Arc<super::session_manager::test_support::ManualClock>,
        pool_clock: Arc<super::address_pool::test_support::PoolManualClock>,
    ) -> (
        Self,
        super::session_manager::test_support::ManualTriggerHandle,
        super::address_pool::test_support::PoolManualTriggerHandle,
    ) {
        let (session_sweep, session_trigger) = super::session_manager::SupervisedSessionSweep::spawn_with_manual(
            Arc::clone(&sessions),
            session_config,
            Arc::clone(&session_clock),
        );
        let (pool_sweep, pool_trigger) =
            super::address_pool::SupervisedPoolSweep::spawn_with_manual_and_sessions(
                Arc::clone(&pool),
                Arc::clone(&sessions),
                pool_config,
                Arc::clone(&pool_clock),
            );
        let clock_dyn: Arc<dyn Clock> = session_clock;
        (
            Self {
                pool,
                sessions,
                clock: clock_dyn,
                session_sweep,
                pool_sweep,
            },
            session_trigger,
            pool_trigger,
        )
    }

    /// Gracefully stops both supervised sweeps and returns their final
    /// metrics. Aborts both production tickers first (no new ticks), then
    /// joins both sweep tasks. Idempotent: a second call returns the same
    /// snapshots without hanging.
    pub async fn stop(&mut self) -> V2GatewaySetupMetrics {
        let pool = self.pool_sweep.stop().await;
        let session = self.session_sweep.stop().await;
        V2GatewaySetupMetrics { session, pool }
    }

    /// Shared address pool. Build the V2 listener setup from this `Arc` so
    /// admission reserves and the autonomous sweep resolve one lease map.
    #[must_use]
    pub fn pool(&self) -> &Arc<AddressPool> {
        &self.pool
    }

    /// Authoritative session map. Build the admission handler from this
    /// `Arc` so admission commits and the autonomous sweeps resolve one map.
    #[must_use]
    pub fn sessions(&self) -> &Arc<V2SessionManager> {
        &self.sessions
    }

    /// Shared monotonic clock for TTL state. The admission listener derives
    /// [`AdmissionTime`](super::admission::AdmissionTime) from this domain.
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Snapshot of the authoritative session map.
    #[must_use]
    pub fn session_snapshot(&self) -> super::session_manager::V2SessionManagerSnapshot {
        self.sessions.snapshot()
    }

    /// Snapshot of the shared address pool.
    #[must_use]
    pub fn pool_snapshot(&self) -> super::address_pool::AddressPoolSnapshot {
        self.pool.snapshot()
    }

    /// Current session-sweep metrics snapshot.
    #[must_use]
    pub fn session_sweep_metrics(&self) -> SweepMetrics {
        self.session_sweep.metrics_snapshot()
    }

    /// Current pool-sweep metrics snapshot.
    #[must_use]
    pub fn pool_sweep_metrics(&self) -> PoolSweepMetrics {
        self.pool_sweep.metrics_snapshot()
    }
}

impl std::fmt::Debug for V2GatewaySetup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2GatewaySetup(REDACTED)")
    }
}

// Dropping aborts both supervised tasks via the owned sweeps' `Drop`
// (ticker plus worker for each). No join happens here by construction;
// call `stop` for a clean join. This mirrors `V2GatewayLifecycle` and
// `V2GatewayEngine` ownership: a live setup dropped without `stop` still
// cannot leak tasks.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::address_pool::AddressPoolConfig;
    use crate::v2::session_manager::V2SessionManagerConfig;
    use sg_auth::ticket::OrganizationId;
    use sg_core::v2::{DeviceId, SessionId};

    fn pool_config() -> AddressPoolConfig {
        AddressPoolConfig::new(
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
        .unwrap()
    }

    fn session_config() -> V2SessionManagerConfig {
        V2SessionManagerConfig {
            maximum_sessions: 4,
            idle_ttl_ms: 120_000,
            maximum_paths_per_session: 1,
            maximum_pending_attaches: 1,
            pending_attach_ttl_ms: 5_000,
            maximum_path_epoch_history: 4,
            maximum_path_tombstones: 1,
            path_tombstone_ttl_ms: 5_000,
        }
    }

    #[tokio::test]
    async fn setup_spawns_pool_sweep_and_expires_autonomously_without_direct_sweep() {
        // The session outlives the pool lease on purpose (idle 120 s vs lease
        // 60 s), so only the autonomous pool sweep can close it. The test
        // never calls `pool.sweep`, `sessions.sweep`, or `sweep_async`
        // directly and never sleeps or polls: expiry arrives solely through
        // the setup-owned supervised tasks driven by deterministic manual
        // trigger/ack handles.
        use crate::v2::address_pool::test_support::PoolManualClock;
        use crate::v2::session_manager::test_support::ManualClock;

        let pool = Arc::new(AddressPool::new(pool_config()).unwrap());
        let sessions = Arc::new(
            V2SessionManager::with_cleanup(
                session_config(),
                vec![Arc::clone(&pool) as Arc<dyn crate::v2::session_manager::SessionCleanup>],
            )
            .unwrap(),
        );
        let session_clock = Arc::new(ManualClock::new(1_000));
        let pool_clock = Arc::new(PoolManualClock::new(1_000));
        let session_sweep = SessionSweepConfig::fixed(5).unwrap();
        let pool_sweep = PoolSweepConfig::fixed(5).unwrap();
        let (mut setup, session_trigger, pool_trigger) = V2GatewaySetup::start_with_manual(
            Arc::clone(&pool),
            Arc::clone(&sessions),
            session_sweep,
            pool_sweep,
            Arc::clone(&session_clock),
            Arc::clone(&pool_clock),
        );
        // Setup owns the exact maps the listener must use.
        assert!(Arc::ptr_eq(setup.pool(), &pool));
        assert!(Arc::ptr_eq(setup.sessions(), &sessions));

        let session_id = SessionId::from_bytes([71; 16]);
        let device_id = DeviceId::from_bytes([72; 16]);
        let reservation = sessions
            .reserve_admission(
                session_id,
                device_id,
                OrganizationId::from_bytes([73; 16]),
                1_000_000,
                1_000,
            )
            .unwrap();
        pool.reserve(session_id, device_id, 1_000).unwrap();
        sessions.commit_admission(reservation, 1_000).unwrap();
        pool.commit(session_id, 1_000).unwrap();
        assert!(pool.lookup_active(session_id).is_some());
        assert_eq!(sessions.snapshot().sessions, 1);

        // Jump both deterministic clocks past the 60 s lease TTL, then drive
        // expiry with manual trigger/ack (no production ticker, no sleep, no
        // poll). The pool tick expires the lease and closes the session
        // idempotently; the session tick reaps deterministically. Each tick
        // awaits its completion ack, so every assertion below is ordered.
        const EXPIRED_MS: u64 = 1_000 + 60_000;
        pool_trigger.advance_and_tick(EXPIRED_MS).await;
        session_trigger.advance_and_tick(EXPIRED_MS).await;
        assert!(pool.lookup(session_id).is_none());
        assert!(pool.lookup_active(session_id).is_none());
        assert_eq!(setup.session_snapshot().sessions, 0);
        assert_eq!(setup.pool_snapshot().active, 0);
        assert!(setup.pool_sweep_metrics().sweeps_completed() >= 1);
        assert_eq!(setup.pool_sweep_metrics().leases_expired(), 1);
        assert_eq!(setup.pool_sweep_metrics().sessions_closed(), 1);

        // Explicit shutdown joins both supervised tasks; idempotent.
        let first = setup.stop().await;
        assert_eq!(first.pool.leases_expired(), 1);
        assert_eq!(first.pool.sessions_closed(), 1);
        let second = setup.stop().await;
        assert_eq!(second.pool.sweeps_completed(), first.pool.sweeps_completed());
        assert_eq!(second.session.sweeps_completed(), first.session.sweeps_completed());
    }

    #[tokio::test]
    async fn setup_production_start_stops_without_hanging() {
        // Production clock path: both tickers spawn and `stop` joins them
        // promptly without any session or lease state.
        let pool = Arc::new(AddressPool::new(pool_config()).unwrap());
        let sessions = Arc::new(
            V2SessionManager::with_cleanup(
                session_config(),
                vec![Arc::clone(&pool) as Arc<dyn crate::v2::session_manager::SessionCleanup>],
            )
            .unwrap(),
        );
        let mut setup = V2GatewaySetup::start(
            pool,
            sessions,
            SessionSweepConfig::fixed(10).unwrap(),
            PoolSweepConfig::fixed(10).unwrap(),
        );
        let metrics = setup.stop().await;
        let _ = metrics.session.sweeps_completed();
        let _ = metrics.pool.sweeps_completed();
        let second = setup.stop().await;
        assert_eq!(
            second.session.sweeps_completed(),
            metrics.session.sweeps_completed()
        );
        assert_eq!(second.pool.sweeps_completed(), metrics.pool.sweeps_completed());
    }
}
