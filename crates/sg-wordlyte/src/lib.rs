//! Wordlyte Pro integration SDK (engineering step 16 scaffold, spec §21 /
//! spec §28 row 16 / spec §22.5).
//!
//! Wordlyte Pro — an external marginal application — displays StreamGuard
//! status via the engine's *stable local API / IPC interface* (spec §21).
//! This crate is the stable, documented, compilable, testable client SDK that
//! any external app consumes; it does **not** bundle the Wordlyte Pro binary
//! (that is an external product) and it does **not** modify the engine.
//!
//! ## Spec §21 — the data set
//!
//! [`WordlyteStatus`] is the flat, versioned, `snake_case` contract faithful
//! to the data spec §21 enumerates for Wordlyte: protection enabled, active
//! paths, path quality, gateway status, aggregate available bandwidth,
//! current mode and warnings. It is `Serializable`/`Deserializable` and leaks
//! **no engine internals** — Wordlyte sees a clean projection of the
//! engine's `StatusSnapshot`, never the raw `Counters`/`Shared` plumbing.
//!
//! ## Spec §22.5 — IPC placement (UI/service separate process)
//!
//! The engine's status plane (`apps/streamguard-service`, engineering step
//! 12) runs as a separate, privileged process and publishes
//! `StatusSnapshot`s over an *authenticated* loopback transport — a Windows
//! named pipe or loopback TCP (spec §22.5 "UI and service are separate
//! processes"). The SDK connects through that **same authenticated channel**:
//! every request completes an HMAC-SHA256 challenge-response bound to the
//! session token and the 4-byte session prefix, exactly as the engine's
//! `StatusClient` does. Transport selection (pipe vs. TCP) is decided by the
//! engine endpoint the SDK addresses; this crate adds **no
//! platform-specific dependencies**.
//!
//! ## Spec §28 row 16 — "Wordlyte displays StreamGuard status via IPC API"
//!
//! [`WordlyteClient`] is the thin, bounded wrapper: `status()` opens a fresh
//! authenticated connection per call and reconnects with a bounded retry on
//! the per-connection quota close (mirroring the desktop shell's
//! `RETRY_ATTEMPTS`/`RETRY_BACKOFF`, spec §22.5 worker-pool semantics).
//!
//! # Errors
//!
//! All fallible APIs return [`sg_core::error::Result`]. Authentication
//! failures surface as [`sg_core::error::Error::Auth`]; transport/connect
//! failures as [`sg_core::error::Error::Transport`].

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use streamguard_service::ipc::{StatusClient, StatusEndpoint};
use streamguard_service::status::{Mode, StatusSnapshot};

use sg_core::error::{Error, Result};

/// Bounded reconnect attempts on the per-connection snapshot quota close
/// (spec §22.5 worker-pool semantics: each connection serves a capped number
/// of snapshots, then the server closes). Mirrors the desktop shell's knobs.
const RETRY_ATTEMPTS: usize = 2;
/// Backoff between reconnect attempts.
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Version marker for the stable v1 Wordlyte contract. Bumped only on an
/// incompatible wire change (see crate docs, spec §21).
const API_VERSION: &str = "1";

/// Per-path quality row of the Wordlyte status table (spec §21 "path
/// quality"), as a clean external projection with no engine types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WordlytePathQuality {
    /// Physical path id within the session (0-255).
    pub path_id: u8,
    /// Whether the path is currently reachable.
    pub reachable: bool,
    /// Round-trip time in milliseconds.
    pub rtt_ms: u32,
    /// Loss ratio as a percentage (0..=100), derived from `loss * 100`.
    pub loss_percent: u16,
    /// Jitter in milliseconds.
    pub jitter_ms: u32,
    /// Available bandwidth share of this path in kbps.
    pub available_kbps: u32,
    /// How long the path has been stably up, in seconds.
    pub stability_secs: u64,
}

impl From<&streamguard_service::status::PathStatus> for WordlytePathQuality {
    fn from(p: &streamguard_service::status::PathStatus) -> Self {
        Self {
            // status.rs `PathStatus.path_id`.
            path_id: p.path_id,
            // status.rs `PathStatus.reachable`.
            reachable: p.reachable,
            // status.rs `PathStatus.rtt_ms`.
            rtt_ms: p.rtt_ms,
            // status.rs `PathStatus.loss` is a ratio 0.0..=1.0; Wordlyte
            // wants a percentage (loss * 100).
            loss_percent: (p.loss * 100.0).round().clamp(0.0, 100.0) as u16,
            // status.rs `PathStatus.jitter_ms`.
            jitter_ms: p.jitter_ms,
            // status.rs `PathStatus.available_kbps`.
            available_kbps: p.available_kbps,
            // status.rs `PathStatus.stability_secs`.
            stability_secs: p.stability_secs,
        }
    }
}

/// The stable v1 Wordlyte status contract (spec §21): a flat, `snake_case`,
/// versioned projection of the engine's `StatusSnapshot` with no engine
/// internals. Exactly the data spec §21 lists for Wordlyte to display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WordlyteStatus {
    /// Spec §21 "protection enabled": true while at least one eligible path
    /// is live and carrying traffic.
    pub protection_enabled: bool,
    /// Spec §21 "current mode": one of `"single_path"`, `"active_standby"`,
    /// `"bonding"`.
    pub mode: String,
    /// Downlink path the gateway was last steered to (spec §21 "active
    /// paths").
    pub active_path: Option<u8>,
    /// Spec §21 "gateway status": whether the gateway session is present.
    /// The status plane carries no dedicated gateway bit, so this derives
    /// from the presence of at least one bound path.
    pub gateway_connected: bool,
    /// Spec §21 "aggregate available bandwidth" over eligible paths (kbps).
    pub aggregate_available_kbps: u32,
    /// Spec §21 "active paths": ids of all bound paths currently reachable.
    pub active_paths: Vec<u8>,
    /// Spec §21 "path quality": one row per bound path, sorted by id.
    pub path_quality: Vec<WordlytePathQuality>,
    /// Spec §21 "warnings": human-readable degradation / state warnings.
    pub warnings: Vec<String>,
}

impl WordlyteStatus {
    /// The version of this contract (see crate docs). Exposed for a marginal
    /// app to pin its expectation against on the wire / in a stored blob.
    pub fn api_version() -> &'static str {
        API_VERSION
    }
}

impl From<&StatusSnapshot> for WordlyteStatus {
    fn from(snap: &StatusSnapshot) -> Self {
        let mode = match snap.mode {
            Mode::SinglePath => "single_path",
            Mode::ActiveStandby => "active_standby",
            Mode::Bonding => "bonding",
        };
        // "Active paths" = every bound path currently reachable.
        let active_paths = snap
            .paths
            .iter()
            .filter(|p| p.reachable)
            .map(|p| p.path_id)
            .collect::<Vec<_>>();
        Self {
            // status.rs `StatusSnapshot.protecting`.
            protection_enabled: snap.protecting,
            // status.rs `StatusSnapshot.mode`.
            mode: mode.to_string(),
            // status.rs `StatusSnapshot.active_path`.
            active_path: snap.active_path,
            // Derived (see field doc): status.rs `StatusSnapshot.paths`.
            gateway_connected: !snap.paths.is_empty(),
            // status.rs `StatusSnapshot.aggregate_kbps`.
            aggregate_available_kbps: snap.aggregate_kbps,
            // Derived from status.rs `StatusSnapshot.paths` (reachable rows).
            active_paths,
            // status.rs `StatusSnapshot.paths` mapped per-path.
            path_quality: snap.paths.iter().map(WordlytePathQuality::from).collect(),
            // status.rs `StatusSnapshot.warnings`.
            warnings: snap.warnings.clone(),
        }
    }
}

/// A Wordlyte-side client for the StreamGuard authenticated status plane
/// (spec §22.5). Holds the resolved endpoint, the session token (only its
/// length is ever logged) and the 4-byte session prefix bound into the HMAC
/// challenge.
///
/// The client relays to the engine's IPC plane; transport (named pipe vs.
/// loopback TCP) is chosen by the [`WordlyteClient`] constructor and needs no
/// platform-specific code here.
#[derive(Debug, Clone)]
pub struct WordlyteClient {
    endpoint: StatusEndpoint,
    token: Arc<str>,
    session_prefix: u32,
    /// True after the most recent [`WordlyteClient::status`] succeeded.
    /// Mirrors the prior `StatusClient` connection expectation.
    connected: bool,
}

impl WordlyteClient {
    /// Constructs a client for an arbitrary resolved [`StatusEndpoint`]
    /// (spec §22.5: the engine's transport is selected at the endpoint).
    /// The token is stored on the `Arc<str>` without ever being logged —
    /// only `token.len()` is ever emitted.
    pub fn new(
        endpoint: StatusEndpoint,
        token: impl Into<String>,
        session_prefix: u32,
    ) -> Result<Self> {
        let token = token.into();
        if session_prefix == 0 {
            return Err(Error::config(
                "session_prefix must be the non-zero wire session id (spec 11.1)",
            ));
        }
        Ok(Self {
            endpoint,
            token: Arc::from(token),
            session_prefix,
            connected: false,
        })
    }

    /// Constructs a client for a Windows named pipe status endpoint
    /// (spec §22.5). Windows-only; on other hosts use [`WordlyteClient::with_tcp`].
    #[cfg(windows)]
    pub fn with_named_pipe(
        pipe_name: impl Into<String>,
        token: impl Into<String>,
        session_prefix: u32,
    ) -> Result<Self> {
        Self::new(StatusEndpoint::NamedPipe(pipe_name.into()), token, session_prefix)
    }

    /// Constructs a client for a loopback TCP status endpoint
    /// (spec §22.5 portable fallback; used on every host).
    pub fn with_tcp(
        addr: std::net::SocketAddr,
        token: impl Into<String>,
        session_prefix: u32,
    ) -> Result<Self> {
        Self::new(StatusEndpoint::Tcp(addr), token, session_prefix)
    }

    /// Returns a ready client handle. This is a thin, non-persistent
    /// constructor mirroring the engine's `StatusClient`: it does not hold a
    /// live transport, and the real (bounded) authenticated work happens
    /// lazily on [`WordlyteClient::status`]. It exists so a marginal app can
    /// create a configured client and then poll it.
    pub async fn connect(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// Fetches one [`WordlyteStatus`] over a fresh authenticated connection.
    ///
    /// On the per-connection snapshot quota close (spec §22.5 worker-pool
    /// semantics — the server closes a connection after serving its capped
    /// number of snapshots), this reconnects with a **bounded** retry using
    /// `RETRY_ATTEMPTS` / `RETRY_BACKOFF`, mirroring the desktop shell. A
    /// wrong token or rejected MAC surfaces as [`Error::Auth`]; transport
    /// failures as [`Error::Transport`].
    pub async fn status(&mut self) -> Result<WordlyteStatus> {
        let client = StatusClient::new(
            self.endpoint.clone(),
            self.token.to_string(),
            self.session_prefix,
        );

        // "connect" in the engine's sense: opens the transport and completes
        // the challenge-response handshake (verified only on the first
        // snapshot read).
        let mut session = client.connect().await.map_err(map_status_err)?;
        match self.one_status(&mut session).await {
            Ok(snap) => {
                self.connected = true;
                Ok(snap)
            }
            Err(first_err) => {
                // Transient quota-close / pipe reset: reconnect, bounded.
                for attempt in 0..RETRY_ATTEMPTS {
                    if attempt > 0 {
                        tokio::time::sleep(RETRY_BACKOFF).await;
                    }
                    let mut retry = match client.connect().await {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if let Ok(snap) = self.one_status(&mut retry).await {
                        self.connected = true;
                        return Ok(snap);
                    }
                }
                self.connected = false;
                Err(map_status_err(first_err))
            }
        }
    }

    /// True after the most recent [`WordlyteClient::status`] succeeded.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Requests and projects a single snapshot from an open session.
    async fn one_status(
        &self,
        session: &mut streamguard_service::ipc::StatusSession,
    ) -> sg_core::error::Result<WordlyteStatus> {
        let snap = session.snapshot().await.map_err(map_status_err)?;
        Ok(WordlyteStatus::from(&snap))
    }
}

/// Maps the engine's errors (which carry `anyhow::Error` at the app
/// boundary) onto the shared `sg_core` error type. Auth/EOF (a rejected MAC
/// closes the connection with an EOF) becomes [`Error::Auth`]; everything
/// else is a transport fault. Generic over `Display` so no `anyhow`
/// dependency is forced on this SDK's consumers.
fn map_status_err<E: std::fmt::Display>(e: E) -> Error {
    let msg = e.to_string();
    let low = msg.to_ascii_lowercase();
    if low.contains("auth")
        || low.contains("connection closed")
        || low.contains("mac mismatch")
        || low.contains("nonce mismatch")
    {
        Error::auth(format!("status authentication failed: {msg}"))
    } else {
        Error::transport(format!("status fetch failed: {msg}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamguard_service::status::{PathStatus, StatusCounters};

    fn fixture_snapshot() -> StatusSnapshot {
        StatusSnapshot {
            session_prefix: 0xdead_beef,
            protecting: true,
            mode: Mode::Bonding,
            paths: vec![
                PathStatus {
                    path_id: 1,
                    reachable: true,
                    rtt_ms: 25,
                    srtt_ms: 20,
                    jitter_ms: 3,
                    loss: 0.01,
                    available_kbps: 50_000,
                    stability_secs: 12,
                },
                PathStatus {
                    path_id: 2,
                    reachable: true,
                    rtt_ms: 40,
                    srtt_ms: 35,
                    jitter_ms: 5,
                    loss: 0.10,
                    available_kbps: 4_000,
                    stability_secs: 300,
                },
            ],
            aggregate_kbps: 54_000,
            active_path: Some(1),
            counters: StatusCounters::default(),
            warnings: vec!["path 2 degraded: loss 10%".to_string()],
        }
    }

    /// The `WordlyteStatus` projection matches the source snapshot field for
    /// field (spec §21 contract fidelity).
    #[test]
    fn projection_maps_every_spec_field() {
        let snap = fixture_snapshot();
        let ws: WordlyteStatus = WordlyteStatus::from(&snap);

        assert!(ws.protection_enabled);
        assert_eq!(ws.mode, "bonding");
        assert_eq!(ws.active_path, Some(1));
        assert!(ws.gateway_connected);
        assert_eq!(ws.aggregate_available_kbps, 54_000);
        assert_eq!(ws.active_paths, vec![1, 2], "both paths reachable");
        assert_eq!(ws.path_quality.len(), 2);
        assert_eq!(ws.path_quality[0].path_id, 1, "rows sorted by path id");
        assert_eq!(ws.path_quality[0].loss_percent, 1, "loss*100 rounded");
        assert_eq!(ws.path_quality[1].loss_percent, 10);
        assert_eq!(ws.warnings, snap.warnings);
    }

    /// The snake_case wire keys match the spec §21 contract exactly
    /// (asserted against the serialized JSON object keys).
    #[test]
    fn serializes_to_snake_case_contract() {
        let ws: WordlyteStatus = WordlyteStatus::from(&fixture_snapshot());
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ws).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "protection_enabled",
            "mode",
            "active_path",
            "gateway_connected",
            "aggregate_available_kbps",
            "active_paths",
            "path_quality",
            "warnings",
        ] {
            assert!(obj.contains_key(key), "missing contract key {key:?}");
        }
        let pq = obj["path_quality"].as_array().unwrap();
        for key in [
            "path_id",
            "reachable",
            "rtt_ms",
            "loss_percent",
            "jitter_ms",
            "available_kbps",
            "stability_secs",
        ] {
            assert!(
                pq[0].as_object().unwrap().contains_key(key),
                "missing path-quality key {key:?}"
            );
        }
    }

    /// `WordlyteStatus` is `Deserialize` so a marginal app can round-trip a
    /// stored / received snapshot blob.
    #[test]
    fn contract_round_trips_through_json() {
        let ws: WordlyteStatus = WordlyteStatus::from(&fixture_snapshot());
        let json = serde_json::to_string(&ws).unwrap();
        let back: WordlyteStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ws);
    }
}
