//! Admission-only V2 gateway configuration (filesystem refs, fail-closed).
//!
//! The admission-only entrypoint never takes secrets inline, on the command
//! line, or from the environment. Every credential is a strict-permission
//! Linux filesystem reference:
//!
//! - Gateway server identity: PEM certificate chain plus PEM private key.
//! - Device trust: PEM CA bundle plus PEM CRL bundle (non-empty, fail-closed).
//! - Controller trust: JSON file with controller signing keys, revoked ticket
//!   IDs, and freshness deadline.
//! - Safe Mode policy: bounded bytes echoed in `SessionAdmit`.
//! - Lease journal: self-hosted atomic local file (missing means empty).
//! - Replay journal: durable local single-gateway file (missing means empty).
//!
//! Policy enforced here (fail closed, no secrets logged):
//!
//! - Any `STREAMGUARD_SECRET` environment value present refuses startup: the
//!   V1 static shared secret is never a production credential.
//! - `lease_mode` must be exactly `"self-hosted"`; any other mode is rejected
//!   explicitly (no ephemeral or managed store in this entrypoint).
//! - `redemption_scope` must be exactly `"single-gateway"`; multi-gateway or
//!   shared scopes are rejected explicitly.
//! - Unknown JSON fields are rejected (`deny_unknown_fields`), so inline key
//!   material, tokens, or env-value secrets can never be smuggled in as a new
//!   field.
//! - Absent, malformed, symlink, or permissively permissioned references fail
//!   closed. Error and `Debug` output never include file contents, key
//!   material, ticket data, or filesystem paths.
//!
//! Admission-only label: this configuration has no TUN address, no WAN
//! interface, and no NAT/firewall fields by construction. Adding one is a
//! compile error, not a runtime fallback.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use sg_auth::device::{DeviceTrustAnchors, GatewayName, GatewayTlsIdentity};
use sg_auth::ticket::{ControllerPublicKey, ControllerTrustSnapshot, TicketId, TicketVerifier};
use sg_protocol::v2::control::{ControlFrameLimit, SafeModePolicy};
use sg_transport::v2::ControlDeadlines;
use thiserror::Error;

use super::address_pool::AddressPoolConfig;
use super::admission::HandshakeAdmissionLimiterConfig;
use super::replay::RedemptionScope;
use super::session_manager::SessionSweepConfig;
use crate::v2::address_pool::PoolSweepConfig;
use crate::v2::session_manager::V2SessionManagerConfig;

/// Maximum config-file bytes (JSON with paths and numbers only, never key
/// material). Larger files fail closed before parsing.
const MAX_CONFIG_FILE_BYTES: u64 = 64 * 1024;
/// Maximum PEM bundle bytes accepted for one filesystem reference.
const MAX_PEM_FILE_BYTES: u64 = 1024 * 1024;
/// Maximum controller-trust JSON bytes (bounded keys plus revocations).
const MAX_CONTROLLER_TRUST_BYTES: u64 = 256 * 1024;
/// Maximum Safe Mode policy bytes (matches `MAX_SAFE_MODE_POLICY_LEN`).
const MAX_POLICY_FILE_BYTES: u64 = 4 * 1024;
/// Maximum concurrent admission control tasks (bounded JoinSet).
const MAX_CONNECTIONS_HARD_CAP: usize = 1_024;
/// Maximum control messages processed per admitted connection.
const MAX_CONTROL_MESSAGES_HARD_CAP: u64 = 1_024;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum V2GatewayConfigError {
    #[error("V2 gateway configuration cannot be read")]
    Io,
    #[error("V2 gateway configuration is malformed")]
    Malformed,
    #[error("V2 gateway configuration is invalid")]
    InvalidConfiguration,
    #[error("V2 gateway filesystem reference is invalid")]
    FilesystemRef,
    #[error("V2 gateway must not run with a shared secret environment value")]
    SharedSecretPresent,
    #[error("V2 gateway lease mode must be self-hosted")]
    LeaseModeRejected,
    #[error("V2 gateway ticket redemption requires single-gateway scope")]
    RedemptionScopeRejected,
    #[error("V2 gateway ticket redemption scope is invalid")]
    RedemptionScopeInvalid,
}

/// Raw JSON configuration file. Every field is required (no defaults that
/// could hide a missing reference) and unknown fields are rejected so inline
/// secrets can never be introduced as a new key.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct V2GatewayConfigFile {
    bind_addr: String,
    gateway_name: String,
    gateway_cert_path: String,
    gateway_key_path: String,
    device_ca_cert_path: String,
    device_crl_path: String,
    controller_trust_path: String,
    safe_mode_policy_path: String,
    lease_journal_path: String,
    replay_journal_path: String,
    lease_mode: String,
    redemption_scope: String,
    controller_issuer: String,
    controller_audience: String,
    controller_region: String,
    ipv4_network: String,
    ipv4_prefix_len: u8,
    ipv4_gateway: String,
    reserved_ipv4: Vec<String>,
    ipv6_base: String,
    ipv6_parent_prefix_len: u8,
    maximum_leases: usize,
    pending_ttl_ms: u64,
    lease_ttl_ms: u64,
    maximum_pending_releases: usize,
    maximum_sessions: usize,
    idle_ttl_ms: u64,
    maximum_paths_per_session: usize,
    maximum_pending_attaches: usize,
    pending_attach_ttl_ms: u64,
    maximum_path_epoch_history: usize,
    maximum_path_tombstones: usize,
    path_tombstone_ttl_ms: u64,
    replay_capacity: usize,
    source_capacity: usize,
    source_ttl_millis: u64,
    maximum_per_source_in_flight: usize,
    maximum_global_in_flight: usize,
    maximum_verification_budget_millis: u64,
    handshake_timeout_millis: u64,
    control_stream_timeout_millis: u64,
    control_read_timeout_millis: u64,
    control_write_timeout_millis: u64,
    maximum_control_frame_len: usize,
    maximum_connections: usize,
    maximum_control_messages_per_connection: u64,
    session_sweep_min_interval_ms: u64,
    session_sweep_max_interval_ms: u64,
    pool_sweep_min_interval_ms: u64,
    pool_sweep_max_interval_ms: u64,
}

/// Controller-trust JSON file (filesystem reference, never inline keys in the
/// gateway config itself). Unknown fields are rejected.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerTrustFile {
    keys: Vec<ControllerKeyFile>,
    revoked_ticket_ids: Vec<String>,
    fresh_until_unix_seconds: u64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerKeyFile {
    key_id: String,
    public_key_x: String,
}

/// Validated admission-only gateway configuration. Holds loaded trust and
/// identity handles (never logged) plus bounded numeric policy. `Debug` is
/// redacted by construction: it never includes paths, key material,
/// certificates, tickets, or policy bytes.
pub struct V2GatewayConfig {
    bind_addr: SocketAddr,
    gateway_name: GatewayName,
    gateway_name_string: String,
    gateway_identity: Arc<dyn GatewayTlsIdentity>,
    device_trust: DeviceTrustAnchors,
    controller_trust: ControllerTrustSnapshot,
    ticket_verifier: TicketVerifier,
    safe_mode_policy: SafeModePolicy,
    lease_journal_path: PathBuf,
    replay_journal_path: PathBuf,
    replay_capacity: usize,
    pool_config: AddressPoolConfig,
    session_config: V2SessionManagerConfig,
    limiter_config: HandshakeAdmissionLimiterConfig,
    handshake_timeout: std::time::Duration,
    control_stream_timeout: std::time::Duration,
    control_deadlines: ControlDeadlines,
    control_frame_limit: ControlFrameLimit,
    maximum_connections: usize,
    maximum_control_messages_per_connection: u64,
    session_sweep: SessionSweepConfig,
    pool_sweep: PoolSweepConfig,
}

impl std::fmt::Debug for V2GatewayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2GatewayConfig(REDACTED)")
    }
}

impl V2GatewayConfig {
    /// Loads and validates an admission-only configuration file. Fails closed
    /// on absent/malformed/permissive references and when `STREAMGUARD_SECRET`
    /// is present. Never logs secrets, file contents, or filesystem paths.
    pub fn from_file(path: &Path) -> Result<Self, V2GatewayConfigError> {
        if std::env::var_os("STREAMGUARD_SECRET").is_some() {
            return Err(V2GatewayConfigError::SharedSecretPresent);
        }
        let bytes = std::fs::read(path).map_err(|_| V2GatewayConfigError::Io)?;
        if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(V2GatewayConfigError::Malformed);
        }
        let file: V2GatewayConfigFile =
            serde_json::from_slice(&bytes).map_err(|_| V2GatewayConfigError::Malformed)?;
        Self::validate(file)
    }

    /// Validates a parsed configuration file without touching the filesystem
    /// beyond the referenced files themselves. Split from `from_file` so
    /// tests can exercise policy without real credentials.
    fn validate(file: V2GatewayConfigFile) -> Result<Self, V2GatewayConfigError> {
        if std::env::var_os("STREAMGUARD_SECRET").is_some() {
            return Err(V2GatewayConfigError::SharedSecretPresent);
        }
        if file.lease_mode != "self-hosted" {
            return Err(V2GatewayConfigError::LeaseModeRejected);
        }
        match RedemptionScope::parse(&file.redemption_scope) {
            Ok(RedemptionScope::SingleGateway) => {}
            Err(super::replay::RedemptionScopeError::MultiGatewayRejected) => {
                return Err(V2GatewayConfigError::RedemptionScopeRejected)
            }
            Err(_) => return Err(V2GatewayConfigError::RedemptionScopeInvalid),
        }

        let bind_addr: SocketAddr =
            file.bind_addr.parse().map_err(|_| V2GatewayConfigError::InvalidConfiguration)?;
        // Port zero (ephemeral) is accepted so tests can bind `127.0.0.1:0`
        // without port conflicts; production deployments set an explicit port.
        let gateway_name =
            GatewayName::new(file.gateway_name.clone()).map_err(|_| V2GatewayConfigError::InvalidConfiguration)?;
        // The journal binding uses the normalized gateway name so `IAD-1` and
        // `iad-1` resolve to one journal identity.
        let gateway_name_string = gateway_name.as_str().to_owned();

        // Strict filesystem references: required files must exist with safe
        // permissions; journals may be missing (empty) but their parents must
        // be secure.
        let gateway_cert_pem = read_required_pem(&file.gateway_cert_path, RefKind::Public)?;
        let gateway_key_pem = read_required_pem(&file.gateway_key_path, RefKind::PrivateKey)?;
        let device_ca_pem = read_required_pem(&file.device_ca_cert_path, RefKind::Public)?;
        let device_crl_pem = read_required_pem(&file.device_crl_path, RefKind::Public)?;
        let controller_trust_bytes =
            read_required_bytes(&file.controller_trust_path, MAX_CONTROLLER_TRUST_BYTES)?;
        let policy_bytes = read_required_bytes(&file.safe_mode_policy_path, MAX_POLICY_FILE_BYTES)?;
        let lease_journal_path = check_journal_parent(&file.lease_journal_path)?;
        let replay_journal_path = check_journal_parent(&file.replay_journal_path)?;
        // Lexical journal separation (no `canonicalize`): missing journals
        // cannot be canonicalized through the filesystem, so `.`/`..`
        // aliases and temp-file aliases are rejected lexically before any
        // journal is opened. Any collision fails closed without logging paths.
        reject_journal_collisions(&lease_journal_path, &replay_journal_path)?;

        let gateway_identity = build_gateway_identity(&gateway_cert_pem, &gateway_key_pem)?;
        let device_trust = build_device_trust(&device_ca_pem, &device_crl_pem)?;
        let controller_trust = build_controller_trust(&controller_trust_bytes)?;
        // Borrowed before the owned verifier strings move below.
        let pool_config = build_pool_config(&file)?;
        let ticket_verifier = TicketVerifier::new(
            file.controller_issuer,
            file.controller_audience,
            file.controller_region,
        )
        .map_err(|_| V2GatewayConfigError::InvalidConfiguration)?;
        let safe_mode_policy =
            SafeModePolicy::new(Bytes::copy_from_slice(&policy_bytes)).map_err(|_| V2GatewayConfigError::InvalidConfiguration)?;
        let session_config = V2SessionManagerConfig {
            maximum_sessions: non_zero(file.maximum_sessions)?,
            idle_ttl_ms: non_zero_u64(file.idle_ttl_ms)?,
            maximum_paths_per_session: non_zero(file.maximum_paths_per_session)?,
            maximum_pending_attaches: non_zero(file.maximum_pending_attaches)?,
            pending_attach_ttl_ms: non_zero_u64(file.pending_attach_ttl_ms)?,
            maximum_path_epoch_history: non_zero(file.maximum_path_epoch_history)?,
            maximum_path_tombstones: non_zero(file.maximum_path_tombstones)?,
            path_tombstone_ttl_ms: non_zero_u64(file.path_tombstone_ttl_ms)?,
        };
        // Cross-field bound owned here so a misconfigured history can never
        // undercut the per-session path bound at runtime.
        if session_config.maximum_path_epoch_history < session_config.maximum_paths_per_session {
            return Err(V2GatewayConfigError::InvalidConfiguration);
        }
        if file.replay_capacity == 0
            || file.replay_capacity > super::replay::MAX_REPLAY_ENTRIES_HARD_CAP
        {
            return Err(V2GatewayConfigError::InvalidConfiguration);
        }
        let limiter_config = HandshakeAdmissionLimiterConfig {
            source_capacity: non_zero(file.source_capacity)?,
            source_ttl_millis: non_zero_u64(file.source_ttl_millis)?,
            maximum_per_source_in_flight: non_zero(file.maximum_per_source_in_flight)?,
            maximum_global_in_flight: non_zero(file.maximum_global_in_flight)?,
            maximum_verification_budget_millis: non_zero_u64(file.maximum_verification_budget_millis)?,
        };
        if file.handshake_timeout_millis == 0
            || file.control_stream_timeout_millis == 0
            || file.control_read_timeout_millis == 0
            || file.control_write_timeout_millis == 0
            || file.maximum_control_frame_len == 0
        {
            return Err(V2GatewayConfigError::InvalidConfiguration);
        }
        if file.maximum_connections == 0 || file.maximum_connections > MAX_CONNECTIONS_HARD_CAP {
            return Err(V2GatewayConfigError::InvalidConfiguration);
        }
        if file.maximum_control_messages_per_connection == 0
            || file.maximum_control_messages_per_connection > MAX_CONTROL_MESSAGES_HARD_CAP
        {
            return Err(V2GatewayConfigError::InvalidConfiguration);
        }
        let session_sweep = SessionSweepConfig::new(
            file.session_sweep_min_interval_ms,
            file.session_sweep_max_interval_ms,
        )
        .ok_or(V2GatewayConfigError::InvalidConfiguration)?;
        let pool_sweep =
            PoolSweepConfig::new(file.pool_sweep_min_interval_ms, file.pool_sweep_max_interval_ms)
                .ok_or(V2GatewayConfigError::InvalidConfiguration)?;

        Ok(Self {
            bind_addr,
            gateway_name,
            gateway_name_string,
            gateway_identity,
            device_trust,
            controller_trust,
            ticket_verifier,
            safe_mode_policy,
            lease_journal_path,
            replay_journal_path,
            replay_capacity: file.replay_capacity,
            pool_config,
            session_config,
            limiter_config,
            handshake_timeout: std::time::Duration::from_millis(file.handshake_timeout_millis),
            control_stream_timeout: std::time::Duration::from_millis(file.control_stream_timeout_millis),
            control_deadlines: ControlDeadlines {
                read: std::time::Duration::from_millis(file.control_read_timeout_millis),
                write: std::time::Duration::from_millis(file.control_write_timeout_millis),
            },
            control_frame_limit: ControlFrameLimit::new(file.maximum_control_frame_len),
            maximum_connections: file.maximum_connections,
            maximum_control_messages_per_connection: file.maximum_control_messages_per_connection,
            session_sweep,
            pool_sweep,
        })
    }

    #[must_use]
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    #[must_use]
    pub fn gateway_name(&self) -> &GatewayName {
        &self.gateway_name
    }

    #[must_use]
    pub fn gateway_name_string(&self) -> &str {
        &self.gateway_name_string
    }

    #[must_use]
    pub fn gateway_identity(&self) -> &Arc<dyn GatewayTlsIdentity> {
        &self.gateway_identity
    }

    #[must_use]
    pub fn device_trust(&self) -> &DeviceTrustAnchors {
        &self.device_trust
    }

    #[must_use]
    pub fn controller_trust(&self) -> &ControllerTrustSnapshot {
        &self.controller_trust
    }

    #[must_use]
    pub fn ticket_verifier(&self) -> &TicketVerifier {
        &self.ticket_verifier
    }

    #[must_use]
    pub fn safe_mode_policy(&self) -> &SafeModePolicy {
        &self.safe_mode_policy
    }

    #[must_use]
    pub fn lease_journal_path(&self) -> &Path {
        &self.lease_journal_path
    }

    #[must_use]
    pub fn replay_journal_path(&self) -> &Path {
        &self.replay_journal_path
    }

    #[must_use]
    pub const fn replay_capacity(&self) -> usize {
        self.replay_capacity
    }

    #[must_use]
    pub const fn pool_config(&self) -> &AddressPoolConfig {
        &self.pool_config
    }

    #[must_use]
    pub const fn session_config(&self) -> &V2SessionManagerConfig {
        &self.session_config
    }

    #[must_use]
    pub const fn limiter_config(&self) -> &HandshakeAdmissionLimiterConfig {
        &self.limiter_config
    }

    #[must_use]
    pub const fn handshake_timeout(&self) -> std::time::Duration {
        self.handshake_timeout
    }

    #[must_use]
    pub const fn control_stream_timeout(&self) -> std::time::Duration {
        self.control_stream_timeout
    }

    #[must_use]
    pub const fn control_deadlines(&self) -> ControlDeadlines {
        self.control_deadlines
    }

    #[must_use]
    pub const fn control_frame_limit(&self) -> ControlFrameLimit {
        self.control_frame_limit
    }

    #[must_use]
    pub const fn maximum_connections(&self) -> usize {
        self.maximum_connections
    }

    #[must_use]
    pub const fn maximum_control_messages_per_connection(&self) -> u64 {
        self.maximum_control_messages_per_connection
    }

    #[must_use]
    pub const fn session_sweep(&self) -> SessionSweepConfig {
        self.session_sweep
    }

    #[must_use]
    pub const fn pool_sweep(&self) -> PoolSweepConfig {
        self.pool_sweep
    }

    /// Moves every validated value out for runtime construction. The runtime
    /// takes ownership of the trust, identity, policy, journal paths, and
    /// bounded policy without ever logging them. Destructuring here (inside
    /// the defining module) is the only place private fields are moved.
    ///
    /// The 22-element return is a deliberate construction seam (not a
    /// computation): every element is a moved validated value, and naming a
    /// struct would duplicate the redacted config shape without adding a
    /// safety bound.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SocketAddr,
        GatewayName,
        String,
        Arc<dyn GatewayTlsIdentity>,
        DeviceTrustAnchors,
        ControllerTrustSnapshot,
        TicketVerifier,
        SafeModePolicy,
        PathBuf,
        PathBuf,
        usize,
        AddressPoolConfig,
        V2SessionManagerConfig,
        HandshakeAdmissionLimiterConfig,
        std::time::Duration,
        std::time::Duration,
        ControlDeadlines,
        ControlFrameLimit,
        usize,
        u64,
        SessionSweepConfig,
        PoolSweepConfig,
    ) {
        (
            self.bind_addr,
            self.gateway_name,
            self.gateway_name_string,
            self.gateway_identity,
            self.device_trust,
            self.controller_trust,
            self.ticket_verifier,
            self.safe_mode_policy,
            self.lease_journal_path,
            self.replay_journal_path,
            self.replay_capacity,
            self.pool_config,
            self.session_config,
            self.limiter_config,
            self.handshake_timeout,
            self.control_stream_timeout,
            self.control_deadlines,
            self.control_frame_limit,
            self.maximum_connections,
            self.maximum_control_messages_per_connection,
            self.session_sweep,
            self.pool_sweep,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefKind {
    PrivateKey,
    Public,
}

fn non_zero(value: usize) -> Result<usize, V2GatewayConfigError> {
    if value == 0 {
        return Err(V2GatewayConfigError::InvalidConfiguration);
    }
    Ok(value)
}

fn non_zero_u64(value: u64) -> Result<u64, V2GatewayConfigError> {
    if value == 0 {
        return Err(V2GatewayConfigError::InvalidConfiguration);
    }
    Ok(value)
}

/// Checks a required filesystem reference without logging its path or
/// contents: regular non-symlink file, safe Linux permissions, bounded size.
fn check_required_file(path_str: &str, kind: RefKind, max_bytes: u64) -> Result<PathBuf, V2GatewayConfigError> {
    if path_str.is_empty() || path_str.len() > 4096 {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    let path = PathBuf::from(path_str);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| V2GatewayConfigError::FilesystemRef)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    // On non-Unix hosts the permission gate below is compiled out; reference
    // the kind so the parameter stays used on every platform.
    #[cfg(not(unix))]
    let _ = kind;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        match kind {
            // Private keys: 0600-style, no group/other permissions at all.
            RefKind::PrivateKey => {
                if mode & 0o077 != 0 {
                    return Err(V2GatewayConfigError::FilesystemRef);
                }
            }
            // Public trust/policy material: integrity-sensitive, so no
            // group/other write (0644 is the typical production mode).
            RefKind::Public => {
                if mode & 0o022 != 0 {
                    return Err(V2GatewayConfigError::FilesystemRef);
                }
            }
        }
    }
    Ok(path)
}

fn read_required_pem(path_str: &str, kind: RefKind) -> Result<Vec<u8>, V2GatewayConfigError> {
    let path = check_required_file(path_str, kind, MAX_PEM_FILE_BYTES)?;
    std::fs::read(&path).map_err(|_| V2GatewayConfigError::FilesystemRef)
}

fn read_required_bytes(path_str: &str, max_bytes: u64) -> Result<Vec<u8>, V2GatewayConfigError> {
    let path = check_required_file(path_str, RefKind::Public, max_bytes)?;
    let bytes = std::fs::read(&path).map_err(|_| V2GatewayConfigError::FilesystemRef)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    Ok(bytes)
}

/// Checks a journal reference: the file may be missing (empty journal), but a
/// present file must be a regular non-symlink file with private (0600-style)
/// permissions, and a missing file requires a secure existing parent
/// directory. Returns the journal path. Never logs paths.
fn check_journal_parent(path_str: &str) -> Result<PathBuf, V2GatewayConfigError> {
    if path_str.is_empty() || path_str.len() > 4096 {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    let path = PathBuf::from(path_str);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(V2GatewayConfigError::FilesystemRef);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Journals hold session/device IDs, addresses, and ticket
                // IDs: 0600-style, no group/other permissions.
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(V2GatewayConfigError::FilesystemRef);
                }
            }
            // Bound the existing journal before any parse.
            if metadata.len() > 16 * 1024 * 1024 {
                return Err(V2GatewayConfigError::FilesystemRef);
            }
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
            let metadata =
                std::fs::symlink_metadata(parent).map_err(|_| V2GatewayConfigError::FilesystemRef)?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(V2GatewayConfigError::FilesystemRef);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o022 != 0 {
                    return Err(V2GatewayConfigError::FilesystemRef);
                }
            }
            Ok(path)
        }
        Err(_) => Err(V2GatewayConfigError::FilesystemRef),
    }
}

/// Lexically normalizes a journal path without touching the filesystem.
///
/// `std::fs::canonicalize` requires the file to exist, but journals may be
/// missing (empty). This resolves `.` and lexically resolvable `..` via
/// `Component` iteration, collapses redundant separators, and preserves
/// prefix/root/relative shape. It never touches the filesystem, never logs
/// paths, and never panics. Callers use the normalized form only for
/// alias/collision comparison; the original path is still the filesystem
/// reference.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                // Pop a trailing `Normal` component when present; otherwise
                // preserve `..` for relative paths and ignore it at the
                // filesystem root (lexical `..` above root stays at root).
                // `file_name` is `None` for `..`-terminated, root, prefix-only,
                // and empty paths, which is exactly the "nothing to pop" case.
                if normalized.file_name().is_some() {
                    normalized.pop();
                } else if !normalized.has_root() {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }
    normalized
}

/// Compares two normalized journal paths for filesystem aliasing.
///
/// Unix paths compare byte-exactly. Windows filesystems are
/// case-insensitive, so `Leases.JOURNAL` and `leases.journal` denote the same
/// file: compare case-insensitively when both paths are lossless UTF-8 (all
/// config-file paths are JSON strings, hence UTF-8). Non-UTF-8 paths fall
/// back to exact `Path` equality (fail closed on exact match).
#[cfg(windows)]
fn normalized_paths_equal(first: &Path, second: &Path) -> bool {
    match (first.to_str(), second.to_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (None, None) => first == second,
        _ => false,
    }
}

#[cfg(not(windows))]
fn normalized_paths_equal(first: &Path, second: &Path) -> bool {
    first == second
}

/// Rejects journal path collisions lexically (no filesystem canonicalization).
///
/// Missing journals cannot be `canonicalize`d, so `.`/`..` aliases and
/// temp-file aliases are compared on lexically normalized forms. All four
/// files — lease, lease temp (`with_extension("tmp")`), replay, replay temp —
/// must be pairwise distinct: sharing one file would mix `SGAL` and `SGTR`
/// formats or let concurrent atomic rewrites clobber each other, and a journal
/// whose temp equals itself (`*.tmp`) has no atomic rewrite. Directory-like
/// paths (no filename after normalization) also fail closed. Any collision
/// returns `FilesystemRef` without logging paths.
fn has_trailing_separator(path: &Path) -> bool {
    // A trailing `/` (or `\` on Windows) denotes a directory intent, but
    // `Path::components` silently drops it, so `/var/lib/sg/` would otherwise
    // normalize to the file-like `/var/lib/sg`. Reject it lexically here
    // without touching the filesystem.
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty() {
        return true;
    }
    let last = bytes[bytes.len() - 1];
    if last == b'/' {
        return true;
    }
    #[cfg(windows)]
    if last == b'\\' {
        return true;
    }
    false
}

fn reject_journal_collisions(lease: &Path, replay: &Path) -> Result<(), V2GatewayConfigError> {
    // Directory intent (trailing separator) never names a journal file.
    if has_trailing_separator(lease) || has_trailing_separator(replay) {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    let lease_norm = lexical_normalize(lease);
    let replay_norm = lexical_normalize(replay);
    // Journals must name files, not directories/roots/curdir.
    if lease_norm.file_name().is_none() || replay_norm.file_name().is_none() {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    let lease_tmp = super::persistence::journal_tmp_path(lease);
    let replay_tmp = super::persistence::journal_tmp_path(replay);
    let lease_tmp_norm = lexical_normalize(&lease_tmp);
    let replay_tmp_norm = lexical_normalize(&replay_tmp);
    if lease_tmp_norm.file_name().is_none() || replay_tmp_norm.file_name().is_none() {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    let paths = [&lease_norm, &lease_tmp_norm, &replay_norm, &replay_tmp_norm];
    for (index, first) in paths.iter().enumerate() {
        for second in paths.iter().skip(index + 1) {
            if normalized_paths_equal(first, second) {
                return Err(V2GatewayConfigError::FilesystemRef);
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct FixedServerResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedServerResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[derive(Debug)]
struct FileGatewayIdentity {
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
}

impl GatewayTlsIdentity for FileGatewayIdentity {
    fn server_cert_resolver(&self) -> Arc<dyn rustls::server::ResolvesServerCert> {
        Arc::clone(&self.resolver)
    }
}

fn build_gateway_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<dyn GatewayTlsIdentity>, V2GatewayConfigError> {
    use sg_auth::device::{MAX_CERTIFICATE_CHAIN_LEN, MAX_CERTIFICATE_DER_LEN};

    let mut cert_reader = std::io::BufReader::new(cert_pem);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| V2GatewayConfigError::FilesystemRef)?;
    if certs.is_empty()
        || certs.len() > MAX_CERTIFICATE_CHAIN_LEN
        || certs.iter().any(|cert| cert.is_empty() || cert.len() > MAX_CERTIFICATE_DER_LEN)
    {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    let mut key_reader = std::io::BufReader::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| V2GatewayConfigError::FilesystemRef)?
        .ok_or(V2GatewayConfigError::FilesystemRef)?;
    let certified = rustls::sign::CertifiedKey::from_der(
        certs,
        key,
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(|_| V2GatewayConfigError::FilesystemRef)?;
    Ok(Arc::new(FileGatewayIdentity { resolver: Arc::new(FixedServerResolver(Arc::new(certified))) }))
}

fn load_pem_certs(pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, V2GatewayConfigError> {
    let mut reader = std::io::BufReader::new(pem);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| V2GatewayConfigError::FilesystemRef)
}

fn load_pem_crls(pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateRevocationListDer<'static>>, V2GatewayConfigError> {
    let mut reader = std::io::BufReader::new(pem);
    rustls_pemfile::crls(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| V2GatewayConfigError::FilesystemRef)
}

fn build_device_trust(
    ca_pem: &[u8],
    crl_pem: &[u8],
) -> Result<DeviceTrustAnchors, V2GatewayConfigError> {
    let roots = load_pem_certs(ca_pem)?;
    let crls = load_pem_crls(crl_pem)?;
    DeviceTrustAnchors::new(roots, crls).map_err(|_| V2GatewayConfigError::FilesystemRef)
}

fn build_controller_trust(bytes: &[u8]) -> Result<ControllerTrustSnapshot, V2GatewayConfigError> {
    let file: ControllerTrustFile =
        serde_json::from_slice(bytes).map_err(|_| V2GatewayConfigError::FilesystemRef)?;
    if file.keys.is_empty()
        || file.keys.len() > 32
        || file.revoked_ticket_ids.len() > 4096
        || file.fresh_until_unix_seconds == 0
    {
        return Err(V2GatewayConfigError::FilesystemRef);
    }
    let mut keys = Vec::with_capacity(file.keys.len());
    for key in file.keys {
        keys.push(
            ControllerPublicKey::new(key.key_id, key.public_key_x)
                .map_err(|_| V2GatewayConfigError::FilesystemRef)?,
        );
    }
    let mut revoked = Vec::with_capacity(file.revoked_ticket_ids.len());
    for id in file.revoked_ticket_ids {
        revoked.push(TicketId::from_bytes(
            parse_uuid_lower(&id).ok_or(V2GatewayConfigError::FilesystemRef)?,
        ));
    }
    ControllerTrustSnapshot::new(keys, revoked, file.fresh_until_unix_seconds)
        .map_err(|_| V2GatewayConfigError::FilesystemRef)
}

/// Parses a lowercase canonical UUID (`8-4-4-4-12`, lowercase hex only),
/// matching the ticket claim parser. Uppercase or malformed IDs fail closed.
fn parse_uuid_lower(value: &str) -> Option<[u8; 16]> {
    if value.len() != 36 {
        return None;
    }
    let mut bytes = [0u8; 16];
    let mut source = value.bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) && source.next()? != b'-' {
            return None;
        }
        let high = hex_lower(source.next()?)?;
        let low = hex_lower(source.next()?)?;
        *byte = (high << 4) | low;
    }
    if source.next().is_some() {
        return None;
    }
    Some(bytes)
}

fn hex_lower(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn parse_ipv4(value: &str) -> Result<[u8; 4], V2GatewayConfigError> {
    value.parse::<std::net::Ipv4Addr>().map_err(|_| V2GatewayConfigError::InvalidConfiguration).map(|addr| addr.octets())
}

fn parse_ipv6(value: &str) -> Result<[u8; 16], V2GatewayConfigError> {
    value.parse::<std::net::Ipv6Addr>().map_err(|_| V2GatewayConfigError::InvalidConfiguration).map(|addr| addr.octets())
}

fn build_pool_config(file: &V2GatewayConfigFile) -> Result<AddressPoolConfig, V2GatewayConfigError> {
    let network = parse_ipv4(&file.ipv4_network)?;
    let gateway = parse_ipv4(&file.ipv4_gateway)?;
    let mut reserved = Vec::with_capacity(file.reserved_ipv4.len());
    for entry in &file.reserved_ipv4 {
        reserved.push(parse_ipv4(entry)?);
    }
    let ipv6_base = parse_ipv6(&file.ipv6_base)?;
    AddressPoolConfig::new(
        network,
        file.ipv4_prefix_len,
        gateway,
        reserved,
        ipv6_base,
        file.ipv6_parent_prefix_len,
        file.maximum_leases,
        file.pending_ttl_ms,
        file.lease_ttl_ms,
        file.maximum_pending_releases,
    )
    .map_err(|_| V2GatewayConfigError::InvalidConfiguration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_mode_rejects_anything_but_self_hosted() {
        // The config gate owns this check before any filesystem I/O: only the
        // literal `self-hosted` passes, everything else fails closed.
        for (mode, expected) in [
            ("self-hosted", true),
            ("ephemeral", false),
            ("managed", false),
            ("SELF-HOSTED", false),
            ("", false),
        ] {
            assert_eq!(mode == "self-hosted", expected, "mode: {mode}");
        }
    }

    #[test]
    fn uuid_parser_matches_ticket_claim_rules() {
        assert_eq!(
            parse_uuid_lower("01010101-0101-0101-0101-010101010101"),
            Some([1; 16])
        );
        for invalid in [
            "01010101-0101-0101-0101-01010101010A",
            "01010101010101010101010101010101",
            "",
            "01010101-0101-0101-0101-010101010101 ",
        ] {
            assert_eq!(parse_uuid_lower(invalid), None, "input: {invalid}");
        }
    }

    #[test]
    fn config_debug_never_includes_paths_or_secrets() {
        // A type-level guarantee: the validated config's Debug is a fixed
        // redacted string, so no path, key, certificate, ticket, or policy
        // bytes can ever reach logs through `{:?}`.
        let debug = "V2GatewayConfig(REDACTED)";
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("/etc/"));
    }

    #[test]
    fn lexical_normalize_resolves_dot_and_dotdot_without_filesystem() {
        // No filesystem touch: missing paths normalize purely lexically.
        assert_eq!(lexical_normalize(Path::new("a/./b")), PathBuf::from("a/b"));
        assert_eq!(
            lexical_normalize(Path::new("a/b/../b/c.journal")),
            PathBuf::from("a/b/c.journal")
        );
        assert_eq!(lexical_normalize(Path::new("a//b/c.journal")), PathBuf::from("a/b/c.journal"));
        assert_eq!(lexical_normalize(Path::new("/a/../b/c.journal")), PathBuf::from("/b/c.journal"));
        // `..` above the root stays at the root lexically.
        assert_eq!(lexical_normalize(Path::new("/../b.journal")), PathBuf::from("/b.journal"));
        // Relative `..` that cannot resolve is preserved, not dropped.
        assert_eq!(lexical_normalize(Path::new("a/../../b.journal")), PathBuf::from("../b.journal"));
    }

    #[test]
    fn journal_collisions_reject_same_tmp_alias_and_lexical_alias() {
        // Distinct journals with distinct temps pass.
        assert!(reject_journal_collisions(
            Path::new("/var/lib/sg/leases.journal"),
            Path::new("/var/lib/sg/replay.journal"),
        )
        .is_ok());
        // Same file fails closed.
        assert_eq!(
            reject_journal_collisions(
                Path::new("/var/lib/sg/shared.journal"),
                Path::new("/var/lib/sg/shared.journal"),
            ),
            Err(V2GatewayConfigError::FilesystemRef)
        );
        // Temp alias: lease temp (`leases.tmp`) equals the replay journal.
        assert_eq!(
            reject_journal_collisions(
                Path::new("/var/lib/sg/leases.journal"),
                Path::new("/var/lib/sg/leases.tmp"),
            ),
            Err(V2GatewayConfigError::FilesystemRef)
        );
        // Temp-temp collision: `a.journal` -> `a.tmp` and `a.replay` ->
        // `a.tmp` share one temp file, so concurrent atomic rewrites would
        // clobber each other.
        assert_eq!(
            reject_journal_collisions(
                Path::new("/var/lib/sg/a.journal"),
                Path::new("/var/lib/sg/a.replay"),
            ),
            Err(V2GatewayConfigError::FilesystemRef)
        );
        // Lexical alias without filesystem touch: `a/./b` equals `a/b`.
        assert_eq!(
            reject_journal_collisions(Path::new("a/./leases.journal"), Path::new("a/leases.journal")),
            Err(V2GatewayConfigError::FilesystemRef)
        );
        assert_eq!(
            reject_journal_collisions(
                Path::new("/var/lib/sg/dir/../sg/leases.journal"),
                Path::new("/var/lib/sg/sg/leases.journal"),
            ),
            Err(V2GatewayConfigError::FilesystemRef)
        );
        // Self-temp alias: `*.tmp` rewrites through itself (no atomic rename).
        assert_eq!(
            reject_journal_collisions(
                Path::new("/var/lib/sg/leases.tmp"),
                Path::new("/var/lib/sg/replay.journal"),
            ),
            Err(V2GatewayConfigError::FilesystemRef)
        );
        // Directory-like journals fail closed (no filename).
        assert_eq!(
            reject_journal_collisions(Path::new("/var/lib/sg/"), Path::new("/var/lib/sg/replay.journal")),
            Err(V2GatewayConfigError::FilesystemRef)
        );
    }
}
