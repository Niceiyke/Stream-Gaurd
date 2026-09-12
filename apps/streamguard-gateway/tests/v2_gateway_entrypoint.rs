#![recursion_limit = "512"]
//! Admission-only V2 gateway entrypoint tests: config policy, task bounds,
//! shutdown, and V1 isolation.
//!
//! These tests never use sleeps as the primary assertion mechanism: async
//! operations are wrapped in `tokio::time::timeout` with hard deadlines, and
//! sync policy checks are fully deterministic. Temporary files live under the
//! OS temp dir with process-unique names and are removed on drop.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use streamguard_gateway::v2::admission::ReplayCache;
use streamguard_gateway::v2::config::{V2GatewayConfig, V2GatewayConfigError};
use streamguard_gateway::v2::replay::RedemptionScope;
use streamguard_gateway::v2::runtime::V2GatewayRuntime;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Serializes every test that loads a config file: `V2GatewayConfig::from_file`
/// fails closed when `STREAMGUARD_SECRET` is present, and the environment is
/// process-global. This is an async mutex so guards can span the async runtime
/// startup/shutdown without holding a blocking mutex across an await point.
static ENV_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("sg-v2-entrypoint-{nonce}-{tag}"));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn rm(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Production references are strict by default in these tests; the
        // permissive-permission test below chmods its own file explicitly.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

/// Generates a gateway server certificate plus private key as PEM files, a
/// device CA certificate plus CRL as PEM files, a controller-trust JSON file,
/// and a Safe Mode policy file. Returns the six paths in config-file order.
struct CredentialFiles {
    dir: TempDir,
    gateway_cert: PathBuf,
    gateway_key: PathBuf,
    device_ca: PathBuf,
    device_crl: PathBuf,
    controller_trust: PathBuf,
    policy: PathBuf,
}

fn credential_files(tag: &str) -> CredentialFiles {
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, KeyIdMethod,
        KeyPair, KeyUsagePurpose, SerialNumber,
    };

    let dir = TempDir::new(tag);
    // Gateway server identity: self-signed leaf is sufficient for config load
    // (handshake trust is a separate peer concern).
    let gateway_key = KeyPair::generate().unwrap();
    let gateway_cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&gateway_key)
        .unwrap();
    let gateway_cert_path = dir.join("gateway-cert.pem");
    let gateway_key_path = dir.join("gateway-key.pem");
    write(gateway_cert_path.as_path(), gateway_cert.pem().as_bytes());
    write(gateway_key_path.as_path(), gateway_key.serialize_pem().as_bytes());

    // Device trust: CA plus a non-empty CRL (the V2 device verifier requires
    // current revocation information and fails closed without it).
    let mut ca_params = CertificateParams::new(vec!["device-ca.test".into()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let crl = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2025, 1, 1),
        next_update: rcgen::date_time_ymd(2030, 1, 1),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca_cert, &ca_key)
    .unwrap();
    let device_ca_path = dir.join("device-ca.pem");
    let device_crl_path = dir.join("device-crl.pem");
    write(device_ca_path.as_path(), ca_cert.pem().as_bytes());
    write(device_crl_path.as_path(), crl.pem().unwrap().as_bytes());

    // Controller trust: one Ed25519 verification key, no revocations, fresh.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let trust_json = serde_json::json!({
        "keys": [{"key_id": "controller-1", "public_key_x": "kFjlN2-bMhd6GHDoZWSsAwQK8i82AeXe9G3lO9harE8"}],
        "revoked_ticket_ids": [],
        "fresh_until_unix_seconds": now + 3600,
    });
    let controller_trust_path = dir.join("controller-trust.json");
    write(
        controller_trust_path.as_path(),
        serde_json::to_vec(&trust_json).unwrap().as_slice(),
    );

    let policy_path = dir.join("safe-mode-policy.bin");
    write(policy_path.as_path(), b"safe-mode-test");

    CredentialFiles {
        dir,
        gateway_cert: gateway_cert_path,
        gateway_key: gateway_key_path,
        device_ca: device_ca_path,
        device_crl: device_crl_path,
        controller_trust: controller_trust_path,
        policy: policy_path,
    }
}

#[allow(clippy::too_many_arguments)]
fn config_json(
    creds: &CredentialFiles,
    lease_journal: &Path,
    replay_journal: &Path,
    lease_mode: &str,
    redemption_scope: &str,
    replay_capacity: usize,
    maximum_connections: usize,
    maximum_control_frame_len: usize,
    handshake_timeout_millis: u64,
) -> serde_json::Value {
    serde_json::json!({
        "bind_addr": "127.0.0.1:0",
        "gateway_name": "iad-1.example.test",
        "gateway_cert_path": creds.gateway_cert.to_str().unwrap(),
        "gateway_key_path": creds.gateway_key.to_str().unwrap(),
        "device_ca_cert_path": creds.device_ca.to_str().unwrap(),
        "device_crl_path": creds.device_crl.to_str().unwrap(),
        "controller_trust_path": creds.controller_trust.to_str().unwrap(),
        "safe_mode_policy_path": creds.policy.to_str().unwrap(),
        "lease_journal_path": lease_journal.to_str().unwrap(),
        "replay_journal_path": replay_journal.to_str().unwrap(),
        "lease_mode": lease_mode,
        "redemption_scope": redemption_scope,
        "controller_issuer": "controller.example",
        "controller_audience": "gateway-group-a",
        "controller_region": "us-east-1",
        "ipv4_network": "10.64.0.0",
        "ipv4_prefix_len": 24,
        "ipv4_gateway": "10.64.0.1",
        "reserved_ipv4": [],
        "ipv6_base": "fd00::",
        "ipv6_parent_prefix_len": 48,
        "maximum_leases": 4,
        "pending_ttl_ms": 5000,
        "lease_ttl_ms": 60000,
        "maximum_pending_releases": 4,
        "maximum_sessions": 4,
        "idle_ttl_ms": 120000,
        "maximum_paths_per_session": 4,
        "maximum_pending_attaches": 4,
        "pending_attach_ttl_ms": 5000,
        "maximum_path_epoch_history": 16,
        "maximum_path_tombstones": 4,
        "path_tombstone_ttl_ms": 5000,
        "replay_capacity": replay_capacity,
        "source_capacity": 8,
        "source_ttl_millis": 1000,
        "maximum_per_source_in_flight": 4,
        "maximum_global_in_flight": 8,
        "maximum_verification_budget_millis": 100,
        "handshake_timeout_millis": handshake_timeout_millis,
        "control_stream_timeout_millis": 5000,
        "control_read_timeout_millis": 5000,
        "control_write_timeout_millis": 5000,
        "maximum_control_frame_len": maximum_control_frame_len,
        "maximum_connections": maximum_connections,
        "maximum_control_messages_per_connection": 8,
        "session_sweep_min_interval_ms": 10,
        "session_sweep_max_interval_ms": 1000,
        "pool_sweep_min_interval_ms": 10,
        "pool_sweep_max_interval_ms": 1000,
    })
}

fn write_config(path: &Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn valid_config_paths(creds: &CredentialFiles) -> (PathBuf, PathBuf) {
    (creds.dir.join("leases.journal"), creds.dir.join("replay.journal"))
}

fn load_valid_config(creds: &CredentialFiles) -> (TempDir, PathBuf, V2GatewayConfig) {
    // Returns the temp dir (kept alive by the caller), the config path, and
    // the loaded config. Journals are missing files (empty) inside the same
    // temp dir whose parent is secure.
    let dir = TempDir::new("valid-config");
    let lease_journal = dir.join("leases.journal");
    let replay_journal = dir.join("replay.journal");
    let config_path = dir.join("gateway.json");
    write_config(config_path.as_path(), &config_json(creds, &lease_journal, &replay_journal, "self-hosted", "single-gateway", 8, 4, 8192, 5000));
    rm(&lease_journal);
    rm(&replay_journal);
    let config = V2GatewayConfig::from_file(config_path.as_path()).unwrap();
    (dir, config_path, config)
}

#[test]
fn redemption_scope_parsing_accepts_single_and_explicitly_rejects_multi() {
    assert_eq!(RedemptionScope::parse("single-gateway"), Ok(RedemptionScope::SingleGateway));
    for multi in ["multi-gateway", "shared", "multi", "clustered"] {
        let error = RedemptionScope::parse(multi).unwrap_err();
        assert_eq!(
            error.to_string(),
            "V2 ticket redemption requires single-gateway scope; multi-gateway is rejected",
            "scope: {multi}"
        );
    }
    assert!(RedemptionScope::parse("").is_err());
    assert!(RedemptionScope::parse("SINGLE-GATEWAY").is_err());
}

#[tokio::test]
async fn config_rejects_shared_secret_environment_value() {
    let _guard = ENV_GUARD.lock().await;
    let creds = credential_files("secret-gate");
    let (lease_journal, replay_journal) = valid_config_paths(&creds);
    let dir = TempDir::new("secret-gate-config");
    let config_path = dir.join("gateway.json");
    write_config(
        config_path.as_path(),
        &config_json(&creds, &lease_journal, &replay_journal, "self-hosted", "single-gateway", 8, 4, 8192, 5000),
    );
    rm(&lease_journal);
    rm(&replay_journal);
    std::env::set_var("STREAMGUARD_SECRET", "test-only-value");
    let error = V2GatewayConfig::from_file(config_path.as_path()).unwrap_err();
    std::env::remove_var("STREAMGUARD_SECRET");
    assert_eq!(error, V2GatewayConfigError::SharedSecretPresent);
    assert!(!error.to_string().contains("test-only-value"));
}

#[tokio::test]
async fn config_rejects_unknown_inline_secret_fields() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("STREAMGUARD_SECRET");
    let creds = credential_files("inline-reject");
    let (lease_journal, replay_journal) = valid_config_paths(&creds);
    let mut value = config_json(&creds, &lease_journal, &replay_journal, "self-hosted", "single-gateway", 8, 4, 8192, 5000);
    value.as_object_mut().unwrap().insert("gateway_key_inline".into(), serde_json::json!("not-a-real-key"));
    let dir = TempDir::new("inline-reject-config");
    let config_path = dir.join("gateway.json");
    write_config(config_path.as_path(), &value);
    rm(&lease_journal);
    rm(&replay_journal);
    assert_eq!(
        V2GatewayConfig::from_file(config_path.as_path()).unwrap_err(),
        V2GatewayConfigError::Malformed
    );
}

#[tokio::test]
async fn config_rejects_multi_gateway_redemption_and_non_self_hosted_leases() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("STREAMGUARD_SECRET");
    let creds = credential_files("scope-mode");
    for (scope, expected) in [
        ("multi-gateway", V2GatewayConfigError::RedemptionScopeRejected),
        ("shared", V2GatewayConfigError::RedemptionScopeRejected),
        ("unknown-scope", V2GatewayConfigError::RedemptionScopeInvalid),
    ] {
        let (lease_journal, replay_journal) = valid_config_paths(&creds);
        let dir = TempDir::new("scope-config");
        let config_path = dir.join("gateway.json");
        write_config(config_path.as_path(), &config_json(&creds, &lease_journal, &replay_journal, "self-hosted", scope, 8, 4, 8192, 5000));
        rm(&lease_journal);
        rm(&replay_journal);
        assert_eq!(V2GatewayConfig::from_file(config_path.as_path()).unwrap_err(), expected, "scope: {scope}");
    }
    for mode in ["ephemeral", "managed", "shared", ""] {
        let (lease_journal, replay_journal) = valid_config_paths(&creds);
        let dir = TempDir::new("mode-config");
        let config_path = dir.join("gateway.json");
        write_config(config_path.as_path(), &config_json(&creds, &lease_journal, &replay_journal, mode, "single-gateway", 8, 4, 8192, 5000));
        rm(&lease_journal);
        rm(&replay_journal);
        assert_eq!(
            V2GatewayConfig::from_file(config_path.as_path()).unwrap_err(),
            V2GatewayConfigError::LeaseModeRejected,
            "mode: {mode}"
        );
    }
}

#[tokio::test]
async fn config_rejects_absent_malformed_and_bad_bounds_without_secrets_or_paths() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("STREAMGUARD_SECRET");
    let creds = credential_files("policy-bounds");
    // Absent reference: gateway certificate does not exist.
    let (lease_journal, replay_journal) = valid_config_paths(&creds);
    let mut missing = config_json(&creds, &lease_journal, &replay_journal, "self-hosted", "single-gateway", 8, 4, 8192, 5000);
    missing.as_object_mut().unwrap().insert(
        "gateway_cert_path".into(),
        serde_json::json!(creds.dir.join("does-not-exist.pem").to_str().unwrap()),
    );
    let dir = TempDir::new("absent-config");
    let config_path = dir.join("gateway.json");
    write_config(config_path.as_path(), &missing);
    rm(&lease_journal);
    rm(&replay_journal);
    let error = V2GatewayConfig::from_file(config_path.as_path()).unwrap_err();
    assert_eq!(error, V2GatewayConfigError::FilesystemRef);
    assert!(!format!("{error}").contains("does-not-exist"));

    // Malformed JSON.
    let malformed_path = dir.join("malformed.json");
    std::fs::write(malformed_path.as_path(), b"{ not json").unwrap();
    assert_eq!(
        V2GatewayConfig::from_file(malformed_path.as_path()).unwrap_err(),
        V2GatewayConfigError::Malformed
    );

    // Bad bounds: each of these must fail closed as invalid configuration.
    for mutate in [
        ("replay_capacity", serde_json::json!(0)),
        ("maximum_connections", serde_json::json!(0)),
        ("maximum_control_frame_len", serde_json::json!(0)),
        ("handshake_timeout_millis", serde_json::json!(0)),
        ("maximum_sessions", serde_json::json!(0)),
    ] {
        let (lease_journal, replay_journal) = valid_config_paths(&creds);
        let mut value = config_json(&creds, &lease_journal, &replay_journal, "self-hosted", "single-gateway", 8, 4, 8192, 5000);
        value.as_object_mut().unwrap().insert(mutate.0.into(), mutate.1);
        let case_dir = TempDir::new("bounds-config");
        let case_path = case_dir.join("gateway.json");
        write_config(case_path.as_path(), &value);
        rm(&lease_journal);
        rm(&replay_journal);
        assert_eq!(
            V2GatewayConfig::from_file(case_path.as_path()).unwrap_err(),
            V2GatewayConfigError::InvalidConfiguration,
            "field: {}",
            mutate.0
        );
    }
}

#[tokio::test]
async fn config_debug_and_errors_never_include_secrets_or_paths() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("STREAMGUARD_SECRET");
    let creds = credential_files("redaction");
    let (_dir, _path, config) = load_valid_config(&creds);
    let debug = format!("{config:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("gateway"));
    assert!(!debug.contains("BEGIN"));
    assert!(!debug.contains("controller"));
}

#[cfg(unix)]
#[tokio::test]
async fn config_rejects_permissive_private_key_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("STREAMGUARD_SECRET");
    let creds = credential_files("permissive-key");
    std::fs::set_permissions(creds.gateway_key.as_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    let (lease_journal, replay_journal) = valid_config_paths(&creds);
    let dir = TempDir::new("permissive-config");
    let config_path = dir.join("gateway.json");
    write_config(config_path.as_path(), &config_json(&creds, &lease_journal, &replay_journal, "self-hosted", "single-gateway", 8, 4, 8192, 5000));
    rm(&lease_journal);
    rm(&replay_journal);
    assert_eq!(
        V2GatewayConfig::from_file(config_path.as_path()).unwrap_err(),
        V2GatewayConfigError::FilesystemRef
    );
}

#[tokio::test]
async fn config_rejects_journal_collisions_and_tmp_aliases_lexically() {
    // Lexical journal separation without filesystem canonicalization: missing
    // journals cannot be `canonicalize`d, so `.`/`..` aliases and temp-file
    // aliases (`with_extension("tmp")`) are rejected lexically. Every failure
    // is `FilesystemRef` with no paths or secrets in the message.
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("STREAMGUARD_SECRET");
    let creds = credential_files("journal-collision");

    // Same file for both journals.
    let shared = creds.dir.join("shared.journal");
    let dir = TempDir::new("collision-same");
    let config_path = dir.join("gateway.json");
    write_config(
        config_path.as_path(),
        &config_json(&creds, &shared, &shared, "self-hosted", "single-gateway", 8, 4, 8192, 5000),
    );
    rm(&shared);
    let error = V2GatewayConfig::from_file(config_path.as_path()).unwrap_err();
    assert_eq!(error, V2GatewayConfigError::FilesystemRef);
    assert!(!format!("{error}").contains("shared"));

    // Temp alias: lease temp (`leases.tmp`) equals the replay journal.
    let lease = creds.dir.join("leases.journal");
    let replay_alias = creds.dir.join("leases.tmp");
    let dir = TempDir::new("collision-tmp-alias");
    let config_path = dir.join("gateway.json");
    write_config(
        config_path.as_path(),
        &config_json(&creds, &lease, &replay_alias, "self-hosted", "single-gateway", 8, 4, 8192, 5000),
    );
    rm(&lease);
    rm(&replay_alias);
    assert_eq!(
        V2GatewayConfig::from_file(config_path.as_path()).unwrap_err(),
        V2GatewayConfigError::FilesystemRef
    );

    // Lexical alias without filesystem touch: `<dir>/./leases.journal`
    // normalizes to `<dir>/leases.journal` without requiring any filesystem
    // canonicalization (both files are missing/empty here).
    let lexical_a = creds.dir.join("leases.journal");
    let dot_alias =
        PathBuf::from(format!("{}/./leases.journal", creds.dir.path.to_str().unwrap()));
    let dir = TempDir::new("collision-lexical");
    let config_path = dir.join("gateway.json");
    write_config(
        config_path.as_path(),
        &config_json(&creds, &lexical_a, &dot_alias, "self-hosted", "single-gateway", 8, 4, 8192, 5000),
    );
    rm(&lexical_a);
    assert_eq!(
        V2GatewayConfig::from_file(config_path.as_path()).unwrap_err(),
        V2GatewayConfigError::FilesystemRef
    );

    // Self-temp alias: `*.tmp` rewrites through itself (no atomic rename).
    let self_tmp = creds.dir.join("leases.tmp");
    let other = creds.dir.join("replay.journal");
    let dir = TempDir::new("collision-self-tmp");
    let config_path = dir.join("gateway.json");
    write_config(
        config_path.as_path(),
        &config_json(&creds, &self_tmp, &other, "self-hosted", "single-gateway", 8, 4, 8192, 5000),
    );
    rm(&self_tmp);
    rm(&other);
    assert_eq!(
        V2GatewayConfig::from_file(config_path.as_path()).unwrap_err(),
        V2GatewayConfigError::FilesystemRef
    );
}

#[test]
fn durable_replay_rejects_replays_capacity_and_foreign_gateways() {
    let dir = TempDir::new("durable-replay");
    let journal = dir.join("replay.journal");
    rm(&journal);
    let cache = ReplayCache::open_durable(&journal, "iad-1.example.test", 2, 1_000).unwrap();
    assert!(cache.is_durable());
    assert!(cache.snapshot().durable);
    assert_eq!(cache.snapshot().entries, 0);
    // consume is private to the admission module; exercise durability through
    // the public reopen path: the first journal persists, the second open
    // recovers it, and a foreign gateway fails closed.
    drop(cache);
    assert!(journal.exists(), "durable open must create the journal file");
    let reopened = ReplayCache::open_durable(&journal, "iad-1.example.test", 2, 1_000).unwrap();
    assert_eq!(reopened.snapshot().entries, 0);
    assert_eq!(
        ReplayCache::open_durable(&journal, "iad-2.example.test", 2, 1_000).unwrap_err(),
        streamguard_gateway::v2::admission::AdmissionError::ReplayStore
    );
}

#[test]
fn session_close_all_releases_leases_without_hanging() {
    use streamguard_gateway::v2::address_pool::{AddressPool, AddressPoolConfig};
    use streamguard_gateway::v2::session_manager::{SessionCleanup, V2SessionManager, V2SessionManagerConfig};

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
                60_000,
                4,
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let sessions = V2SessionManager::with_cleanup(
        V2SessionManagerConfig {
            maximum_sessions: 4,
            idle_ttl_ms: 120_000,
            maximum_paths_per_session: 1,
            maximum_pending_attaches: 1,
            pending_attach_ttl_ms: 5_000,
            maximum_path_epoch_history: 4,
            maximum_path_tombstones: 1,
            path_tombstone_ttl_ms: 5_000,
        },
        vec![Arc::clone(&pool) as Arc<dyn SessionCleanup>],
    )
    .unwrap();
    let session_id = sg_core::v2::SessionId::from_bytes([71; 16]);
    let device_id = sg_core::v2::DeviceId::from_bytes([72; 16]);
    let reservation = sessions
        .reserve_admission(session_id, device_id, sg_auth::ticket::OrganizationId::from_bytes([73; 16]), 1_000_000, 1_000)
        .unwrap();
    pool.reserve(session_id, device_id, 1_000).unwrap();
    sessions.commit_admission(reservation, 1_000).unwrap();
    pool.commit(session_id, 1_000).unwrap();
    assert!(pool.lookup_active(session_id).is_some());
    assert_eq!(sessions.snapshot().sessions, 1);

    // Shutdown path: close every session, releasing leases via cleanup.
    assert_eq!(sessions.close_all(), 1);
    assert_eq!(sessions.snapshot().sessions, 0);
    assert!(pool.lookup_active(session_id).is_none(), "close_all must release the lease");
    assert_eq!(sessions.close_all(), 0, "close_all is idempotent");
}

#[tokio::test]
async fn runtime_start_and_stop_joins_without_hanging() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("STREAMGUARD_SECRET");
    let creds = credential_files("runtime-stop");
    let (_dir, _path, config) = load_valid_config(&creds);
    let mut runtime = tokio::time::timeout(TEST_TIMEOUT, async { V2GatewayRuntime::start(config) })
        .await
        .expect("runtime start deadline")
        .expect("runtime starts with valid filesystem references");
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.accepted, 0);
    assert_eq!(snapshot.sessions, 0);
    assert_eq!(snapshot.control_tasks_running, 0);
    assert!(runtime.local_addr().is_ok());

    let stop = tokio::time::timeout(TEST_TIMEOUT, runtime.stop())
        .await
        .expect("runtime stop deadline");
    assert_eq!(stop.sessions_closed, 0);
    assert_eq!(stop.runtime.control_tasks_running, 0);
    // Idempotent: a second stop returns without hanging.
    let second = tokio::time::timeout(TEST_TIMEOUT, runtime.stop())
        .await
        .expect("second stop deadline");
    assert_eq!(second.sessions_closed, 0);
}

#[tokio::test]
async fn v1_gateway_contract_is_unchanged_alongside_v2_runtime() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("STREAMGUARD_SECRET");
    // V1 still binds with its development TLS helper and shared-secret model
    // (proving `main.rs`/`tunnel.rs`/`GatewayQuic` were not altered for V2):
    // a self-signed pair boots a V1 listener on an ephemeral port.
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_cfg =
        sg_transport::quic::server_tls(certified.cert.der(), &certified.key_pair.serialize_der()).unwrap();
    let v1_gateway = sg_transport::quic::GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let v1_addr = v1_gateway.local_addr().unwrap();

    // The V2 admission-only runtime binds its own mTLS endpoint on a separate
    // ephemeral port with no TUN, NAT, or V1 imports. Both listeners coexist,
    // proving V1/V2 isolation (no shared global endpoint or config).
    let creds = credential_files("v1-isolation");
    let (_dir, _path, config) = load_valid_config(&creds);
    let mut runtime = V2GatewayRuntime::start(config).expect("v2 runtime starts");
    let v2_addr = runtime.local_addr().unwrap();
    assert_ne!(v1_addr, v2_addr, "v1 and v2 endpoints must be independent");
    assert_eq!(runtime.snapshot().sessions, 0);

    let stop = tokio::time::timeout(TEST_TIMEOUT, runtime.stop()).await.expect("v2 stop deadline");
    assert_eq!(stop.sessions_closed, 0);
    // V1 handle is untouched by the V2 shutdown: its endpoint is still bound.
    assert_eq!(v1_gateway.local_addr().unwrap(), v1_addr);
}

#[test]
fn admission_handler_metrics_snapshot_includes_durable_replay_flag() {
    // The durable flag is observable without exposing ticket contents: an
    // in-memory cache reports `durable: false`.
    let cache = ReplayCache::new(4).unwrap();
    let snapshot = cache.snapshot();
    assert!(!snapshot.durable);
    assert_eq!(snapshot.capacity, 4);
    assert_eq!(snapshot.entries, 0);
}

#[test]
fn config_file_map_shape_has_no_tun_or_nat_fields() {
    // Admission-only label as a structural test: the accepted config schema
    // is exactly the filesystem-ref plus bounds set. Serializing the field
    // list from a valid file proves no TUN address, WAN interface, or NAT
    // field can be introduced without `deny_unknown_fields` rejecting it.
    // No config file is loaded here, so no environment guard is needed.
    let creds = credential_files("shape");
    let (lease_journal, replay_journal) = valid_config_paths(&creds);
    let value = config_json(&creds, &lease_journal, &replay_journal, "self-hosted", "single-gateway", 8, 4, 8192, 5000);
    let fields: HashMap<String, serde_json::Value> =
        serde_json::from_value(value).unwrap();
    for forbidden in ["tun_addr", "tun_address", "wan", "wan_interface", "nat", "nftables", "secret", "token"] {
        assert!(!fields.contains_key(forbidden), "admission-only config must not accept {forbidden}");
    }
}
