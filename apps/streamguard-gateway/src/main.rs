//! StreamGuard gateway (Linux by default).
//!
//! Responsibilities (spec section 15): authenticate client, associate
//! multiple paths with a session, sequence/deduplicate/reorder, inject
//! client IP packets into the gateway TUN, forward/NAT to the Internet,
//! capture return traffic, expose telemetry. Gateway must not transcode video.
//!
//! Engineering step 2 (Linux): real TUN adapter on the platform, kernel
//! forwarding + nftables masquerade for the client subnet. Without the
//! `native-tun` feature the binary falls back to an in-memory TUN when
//! `STREAMGUARD_DEV` is set, so the scaffold runs on any host.
//!
//! CLI surface (spec 15 / 22):
//! - `STREAMGUARD_CERT_DIR`     directory holding `cert.der` + `key.der`
//!   (default `./sgcerts`; a self-signed pair is generated on first run —
//!   copy `cert.der` to the service host so it can trust this gateway).
//! - `STREAMGUARD_SECRET`       shared HMAC secret the service mints
//!   bootstrap tickets with (spec 22 handshake) — required.
//! - `STREAMGUARD_PORT`         QUIC listener port (default 12423).
//! - `STREAMGUARD_WAN`          WAN interface for NAT planning (default eth0).
//! - `STREAMGUARD_TUN_ADDR`     IPv4 address for the gateway TUN (default
//!   10.0.85.1, spec 26.5; override only to dodge a client-address clash
//!   during same-host real testing).
//! - `STREAMGUARD_DEV`          any value -> in-memory TUN fallback.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use sg_core::{SessionId, path_registry::PathRegistry};
use sg_platform::{Os, gateway_net::GatewayNetConfig};
use sg_transport::quic::{GatewayQuic, server_tls};
use sg_tun::{LoopbackTun, Tun, TunConfig};

/// `sg_tun::create` returns `Box<dyn Tun>` without a `Send` bound, but
/// `tunnel::start` (and the client engine) need `T: Tun + Send + 'static`.
/// Both concrete adapters this binary can produce are in fact Send:
///
/// - `LoopbackTun` owns only `Bytes` queues (plain `Vec`s — Send).
/// - `PlatformTun` owns a `tun_rs::SyncDevice`: on Windows that is an
///   `RwLock<()>` guard plus an owned Wintun session handle, on Unix a file
///   descriptor — all `Send`; the device is additionally driven through
///   `Arc` by its own blocking thread in the engine.
///
/// # Safety
/// `Tun` is a `&mut self` interface, so the engine never calls `read` or
/// `write` from two threads at once; handing the wrapped adapter to the
/// engine's spawned tasks preserves the single-owner contract of both
/// concrete adapters and the OS handles inside them.
struct AnyTun(Box<dyn Tun>);

unsafe impl Send for AnyTun {}

impl Tun for AnyTun {
    fn read(&mut self, buf: &mut [u8]) -> sg_core::error::Result<usize> {
        self.0.read(buf)
    }

    fn write(&mut self, packet: &[u8]) -> sg_core::error::Result<usize> {
        self.0.write(packet)
    }

    fn name(&self) -> &str {
        self.0.name()
    }

    fn mtu(&self) -> u32 {
        self.0.mtu()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("streamguard-gateway starting");

    let tun_cfg = TunConfig {
        address: std::env::var("STREAMGUARD_TUN_ADDR")
            .unwrap_or_else(|_| String::from("10.0.85.1")),
        ..TunConfig::default()
    };
    let tun: Box<dyn Tun> = match sg_tun::create(&tun_cfg) {
        Ok(tun) => tun,
        Err(err) if std::env::var_os("STREAMGUARD_DEV").is_some() => {
            tracing::warn!(error = %err, "native TUN unavailable; dev simulation (LoopbackTun)");
            Box::new(LoopbackTun::with_config(tun_cfg.clone()))
        }
        Err(err) => return Err(err.into()),
    };
    let any_tun = AnyTun(tun);
    tracing::info!(iface = any_tun.name(), mtu = any_tun.mtu(), "tun adapter ready");

    // Kernel forwarding + NAT planning is Linux-only today; dev hosts just
    // log the plan (engineering step 2).
    let wan = std::env::var("STREAMGUARD_WAN").unwrap_or_else(|_| String::from("eth0"));
    let net = GatewayNetConfig::tun(&tun_cfg, wan, vec!["1.1.1.1".into(), "1.0.0.1".into()]);
    for cmd in net.plan() {
        tracing::info!(command = %cmd, "gateway net plan");
    }
    if Os::current() == Os::Linux {
        net.apply()?;
        tracing::info!("kernel forwarding + nftables NAT applied");
    } else {
        tracing::warn!(
            platform = Os::current().name(),
            "gateway net apply is Linux-only; skipped in dev mode"
        );
    }

    // Shared secret with the client service (spec 22 handshake). The service
    // mints bootstrap tickets with the same secret, so a gateway without it
    // cannot authenticate anyone.
    let secret = std::env::var("STREAMGUARD_SECRET").context(
        "STREAMGUARD_SECRET is required (the service mints sessions with the same secret)",
    )?;

    // Trust anchor pair (spec 15.5): load existing, else mint + persist a
    // self-signed pair so both ends can be booted end-to-end on first run.
    let cert_dir = std::env::var("STREAMGUARD_CERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./sgcerts"));
    let (cert_der, key_der) = load_or_create_cert(&cert_dir)?;

    let port: u16 = std::env::var("STREAMGUARD_PORT")
        .unwrap_or_else(|_| String::from("12423"))
        .parse()
        .context("STREAMGUARD_PORT must be a u16 port number")?;

    let server_cfg = server_tls(&cert_der, &key_der).context("building QUIC server TLS")?;
    let gateway =
        GatewayQuic::bind(format!("0.0.0.0:{port}").parse().context("parsing bind address")?, server_cfg)
            .context("binding QUIC listener")?;
    tracing::info!(addr = %gateway.local_addr()?, "gateway QUIC listener bound");

    let session = SessionId::new();
    let mut registry = PathRegistry::default();
    registry.register(session);
    tracing::info!(
        session = ?session,
        paths = registry.paths_for(session).len(),
        "gateway ready; waiting for client connections"
    );

    let mut handle = streamguard_gateway::tunnel::start(any_tun, gateway, secret.into_bytes()).await;
    tokio::signal::ctrl_c().await.context("awaiting Ctrl-C")?;
    tracing::info!("shutdown signal received; tearing down");
    handle.stop().await;
    tracing::info!("streamguard-gateway stopped");
    Ok(())
}

/// Loads `cert.der`/`key.der` from `dir`, or generates a fresh self-signed
/// pair on first run and persists both files (spec 15.5 "gateway trust
/// anchor": the client trusts the same `cert.der`).
fn load_or_create_cert(dir: &Path) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let cert_path = dir.join("cert.der");
    let key_path = dir.join("key.der");
    if let (Ok(cert), Ok(key)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
        tracing::info!(cert = %cert_path.display(), "loaded existing gateway certificate");
        return Ok((cert, key));
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating cert dir {}", dir.display()))?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .context("generating self-signed gateway certificate")?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();
    std::fs::write(&cert_path, &cert_der)
        .with_context(|| format!("writing {}", cert_path.display()))?;
    std::fs::write(&key_path, &key_der)
        .with_context(|| format!("writing {}", key_path.display()))?;
    tracing::info!(
        cert = %cert_path.display(),
        "generated self-signed gateway certificate; copy cert.der to the service host"
    );
    Ok((cert_der, key_der))
}