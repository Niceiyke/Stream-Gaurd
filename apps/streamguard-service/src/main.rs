//! StreamGuard networking service (client engine).
//!
//! Runs as a privileged background process separate from the UI
//! (spec 22): adapter administration, route changes, persistence, crash
//! isolation and privilege separation live here.
//!
//! CLI surface (spec 22 / 22.5):
//! - `STREAMGUARD_ADDR`        gateway QUIC endpoint (default 127.0.0.1:12423).
//! - `STREAMGUARD_SECRET`      shared HMAC secret — required; mints the
//!   bootstrap ticket the gateway verifies (spec 22 handshake).
//! - `STREAMGUARD_SESSION`     optional session wire-prefix as hex u32
//!   (default: freshly generated random id).
//! - `STREAMGUARD_CERT_DIR`    directory holding the gateway's `cert.der`
//!   trust anchor (default ./sgcerts; same dir the gateway publishes).
//! - `STREAMGUARD_SERVER_NAME` TLS SNI / cert CN to expect (default localhost
//!   — matches the gateway's generated cert).
//! - `STREAMGUARD_DEV`         any value -> in-memory TUN dev simulation
//!   instead of bailing when the native adapter is unavailable.
//! - `STREAMGUARD_PRINT_TICKET` any value -> log the bootstrap ticket and
//!   drop the TEMP hint like dev does (opt-in convenience for the run-real
//!   launcher; never on in production).
//! - `STREAMGUARD_TUN_ADDR`     IPv4 address for this host's TUN adapter
//!   (default 10.0.85.1; the real launcher assigns the client 10.0.85.2 so
//!   one host can ride gateway + client without an address clash).
//! - `WINTUN_DLL`               optional path override passed to tun-rs
//!   (Windows only; otherwise `wintun.dll` is loaded from the working dir).
//! - `STREAMGUARD_PIPE`        status-server named pipe (Windows; default
//!   `\\.\pipe\streamguard-status`). Non-Windows hosts use loopback TCP
//!   127.0.0.1:9100 instead.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use sg_core::{PathId, SessionId};
use sg_network::{InterfaceScanner, NullScanner, PathMap, RealScanner};
use sg_session::session_id_from_wire;
use sg_transport::quic::client_tls;
use sg_tun::{LoopbackTun, Tun, TunConfig};

/// `sg_tun::create` returns `Box<dyn Tun>` without a `Send` bound; the
/// client engine needs `T: Tun + Send + 'static`. Both concrete adapters the
/// service can produce are Send (see the gateway's `AnyTun` for the full
/// reasoning): `LoopbackTun` owns `Bytes` queues and `PlatformTun` owns a
/// `tun_rs::SyncDevice` (OS handle + lock guard) driven through `Arc` by its
/// own blocking thread.
///
/// # Safety
/// `Tun` is a `&mut self` interface, so the engine never touches the
/// wrapped adapter from two threads at once; the single-owner contract of
/// both concrete adapters and their OS handles is preserved.
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

    tracing::info!("streamguard-service starting");

    // --- Trust anchor (spec 15.5) ---------------------------------------
    // The gateway publishes self-signed `cert.der` into its cert dir; the
    // service reads the same file as the QUIC client trust anchor. Running
    // the gateway once is enough to materialize it.
    let cert_dir = std::env::var("STREAMGUARD_CERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./sgcerts"));
    let cert_path = cert_dir.join("cert.der");
    let cert_der = std::fs::read(&cert_path).with_context(|| {
        format!(
            "reading client trust anchor {}; run the gateway first or copy its cert.der",
            cert_path.display()
        )
    })?;

    // --- Shared secret -> bootstrap ticket (spec 22 handshake) -----------
    let secret = std::env::var("STREAMGUARD_SECRET").context(
        "STREAMGUARD_SECRET is required (the gateway verifies sessions minted with the same secret)",
    )?;
    let session = match std::env::var("STREAMGUARD_SESSION") {
        Ok(hex) => {
            let prefix = u32::from_str_radix(hex.trim_start_matches("0x"), 16)
                .context("STREAMGUARD_SESSION must be hex, e.g. 0xfeedbeef")?;
            session_id_from_wire(prefix)
        }
        Err(_) => {
            // Only the 4-byte wire prefix crosses the tunnel (spec 3), so the
            // full id must be zero-tailed (`session_id_from_wire`) or the
            // gateway's accredited id never matches ours. Derive a random
            // prefix from a fresh id and rebuild it zero-tailed.
            session_id_from_wire(streamguard_service::status::session_prefix(SessionId::new()))
        }
    };
    let token = sg_auth::issue(secret.as_bytes(), session, 3600);
    tracing::info!(
        session_prefix = %format!("{:08x}", streamguard_service::status::session_prefix(session)),
        token_len = token.len(),
        "bootstrap ticket minted (1h TTL)"
    );
    // Dev simulation prints the ticket once so a local status shell can be
    // launched with `--token <this>`; production never logs the token value.
    // `STREAMGUARD_PRINT_TICKET` opts the real launcher (`run-real.ps1 -Shell`)
    // into the same convenience — still never default-on.
    if std::env::var_os("STREAMGUARD_DEV").is_some() || std::env::var_os("STREAMGUARD_PRINT_TICKET").is_some() {
        let prefix = streamguard_service::status::session_prefix(session);
        tracing::info!("dev status-shell ticket: {token}");
        // Also drop credential hints in TEMP so `run-dev.ps1 -Shell` can
        // launch the shell with zero copying (dev-only; the ticket is
        // short-lived and scoped to this simulated session).
        let hint = format!("{token}\n{:08x}\n", prefix);
        let _ = std::fs::write(
            std::env::temp_dir().join("streamguard-dev-ticket.txt"),
            hint.as_bytes(),
        );
    }

    // --- Interface discovery -> physical paths (spec 7/8) ----------------
    // Real platform adapters when available; the scanner falls back to an
    // empty NullScanner (dev hosts / unsupported platforms).
    let interfaces = match RealScanner.list() {
        Ok(ifaces) => ifaces,
        Err(err) => {
            tracing::warn!(error = %err, "RealScanner failed; falling back to NullScanner");
            NullScanner.list()?
        }
    };
    // Highest-confidence physical paths first: Up, not loopback/virtual, and
    // carrying a default gateway (spec 7 "route suitability" — a path that
    // cannot reach the internet is useless). Hyper-V/WSL/VirtualBox adapters
    // report as Ethernet on Windows, so relying on `kind` alone leaks dozens
    // of virtual bridges into the path table; the gateway + loopback filter
    // is the reliable discriminator. Shared with the engine's rescan loop so
    // both use the exact same candidate rule (extracted to client.rs).
    let chosen: Vec<&sg_network::Interface> =
        streamguard_service::client::filter_candidates(&interfaces);
    if chosen.is_empty() {
        anyhow::bail!(
            "no network interfaces discovered; cannot build bound paths \
             (native adapter scan needed on real platforms)"
        );
    }
    let mut path_map = PathMap::new();
    let mut path_ids = Vec::with_capacity(chosen.len());
    let mut path_interfaces = Vec::with_capacity(chosen.len());
    // Friendly interface names per path for the status dashboard ("Wi-Fi",
    // "Ethernet", …). Pushed into the handle after `start()` so the rescan
    // loop and the status plane share them (spec 21 path rows).
    let mut path_names: HashMap<PathId, String> = HashMap::new();
    // Dev simulation talks to a 127.0.0.1 gateway; per-NIC bound sockets
    // cannot route to loopback, so dev forces unbound paths (spec 8).
    let dev_binding_free = std::env::var_os("STREAMGUARD_DEV").is_some();
    for iface in chosen {
        let path = path_map.id_for(iface);
        path_ids.push(path);
        path_names.insert(path, iface.id.clone());
        // index 0 means "no reportable index" on that platform -> unbound.
        // Effective per-interface binding only when NOT in dev simulation.
        path_interfaces.push(
            if dev_binding_free {
                None
            } else {
                (iface.ifindex != 0).then_some(iface.ifindex)
            },
        );
        tracing::info!(
            iface = %iface.name,
            ifindex = iface.ifindex,
            kind = ?iface.kind,
            path = path.get(),
            bound = !dev_binding_free,
            "path ready"
        );
    }

    // --- TUN (spec 22.5) -------------------------------------------------
    // The engine drives real adapters from a dedicated OS thread; without
    // `native-tun` or a driver the binary only runs in dev simulation.
    // `STREAMGUARD_TUN_ADDR` lets the real launcher give the client side of
    // the tunnel its own address on the gateway subnet (spec 26.5).
    let tun_cfg = TunConfig {
        address: std::env::var("STREAMGUARD_TUN_ADDR")
            .unwrap_or_else(|_| String::from("10.0.85.1")),
        ..TunConfig::default()
    };
    let tun = match sg_tun::create(&tun_cfg) {
        Ok(tun) => tun,
        Err(err) if std::env::var_os("STREAMGUARD_DEV").is_some() => {
            tracing::warn!(
                error = %err,
                "native TUN unavailable; dev simulation (LoopbackTun). \
                 Build with --features sg-tun/native-tun and provide Wintun for a real adapter"
            );
            Box::new(LoopbackTun::with_config(tun_cfg.clone()))
        }
        Err(err) => {
            return Err(err).with_context(|| {
                if std::env::var_os("WINTUN_DLL").is_none() {
                    "native TUN backend unavailable; set STREAMGUARD_DEV=1 for the \
                     in-memory dev adapter, or build --features sg-tun/native-tun \
                     and provide wintun.dll"
                } else {
                    "native TUN backend unavailable despite WINTUN_DLL being set"
                }
            });
        }
    };
    let any_tun = AnyTun(tun);
    tracing::info!(iface = any_tun.name(), mtu = any_tun.mtu(), "tun adapter ready");

    if let Ok(dll) = std::env::var("WINTUN_DLL") {
        tracing::info!(dll, "wintun driver override in effect");
    }

    let addr: SocketAddr = std::env::var("STREAMGUARD_ADDR")
        .unwrap_or_else(|_| String::from("127.0.0.1:12423"))
        .parse()
        .context("STREAMGUARD_ADDR must be host:port")?;
    let server_name =
        std::env::var("STREAMGUARD_SERVER_NAME").unwrap_or_else(|_| String::from("localhost"));
    let server_name_log = server_name.clone();

    // Status plane (spec 22 status endpoint): Windows serves a named pipe
    // (Tauri/Wordlyte consume it); every other host uses loopback TCP.
    #[cfg(windows)]
    let status_endpoint = {
        let pipe = std::env::var("STREAMGUARD_PIPE")
            .unwrap_or_else(|_| String::from(r"\\.\pipe\streamguard-status"));
        streamguard_service::ipc::StatusEndpoint::NamedPipe(pipe)
    };
    #[cfg(not(windows))]
    let status_endpoint = {
        let _ = std::env::var("STREAMGUARD_PIPE"); // accepted but only honored on Windows
        streamguard_service::ipc::StatusEndpoint::Tcp("127.0.0.1:9100".parse()?)
    };

    let mut handle = streamguard_service::client::start(
        any_tun,
        streamguard_service::client::ClientOptions {
            addr,
            path_interfaces,
            server_name,
            client_config: client_tls(&cert_der).context("building QUIC client TLS")?,
            keepalive_interval: Duration::from_secs(20),
            probe_interval: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(1),
            probe_failure_threshold: 2,
            redundancy_loss_threshold: 0.10,
        },
        session,
        &path_ids,
        &token,
        Some(status_endpoint),
    )
    .await
    .context("starting the client engine (is the gateway up?)")?;

    // Publish the friendly interface names for the status dashboard (spec 21
    // path rows). The rescan loop updates this map as interfaces appear and
    // disappear; the initial set is what the user sees at startup.
    handle.set_path_names(path_names).await;

    tracing::info!(
        gateway = %addr,
        server_name = %server_name_log,
        paths = handle.counters().await.paths,
        "service ready; awaiting shutdown"
    );

    tokio::signal::ctrl_c().await.context("awaiting Ctrl-C")?;
    tracing::info!("shutdown signal received; tearing down");
    handle.stop().await;
    tracing::info!("streamguard-service stopped");
    Ok(())
}