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

use sg_core::{SessionId, path_registry::PathRegistry};
use sg_platform::{Os, gateway_net::GatewayNetConfig};
use sg_tun::{LoopbackTun, Tun, TunConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("streamguard-gateway starting");

    let tun_cfg = TunConfig::default();
    let tun: Box<dyn Tun> = match sg_tun::create(&tun_cfg) {
        Ok(tun) => tun,
        Err(err) if std::env::var_os("STREAMGUARD_DEV").is_some() => {
            tracing::warn!(error = %err, "native TUN unavailable; dev simulation (LoopbackTun)");
            Box::new(LoopbackTun::with_config(tun_cfg.clone()))
        }
        Err(err) => return Err(err.into()),
    };
    tracing::info!(iface = tun.name(), mtu = tun.mtu(), "tun adapter ready");

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

    let session = SessionId::new();
    let mut registry = PathRegistry::default();
    registry.register(session);
    tracing::info!(
        session = ?session,
        paths = registry.paths_for(session).len(),
        "gateway ready"
    );
    Ok(())
}