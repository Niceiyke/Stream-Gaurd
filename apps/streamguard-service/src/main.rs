//! StreamGuard networking service (client engine).
//!
//! Runs as a privileged background process separate from the UI
//! (spec section 22): adapter administration, route changes, persistence,
//! crash isolation and privilege separation live here.
//!
//! Scaffold: wires the crates together and exercises the core types
//! without opening real adapters or sockets yet.

use sg_core::{Config, SessionId};
use sg_health::DefaultScorer;
use sg_multipath::{Sequencer, default_reorder_window};
use sg_network::{InterfaceScanner, NullScanner, PathMap};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("streamguard-service starting (scaffold)");

    let cfg = Config::default();
    tracing::info!(
        session = ?SessionId::new(),
        gateway = %cfg.session.gateway_host,
        port = cfg.session.gateway_port,
        "loaded configuration"
    );

    let mut path_map = PathMap::new();
    let scanner = NullScanner;
    let interfaces = scanner.list()?;
    tracing::info!(count = interfaces.len(), "discovered interfaces (scaffold)");
    for iface in &interfaces {
        let path = path_map.id_for(iface);
        tracing::info!(iface = %iface.name, path = path.get(), "mapped interface to path");
    }

    let scorer = DefaultScorer::default();
    let _ = scorer;

    let mut sequencer = Sequencer::new();
    let _ = sequencer.next_sequence();

    let mut window = default_reorder_window();
    let first = sequencer.next_sequence();
    let _ = window.accept(first);

    tracing::info!(
        phase = "active-standby",
        tun_mtu = sg_tun::TunConfig::default().mtu,
        "service ready (scaffold)"
    );
    Ok(())
}