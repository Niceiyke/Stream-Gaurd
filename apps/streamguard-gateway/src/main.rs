//! StreamGuard gateway (Linux).
//!
//! Responsibilities (spec section 15): authenticate client, associate
//! multiple paths with a session, sequence/deduplicate/reorder, inject
//! client IP packets into the gateway TUN, forward/NAT to the Internet,
//! capture return traffic, expose telemetry. Gateway must not transcode video.
//!
//! Scaffold: loads configuration and starts the (empty for now) path
//! registry. Real transport/session/NAT arrives with the Linux gateway
//! milestone.

use sg_core::{SessionId, path_registry::PathRegistry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("streamguard-gateway starting (scaffold)");

    let session = SessionId::new();
    let mut registry = PathRegistry::default();
    registry.register(session);
    tracing::info!(
        session = ?session,
        paths = registry.paths_for(session).len(),
        "gateway ready (scaffold)"
    );
    Ok(())
}