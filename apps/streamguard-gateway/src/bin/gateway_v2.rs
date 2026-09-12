//! Admission-only V2 gateway entrypoint (opt-in `v2-gateway` feature).
//!
//! This binary runs the V2 mTLS admission plane only: device handshake,
//! controller-ticket verification with the durable single-gateway redemption
//! journal, bounded session/path admission, self-hosted atomic lease
//! allocation, and reliable control streams. It performs no TUN I/O, no flow
//! forwarding, no NAT/firewall programming, and no V1 tunnel work by
//! construction (none of those modules are imported here).
//!
//! Configuration is a JSON file of strict-permission Linux filesystem
//! references (never inline secrets):
//!
//! - `--config <path>` wins, else `STREAMGUARD_V2_CONFIG`.
//! - Any `STREAMGUARD_SECRET` environment value present refuses startup: the
//!   V1 static shared secret is never a production credential.
//! - Absent, malformed, symlink, or permissively permissioned references fail
//!   closed. Errors and logs never include secrets, tickets, certificates,
//!   or filesystem paths.

use std::path::PathBuf;

use anyhow::Context as _;
use streamguard_gateway::v2::config::V2GatewayConfig;
use streamguard_gateway::v2::runtime::V2GatewayRuntime;

fn usage() -> &'static str {
    "streamguard-gateway-v2 (admission-only; no TUN/NAT)\n\nUSAGE:\n    streamguard-gateway-v2 --config <path>\n\nENV:\n    STREAMGUARD_V2_CONFIG    config file path when --config is absent\n\nThe config file holds strict-permission filesystem references only. Any\nSTREAMGUARD_SECRET value present refuses startup."
}

fn resolve_config_path(args: &[String]) -> anyhow::Result<PathBuf> {
    let mut config: Option<PathBuf> = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                let value = args.get(index).context("missing value for --config")?;
                if config.is_some() {
                    anyhow::bail!("duplicate --config");
                }
                if value.is_empty() {
                    anyhow::bail!("--config must not be empty");
                }
                config = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                println!("{usage}", usage = usage());
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
        index += 1;
    }
    if let Some(path) = config {
        return Ok(path);
    }
    std::env::var("STREAMGUARD_V2_CONFIG")
        .map(PathBuf::from)
        .context("no --config and STREAMGUARD_V2_CONFIG is absent")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("streamguard-gateway-v2 starting (admission-only; no TUN/NAT)");
    if std::env::var_os("STREAMGUARD_SECRET").is_some() {
        // Fail closed without logging any secret value.
        anyhow::bail!("refusing to start with STREAMGUARD_SECRET set");
    }

    let args: Vec<String> = std::env::args().collect();
    let config_path = resolve_config_path(&args).context("resolving V2 gateway config")?;
    let config = V2GatewayConfig::from_file(&config_path).context("loading V2 gateway config")?;

    let mut runtime = V2GatewayRuntime::start(config).context("starting V2 admission runtime")?;
    tracing::info!(addr = %runtime.local_addr().context("reading V2 listener address")?, "v2 admission listener bound");

    tokio::select! {
        () = runtime.run() => {
            tracing::info!("v2 admission loop exited");
        }
        result = tokio::signal::ctrl_c() => {
            result.context("awaiting shutdown signal")?;
            tracing::info!("shutdown signal received; stopping admission runtime");
        }
    }

    // Graceful shutdown joins control tasks and sweeps, closes every session
    // (releasing leases via cleanup), and closes the endpoint. Idempotent.
    let stop = runtime.stop().await;
    tracing::info!(
        accepted = stop.runtime.accepted,
        refused_full = stop.runtime.refused_full,
        sessions_closed = stop.sessions_closed,
        "streamguard-gateway-v2 stopped"
    );
    Ok(())
}
