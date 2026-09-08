//! StreamGuard Tauri v2 desktop status shell (spec 22 "Desktop Service",
//! engineering step 12 "Desktop status UI"). A *thin client*: the privileged
//! engine service (spec 22.5) publishes an authenticated `StatusSnapshot`
//! over named pipe / loopback TCP; this window is only a viewer that polls it.
//!
//! The single invariant this binary owns: never panic when the service is
//! absent. If no IPC endpoint / token / session prefix is supplied (CLI args
//! or env vars), the managed state is left unset and the `status_snapshot`
//! command reports "service not connected" — the UI renders an offline card
//! instead of crashing.

use std::env;
use std::sync::Mutex;

use streamguard_service::ipc::{StatusClient, StatusEndpoint};
use tauri::State;

/// Bounded reconnect/backoff knobs for the status plane (spec 22.5 worker
/// pool). These mirror the engine client's own tolerances; the engine's
/// `StatusClient::connect()` also performs its own bounded open-retry.
const RETRY_ATTEMPTS: usize = 2;
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Resolved IPC destination (endpoint + token + session prefix) supplied at
/// startup. `token` and `prefix` are required to bind the HMAC challenge so
/// the UI cannot connect without both.
struct UiConfig {
    endpoint: StatusEndpoint,
    token: String,
    session_prefix: u32,
    /// Human-readable description of the destination for the offline label.
    label: String,
}

/// Managed Tauri state. `config: None` means "service not connected" — the UI
/// must degrade gracefully, never panic.
struct UiState {
    config: Option<UiConfig>,
}

/// Tauri manages exactly one of these; `status_snapshot` clones the client
/// config out from under a short-lived lock, then does the async work.
struct UiStateWrap(Mutex<UiState>);

/// Read one `StatusSnapshot` from the engine and return it as JSON.
///
/// Every call opens a *fresh* authenticated connection and requests a single
/// snapshot. The engine server caps each connection at
/// `MAX_SNAPSHOTS_PER_CONNECTION`; on the boundary the server closes and the
/// next read EIOs — so on a read error we reconnect once and retry (T1 quota
/// semantics). Errors carry only the failure text; the auth token is never
/// logged or returned.
#[tauri::command]
async fn status_snapshot(state: State<'_, UiStateWrap>) -> Result<serde_json::Value, String> {
    let client = {
        let guard = state.0.lock().map_err(|_| "state poisoned".to_string())?;
        let cfg = guard
            .config
            .as_ref()
            .ok_or_else(|| "service not connected".to_string())?;
        StatusClient::new(cfg.endpoint.clone(), cfg.token.clone(), cfg.session_prefix)
    };

    let mut session = client
        .connect()
        .await
        .map_err(|e| format!("connect: {e}"))?;
    match session.snapshot().await {
        Ok(snapshot) => serde_json::to_value(snapshot).map_err(|e| e.to_string()),
        Err(first_err) => {
            // Quota-close (or a transient pipe reset): reconnect, bounded.
            for attempt in 0..RETRY_ATTEMPTS {
                if attempt > 0 {
                    tokio::time::sleep(RETRY_BACKOFF).await;
                }
                let mut retry = match client.connect().await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                match retry.snapshot().await {
                    Ok(snapshot) => {
                        return serde_json::to_value(snapshot).map_err(|e| e.to_string())
                    }
                    Err(_) => continue,
                }
            }
            Err(format!("first: {first_err}; reconnects exhausted"))
        }
    }
}

/// Assemble a connection plan from CLI args, falling back to env vars.
///
/// CLI: `--pipe <name>`, `--port <u16>`, `--token <string>`,
/// `--session-prefix <u32 hex>` (a leading `0x` is accepted). Env fallbacks:
/// `STREAMGUARD_STATUS_PIPE` / `STREAMGUARD_STATUS_PORT` /
/// `STREAMGUARD_TOKEN` / `STREAMGUARD_SESSION_PREFIX`. A CLI flag beats the
/// matching env var. `None` when no destination or no credentials resolve.
fn resolve_config() -> Option<UiConfig> {
    let args: Vec<String> = env::args().collect();

    let mut pipe: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut token: Option<String> = None;
    let mut prefix: Option<u32> = None;

    let mut i = 1;
    while i < args.len() {
        // Consumed-arguments count for this iteration (a flag + its value).
        let take = match args[i].as_str() {
            "--pipe" => {
                pipe = args.get(i + 1).cloned();
                2
            }
            "--port" => {
                port = args.get(i + 1).and_then(|s| s.parse().ok());
                2
            }
            "--token" => {
                token = args.get(i + 1).cloned();
                2
            }
            "--session-prefix" => {
                prefix = args.get(i + 1).and_then(|s| parse_hex_u32(s));
                2
            }
            _ => 1,
        };
        i += take;
    }

    pipe = pipe.or_else(|| env::var("STREAMGUARD_STATUS_PIPE").ok());
    port = port.or_else(|| {
        env::var("STREAMGUARD_STATUS_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
    });
    token = token.or_else(|| env::var("STREAMGUARD_TOKEN").ok());
    prefix = prefix.or_else(|| {
        env::var("STREAMGUARD_SESSION_PREFIX")
            .ok()
            .and_then(|s| parse_hex_u32(&s))
    });

    // Both credentials are mandatory: the HMAC challenge is bound to the
    // session prefix, so a UI without the token or prefix cannot authenticate.
    let token = token?;
    let session_prefix = prefix?;

    let (endpoint, label) = make_endpoint(pipe, port)?;
    Some(UiConfig {
        endpoint,
        token,
        session_prefix,
        label,
    })
}

/// Resolve the transport endpoint: prefer a Windows named pipe, otherwise a
/// loopback TCP port (spec 22.5).
#[cfg(windows)]
fn make_endpoint(pipe: Option<String>, port: Option<u16>) -> Option<(StatusEndpoint, String)> {
    if let Some(name) = pipe {
        return Some((
            StatusEndpoint::NamedPipe(name.clone()),
            format!("pipe {name}"),
        ));
    }
    if let Some(p) = port {
        let addr = format!("127.0.0.1:{p}");
        let parsed = addr.parse().expect("loopback address is syntactically valid");
        return Some((StatusEndpoint::Tcp(parsed), format!("tcp 127.0.0.1:{p}")));
    }
    None
}

/// Non-Windows builds have no named-pipe transport; only loopback TCP.
#[cfg(not(windows))]
fn make_endpoint(_pipe: Option<String>, port: Option<u16>) -> Option<(StatusEndpoint, String)> {
    if let Some(p) = port {
        let addr = format!("127.0.0.1:{p}");
        let parsed = addr.parse().expect("loopback address is syntactically valid");
        return Some((StatusEndpoint::Tcp(parsed), format!("tcp 127.0.0.1:{p}")));
    }
    None
}

/// Parse a `u32` from decimal or hexadecimal. An explicit `0x`/`0X` prefix
/// forces hex; otherwise decimal is tried first and hex is the fallback (the
/// engine emits bare 8-hex-digit prefixes, e.g. `346100b7`).
fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.trim();
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
            .or_else(|_| u32::from_str_radix(s, 16))
    };
    parsed.ok()
}

fn main() {
    let config = resolve_config();
    match &config {
        Some(c) => {
            // Only the destination's shape is logged — never the token.
            eprintln!("streamguard-desktop: connected to {}", c.label);
        }
        None => eprintln!("streamguard-desktop: service not connected (no endpoint/credentials)"),
    }

    let state = UiStateWrap(Mutex::new(UiState { config }));

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![status_snapshot])
        .run(tauri::generate_context!())
        .expect("error while running StreamGuard desktop shell");
}
