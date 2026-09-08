# StreamGuard Desktop (V1 Tauri status shell)

Thin-client status UI for the StreamGuard privileged engine service (spec
§22 "Desktop Service", engineering step 12 "Desktop status UI"). The engine
runs as a separate, privileged background service and publishes an
**authenticated** `StatusSnapshot` over Windows named pipe or loopback TCP
(spec 22.5). This shell is only a viewer: it polls `status_snapshot` every
2 s and renders the snapshot.

This crate is intentionally **not** a member of the root Cargo workspace
(root `Cargo.toml` has `exclude = ["desktop"]`), so a broken UI build can
never affect the engine gates (`cargo check/test/clippy --workspace`).
It keeps its own `Cargo.lock` and toolchain.

## Prerequisites

- **Rust stable** (1.85+; the engine lib the shell links to requires 1.85).
- **Node.js / npm** — *optional*; only needed if you use the npm-installed
  Tauri CLI instead of `cargo install`. The frontend is plain static
  `HTML/JS/CSS` with **no build step** (`build.frontendDist = ../ui`).
- The Tauri v2 Linux/webview2 system deps for your platform (WebView2 on
  Windows ships with the OS).

## Install the Tauri CLI (one of)

```powershell
# Option A: cargo
cargo install tauri-cli

# Option B: npm (global)
npm install -g @tauri-apps/cli
```

## Run (dev)

From this directory (`desktop/`), the engine service must already be
publishing a status endpoint. Point the shell at it with CLI args or env:

```powershell
# Windows named pipe + token:
cargo tauri dev -- --pipe \\.\pipe\streamguard-status --token <ticket> --session-prefix 0x1a2b3c4d

# Or loopback TCP + token:
cargo tauri dev -- --port 9100 --token <ticket> --session-prefix 0x1a2b3c4d
```

You may instead set the environment variables
`STREAMGUARD_STATUS_PIPE` / `STREAMGUARD_STATUS_PORT` /
`STREAMGUARD_TOKEN` / `STREAMGUARD_SESSION_PREFIX` (CLI args win over env).

If no IPC destination **and** no credentials are supplied, the window opens
in a "service not connected" state — it never panics.

> The `<ticket>` is the same session token the engine uses to key the
> HMAC-SHA256 challenge-response handshake (`streamguard_service::ipc`).
> Only the destination's shape is logged — the token itself is never printed.

## V1 Development Status

This V1 shell is a development-only status viewer. Its status token is not a
V2 gateway credential and its IPC contract is not the V2 local-agent API.
Bundling/installing the engine as a Windows service is out of scope for this
prototype. The V2 desktop/operator console and secure local API are defined by
`REBUILD_V2_AGENT_PLAN.md` WP-700 and WP-701.
