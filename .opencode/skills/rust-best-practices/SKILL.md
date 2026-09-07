---
description: Modern, idiomatic Rust for this workspace — keep dependencies current (cargo update/outdated, latest crates on crates.io), consult current docs.rs API docs before writing code, and follow repo conventions. Load when writing or reviewing any Rust code here.
---

# Rust best practices (StreamGuard)

Modern Rust still means "latest stable, verified against real docs." Apply both.

## Toolchain & versions (grounded in this repo)
- `rust-toolchain.toml`: stable channel, components `rustfmt` + `clippy`.
- Workspace: edition **2021**, `rust-version = "1.85"` (this is the MSRV), resolver 2.
- Do NOT silently bump edition/MSRV or do a major-dep migration (e.g. quinn 0.11 → 0.12) as part of feature work — that is a project decision; flag it to the owner first.
- Any crate you add must be compatible with MSRV 1.85 and edition 2021.

## Keeping dependencies current
- Before adding a crate, check crates.io for the **latest version** — `cargo add <crate>` resolves the newest, but you must confirm what that version is and what it pulls in.
- Keep the lockfile fresh: `cargo update` (stays within semver in the manifests). To see what's stale: `cargo install cargo-outdated`, then `cargo outdated`.
- Workspace deps live centralized in the root `Cargo.toml` `[workspace.dependencies]`; add new deps there once and reference with `crate.workspace = true` from member crates.
- Feature discipline: adds are lazy. `sg-transport` keeps `quic` off by default — consuming crates add `features = ["quic"]`. Follow that pattern rather than enabling everything.

## Checking documentation before you code
- Do NOT write crate API calls from memory. Crate APIs churn between minors (quinn 0.11 vs 0.12, rcgen, bytes, tokio). Fetch the docs.rs page for the **version actually in Cargo.toml** before using unfamiliar APIs.
- Cross-check signatures against the resolved version with `cargo doc` / rust-analyzer if offline.

## Idioms that match this codebase
- Payloads travel as `bytes::Bytes` (zero-copy refcounted) — do not introduce `Arc<Vec<u8>>` or `Arc<[u8]>` for packet buffers.
- Library crates: `thiserror` for typed errors; applications may use `anyhow` at their boundary. Both already in workspace deps.
- Log with `tracing` (already a dep), not `println!`/`dbg!`.
- Long-running loops (readers, keepalive, probe loops) return `Result`/break cleanly; no `unwrap`/`expect` on I/O paths.
- `#[must_use]` on new pure functions that return values; avoid unsafe unless asked.
- Lock ordering in this workspace: `session → metrics` and `probes → metrics` OK; never hold `metrics` while acquiring `session`.
- Keep test sequences small — `Sequence` is 48-bit on the wire (see the `streamguard-wire` skill).

## Verify before committing
- `cargo check --workspace --all-targets` → `cargo test --workspace` → `cargo clippy --workspace --all-targets` must all pass; clippy must be warning-free. See the `streamguard-verify` skill for host gotchas.
- Do NOT run `cargo fmt` (repo is intentionally not formatted).