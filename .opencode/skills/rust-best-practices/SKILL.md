---
name: rust-best-practices
description: Production Rust practices for StreamGuard V2. Load when writing or reviewing Rust code, adding dependencies, designing concurrency, or touching native networking.
---

# Rust best practices (StreamGuard)

Modern Rust means reviewed dependencies, version-verified APIs, explicit
ownership, bounded resources, and testable failure behavior.

## Toolchain & versions (grounded in this repo)
- `rust-toolchain.toml`: stable channel, components `rustfmt` + `clippy`.
- Workspace: edition **2021**, `rust-version = "1.85"` (this is the MSRV), resolver 2.
- Do NOT silently bump edition/MSRV or do a major-dep migration (e.g. quinn 0.11 → 0.12) as part of feature work — that is a project decision; flag it to the owner first.
- Any crate you add must be compatible with MSRV 1.85 and edition 2021.

## Dependency discipline
- Before adding a crate, justify it in the active work packet, check its MSRV,
  maintenance state, license, transitive security surface, and pinned API docs.
- Do not run broad `cargo update` or `cargo add` as incidental feature work.
  Dependency changes need a reviewed, scoped diff.
- Workspace deps live centralized in the root `Cargo.toml` `[workspace.dependencies]`; add new deps there once and reference with `crate.workspace = true` from member crates.
- Feature discipline: adds are lazy. `sg-transport` keeps `quic` off by default — consuming crates add `features = ["quic"]`. Follow that pattern rather than enabling everything.

## Checking documentation before you code
- Do NOT write crate API calls from memory. Crate APIs churn between minors (quinn 0.11 vs 0.12, rcgen, bytes, tokio). Fetch the docs.rs page for the **version actually in Cargo.toml** before using unfamiliar APIs.
- Cross-check signatures against the resolved version with `cargo doc` / rust-analyzer if offline.

## Idioms that match this codebase
- Payloads travel as `bytes::Bytes` (zero-copy refcounted) — do not introduce `Arc<Vec<u8>>` or `Arc<[u8]>` for packet buffers.
- Library crates: `thiserror` for typed errors; applications may use `anyhow` at their boundary. Both already in workspace deps.
- Log with `tracing` (already a dep), not `println!`/`dbg!`.
- Long-running loops return `Result`/break cleanly; no `unwrap`/`expect` on I/O
  paths. Supervise all spawned tasks and make cancellation explicit.
- Use bounded channels and collections. Define overflow, timeout, TTL, and
  shutdown behavior before implementation.
- `#[must_use]` on new pure functions that return values. Avoid unsafe; when
  unavoidable, isolate it behind a small API with a written ownership proof and
  tests.
- Never hold async locks across network I/O, blocking TUN I/O, or other await
  points. Prefer ownership transfer or snapshots.
- Consult `streamguard-wire` for V1 containment and V2 wire invariants.

## Verify before committing
- `cargo check --workspace --all-targets` → `cargo test --workspace` → `cargo clippy --workspace --all-targets` must all pass; clippy must be warning-free. See the `streamguard-verify` skill for host gotchas.
- Do NOT run `cargo fmt` (repo is intentionally not formatted).
