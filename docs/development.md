# Development And CI Gates

## Supported Toolchain

StreamGuard's current MSRV is Rust 1.85, edition 2021. CI installs Rust
1.85.0 explicitly and uses `--locked` for both lockfiles. Updating the MSRV,
toolchain, lockfiles, or a major dependency is an approved work packet, not
incidental feature work.

The root workspace validates the Rust engine. The Tauri desktop shell keeps a
separate lockfile and is validated by its own Windows CI job.

## Local Engine Gates

Run these commands in order from the repository root:

```powershell
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets
```

Do not run `cargo fmt`; this repository intentionally has formatting diffs.
On Windows, redirect Cargo output to a temporary UTF-8 log and inspect every
`test result:` line. A locked executable is a process-management blocker, not
a reason to terminate another user's process.

## Desktop Gate

The V1 desktop shell is outside the root workspace and has its own lockfile:

```powershell
cargo check --manifest-path desktop/src-tauri/Cargo.toml --all-targets --locked
cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked
cargo build --manifest-path desktop/src-tauri/Cargo.toml --locked
```

This validates compilation only. It does not sign, package, publish, or claim
the V1 shell is production-ready.

## CI And Dependency Policy

- CI runs root engine check, test, and clippy in order on Linux, plus a Windows
  compile check and a separate Windows desktop job.
- CI caches only Cargo registry and Git dependency directories. It never caches
  `target`, credentials, generated certificates, diagnostics, packet captures,
  or deployment state.
- Failure artifacts name each allowed command log explicitly. SBOM artifacts
  name the root and desktop CycloneDX files explicitly; no extension globs are
  uploaded.
- Cargo audit and cargo-deny are non-blocking while the dependency baseline is
  triaged. Their findings must be reviewed; exceptions require an owner,
  reason, and review date before the policy becomes blocking.
- CI pins the `cargo-audit` release it installs. Third-party GitHub Actions are
  pinned to immutable commits and must be reviewed when updated.
