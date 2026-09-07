---
description: Verify StreamGuard workspace health correctly — required gate order (cargo check → test → clippy), single-test invocation, and Windows/PowerShell output parsing. Load when running or writing tests, checking the workspace, or preparing any change for commit.
---

# StreamGuard verification gates

Use this workflow whenever a change touches the workspace or a milestone is being readied for commit.

## Required order
1. `cargo check --workspace --all-targets`
2. `cargo test --workspace`
3. `cargo clippy --workspace --all-targets` — must stay clean (no warnings)

Never reorder. Both test and clippy must pass before committing a milestone.

## Do NOT run `cargo fmt`
The repo is intentionally not rustfmt-formatted. `cargo fmt` rewrites the entire tree into an unrelated giant diff. Use `cargo fmt --check` only if you must inspect formatting.

## Windows / PowerShell host gotchas
- Redirect cargo output to a log file and scan the log; never pipe huge output inline:
  `cargo test --workspace 2>&1 | Out-File "$env:TEMP\sg-test.txt"`
- `Select-String` is case-insensitive: pattern `FAILED` also matches the words `0 failed` in every `test result:` line. Verify `test result:` lines manually by eye.
- Prefer `rg` (ripgrep) over `Select-String` once the full output is saved.

## Single test invocation
- App integration suites live under `apps/*/tests/*.rs` (`--test`); crate unit tests under `crates/*/src`.
- Example: `cargo test -p streamguard-gateway --test path_control -- gateway_injects_frames_to_host_in_sequence_order`

## Before a milestone commit
- All 3 gates green.
- Full workspace = 33 test binaries; confirm the `test result: ok` counts across them.
- `git status` free of unintended files. Wintun `*.dll` / `wintun-*.zip` are gitignored binaries — never staged.