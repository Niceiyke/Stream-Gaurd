# AGENTS.md

StreamGuard: resilient client→gateway multipath tunnel in Rust. No README; `spec(6).md` is the authoritative engineering spec (code comments cite section numbers, e.g. "spec 11.2"), `prd.md` is the product doc.

## Commands

```powershell
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets   # must stay clean
```

- Order matters: `test` then `clippy`; both must pass before committing a milestone.
- Do **not** run `cargo fmt`. The repo is intentionally not rustfmt-formatted (`cargo fmt --check` reports diffs); formatting would create an unrelated giant diff.
- Single test: e.g. `cargo test -p streamguard-gateway --test path_control -- in_order`. App integration suites live under `apps/*/tests/*.rs` (`--test`), crate unit tests under `crates/*/src`.
- On this Windows/PowerShell host, redirect cargo output to a file and scan it, e.g. `cargo test --workspace 2>&1 | Out-File "%TEMP%\t.txt"`. Beware: `Select-String` is case-insensitive, so pattern `FAILED` also matches "0 failed" — verify `test result:` lines manually.

## Workspace map

- Pure crates in `crates/`: `sg-core` (IDs: `PathId`/`SessionId`/`Sequence`, `Config`), `sg-protocol` (v1 envelope + control msgs), `sg-tun` (`Tun` trait + async-free `LoopbackTun`), `sg-health` (`PathMetrics`), `sg-multipath` (`Sequencer`, `ReorderWindow`, `ReorderBuffer`), `sg-session` (`Session`/`SessionManager`, shared by both ends), `sg-transport` (QUIC via quinn; **`quic` feature is off by default** — new consumers must add `features = ["quic"]`), `sg-auth`, `sg-routing`, `sg-network`, `sg-platform` (WFP selected-app scaffold in `wfp.rs`), `sg-wordlyte` (consumer status SDK over the IPC plane).
- `apps/streamguard-service` = client engine: `client::start(Tun, ClientOptions, session_id, &[PathId], token, status: Option<StatusEndpoint>)` spawns per-path reader/keepalive/probe loops + uplink loop; also the status plane (`status.rs` `StatusProvider`/`StatusSnapshot`, `ipc.rs` authenticated named-pipe/TCP server, `StatusClient`). `main.rs` owns real TUN setup.
- `apps/streamguard-gateway` = gateway: `tunnel::start(host_tun, GatewayQuic, secret)` runs one uplink reader per accepted connection + a downlink loop with a reverse flow table.
- `desktop/src-tauri` = non-workspace Tauri v2 status shell (step 12): own Cargo.lock, `frontendDist ../ui`, consumes the engine's status IPC via `StatusClient`; excluded from root gates by design.

## Wire / protocol gotchas

- Envelope is a 20-byte fixed header inside each QUIC datagram. Sequence is **48-bit on the wire** but `u64` in code (`Sequence`): values ≥ 2^48 truncate silently across encode/decode. Keep test sequences small.
- Only the **first 4 bytes** of `SessionId` cross the wire (decode zero-fills the tail). For any id that travels, build it with `sg_session::session_id_from_wire(prefix)`; `SessionId::new()` is only safe locally.
- `PacketType`: `Data=0`, `Duplicate=1`, `Control=2`, `Probe=3`, `Keepalive=4`, `PathStatus=5`. `Duplicate` carries an already-seen sequence (redundancy), first-valid-wins.
- In-order reassembly is the active model (`ReorderBuffer`, spec 11.2): both the gateway reader and client downlink reader call `Session::enqueue_incoming(seq, payload) -> ReorderOutcome` (`delivered` / `buffered` / `dropped`), and `next_expected` starts at **0**. A first packet with seq ≠ 0 is buffered forever. Echo/data tests must start at `Sequence::new(0)` and bounce the same sequence back (echo gateways previously used `+1_000_000` — do not reintroduce).

## Code conventions

- `ClientOptions` has **no `Default` impl**; every field is set at all 6 construction sites (3 in `apps/streamguard-service/tests/e2e.rs`, 3 in `client.rs` unit tests). Adding a field means updating all 6, or the build breaks.
- `PathMetrics::default()` has `reachable: false`. Fresh path entries must be inserted as `PathMetrics { reachable: true, ..Default::default() }` — unmetered = eligible. `or_default()` here makes `fail_path` early-return forever.
- Lock order: never hold `metrics` while acquiring `session`; `session → metrics` and `probes → metrics` are fine. `fail_path` is idempotent (early-returns when the path is already unreachable) — keep it that way, counters depend on it.

## Testing

- `LoopbackTun` is non-blocking: engine writes land in an outbound queue drained via `drain_outbound()`; tests inject downlink via `enqueue()`.
- Integration tests (in `apps/*/tests/`) use real quinn over `127.0.0.1:0` with an rcgen self-signed cert and `let _ = sleep(Duration::from_millis(100))` to let the reader loops run — keep that cadence.
- Assertions read counters: `handle.counters().await.frames_to_host`, `duplicates_dropped`, `sessions`, `keepalives`, `probes_replied`, plus client-side `probes_sent`/`soft_failures`/`duplicates_sent`.
- `.gitattributes` forces LF for `.rs` (git may warn "LF will be replaced by CRLF" on `Cargo.lock` — harmless). `wintun-*.zip` is a gitignored build artifact; never commit binaries/DLLs.

## Milestone status

Engineering sequence is spec §28. Committed so far: steps 1-10 plus 12-16 — probes `8b88eaf`, active/standby failover `1073978`, adaptive duplication `9086e0f`, reorder buffer `bb2d06e`, weighted scheduling/bonding (step 14) `1b6515b` + downlink mirror `c290df8`, status plane (step 12 T1) `6b3cea7` + Tauri shell (step 12 T2) `4130da4`, WFP selected-app scaffold (step 15) `d99b29a`, Wordlyte SDK (step 16) `da0ae3c` + `StatusProvider::from_snapshot_fn` seam `c3418ed`. Remaining: step 11 (live egress unplug test, spec §27 — needs two real NICs and admin; only the scaffold/harness can be done here). Real-platform verification still outstanding: WFP ALE filters need an elevated run with real app paths; the Tauri/Wordlyte UI needs the engine service publishing the pipe in production.