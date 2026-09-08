# StreamGuard V2: AI Agent Build Plan

## Purpose

This is the executable rebuild plan for turning the current StreamGuard
prototype into a production-grade multipath tunnel product. It is deliberately
ordered. An agent must complete, review, and verify one work packet before
starting a dependent packet.

V1 is a prototype and must not be exposed to Internet users. Do not attempt to
retain V1 wire compatibility: its four-byte session identity, unauthenticated
gateway fallback, and global reorder semantics are unsafe production contracts.

The target first release is **Safe Mode**:

- Windows client service and desktop application.
- Linux gateway.
- Stable gateway egress IP.
- Whole-device protected routing.
- mTLS device identity.
- One active path plus warm standbys.
- Fast, tested failover.
- Observable, reversible platform configuration.

Bonding, selected-app routing, mobile clients, usage billing, and managed
multi-region operations come after Safe Mode proves reliable on real hardware.

## Non-Negotiable Engineering Rules

1. Do not permit any unauthenticated payload to reach a session, flow table, or
   TUN device.
2. Do not call blocking TUN operations from Tokio tasks or while holding a
   Tokio mutex.
3. Do not use a session-global ordering queue. A lost packet in one flow must
   never block unrelated flows.
4. Use a reliable QUIC stream for control-plane messages. QUIC datagrams carry
   latency-sensitive payload only.
5. Use a full-width, server-issued session ID on the wire. Never use a UUID
   prefix as a session key.
6. Use structured platform APIs or validated command arguments. Never use
   `sh -c`, shell interpolation, or unvalidated interface names for privileged
   network changes.
7. Every cache, queue, task set, session map, and flow map needs a stated upper
   bound, TTL/eviction policy, and metric.
8. Every operating-system route, DNS, firewall, and WFP change needs durable
   rollback/recovery state.
9. Do not add a feature flag to bypass authentication, routing safety, or
   packet validation in a production build.
10. Do not run `cargo fmt`; this repository intentionally has formatting diffs.

## Agent Workflow

Each work packet must be performed in this order:

1. Read `AGENTS.md`, this document, and the dependent work packets.
2. Inspect existing code and tests before editing. Do not assume the plan's
   file paths remain exact after earlier work.
3. Make the smallest coherent change for the packet.
4. Add focused unit tests and integration tests stated by the packet.
5. Run `cargo check --workspace --all-targets`.
6. Run the named focused tests.
7. Run `cargo test --workspace` and then
   `cargo clippy --workspace --all-targets` when the packet changes workspace
   behavior. Redirect output to a temporary file on this host as required by
   `AGENTS.md`.
8. Inspect `git diff --check`, `git status --short`, and the final diff.
9. Ask for review before starting a milestone boundary. Do not commit unless
   explicitly asked.

An agent must stop and ask for direction if an existing user change conflicts
with a packet. It must not revert unrelated changes.

## Target Repository Shape

Keep current V1 code operational only for tests until V2 Safe Mode passes. New
production code lives under clearly separate modules until the V2 cutover.

```text
crates/
  sg-core/                 IDs, error types, time, bounded primitives
  sg-protocol/             v1 retained temporarily; v2 envelope/control
  sg-auth/                 device identity, admission ticket validation
  sg-session/              V2 session lifecycle and path state
  sg-multipath/            V2 dedup, flow reorder, scheduler state
  sg-transport/            QUIC path plus reliable control stream
  sg-tun/                  blocking-driver boundary and packet channels
  sg-routing/              transactional platform-neutral desired state
  sg-network/              interface discovery and path candidates
  sg-platform/             Windows/Linux implementations behind traits
  sg-observability/        metrics, events, diagnostic bundle contracts
apps/
  streamguard-service/     privileged Windows/Linux agent process
  streamguard-gateway/     Linux packet-forwarding service
  streamguard-controller/  later: enrollment, tickets, gateway registry
desktop/
  src-tauri/               unprivileged control application
  ui/                      production desktop experience
tests/
  netem/                   deterministic loss, reorder, MTU, and outage tests
  hardware/                documented elevated/manual acceptance harnesses
deploy/
  gateway/                 container, systemd, Terraform, Ansible
```

Do not create empty crates speculatively. Create `sg-observability` and
`streamguard-controller` only when their corresponding packet begins.

## Milestone 0: Freeze And Secure The Prototype

### WP-000: Add rebuild boundaries and secret safety

Goal: prevent accidental V1 deployment and private-key exposure while leaving
the existing prototype available for development tests.

Files likely touched:

- `.gitignore`
- `AGENTS.md`
- New `docs/v1-prototype-status.md`
- New `docs/security-boundaries.md`

Tasks:

1. Ignore `sgcerts/`, `*.der`, generated diagnostics, and local deployment
   state.
2. Record that V1 is development-only and list its release blockers.
3. Define supported V2 target platforms: Windows client and Linux gateway.
4. Define secret classes: device private key, gateway server key, controller
   signing key, short-lived admission ticket, local IPC credential.
5. State that no static shared secret is an acceptable production credential.

Acceptance:

- `git status --short` does not show generated certificate material after a
  local run.
- No existing source path advertises V1 as production-ready.
- The document names the owner and storage location for every secret class.

### WP-001: Add CI and dependency hygiene

Goal: establish an enforceable baseline before rebuilding networking behavior.

Files likely touched:

- `.github/workflows/ci.yml`
- `.github/workflows/security.yml`
- `deny.toml` or equivalent dependency policy
- Root documentation for supported toolchain and gates

Tasks:

1. Run check, test, and clippy in the order specified by `AGENTS.md`.
2. Add dependency audit and license/SBOM generation as non-blocking initially.
3. Add a separate desktop build job; root workspace exclusion must not hide a
   broken Tauri build.
4. Cache Cargo dependencies but never cache generated keys or credentials.
5. Publish test logs and generated SBOM artifacts on CI failures.

Acceptance:

- A pull request runs engine and desktop validation independently.
- CI does not run `cargo fmt`.
- CI never uploads keys, tickets, or unredacted diagnostic captures.

## Milestone 1: V2 Contracts And Test Laboratory

### WP-100: Define V2 identifiers and envelope

Goal: create a safe, independently versioned wire contract without changing
the current V1 implementation yet.

Primary files:

- `crates/sg-core/src/lib.rs`
- `crates/sg-protocol/src/v2.rs` or `crates/sg-protocol/src/v2/mod.rs`
- `crates/sg-protocol/src/lib.rs`

Required types:

```rust
pub struct SessionId([u8; 16]);
pub struct DeviceId([u8; 16]);
pub struct PathId(u16);
pub struct FlowId(u64);
pub struct PacketId(u64);
pub enum TrafficClass { Realtime, Interactive, Bulk, Control }
pub struct V2Envelope { /* fixed validated header plus payload */ }
```

Requirements:

1. A V2 session ID is a cryptographically random 128-bit opaque value.
2. The decoder validates protocol version, flags, enum values, lengths, and
   exact header framing before allocating payload buffers.
3. `PathId` is scoped to an authenticated session and never trusted across
   sessions.
4. The envelope has a strict maximum payload supplied by the transport path,
   not merely a `u16` maximum.
5. Include a direction/key epoch field if it is required to prevent accidental
   cross-direction packet identity reuse.
6. All encoding uses explicit network byte order.

Tests:

- Round trip and golden-wire tests.
- Unsupported version, nonzero reserved flags, bad lengths, unknown enums,
  truncated header, and trailing-data behavior.
- Property/fuzz target for decoder never panicking or allocating over limit.

Acceptance:

- No V2 type truncates a session identifier.
- V1 behavior is unchanged until cutover.
- Fuzzing corpus includes malformed packets and passes under sanitizing tools
  available to CI.

### WP-101: Define reliable V2 control protocol

Goal: move admission and path state changes off datagrams.

Primary files:

- `crates/sg-protocol/src/v2/control.rs`
- `crates/sg-transport/src/lib.rs`

Required messages:

```text
ClientHello(device identity and requested gateway/session)
SessionAdmit(session ID, assigned addresses, policy, expiry)
PathAttach(session ID, path nonce, path metadata)
PathAttached(path ID, path epoch)
PathDetach(path ID, reason)
PathHealth(path ID, measured properties)
PolicyUpdate(versioned policy)
Close(reason)
```

Requirements:

1. Every state-changing message has a request ID or monotonic epoch.
2. Every state-changing message receives an explicit success/rejection reply.
3. Reject control messages that arrive in an invalid state.
4. Define maximum frame size and timeouts.
5. Use serde only if it is constrained by explicit limits; do not deserialize
   attacker-controlled unbounded structures.

Acceptance:

- A duplicate `PathAttach` is idempotent.
- A stale epoch cannot replace current path or policy state.
- All control state transitions have unit tests.

### WP-102: Build deterministic network test harness

Goal: make loss, reorder, path death, and time controllable without sleeps.

Primary files:

- New `tests/netem/`
- Test-only helpers in `sg-transport`, `sg-tun`, and `sg-multipath`

Requirements:

1. Implement fake clock, fake TUN, fake path transport, and scripted gateway.
2. Simulate independent path latency, jitter, loss, duplication, MTU, and
   sudden connection loss.
3. Expose event ordering deterministically; tests must not rely on arbitrary
   `sleep(Duration::from_millis(100))` for correctness.
4. Keep a small real-Quinn loopback suite for transport integration.

Acceptance:

- A test can reproduce a failure from a seed.
- The harness can assert delivery deadline, path choice, packet drop reason,
  and resource bound.

## Milestone 2: Secure Admission And Session Lifecycle

### WP-200: Implement device identity interfaces

Goal: replace static shared-secret authentication with explicit device identity.

Primary files:

- `crates/sg-auth/src/lib.rs`
- New `crates/sg-auth/src/device.rs`
- `crates/sg-transport/src/quic.rs`
- Platform credential module under `sg-platform`

Requirements:

1. Define traits for device credential loading, certificate rotation, and
   ticket validation.
2. Configure gateway rustls with client certificate verification.
3. Configure client rustls with its device certificate/private key.
4. Store client private keys using DPAPI/Credential Manager on Windows and a
   documented secure mechanism on Linux.
5. Implement an in-memory test credential provider only under test features.

Do not:

- Mint a production admission ticket on the client.
- Reuse the local UI IPC credential as gateway authentication.
- Log certificate DER, tokens, or private-key paths.

Tests:

- Unknown CA, revoked device, expired client cert, wrong gateway name, and
  missing client identity fail the handshake.
- Valid device certificate completes a real Quinn mTLS handshake.

### WP-201: Implement server-issued admission tickets

Goal: bind an authenticated device to an ephemeral tunnel session.

Primary files:

- `crates/sg-auth/src/ticket.rs`
- Future controller ticket endpoint or a test issuer
- Gateway V2 session admission handler

Ticket claims:

```text
ticket ID, issuer, audience gateway/gateway-group, device ID,
organization ID, session ID, issued-at, expires-at, policy version,
allowed regions, nonce/key ID
```

Requirements:

1. Use a reviewed JWT/PASETO library or signed compact token library; do not
   hand-roll JSON parsing, base64, or signature verification.
2. Use asymmetric signing so gateways verify but cannot mint tickets.
3. Make tickets short-lived, single-session, and replay-resistant.
4. Add revocation cache behavior and controller-unavailable policy.
5. Rate limit mTLS handshakes and ticket verification before allocating session
   state.

Acceptance:

- A ticket cannot be used by another device, gateway audience, or after expiry.
- Replay attempts have a bounded, observable rejection path.
- Gateway creates no session until mTLS and ticket validation pass.

### WP-202: Implement bounded V2 session/path state machine

Goal: have one authoritative lifecycle for session and paths.

Primary files:

- `crates/sg-session/src/v2.rs`
- `apps/streamguard-gateway/src/v2/session_manager.rs`

States:

```text
Session: Pending -> Active -> Draining -> Closed
Path: Connecting -> Attached -> Healthy -> Suspect -> Failed -> Reconnecting
```

Requirements:

1. Session map has maximum entries, idle TTL, and removal callback.
2. A connection may attach only one authenticated path identity at a time.
3. Envelope session/path fields must match the transport's authenticated bind.
4. Connection close detaches exactly its bound path.
5. Session cleanup removes flows, dedup state, scheduler state, and address
   allocation.

Acceptance:

- One authenticated connection cannot create arbitrary path IDs.
- Session expiration frees all associated state.
- Concurrent attach/detach tests prove no duplicate path ownership.

## Milestone 3: Packet Delivery And TUN Ownership

### WP-300: Replace async-mutex TUN access with a blocking driver

Goal: guarantee duplex packet flow with native adapters.

Primary files:

- `crates/sg-tun/src/driver.rs`
- `apps/streamguard-service/src/v2/engine.rs`
- `apps/streamguard-gateway/src/v2/engine.rs`

Design:

```text
Dedicated blocking TUN owner
  OS -> bounded inbound packet channel -> async scheduler
  async downlink channel -> OS write
```

Requirements:

1. The blocking thread exclusively owns the `Tun` object.
2. Use bounded channels and define overflow behavior per traffic class.
3. Propagate read/write errors to a supervised engine state machine.
4. Shutdown must unblock the worker, join it, and report failure to join.
5. Measure queue depth, drops, read errors, write errors, and packet sizes.

Tests:

- A deliberately blocked read does not prevent a downlink write.
- Queue saturation has deterministic drop/backpressure behavior.
- Shutdown while read is blocked does not hang the process.

### WP-301: Implement per-flow dedup and deadline-based reorder

Goal: retain useful multipath ordering without global head-of-line blocking.

Primary files:

- `crates/sg-multipath/src/v2/dedup.rs`
- `crates/sg-multipath/src/v2/reorder.rs`
- `crates/sg-multipath/src/v2/classifier.rs`

Requirements:

1. Key state by session plus flow ID, never only session.
2. Bound each flow's packets, bytes, age, and total session memory.
3. Realtime traffic gets a small delivery deadline; missed gaps are skipped and
   counted rather than blocking later packets.
4. Interactive traffic gets a bounded reorder deadline.
5. Bulk/TCP traffic may tolerate a larger reorder budget, but TCP remains the
   ultimate recovery protocol.
6. First valid arrival wins whether it is marked primary or duplicate.
7. Inactive flow state expires.

Tests:

- Loss in flow A does not delay flow B.
- Duplicate-first delivery works.
- Reorder deadlines release later packets when a gap expires.
- Memory limits evict safely and increment metrics.

### WP-302: Implement MTU and effective payload calculation

Goal: never sequence or claim to send a packet too large for the selected path.

Primary files:

- `crates/sg-transport/src/mtu.rs`
- `crates/sg-tun/src/lib.rs`
- V2 client/gateway engines

Requirements:

1. Compute effective payload MTU from path datagram limit minus V2 envelope.
2. Advertise a conservative TUN MTU before path discovery completes.
3. On path MTU reduction, lower available payload immediately and report it.
4. Do not fragment inside the application protocol unless the design includes a
   tested fragment/reassembly mechanism with strict bounds.
5. Failed sends must not advance delivery counters; the scheduler must classify
   and report the drop.

Acceptance:

- A TUN MTU-sized payload can be handled without silent QUIC rejection.
- MTU-black-hole tests report a reason and preserve session liveness.

## Milestone 4: Gateway Forwarding And Tenant Isolation

### WP-400: Allocate addresses and enforce source validation

Goal: make the gateway safely support multiple devices.

Primary files:

- `apps/streamguard-gateway/src/v2/address_pool.rs`
- `apps/streamguard-gateway/src/v2/forwarding.rs`

Requirements:

1. Allocate a unique IPv4 address and IPv6 prefix per active session.
2. Persist/recover allocation state according to managed vs self-hosted mode.
3. Drop uplink packets whose source address is not allocated to that session.
4. Define policy for DHCP-like renewal, session resume, and address exhaustion.
5. Ensure gateway and client default addresses cannot collide.

Tests:

- Two sessions receive distinct addresses.
- Source spoofing is dropped before TUN/NAT forwarding.
- Allocation is released on session expiry.

### WP-401: Replace flow table with bounded IPv4/IPv6 forwarding state

Goal: correctly return packets to their owning session.

Primary files:

- `apps/streamguard-gateway/src/v2/flow_table.rs`
- `apps/streamguard-gateway/src/v2/packet_parse.rs`

Requirements:

1. Parse IPv4 and IPv6 safely with a reviewed parser or strict bounded parser.
2. Use complete protocol-appropriate keys: addresses, protocol, source port,
   destination port, and ICMP identifiers where relevant.
3. Define a secure fragment policy; never read ports from a non-initial
   fragment.
4. Bound flow entries by count and memory with idle TTL/LRU eviction.
5. Delete flows when their session closes.
6. Export flow hit, miss, expiry, parse-drop, and capacity-drop metrics.

Acceptance:

- Concurrent TCP/UDP flows with matching source ports but different targets do
  not collide.
- IPv6 test traffic completes round-trip forwarding.
- A hostile flow spray cannot grow memory beyond the configured bound.

### WP-402: Rebuild Linux gateway networking idempotently

Goal: configure forwarding/NAT without shell injection or orphaned host state.

Primary files:

- `crates/sg-platform/src/linux/`
- `deploy/gateway/`

Requirements:

1. Validate interface names and CIDRs at configuration parsing boundaries.
2. Apply desired nftables/routing state through netlink/nftables APIs or
   structured command arguments only.
3. Reconcile existing StreamGuard-owned state; do not blindly `add table`.
4. Track original forwarding values and restore only values owned by the
   service on shutdown/uninstall.
5. Install a systemd unit with least privileges and explicit capabilities.

Acceptance:

- Start, stop, restart, and upgrade are idempotent.
- Invalid WAN input cannot execute arbitrary shell syntax.
- Uninstall leaves no StreamGuard NAT/firewall rules.

## Milestone 5: Client Platform Policy And Safe Mode

### WP-500: Build transactional route and DNS managers

Goal: make protected traffic enter the TUN without routing the gateway into it.

Primary files:

- `crates/sg-routing/src/lib.rs`
- `crates/sg-platform/src/windows/routes.rs`
- `crates/sg-platform/src/linux/routes.rs`
- `apps/streamguard-service/src/v2/platform_lifecycle.rs`

Requirements:

1. Replace log-only `RouteState` with desired state plus applied-state journal.
2. Pin gateway endpoint routes to each selected physical interface.
3. Install protected default routes only after tunnel admission succeeds.
4. Implement DNS policy and DNS leak prevention for whole-device mode.
5. Recover and roll back stale state on startup, crash recovery, disconnect,
   update, and uninstall.
6. Detect competing VPN routes/adapters and require an explicit user choice.

Acceptance:

- Gateway QUIC packets never enter the TUN after default-route installation.
- Forced agent termination is recovered safely on next startup.
- DNS and IPv6 behavior are covered by integration tests.

### WP-501: Implement Safe Mode path supervisor

Goal: deliver stable egress across active/standby paths before bonding.

Primary files:

- `apps/streamguard-service/src/v2/path_supervisor.rs`
- `crates/sg-health/src/v2.rs`
- `crates/sg-session/src/v2.rs`

Requirements:

1. Supervise each physical path independently.
2. Use fast bounded probes and transport errors to move Healthy -> Suspect ->
   Failed.
3. Use configurable hysteresis, minimum active hold time, alternate advantage,
   and recovery stabilization.
4. Reconnect failed paths with jittered exponential backoff.
5. Require control-stream acknowledgement before considering a path reattached.
6. Produce a typed failover event containing cause, old path, new path, and
   observed interruption.

Acceptance:

- Simulated active-path loss fails over inside the agreed Safe Mode SLO.
- A flaky recovered path does not flap active selection.
- All-path loss enters an explicit degraded state and reconnects safely.

### WP-502: Implement native Windows service lifecycle

Goal: turn the client engine into an installable, recoverable agent.

Primary files:

- `apps/streamguard-service/src/main.rs`
- New Windows service/install modules
- Installer/package configuration

Requirements:

1. Run privileged networking code in a Windows Service.
2. Keep UI and user interactions outside the privileged process.
3. Use signed binaries and a service recovery policy.
4. Support start, stop, pause/resume if appropriate, upgrade, uninstall, and
   crash recovery.
5. Document required driver, elevation, and rollback behavior.

Acceptance:

- Service restart restores safe routing state.
- UI loss does not interrupt the tunnel.
- Service loss restores or kills traffic according to the selected policy.

## Milestone 6: Resilient And Bonded Modes

### WP-600: Add reliable control stream to QUIC paths

Goal: remove all production control messages from datagrams.

Primary files:

- `crates/sg-transport/src/quic.rs`
- V2 client/gateway session engines

Requirements:

1. Open and supervise one control stream per authenticated connection or
   define an explicit session-control leader path.
2. Frame all control messages with bounded size and timeout.
3. Handle control leader failover without stale state regression.
4. Apply path attach, detach, policy, and health changes only after ACK.

Acceptance:

- Dropped payload datagrams do not lose path-control state.
- Control stream reconnection preserves epochs and rejects stale messages.

### WP-601: Implement resilient duplication policy

Goal: selectively duplicate important traffic without doubling all traffic.

Primary files:

- `crates/sg-multipath/src/v2/redundancy.rs`
- `apps/streamguard-service/src/v2/policy.rs`

Requirements:

1. Duplicate only traffic classes/policies eligible for low-latency protection.
2. Require a healthy alternate path and enforce cellular/cost budget.
3. Use the same packet ID for all copies.
4. Track duplication rate, first-arrival path, redundant-copy waste, and
   recovery benefit.
5. Disable duplication under queue pressure or all-path degradation.

Acceptance:

- Duplicate-first and original-first both deliver exactly once.
- A configured data budget prevents uncontrolled cellular consumption.

### WP-602: Implement queue-aware bonded scheduler

Goal: improve aggregate capacity without sacrificing real-time behavior.

Primary files:

- `crates/sg-multipath/src/v2/scheduler.rs`
- `crates/sg-health/src/v2.rs`

Requirements:

1. Estimate usable capacity from delivery rate, congestion state, RTT, loss,
   queue depth, and pacing state.
2. Avoid sending latency-sensitive packets to paths whose predicted arrival is
   materially late unless redundancy policy permits it.
3. Weight bulk traffic across paths with pacing rather than immediate
   per-packet round robin.
4. Add per-path and global queue bounds.
5. Make scoring weights product policy, not hard-coded constants.

Acceptance:

- Two healthy asymmetric paths improve sustained bulk throughput in netem.
- Realtime latency stays inside configured budget under concurrent bulk load.
- Path score changes do not cause rapid scheduler oscillation.

## Milestone 7: Product UI And Local API

### WP-700: Version the local agent API

Goal: replace status-only IPC with a secure command/status contract.

Primary files:

- `apps/streamguard-service/src/ipc.rs`
- New `apps/streamguard-service/src/v2/api.rs`
- `desktop/src-tauri/src/`

Required API groups:

```text
Status: snapshot, event stream, diagnostics state
Protection: connect, disconnect, choose mode, kill-switch state
Policy: whole-device, selected apps, exclusions, cellular budget
Preflight: run, result, export
Account: device identity and selected gateway only
```

Requirements:

1. Separate local IPC credential from gateway admission credentials.
2. Apply named-pipe ACLs on Windows and connection/request deadlines.
3. Use bounded worker concurrency and request sizes.
4. Make state-changing UI calls authorized, audited, and idempotent.

Acceptance:

- A local untrusted process cannot change tunnel policy.
- A hung IPC peer cannot create unbounded tasks.

### WP-701: Rebuild the desktop shell as an operator console

Goal: ship a sleek, low-stress live-production interface rather than a counter
viewer.

Primary files:

- `desktop/ui/index.html`
- `desktop/ui/app.js`
- `desktop/ui/style.css`
- `desktop/src-tauri/tauri.conf.json`

Design constraints:

1. Use a graphite/dark-slate base, warm high-contrast text, and one primary
   signal color. Reserve amber for degradation and red for loss of protection.
2. Home screen shows protection state, selected mode, stable egress, gateway,
   current active path, and connection lanes.
3. Provide dedicated Preflight, Connections, Protection Rules, Usage, and
   Diagnostics screens.
4. Keep raw counters out of the primary operational view.
5. Do not use `innerHTML` with data received from the IPC server; construct DOM
   content safely.
6. Enable a strict Tauri CSP, narrow permissions, keyboard navigation,
   screen-reader labels, reduced motion, and high-contrast support.
7. Enable signed production bundling and update flow only after service
   packaging is complete.

Acceptance:

- An operator can understand protection state in under five seconds.
- Every error has an action-oriented explanation.
- UI end-to-end tests cover disconnected agent, degraded path, failover,
  all-path loss, and reconnect.

## Milestone 8: Controller, Operations, And Release

### WP-800: Build the minimal controller

Goal: support managed device enrollment and gateway selection.

Create this only after V2 agent/gateway admission contracts are stable.

Requirements:

1. Device enrollment with organization ownership.
2. Certificate issuance/rotation/revocation.
3. Gateway registry with region, capacity, and health.
4. Admission-ticket issuance.
5. Audit log for enrollment, revocation, policy changes, and ticket issuance.
6. Rate limiting, secure admin access, backups, and retention policy.

Acceptance:

- Revoking a device prevents new sessions within the defined propagation SLO.
- Gateway outage causes clients to choose a healthy allowed gateway.

### WP-801: Add observability and support diagnostics

Goal: operate the service without inspecting user packet contents.

Metrics:

```text
authenticated sessions, path state transitions, failover duration,
packet delivery/drop reason, reorder expiry, duplicate benefit,
effective MTU, TUN queue depth, flow-table eviction, gateway CPU/RAM,
quota consumption, route/DNS/WFP operation results
```

Requirements:

1. Use structured logs with session/device identifiers that can be redacted.
2. Use OpenTelemetry-compatible traces/metrics where practical.
3. Never record payloads, auth tokens, certificates, private keys, or full
   customer destination history by default.
4. Build an explicit user-consented diagnostic bundle with redaction.
5. Define alerts and SLOs before public pilot.

### WP-802: Build deployment and release pipeline

Goal: make managed and self-hosted operation reproducible.

Files likely created:

- `deploy/gateway/Dockerfile`
- `deploy/gateway/systemd/`
- `deploy/terraform/`
- `deploy/ansible/`
- Release signing/update configuration

Requirements:

1. Immutable Linux gateway image with non-root runtime where possible.
2. Explicit capabilities and host networking documentation.
3. Terraform/Ansible for a supported Ubuntu gateway baseline.
4. Signed Windows installer and updater.
5. SBOM, license manifest, release notes, rollback guide, and key-rotation
   procedure for every release.

## Milestone 9: Validation Gates

### WP-900: Network-emulation acceptance suite

Required automated scenarios:

1. One healthy path, bidirectional IPv4 and IPv6 traffic.
2. Active-path hard loss with warm standby.
3. Soft loss, high jitter, and latency spike.
4. Duplicate-first and primary-first arrival.
5. Loss in one flow while other flows keep making progress.
6. Datagram size reduction and MTU black hole.
7. Gateway restart and client reconnect.
8. Session expiry, ticket replay, revoked device, and invalid certificate.
9. Flow spray/resource-exhaustion attempt.
10. Route/DNS rollback after forced agent termination.

### WP-901: Elevated hardware acceptance suite

Required manual/elevated evidence before public beta:

1. Windows native TUN with real routes and gateway exclusion.
2. Two real NICs: Ethernet plus Wi-Fi or tethered 5G.
3. Ethernet unplug/replug while sustained ping, HTTP transfer, and OBS/SRT
   traffic run through the gateway.
4. DHCP/IP change, sleep/resume, and gateway process restart.
5. IPv6 forwarding and DNS leak validation.
6. WFP application-policy validation with a real protected app.
7. Twelve-hour soak test with packet and memory metrics.

The release report must include measured interruption, egress continuity,
packet loss, added latency, gateway CPU/RAM per active session, and any known
platform limitations.

## Cutover Policy

V1 can be removed only when all conditions are true:

1. V2 Safe Mode passes WP-900 and WP-901.
2. V2 has no authentication bypass, global reorder queue, four-byte session ID,
   or shell-built privileged networking commands.
3. Upgrade/uninstall rollback is tested.
4. CI, SBOM, signed release, and support diagnostics are operating.
5. A security review approves the device identity, ticket, and gateway threat
   model.

Until then, label V1 binaries and UI as development/experimental and do not
use them for customer live streams.
