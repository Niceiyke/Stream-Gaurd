# StreamGuard --- Technical Specification

**Version:** 1.1\
**Date:** 6 September 2026\
**Status:** Initial architecture specification (revised)

## 1. Scope

This specification defines the initial technical architecture for
StreamGuard: a Rust client (Windows-first) and Linux gateway providing a
stable IP tunnel over multiple physical Internet interfaces.

The core (protocol, scheduler, health, multipath, transport) is platform-
agnostic Rust. OS-specific behavior is isolated behind `sg-tun` /
`sg-platform` so desktop and mobile ports are thin adapter layers.

Target platform rollout:

| Milestone | Client platforms | Gateway |
|-----------|------------------|---------|
| MVP 1 | Windows | Linux |
| MVP 2 | Windows, macOS | Linux |
| MVP 3 | Windows, macOS, Linux | Linux |
| MVP 4 | Windows, macOS, Linux, iOS, Android | Linux, multi-region |

The first engineering objective is not full bandwidth aggregation. It is
proving that one logical StreamGuard session can survive loss of a
physical path while maintaining a stable gateway egress.

## 2. High-Level Components

    +------------------------------------------+
    |            StreamGuard Desktop           |
    |              Tauri / Web UI              |
    +---------------------+--------------------+
                          | IPC
    +---------------------v--------------------+
    |          streamguard-service             |
    |                                          |
    | TUN -> policy -> multipath -> transport  |
    +------+----------------------------+------+
           |                            |
      physical NICs               control plane
           |
           v
    +------------------------------------------+
    |           StreamGuard Gateway            |
    |                 Linux                    |
    | transport -> session -> TUN -> NAT       |
    +---------------------+--------------------+
                          |
                       Internet

## 3. Rust Workspace

    streamguard/
    |
    +-- crates/
    |   +-- sg-core
    |   +-- sg-protocol
    |   +-- sg-tun
    |   +-- sg-network
    |   +-- sg-health
    |   +-- sg-transport
    |   +-- sg-multipath
    |   +-- sg-routing
    |   +-- sg-platform
    |
    +-- apps/
    |   +-- streamguard-service
    |   +-- streamguard-gateway
    |
    +-- desktop/
        +-- StreamGuard UI

Responsibilities:

### sg-core

Shared IDs, sessions, configuration, errors and common types.

### sg-protocol

StreamGuard control messages, packet envelope and protocol versioning.

### sg-tun

Cross-platform virtual NIC abstraction.

Per-platform backends:
- Windows: Wintun (Windows 10 2004+)
- Linux: TUN (`/dev/net/tun`)
- macOS: utun (user-space tunnel, no extra kernel module)
- iOS: NetworkExtension `packet_tunnel_provider` (App Store entitlements)
- Android: `VpnService` (workspace device owner API)

### sg-network

Physical-interface discovery and bound-path creation.

### sg-health

Latency/loss/jitter/reachability measurements and path scoring.

### sg-transport

Secure client-to-gateway transport.

### sg-multipath

Scheduling, failover, redundancy, sequencing, deduplication and
reordering.

### sg-routing

Host route configuration and tunnel-route exclusions.

### sg-platform

Per-OS adapter, socket, route and firewall behavior.

| OS | TUN | Binding | Routes | Firewall/policy |
|----|-----|---------|--------|-----------------|
| Windows | Wintun | `socket2` + interface index | `netsh`/IP Helper | WFP (`ALE_APP_ID`) |
| Linux | `/dev/net/tun` | `socket2` + SO_BINDTODEVICE | rtnetlink/policy routing | nftables (gateway) |
| macOS | utun | `socket2` | route socket / NetworkExtension | NE filter data provider |
| iOS | NE `packet_tunnel` | NE per-path | NE routing | NE (sandboxed) |
| Android | `VpnService` | per-network sockets | `VpnService` routes | app UID filters |

## 4. Proposed Crates

Initial candidates identified during architecture investigation:

-   `tokio` --- async runtime
-   `tun-rs` --- primary cross-platform TUN/TAP candidate
-   `wintun` --- Windows-specific fallback/direct Wintun integration
-   `netdev` --- physical interface discovery/statistics
-   `socket2` --- lower-level sockets and per-interface binding
-   `quinn` --- primary QUIC candidate
-   `rustls` --- TLS
-   `etherparse` --- IP/TCP/UDP packet parsing
-   `rtnetlink` --- Linux routing/netlink control
-   `net-route` --- candidate cross-platform route abstraction
-   `chacha20poly1305` --- only if an application-level AEAD is later
    required

All dependencies must be pinned and reviewed before production. Do not
implement custom cryptography.

## 5. Client Packet Flow

Normal protected traffic:

    Application
       |
       v
    StreamGuard TUN
       |
       v
    Packet classifier
       |
       v
    Multipath scheduler
       |
       +--> Path A / Ethernet
       +--> Path B / Wi-Fi
       +--> Path C / 5G
                 |
                 v
              Gateway

Return traffic reverses this process and is written back into the client
TUN.

## 6. Routing

The StreamGuard virtual NIC can become the route for protected traffic.

Critical rule: transport packets used to reach the StreamGuard Gateway
must bypass the StreamGuard TUN and leave through their selected
physical NIC.

Otherwise:

    tunnel -> default route -> TUN -> tunnel -> ...

creates a routing loop.

The routing subsystem must therefore maintain:
- protected application/default routes
- explicit gateway endpoint exclusions
- physical-interface routes
- rollback state

If StreamGuard crashes, routing should fail safely and be recoverable.

## 7. Interface Discovery

`sg-network` should enumerate:
- stable interface identifier
- name
- interface type where detectable
- operational state
- IPv4/IPv6 addresses
- MTU
- default gateway
- RX/TX counters
- route suitability

Example internal representation:

    Interface {
        id,
        name,
        kind,
        addresses,
        mtu,
        state,
        gateway,
        metrics
    }

Do not assume a "cellular" path is always reported as cellular. Phone
tethering may appear as Wi-Fi or Ethernet.

## 8. Path Binding

Each physical path must have independently controllable transport
sockets.

Conceptually:

    SG Path A -> bound to Ethernet -> Gateway
    SG Path B -> bound to Wi-Fi   -> Gateway
    SG Path C -> bound to 5G      -> Gateway

Platform-specific binding behavior must be hidden behind an abstraction.

## 9. Secure Transport

Primary prototype candidate: QUIC using Quinn + rustls.

Requirements:
- authenticated gateway
- encrypted client/gateway traffic
- UDP-based transport
- support for real-time datagram-style delivery where appropriate
- reconnect/resume strategy
- telemetry for RTT/loss/congestion

QUIC is a transport primitive, not the complete bonding solution.

Do not assume one normal QUIC connection automatically provides
arbitrary multi-interface packet bonding.

### 9.5 QUIC Multipath Strategy

RFC 9000 (QUIC v1) provides connection **migration**, not simultaneous
multipath usage. A single QUIC connection can move between paths but
cannot aggregate them.

The IETF QUIC Multipath extension (draft-ietf-quic-multipath) is in
active development (draft-21, expiring September 2026) but is not yet
stable. Quinn does not currently implement it natively.

**Adopted approach:**

| Phase | Strategy | Detail |
|-------|----------|--------|
| Phase 1-2 (MVP 1-2) | Multiple independent QUIC connections | One QUIC connection per physical path, each with its own connection ID. StreamGuard packet envelope provides application-layer sequencing/deduplication/reordering. |
| Phase 3+ (MVP 3+) | IETF Multipath QUIC | Adopt when the draft stabilizes. Provides native path management, `ACK_MP` frames, per-path packet number spaces, PATH_CHALLENGE/PATH_RESPONSE validation. |

**Why not a single QUIC connection for everything?**
- Connection migration is one-at-a-time failover, not aggregation
- No bandwidth bonding semantics
- No per-path congestion control separation
- Control over scheduling lives in StreamGuard, not the transport

**Implementation notes (Phase 1-2):**
- Each path owns an independent `quinn::Connection`
- Allocation: one runtime task per path reading/writing UDP
- The scheduler (sg-multipath) chooses which connection carries each packet
- Sequencing and deduplication happen above QUIC (see Section 11 envelope)
- Path health probes ride inside each path's own connection
- Reconnect semantics are per-path (one dead connection does not kill the session)

**Migration to Phase 3:**
- Keep the envelope (paths still need identity/ordering hints)
- Replace per-path connections with single Multipath QUIC connection
- Path creation via `PATH_CHALLENGE`/`PATH_RESPONSE`
- Per-path congestion control from draft
- Direct control mapping from scheduler into the multipath API

## 10. Multipath Session Model

Recommended initial design:

    StreamGuard Session
       |
       +-- Path A transport -> Ethernet
       +-- Path B transport -> Wi-Fi
       +-- Path C transport -> 5G

The gateway associates all authenticated paths with the same logical
StreamGuard session.

This gives StreamGuard explicit control over path selection even if the
underlying QUIC implementation does not provide the required multipath
semantics.

## 11. StreamGuard Packet Envelope

An application-level envelope is required for packets carried across
independently scheduled paths. It provides the scheduler and gateway
with path identity, ordering and deduplication information that QUIC
cannot supply.

### 11.1 Wire Format (v1)

All integers are big-endian. Total fixed header: 20 bytes.

    +--------+--------+--------+--------+--------+--------+--------+--------+
    |  ver   |  type  | flags  | path_id|             session_id             |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                          sequence_number                             |
    |                                                (continued)            |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               timestamp                              |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |  payload_length  |                     payload...                     |
    +--------+--------+--------+--------+--------+--------+--------+--------+

| Field | Size | Description |
|-------|------|-------------|
| `version` | 1B | Envelope version (0x01) |
| `type` | 1B | Packet type: 0=data, 1=duplicate, 2=control, 3=probe, 4=keepalive, 5=path_status |
| `flags` | 1B | Reserved; 0 in v1 |
| `path_id` | 1B | Physical path index (0-255) |
| `session_id` | 4B | Logical StreamGuard session |
| `sequence_number` | 6B | Monotonic per-session sequence |
| `timestamp` | 4B | ms since session start |
| `payload_length` | 2B | Payload length (0-65535) |
| `payload` | N | Encapsulated IP packet (optionally compressed/obfuscated) |

### 11.2 Sequencing

- `sequence_number` is assigned by the scheduler before a packet is submitted to a path
- `duplicate` packets reuse the original `sequence_number` (same seq, type=1)
- The gateway reorders by `sequence_number` within a bounded window before injection into TUN
- First valid arrival wins; duplicates beyond the reorder window are discarded

### 11.3 Window Size

Reorder window sized from the worst-case RTT delta between active paths
plus scheduling latency. Initial recommendation: 128 packets or 100 ms,
whichever is larger. Tunable per policy.

### 11.4 Control Messages

Control messages ride inside QUIC streams (reliable) rather than the
envelope. Envelope `type=control` is reserved for future use.

Avoid adding reliability mechanisms that duplicate QUIC behavior unless
testing proves they are necessary.

## 12. Scheduler

### Phase 1

Active/standby:
- select best healthy path
- keep alternate path alive
- migrate on failure/degradation

### Phase 2

Adaptive redundancy:
- duplicate selected packets when active path degrades
- first valid arrival wins
- gateway discards duplicate

### Phase 3

Weighted bonding:
- distribute packets according to path capacity/quality
- account for different RTTs
- prevent slow paths from causing excessive reordering
- adjust weights continuously

The scheduler is a primary differentiating component.

## 13. Health Engine

Per-path metrics:
- reachability
- RTT
- smoothed RTT
- jitter
- packet loss
- recent failures
- estimated available throughput
- stability duration

The health engine must distinguish:
- link down
- Internet unreachable
- gateway unreachable
- high loss
- high latency
- bandwidth collapse

Scoring should be policy-based rather than hard-coded globally.

## 14. Hysteresis

Path selection must avoid flapping.

Initial configurable concepts:
- degradation persistence interval
- minimum alternate advantage
- minimum active-path hold time
- emergency failure threshold
- recovery stabilization interval

Hard numbers should be established through field testing.

## 15. Gateway

Initial deployment: Linux VPS.

Responsibilities:
- authenticate client
- associate multiple paths with a session
- receive StreamGuard packets
- sequence/deduplicate/reorder as required
- inject client IP packets into gateway TUN
- forward/NAT traffic to Internet
- capture return traffic
- route return packets into the correct StreamGuard session
- expose health/usage telemetry

Gateway should not transcode video.

### 15.5 Gateway Authentication

**Model: mTLS with per-device certificates + short-lived session tokens.**

Components:

| Component | Detail |
|-----------|--------|
| Root CA | StreamGuard internal CA, offline root kept air-gapped |
| Device Certificate | Issued at registration, unique per device, Ed25519 keypair |
| Gateway Certificate | TLS server cert auto-renewed (e.g. via ACME/LetsEncrypt) |
| Session Token | JWT, 15-minute expiry, issued after successful mTLS handshake |

Certificate storage:
- Windows: Windows Certificate Store (machine store, private key non-exportable where supported)
- Linux: system keyring (`keyring` crate)
- Private keys never leave secure storage

### 15.6 Authentication Flow

    Device                     Gateway
      |  1. TLS ClientHello        |
      |---------------------------->|
      |  2. Server cert + chain    |
      |<----------------------------|
      |  3. Client cert presented  |
      |---------------------------->|
      |  4. mTLS established       |
      |---------------------------->|
      |  5. POST /session (token)  |
      |---------------------------->|
      |  6. JWT (15 min)            |
      |<----------------------------|
      |  7. Path A: QUIC + token   |
      |---------------------------->|
      |  8. Path B: QUIC + token   |
      |---------------------------->|

### 15.7 Revocation

- Certificate revocation: CRL or OCSP on the gateway; revoked device certs rejected at handshake
- Session token: signed JWT; short expiry limits replayed-token window
- Rate limiting on `POST /session` and handshake endpoints (e.g. 5/min per IP)
- Lost/stolen device: revoke device cert; device locked out on next connect

### 15.8 Security Properties

- No passwords to phish (device keys, not credentials)
- Each device is uniquely identifiable and independently revocable
- Replay resistance via token freshness + QUIC per-connection CIDs
- Gateway rate limits mitigate control-plane abuse

## 16. Linux Gateway Networking

Candidate mechanisms:
- TUN
- `rtnetlink` for link/route management
- kernel IP forwarding
- nftables/NAT

Gateway setup must be automated and reproducible.

### 16.5 DNS Strategy

**Model: Split DNS. Protected traffic resolves through the gateway; unprotected traffic uses the local ISP resolver.**

    Protected apps -> TUN -> tunnel -> Gateway DNS (Unbound) -> upstream (Cloudflare 1.1.1.1)
    Unprotected apps -> local ISP DNS                   -> upstream (ISP resolver)

Implementation:
- Gateway runs Unbound (recursive/caching resolver) listening on the TUN address
- Client installs the gateway TUN IP as DNS server for protected flows
- Default upstream: Cloudflare 1.1.1.1 (fast, privacy-friendly, no logging)
- Configurable upstreams later: Google 8.8.8.8, Quad9 9.9.9.9, or user-provided
- Client-side DNS query capture for protected apps routes through the tunnel

Key behaviors:
- DNS for protected apps never leaks to the ISP (prevents resolution and filter inconsistencies)
- DNS fails over with the tunnel; if all paths die, protected DNS is intentionally unavailable (fail-closed)
- No DNS in local failover mode unless a local gateway is used
- DNSSEC validation enabled on Unbound by default

## 17. Stable Egress

External destinations should see the gateway public IP.

Example:

    OBS -> StreamGuard -> Ethernet -> Gateway -> YouTube

After Ethernet failure:

    OBS -> StreamGuard -> 5G -> same Gateway -> YouTube

The client's physical ISP/public IP changes, while the
destination-facing gateway egress remains stable.

This is the key mechanism enabling session continuity.

## 18. VPN Detection

At startup/protection activation:
- inspect interfaces
- inspect routes
- identify likely tunnel/VPN adapters
- identify conflicting default routes
- warn rather than silently override

V1 should not promise universal VPN coexistence.

Corporate VPN policies and kill switches must not be intentionally
bypassed.

## 19. Application Protection

V1 may initially protect all routed traffic for simplicity.

Later selected-app mode should allow:

    OBS Studio       protected
    vMix             protected
    Wordlyte Pro     protected
    Browser          optional
    OS updates       bypass/deprioritized

### Windows per-process routing

Per-process routing/filtering on Windows is more involved than a simple
TUN default route. Candidate mechanisms (ranked by fit):

**Windows Filtering Platform (WFP) — Callout Driver**
- Highest control: mark packets by owning PID at the ALET/AALE layers
- Requires a kernel driver (signed, WHQL) --- higher engineering cost
- Post-MVP 2 option

**Windows Filtering Platform (WFP) — User-Mode API**
- `FwpmFilterAdd` with `FWPM_CONDITION_ALE_APP_ID` matches by app,
  no driver required
- Good fit for enforcement at connect level; not packet-by-packet
- Recommended primary approach for selected-app mode

**WinDivert (user-space)**
- Simple interception of packets by PID at user level
- Higher CPU overhead per packet
- Acceptable for filtering, not for high-throughput paths

**Network policy routing (netsh `pktmon`/route policy)**
- Coarse; no per-process semantics

### Recommended approach

| Mechanism | Phase | Role |
|-----------|-------|------|
| All-traffic TUN route | MVP 1 | Default protection |
| WFP user-mode `ALE_APP_ID` filters | MVP 2 | Selected-app enforcement |
| Optional WFP callout driver | Later | Packet-level per-app marking |

### vMix / OBS Notes

OBS and vMix both buy sockets and send UDP (RTMP/SRT) without per-app
proxy support. Marking by PID via WFP covers them without app changes.

## 20. Streaming Policy

Streaming Mode should optimize network behavior rather than terminate
RTMP/SRT.

Possible policies:
- prioritize sustained real-time upload flows
- reserve capacity for protected traffic
- avoid low-quality/high-jitter paths
- enable redundancy earlier
- prevent background traffic from consuming cellular capacity

Video codec/resolution awareness is outside core V1 unless explicitly
provided by an integrated application such as Wordlyte.

## 21. Wordlyte Integration

Wordlyte Pro should communicate with StreamGuard through a stable local
API/IPC interface.

Possible data:
- protection enabled
- active paths
- path quality
- gateway status
- aggregate available bandwidth
- current mode
- warnings

Wordlyte UI can remain simple while StreamGuard retains its standalone
advanced UI.

## 22. Desktop Service

The networking engine should run as a privileged background service
rather than inside the Tauri UI process.

Reasons:
- adapter administration
- route changes
- persistence
- crash isolation
- privilege separation
- UI restart without dropping networking

UI communicates with the service using authenticated local IPC.

### 22.5 Thread / Async Model

**Runtime: Tokio multi-threaded runtime (default worker count = physical cores, capped at 8).**

Component placement:

| Component | Placement | Reason |
|-----------|-----------|--------|
| TUN read/write | Dedicated blocking/driver task | Buffered, not async I/O in user space |
| Path sockets (QUIC) | One task per path | Independent reconnect/failure domains |
| Scheduler | Single dedicated task | Serializes state mutations, no locks in hot path |
| Health engine | Dedicated task, 1 Hz tick | Iterative estimators, not RT |
| IPC (named pipe) | Worker pool | Handles UI client lifecycle |
| DNS resolver | Worker pool | Non-critical path |
| Telemetry/logging | Separate task + channel | Never blocks data plane |

Design rules:
- The scheduler owns the authoritative path state; health engine submits
  updates via channel (no shared mutable state)
- Packets move via `bytes::Bytes` buffers with zero copy between stages
  (TUN -> classifier -> scheduler -> path socket)
- CPU-bound scoring runs on a `spawn_blocking` worker to avoid blocking
  async workers
- All cross-task communication uses bounded channels; backpressure drops
  non-critical probes first, never data-plane packets
- No `unsafe` in the data path without review

## 23. Security Requirements

-   TLS 1.3/modern authenticated transport
-   unique device credentials
-   gateway authentication
-   secure credential storage
-   replay-resistant session establishment
-   no custom cryptographic algorithms
-   least-privilege service design
-   signed desktop binaries
-   secure update mechanism
-   rate limits on gateway control plane
-   telemetry must avoid unnecessary payload inspection

## 24. Observability

Client metrics:
- active interfaces
- per-path RTT/loss/jitter
- bytes sent/received
- path transitions
- duplication rate
- tunnel uptime
- reconnects
- gateway RTT

Gateway metrics:
- active devices/sessions
- active paths
- bandwidth per session
- packets/s
- CPU/RAM
- dropped/duplicate/reordered packets
- tunnel errors
- NAT/forwarding health

## 25. Failure Cases

Must test:
- Ethernet unplug
- Wi-Fi disconnect
- ISP reachable but gateway unreachable
- gateway restart
- client sleep/resume
- IP address change
- DHCP renewal
- high packet loss
- high jitter
- extreme RTT difference between links
- cellular data path appearing/disappearing
- external VPN enabled
- DNS failure
- client service crash
- UI crash
- route rollback after uninstall

## 26. Performance Goals

Exact targets require measurement, but engineering should optimize
for:
- minimal added latency
- bounded reordering delay
- fast failure detection
- low CPU overhead
- no video transcoding
- zero-copy/low-allocation packet paths where practical
- high sustained upload throughput

Do not sacrifice correctness for premature micro-optimization.

### 26.5 MTU Handling

Tunneling adds overhead per packet. The client TUN must advertise a
reduced MTU so encapsulated packets fit inside path MTUs.

Overhead budget (per packet):

    IP (encapsulated)        20
    UDP (outer)              8
    QUIC/TLS header          ~45 (variable)
    StreamGuard envelope    20
    --------------------------------
    Total overhead           ~93 bytes

Initial value: TUN MTU = 1300 (safe for all paths including cellular).

Handling rules:
- PMTU discovery off within the tunnel; the tunnel MTU is fixed/adjustable
- If a physical path reports a lower MTU (e.g. cellular PDN 1400 minus
  overhead), send smaller datagrams on that path; do not fragment
- ICMP Fragmentation Needed outside the tunnel is observed for the outer
  socket and path MTU adjusted per-path
- Enforce per-path effective MTU at the scheduler so honest sizing happens
  in one place
- Ethernet jumbo frames are out of scope

## 27. Prototype Acceptance Test

Setup:
- Windows laptop
- Ethernet Internet
- independent 4G/5G hotspot
- Linux VPS gateway

Procedure:
1. Start StreamGuard.
2. Confirm both physical paths.
3. Activate virtual NIC protection.
4. Confirm gateway egress public IP.
5. Start continuous ping/HTTP/UDP tests.
6. Start sustained OBS stream.
7. Physically unplug Ethernet.
8. Confirm 5G becomes active.
9. Confirm logical StreamGuard session survives or recovers within the defined prototype objective.
10. Confirm public egress remains the gateway IP.
11. Restore Ethernet and verify hysteresis prevents route flapping.

The prototype is successful when the architecture demonstrates that
physical-path loss does not require the protected application to
intentionally reconnect to a different ISP itself.

## 28. Engineering Sequence

| # | Step | Done When |
|---|------|-----------|
| 1 | Rust workspace and shared protocol types | `cargo build` passes; crates compile; shared types in `sg-core`/`sg-protocol` |
| 2 | Linux gateway TUN + forwarding/NAT | Gateway forwards a TUN-injected ping to the Internet; NAT works |
| 3 | Windows TUN creation | Client creates virtual NIC; ping across it succeeds |
| 4 | Single-path encrypted client/gateway tunnel | Bidirectional traffic flows end-to-end via QUIC |
| 5 | Full bidirectional Internet access through gateway | `curl` from client reaches any site via gateway egress |
| 6 | Physical NIC discovery | All interfaces enumerated with state/addresses/MTU/gateway |
| 7 | Explicit per-interface transport binding | Two sockets bound to different NICs in a test |
| 8 | Two simultaneous gateway paths | Ethernet + Wi-Fi both connected to same session |
| 9 | Health probes | Per-path RTT/loss/jitter reported to scheduler |
| 10 | Active/standby failover | Path loss migrates traffic; interruption under 500 ms |
| 11 | Stable egress failover test | Public egress unchanged after unplug (per Section 27) |
| 12 | Desktop status UI | Tauri UI shows paths/mode; IPC authenticated |
| 13 | Adaptive duplication | Degradation triggers duplication; gateway dedups |
| 14 | Weighted scheduling/bonding | Combined throughput exceeds single link with bounded reorder |
| 15 | Application policies | WFP `ALE_APP_ID` filters enforce selected-app protection |
| 16 | Wordlyte integration | Wordlyte displays StreamGuard status via IPC API |

## 29. Technical Risks

### Multipath transport complexity

Different RTTs, congestion states and loss rates can make naive packet
striping perform worse than one good connection.

### Windows routing

Virtual adapters, route metrics, VPNs and per-process policies require
careful platform-specific handling.

### QUIC fit

Quinn is a strong candidate but StreamGuard's multipath requirements
must be validated experimentally rather than assumed.

### Cellular cost

Duplication/bonding can consume substantially more data.

### Gateway bandwidth

Sustained video makes network transfer/egress a major infrastructure
cost.

### Failure detection

Too slow causes visible interruption; too aggressive causes unnecessary
switching.

## 30. Architectural Decision

The canonical StreamGuard architecture is:

    Virtual NIC
        |
    StreamGuard Core
        |
    Multipath Scheduler
        |
    Secure independent physical paths
        |
    StreamGuard Gateway
        |
    Internet

A local RTMP/SRT stream proxy is not required by the core architecture.

StreamGuard should first prove resilient two-path tunneling. True
bonding, advanced streaming policies and general-purpose connectivity
are subsequent layers.

## 31. Connection Lifecycle

### 31.1 First-Time Registration

    User launches desktop app
        -> signs up / logs in (OAuth or email+password)
        -> device id generated locally
        -> CSR sent to StreamGuard portal CA
        -> device certificate issued and stored in platform keychain
        -> gateway selection (auto: nearest region, or manual)

### 31.2 Session Establishment (per app start)

    Service starts
        -> discover physical NICs (sg-network)
        -> open TUN adapter (sg-tun)
        -> mTLS handshake with gateway (Section 15.6)
        -> exchange JWT session token
        -> open QUIC connections on each eligible path
        -> register paths with gateway session
        -> install routes / VPN detection checks
        -> protection active, UI shows live status

### 31.3 Steady State

    1 Hz health probes per path
        -> health engine updates scores
        -> scheduler evaluates against policy + hysteresis
        -> active path carries traffic; alternates stay eligible
        -> telemetry flows to logs/dashboard

### 31.4 Path Failure

    Ethernet unplug detected (health probe fail / link down)
        -> scheduler immediately promotes standby path
        -> affected lost packets are not retransmitted (real-time)
        -> hysteresis prevents flapping when Ethernet returns
        -> UI reflects path change

### 31.5 All Paths Lost

        -> protected traffic halts (fail-closed)
        -> UI shows fatal-level warning
        -> retry backoff re-establishes paths as they return
        -> DNS for protected apps fails closed (no leak to local)

### 31.6 Shutdown / Uninstall

    User disables protection or exits
        -> session ends (gateway notified)
        -> paths drained gracefully
        -> routes rolled back to pre-StreamGuard state
        -> TUN adapter removed
        -> on uninstall: device cert optionally revoked at portal

### 31.7 Desired Recovery Times

| Event | Target |
|-------|--------|
| Path loss → path switch | < 500 ms |
| Service crash → restart | < 2 s (auto) |
| All-paths-recover → session re-established | < 5 s |
| UI restart (service persists) | < 1 s |
