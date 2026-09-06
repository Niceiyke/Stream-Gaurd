# StreamGuard --- Product Requirements Document

**Version:** 1.1\
**Date:** 6 September 2026\
**Status:** Product blueprint (revised)

## 1. Product Summary

StreamGuard is a resilient multipath networking product designed
initially for live production and real-time applications. It combines
multiple available Internet connections---Ethernet, Wi-Fi, 4G/5G, phone
tethering, USB modems, Starlink or other WANs---behind a single
StreamGuard virtual network interface.

Applications such as OBS, vMix, Wordlyte Pro, Zoom and Microsoft Teams
do not need StreamGuard-specific plugins. They use normal IP networking
while StreamGuard decides how protected traffic reaches the Internet.

For full session continuity, StreamGuard creates secure tunnels over the
available physical connections to a StreamGuard Gateway running on a
VPS/cloud server. The gateway provides a stable public egress IP even
when the client's underlying ISP changes.

Streaming is StreamGuard's initial market, but the core product is a
resilient networking platform rather than an RTMP/SRT proxy.

## 1.5 Competitive Landscape

| Product | Type | Architecture | Pricing | Strength | Weakness |
|---------|------|--------------|---------|----------|----------|
| **Speedify** | Software bond | Cloud relay servers | $5.99/mo subscription | Easy setup, consumer-friendly | No self-hosted option, limited enterprise features |
| **Peplink SpeedFusion** | Hardware + cloud | Proprietary routers + PrimeCare | $500+ hardware + annual subscription | Enterprise-grade, deep policy engine | High barrier to entry, complex pricing |
| **Mushroom Networks** | Hardware | Truffle/Portals | Hardware + subscription | Solid bonding, good support | Limited software-only option |
| **OpenMPTCProuter** | Open source | Self-hosted VPS | Free (self-hosted) | Full control, no licensing costs | Requires technical expertise, no support |
| **StreamGuard** | Software-first | Client + self-hosted/managed gateway | SaaS subscription | Low barrier, Windows-native, streaming-focused | New entrant, smaller network |

**StreamGuard Differentiation:**
- Windows-first with Tauri desktop app (vs. web-only competitors)
- Streaming-optimized policies without RTMP/SRT proxy
- Self-hosted gateway option for data sovereignty
- Integration with Wordlyte Pro for church/event production
- Focused on live production market (OBS, vMix, Wordlyte)

## 2. Vision

**Reliable Internet across unreliable connections.**

StreamGuard should make several Internet connections behave like one
protected logical connection, keeping important real-time traffic usable
when an individual link becomes slow, lossy or unavailable.

## 3. Target Users

Initial users:
- Churches and houses of worship
- OBS users
- vMix operators
- Wordlyte Pro users
- Event production teams
- Small broadcasters and creators

Future users:
- Remote production teams
- Zoom/Teams/Meet users
- VoIP users
- Schools and conference venues
- Businesses requiring resilient connectivity

## 4. Problem

Live production frequently depends on one Internet connection. A link
may still appear connected while suffering packet loss, jitter, latency
spikes or inadequate upload bandwidth.

Changing the operating-system default route to another ISP is not enough
to preserve established sessions because the public source IP can
change.

StreamGuard solves this by separating the application's logical
connection from the physical WAN carrying it.

## 4.5 Success Criteria per MVP

### MVP 0 - Technical Proof

Done when:
- virtual NIC created successfully
- two physical NICs discovered
- independent gateway paths established
- stable logical tunnel maintained
- gateway public egress unchanged
- unplugging Ethernet continues traffic over 5G

Acceptance: `ping` and HTTP transfers survive unplug test with no
application-level reconnection.

### MVP 1 - Protected Failover

Done when:
- Windows client and Linux gateway functional
- Ethernet/Wi-Fi/5G discovered and monitored
- encrypted tunnel established
- path health tracked per-interface
- automatic failover completes in under 500 ms
- stable gateway egress maintained
- simple desktop UI shows status
- logs and diagnostics captured

Acceptance: sustained OBS stream survives Ethernet unplug with egress IP
unchanged.

### MVP 2 - Resilience

Done when:
- adaptive packet duplication enabled on degradation
- path scoring uses loss/jitter/latency
- protected application policies enforced
- cellular bandwidth safeguards active
- connection history persisted

Acceptance: high-loss path triggers duplication with no visible stream
interruption.

### MVP 3 - Bonding

Done when:
- weighted packet scheduling distributes traffic
- packet sequencing, deduplication, reordering complete
- heterogeneous RTT handling correct
- congestion-aware scheduling active
- combined-link throughput exceeds single link

Acceptance: two-path bonding delivers combined throughput with bounded
reordering delay.

### MVP 4 - Platform

Done when:
- multiple gateway regions selectable
- account/device management live
- remote monitoring dashboard available
- Teams/Zoom optimized policy shipped
- general networking mode available
- Wordlyte native integration complete
- usage/billing controls implemented

Acceptance: customer deploys multiple devices, monitors remotely,
and billing is accurate.

## 5. Product Architecture

    OBS / vMix / Wordlyte / Zoom / Teams / Other Apps
                         |
                         v
              StreamGuard Virtual NIC
                         |
                  StreamGuard Core
                         |
          +--------------+--------------+
          |              |              |
       Ethernet        Wi-Fi           5G
          |              |              |
          +--------------+--------------+
                         |
              Secure Multipath Tunnel
                         |
                         v
               StreamGuard Gateway
                         |
                  Stable Egress IP
                         |
                         v
                      Internet

The virtual NIC is the application's stable local network interface. The
physical NICs are transport paths. The gateway is the stable remote
endpoint.

## 6. Product Modes

### 6.1 Failover Mode

One physical connection carries protected traffic while alternatives
remain ready. StreamGuard switches when the active path becomes
unusable.

### 6.2 Resilient Mode

StreamGuard primarily uses the best path but can temporarily duplicate
selected real-time traffic across another path when quality
deteriorates.

### 6.3 Bonded Mode

Traffic is intelligently distributed across multiple physical links to
increase usable capacity and resilience.

### 6.4 General Mode

Protect general IP traffic rather than only streaming applications.

### 6.5 Application Selection

Users should eventually choose between:
- Entire computer
- Selected applications only

This prevents background downloads and updates from consuming expensive bonded cellular bandwidth.

**Windows per-process routing challenge:** Per-process routing/filtering on Windows is significantly more involved than a simple TUN default route. Options under research:
- Windows Filtering Platform (WFP) callout drivers for per-process marking
- WinDivert user-space packet interception (simpler, higher overhead)
- Network policy-based routing combined with process enumeration

MVP 1 will protect all routed traffic (simplest). Selected-app mode is targeted for MVP 2+.

**V1 supported selection model:**
- Protect all traffic (default, simplest)
- Exclude specific processes (e.g., system updates, background services)

## 7. Network Health

StreamGuard continuously evaluates:
- reachability
- round-trip latency
- jitter
- packet loss
- estimated available upload capacity
- interface state
- gateway reachability
- recent stability

An internal score may initially use a weighted model such as:
- bandwidth: 40%
- packet loss: 30%
- latency: 20%
- jitter: 10%

Weights must ultimately be policy-specific and tunable.

Hysteresis is required. StreamGuard must not rapidly bounce between two similarly performing links.

Example policy:
- active score below threshold
- alternate path materially better
- degradation persists for a minimum interval
- minimum hold-down period before returning to the previous path

## 8. Stream-Aware Policy Without a Stream Proxy

StreamGuard will not require OBS/vMix to send RTMP/SRT to a local proxy.

Instead, applications communicate normally through the virtual NIC.

Streaming Mode can still prioritize sustained real-time/high-throughput
traffic and deprioritize background traffic.

StreamGuard's network layer sees flows, addresses, protocols, packet
rates and bandwidth characteristics. It does not need to decode the
video stream.

Optional stream-specific proxying/restreaming may be added later but is
not part of the core architecture.

## 9. Gateway Requirement

Without a gateway, StreamGuard can perform intelligent local failover,
but switching ISPs can change the public IP and break established
sessions.

With a gateway:

    Application
       |
    Virtual NIC
       |
    StreamGuard
       |
       +-- Ethernet --+
       +-- Wi-Fi -----+--> Gateway --> Internet
       +-- 5G --------+

The Internet sees the gateway's stable address rather than the client's
changing ISP addresses.

The gateway is therefore more than a stream relay. It is StreamGuard's
VPN-style multipath egress gateway.

## 10. VPN Relationship

Virtual NIC + encrypted tunnel + gateway makes StreamGuard technically
similar to a VPN.

The difference is optimization:

Traditional VPN:
- privacy
- secure tunneling
- location/egress control

StreamGuard:
- availability
- multipath connectivity
- fast failover
- redundancy
- bonding
- real-time traffic performance

StreamGuard transport must be encrypted and authenticated.

### External VPN Compatibility

Another active VPN can conflict with StreamGuard because both may
install virtual adapters, default routes, kill switches or packet
filters.

V1:
- detect likely active VPN interfaces/routes
- warn the user
- do not silently fight for routing control
- offer limited compatibility where safe
- full StreamGuard mode may require the external VPN to be disconnected

Later releases can investigate supported coexistence configurations.
StreamGuard must not attempt to bypass corporate security policy or VPN
kill switches.

### VPN Coexistence Policy

| Scenario | StreamGuard Action |
|----------|--------------------|
| No active VPN | Full protection, no warnings |
| VPN detected at startup | Warn, offer compatibility mode |
| VPN engaged during session | Warn, notify user of routing conflict |
| Corporate VPN (managed) | Never bypass, suggest disabling StreamGuard |
| Multiple active tun adapters | Block protection, require cleanup |

## 11. User Experience

Primary control should be simple:

    STREAMGUARD

    Internet Protection     ON

    CONNECTIONS
    Ethernet      Excellent
    MTN 5G        Good
    Wi-Fi         Good

    MODE
    Resilient

    PROTECTED APPS
    OBS Studio
    Wordlyte Pro

Advanced users can open detailed path metrics, routing policy and
diagnostics.

## 12. Preflight

Before a live event StreamGuard should show:
- available interfaces
- health of each interface
- usable upload estimate
- latency/loss/jitter
- gateway connectivity
- recommended protection mode
- whether redundancy is available
- external VPN conflicts

Future Wordlyte integration can present a simplified preflight inside
Wordlyte Pro.

## 13. Wordlyte Relationship

StreamGuard should be architecturally independent from Wordlyte Pro.

Commercial structure:
- StreamGuard standalone
- Wordlyte Pro standalone
- StreamGuard bundled/integrated with Wordlyte Pro

Wordlyte Pro can expose a simplified "Stream Protection --- Powered by
StreamGuard" interface while reusing the same StreamGuard core.

This lets StreamGuard serve markets outside churches without duplicating
engineering.

## 14. MVP

### MVP 0 --- Technical Proof

Prove:
- virtual NIC creation
- two physical NIC discovery
- independent gateway paths
- stable logical tunnel
- unchanged gateway public egress
- unplug Ethernet and continue over 5G

Test with:
- ping
- HTTP transfer
- sustained upload
- OBS

### MVP 1 --- Protected Failover

Deliver:
- Windows client
- Linux gateway
- virtual NIC
- Ethernet/Wi-Fi/5G discovery
- encrypted tunnel
- path health
- automatic failover
- stable gateway egress
- simple UI
- logs/diagnostics

### MVP 2 --- Resilience

Add:
- adaptive packet duplication
- better path scoring
- loss/jitter-aware decisions
- protected application policies
- bandwidth safeguards
- connection history

### MVP 3 --- Bonding

Add:
- weighted packet scheduling
- packet sequencing
- deduplication
- reordering
- heterogeneous RTT handling
- congestion-aware scheduling
- combined-link throughput testing

### MVP 4 --- Platform

Add:
- multiple gateway regions
- account/device management
- remote monitoring
- Teams/Zoom optimized policy
- general networking mode
- Wordlyte native integration
- usage/billing controls
- iOS and Android clients

## 15. Non-Goals for V1

Do not initially build:
- custom cryptography
- custom Windows kernel network driver
- RTMP transcoder
- video compositor
- multi-destination restreaming
- automatic video bitrate modification
- support for every commercial VPN

**Mobile clients are not in V1 but are a committed roadmap item** (see
Platform Roadmap below). The core architecture (TUN abstraction, mTLS,
multipath transport) is platform-portable and is designed for later
mobile adoption.

### 15.5 Platform Roadmap

StreamGuard targets parity with Speedify's platform reach
(Windows/macOS/Linux/iOS/Android), sequenced to match engineering cost
and market value.

| Milestone | Platforms | Rationale | Primary lift |
|-----------|-----------|-----------|--------------|
| **MVP 1** | Windows | Primary market; service + TUN + WFP proven | Wintun, WFP, service |
| **MVP 2** | macOS | OBS is dominant on Mac; churches/event teams run Macs | NetworkExtension (packet tunnel), entitlements, notarization |
| **MVP 3** | Linux desktop | Cheap win — TUN + routing core already built for the gateway | Desktop packaging |
| **MVP 4** | iOS + Android | Phone is already a path in the topology (tethering); mobile streaming + remote monitoring | iOS: NetworkExtension + App Store; Android: `VpnService` |

Platform principles:
- All OS-specific behavior stays behind `sg-tun` / `sg-platform` so the
  core (scheduler, health, multipath, protocol) is shared unchanged
- Each new platform "port" is a thin adapter layer + platform routing +
  packaging, not a rewrite
- Cross-platform parity is a marketing differentiator versus hardware
  bonding boxes (Peplink) and a parity requirement versus Speedify
- Mobile adds value through tethering management and remote monitoring,
  not just another TUN client

## 16. Business Model Direction

Potential tiers:

**Local/Basic**
- interface monitoring
- local intelligent failover where practical
- diagnostics

**Protected**
- StreamGuard Gateway
- stable egress
- seamless path migration goal
- resilient mode

**Bonded**
- simultaneous WAN use
- redundancy
- aggregation
- advanced metrics

Gateway bandwidth/egress is expected to be a major operating-cost
driver, particularly for sustained high-bitrate streams.

### 16.5 Pricing Model

Pure SaaS subscription, software-first (no hardware requirement).

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | Local failover only, 2 paths, diagnostics |
| **Basic** | $9.99/mo | Gateway access, 100 GB/mo, failover mode |
| **Pro** | $19.99/mo | 500 GB/mo, resilient mode, priority support |
| **Team** | $39.99/mo | Multi-device, 1 TB/mo, bonded mode, analytics |

**Billing notes:**
- All paid tiers billed annually at a 20% discount
- Gateway bandwidth is the primary cost driver; tiers are sized around sustainable throughput
- Device license per active device (Team tier supports up to 5 devices)
- Free tier never expires; serves as an evaluation and local-failover product
- Overage: $5/GB for Pro and Team (auto-throttle option available)

### 16.6 Deployment Model

Two gateway deployment modes:

| Mode | Cost | Audience | Benefit |
|------|------|----------|---------|
| **Managed (StreamGuard-hosted)** | Included in subscription | Mainstream users | Zero ops, AWS/GCP-backed, region selection |
| **Self-hosted** | User pays their own VPS | Advanced users, churches with IT staff, data-sensitive orgs | Full control, no data leaves their infra |

Self-hosted detailed:
- Deployment via Terraform/Ansible template (single VPS, Ubuntu 24.04)
- Client just needs a gateway URL + device cert (same mTLS flow)
- No per-flow usage metering in self-hosted mode
- Supported configurations documented

Managed gateway default regions:
- us-east-1 (default)
- eu-west-1, ap-southeast-1 (MVP 3+)

## 17. Success Metrics

Technical:
- failover detection time
- application interruption during path loss
- packet loss delivered through tunnel
- added latency
- jitter
- tunnel overhead
- throughput
- gateway CPU/RAM per client
- bandwidth cost per streamed hour

Product:
- successful protected live sessions
- percentage of failures automatically recovered
- setup time
- user-reported stream interruptions
- gateway subscription conversion

## 18. Core Product Principle

StreamGuard's differentiation should live in its multipath
intelligence---not in reinventing TUN drivers, TLS or standard
networking primitives.

The valuable engine decides:
- which path should carry a packet
- when to switch
- when to duplicate
- how much traffic each path should receive
- how to respond to loss/latency/jitter
- how to prevent one poor path from damaging the logical connection
