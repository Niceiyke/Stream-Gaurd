# V1 Prototype Status

## Status

StreamGuard V1 is experimental development scaffolding. It may be used for
local tests and engineering investigation only. It must not be exposed to the
Internet, used for customer traffic, or represented as a production VPN,
multipath bonding service, or live-stream protection product.

The V2 rebuild is defined by `REBUILD_V2_AGENT_PLAN.md`. V1 is removed only
after the V2 cutover policy and hardware acceptance gates are complete.

## What V1 Demonstrates

- Rust workspace boundaries for a client, gateway, TUN abstraction, transport,
  session handling, health sampling, and status UI.
- Loopback QUIC data-path tests, multi-path prototypes, and basic status IPC.
- Platform research for Wintun, Linux NAT, Windows WFP, and per-interface
  socket binding.

These are engineering prototypes, not production guarantees.

## V1 Release Blockers

1. The gateway has an unauthenticated first-frame fallback, so an untrusted
   peer can reach gateway session/forwarding state.
2. Authentication is a static shared-secret HMAC ticket minted on the client;
   there is no device enrollment, mTLS, certificate rotation, revocation, or
   replay-resistant server-issued admission.
3. The wire protocol carries only a four-byte session prefix and cannot safely
   identify managed-service sessions.
4. Control messages use lossy QUIC datagrams rather than acknowledged reliable
   control streams.
5. TUN reads can block Tokio tasks while holding shared async locks.
6. Session-global reorder means loss in one flow can block unrelated traffic.
7. Payload MTU is not negotiated/enforced before sequencing and send
   accounting.
8. Gateway forwarding lacks per-session address allocation, source validation,
   IPv6 support, bounded complete flow state, and tenant isolation.
9. Client route, DNS, kill-switch, rollback, and crash-recovery behavior are
   not production implementations.
10. Linux firewall/NAT setup is shell-built and not idempotent or recoverable.
11. Windows service lifecycle, WFP policy lifecycle, signed deployment, update,
   observability, and hardware acceptance evidence are incomplete.

## Development Credential Warning

`STREAMGUARD_SECRET`, client-side `sg_auth::issue`, self-signed `cert.der`,
`key.der`, and `sgcerts/` are V1 local-development mechanisms only. They are
not valid V2 credentials and must never be committed, distributed, logged, or
used to authenticate a production client or gateway.
