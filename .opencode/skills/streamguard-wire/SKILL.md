---
name: streamguard-wire
description: StreamGuard V1/V2 wire and packet-delivery guardrails. Load before editing protocol, QUIC control, session, dedup, reorder, tunnel, or packet integration tests.
---

# StreamGuard Wire Guardrails

## V2 requirements

- Treat `REBUILD_V2_AGENT_PLAN.md` WP-100, WP-101, WP-301, and WP-302 as the
  implementation contract.
- V2 session IDs are full-width, opaque, and server-issued. Never truncate or
  reconstruct an ID from a prefix.
- Validate version, flags, enums, framing, and payload size before state
  allocation. All attacker-controlled collections have an explicit bound.
- QUIC datagrams carry payload only. Authentication, admission, attach/detach,
  policy, and path state use a reliable framed control stream with request IDs
  or epochs and acknowledgements.
- Bind every received envelope to the authenticated session and path that owns
  its transport connection.
- Dedup and reorder are per flow and bounded by packet count, bytes, and age.
  A missing packet must expire rather than block unrelated flows.
- First valid payload wins whether it arrives as a primary or redundant copy.
- Compute effective payload MTU before sequence/packet-ID allocation. Failed
  sends never count as delivered.

## V1 containment

- V1's 20-byte envelope, 48-bit sequence, four-byte session prefix, and
  session-global reorder queue are experimental legacy behavior only.
- Preserve those V1 rules only in explicitly scoped V1 tests or compatibility
  seams. Do not copy them into V2 code.
- V1 tests that use the existing reorder model still start at sequence zero and
  echo the same sequence.

## Shared code discipline

- `PathMetrics::default()` starts unreachable; fresh usable entries explicitly
  set `reachable: true`.
- Never acquire `session` after `metrics`; use a documented lock order or
  snapshot state before awaiting I/O.
- Do not hold a lock across a network send, TUN operation, or control-stream
  await unless the ownership proof is explicit and reviewed.
