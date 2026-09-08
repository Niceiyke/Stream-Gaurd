---
name: streamguard-v2
description: StreamGuard V2 rebuild execution guide. Load when implementing or reviewing a REBUILD_V2_AGENT_PLAN.md work packet, especially protocol, authentication, gateway, routing, scheduler, or release work.
---

# StreamGuard V2 Rebuild Execution

## Start Here

1. Read the exact work packet in `REBUILD_V2_AGENT_PLAN.md`.
2. Read its dependencies and acceptance criteria.
3. Inspect existing code before proposing a file layout.
4. Keep V2 in separate modules until the V2 cutover policy is met.

## Production Invariants

- No payload before mTLS and ticket admission.
- Full-width server-issued session IDs only.
- Reliable QUIC control stream; datagrams are payload only.
- Per-flow bounded dedup/reorder with deadlines, never session-global HOL.
- Effective MTU validated before packet identity allocation/send accounting.
- Blocking TUN ownership belongs to a dedicated blocking worker.
- Routes, DNS, and firewall state are transactional and recoverable.
- Every state map, queue, and spawned task has an explicit resource bound.

## Delivery Standard

- Implement one work packet at a time.
- Add deterministic focused tests before broad integration tests.
- Record every intentional deferral against a later work packet.
- Request architecture, compliance, and gate review at milestone boundaries.
