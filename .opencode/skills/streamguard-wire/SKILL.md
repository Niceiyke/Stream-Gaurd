---
description: Wire-format and in-order reassembly rules for StreamGuard. Load before editing envelope/protocol/session/reorder code (sg-protocol, sg-session, sg-multipath, tunnel.rs, client.rs) or any echo/data integration test.
---

# StreamGuard wire & reassembly rules

## Envelope (spec 11.1)
- Envelope is a 20-byte fixed header inside each QUIC datagram.
- `Sequence` is `u64` in code but **48-bit (6 bytes) on the wire**: values ≥ 2^48 truncate silently across encode/decode. Keep test sequences small.
- Only the **first 4 bytes** of `SessionId` cross the wire; decode zero-fills the tail. For any id that travels, build it with `sg_session::session_id_from_wire(prefix)`. `SessionId::new()` is only safe locally.
- `PacketType`: Data=0, Duplicate=1, Control=2, Probe=3, Keepalive=4, PathStatus=5. `Duplicate` carries an already-seen sequence (redundancy); first-valid-wins.

## In-order reassembly (spec 11.2)
- Active model: both the gateway reader and client downlink reader call `Session::enqueue_incoming(seq, payload) -> sg_multipath::ReorderOutcome` and write every `outcome.delivered` payload to the TUN; `outcome.dropped` increments `duplicates_dropped`.
- `next_expected` starts at **0**. A first packet with seq ≠ 0 is buffered forever — echo/data tests MUST start at `Sequence::new(0)`.
- Echo gateways bounce the SAME sequence back. Do NOT reintroduce the old `+1_000_000` echo offset — it silently buffers.
- `ReorderBuffer` dedups via `ReorderWindow` (first-valid-wins), uses `BTreeMap<u64, Bytes>` for the wait buffer, drops far-ahead packets when `seq.saturating_sub(next_expected) > capacity`, and drops-when-full without evicting.

## Code conventions that affect the wire
- `ClientOptions` has no `Default`; every field is set at all 6 construction sites (3 in `apps/streamguard-service/tests/e2e.rs`, 3 in `client.rs` unit tests). Adding a field means updating all 6.
- `PathMetrics::default()` has `reachable: false`; fresh entries must be `PathMetrics { reachable: true, ..Default::default() }` (unmetered = eligible).
- Lock order: never hold `metrics` while acquiring `session`; `session → metrics` and `probes → metrics` are fine.