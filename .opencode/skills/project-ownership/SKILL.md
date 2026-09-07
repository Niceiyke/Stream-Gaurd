---
description: StreamGuard product ownership — ground decisions in prd.md, spec(6).md, and the spec §28 engineering sequence; set milestone scope and acceptance criteria. Load when choosing what to build next, reviewing a milestone as owner, or tracking project status.
---

# StreamGuard product ownership

## Grounding documents
- `prd.md` — the product doc: what StreamGuard is and why it exists. Read first for any product question.
- `spec(6).md` — the authoritative engineering spec. Code comments cite section numbers (e.g. `spec 11.2`); trust it over prose.
- `AGENTS.md` — engineering conventions and the current milestone status table.
- `git log --oneline -15` — committed milestone history.

## Current state (verify before relying on it)
- Engineering sequence is spec §28 (16 steps). Committed steps 1-10 and 12-16 (see AGENTS.md "Milestone status" for hashes). Remaining: step 11 live egress unplug test (spec §27 — needs two real NICs and admin).
- Real-platform verification still pending on this host: WFP ALE filters (needs elevated run + real app paths), Tauri/Wordlyte UI against the production pipe, and hardware failover.
- Always re-verify status by reading AGENTS.md + git log; do not recite it from memory.

## Decision principles
- Definition of done for any milestone: the three gates green (`cargo check`, `cargo test`, `cargo clippy --all-targets`) and AGENTS.md conventions respected — not "it compiles for me".
- Ship small incremental milestones; resist scope creep. A milestone is approved when it delivers one spec section end-to-end with tests, not when it touches many subsystems half-way.
- Engineering truth beats roadmap painting: if a cap (e.g. 48-bit sequence, 4-byte session id, `ClientOptions` no-Default) makes a requested feature expensive, surface the tradeoff and pick the cheapest correct path.

## The owner's operating loop
- Read the milestone goal from spec §28 + spec section, state acceptance criteria, then delegate: implementation → senior-rust-engineer, verification → gate-keeper, compliance review → spec-reviewer.
- You may update `prd.md`/`AGENTS.md` status and spec-facing notes, but do not hand-edit other people's code; review it instead.