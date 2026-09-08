---
name: project-ownership
description: StreamGuard V2 product ownership. Load when selecting rebuild work, reviewing a V2 milestone, assessing release readiness, or tracking prototype versus production status.
---

# StreamGuard product ownership

## Grounding documents
- `prd.md` — the product doc: what StreamGuard is and why it exists. Read first for any product question.
- `spec(6).md` — the authoritative engineering spec. Code comments cite section numbers (e.g. `spec 11.2`); trust it over prose.
- `AGENTS.md` — engineering conventions and the current milestone status table.
- `REBUILD_V2_AGENT_PLAN.md` — V2 implementation order, work packets, and
  acceptance gates. It supersedes V1 sequencing for the rebuild.
- `git log --oneline -15` — committed milestone history.

## Current state (verify before relying on it)
- V1 milestones are prototype evidence, not production release evidence.
- V2 starts at WP-000 and must reach Safe Mode validation before bonding or
  managed-service claims.
- Always re-verify status from the rebuild plan, AGENTS.md, git history, and
  the current worktree; do not recite it from memory.

## Decision principles
- Definition of done: work-packet acceptance criteria, focused tests, all cargo
  gates, compliance review, and required hardware evidence are complete.
- Ship one dependency-ready work packet at a time. Do not mix protocol,
  platform routing, UI, and controller work in one milestone.
- Engineering truth beats roadmap painting: preserve V1 only when needed for a
  scoped test; prefer the V2 secure contract over compatibility shortcuts.

## The owner's operating loop
- Read the earliest unblocked work packet, state its dependencies and
  acceptance criteria, then delegate: implementation -> senior-rust-engineer,
  architecture review -> v2-architecture-reviewer, verification ->
  gate-keeper, compliance -> spec-reviewer.
- Do not approve a public release without WP-900/WP-901 evidence, security
  review, and deployment/recovery validation.
