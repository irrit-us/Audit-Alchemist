---
name: audit-context-building
description: Map unfamiliar code's entry points, state, and cross-function assumptions before focused auditing.
---

# Audit context building

Use for an unfamiliar target or when a finding cannot be judged without its surrounding architecture. Start with a bounded area relevant to the assigned target; do not turn a focused audit into an exhaustive repository inventory. Use the existing list/search/read tools and Bash. No extra workflow runner, subagent, package, or network access is required.

Map entry points, actors and trust boundaries, persistent state, and the calls linking them. For each important function, record inputs, preconditions, state changes, return paths, and what its callers assume it guarantees. Follow available callee source through success and failure paths; a name such as `validate` does not establish a check. Mark an assumption `nothing found` only after a bounded search for its enforcement. Put unresolved claims in open questions.

Load `references/analysis-format.md` for a compact note template and `references/domain-notes.md` only for a relevant domain. Keep any notes in a new, task-specific scratch file if persistence is useful; preserve existing files. Notes are investigation aids, not final findings. Continue the assigned vulnerability audit using code-audit, PoC validation, and the normal evidence/JSON contract. Do not report an unchecked assumption as a vulnerability without a reachable consequence.

Adapted from Trail of Bits' audit-context-building skill by Omar Inuwa. This adapted skill and its references are CC BY-SA 4.0; see `skills/UPSTREAM.md` and `skills/LICENSE.trailofbits-CC-BY-SA-4.0` in the source distribution.
