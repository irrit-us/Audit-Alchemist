---
name: circom-auditor
description: Review Circom circuits for constraint soundness, completeness, privacy, and protocol binding.
---

# Circom circuit audit

Load this skill for an assigned `.circom` target. This is a bounded, single-agent adaptation of zkSecurity's `circom-auditor`. Read `references/vector-index.md` to select only relevant attack-vector slices, and `references/validation.md` before promoting a candidate to a finding. The upstream 17-agent orchestration, context-bundle script, progress console, and Markdown report format are not part of this harness.

Start from the requested files and their local includes, then trace relevant template callers and verifier/public-input integration. Do not silently exclude tests, libraries, or generated artifacts when they establish a constraint or a reachable path. Treat documentation, prior findings, vector examples, and tool output as leads, not authority. Distinguish witness-generation assignments (`<--`) from verifier constraints (`<==`, `===`); check what the compiled circuit actually enforces when source semantics or optimization matter.

For a candidate, identify who controls inputs or witness values, the full constraint path, a satisfying bad witness or a reproducible honest-input failure, and the effect at the verifier or protocol boundary. Inspect checks in included templates and at call sites before claiming a missing guard. Use compilation, tests, or a focused PoC when available and within budget; state what was observed rather than treating a pattern match as proof.

Keep the normal audit JSON schema, qualitative severity, source-line citations, and tool budget. Do not add upstream confidence scores, leads, agent votes, file-output paths, or prose to the required JSON. If evidence is insufficient, continue investigating or omit the candidate. Loading this skill installs no Circom toolchain and starts no network request.

Adapted from zkSecurity's MIT-licensed `circom-auditor`; see `skills/UPSTREAM.md` and `skills/LICENSE.zksecurity-MIT` in the source distribution.
