---
name: cvss
description: Assess a supported finding with CVSS v4.0 or interpret a published CVSS vector.
---

# CVSS assessment

Use this skill when the task asks for a CVSS score/vector or when a published score needs interpretation. Read `references/scoring.md` for the version choice, metric checklist, and official calculators. No executable or account is required; an official calculator needs network access if used.

Establish the vulnerable behavior, attacker prerequisites, and demonstrated impact from the audited code first. Score the stated scenario, not a CVE's reputation or an imagined worst case. Record the CVSS version, complete vector, score, calculator/source, and assumptions together. Base severity is not deployment risk; add Threat and Environmental metrics only with supporting evidence.

The audit protocol's `severity` field is qualitative and has no CVSS score/vector field. Do not add fields to the required JSON or replace code evidence with a public score. If the scenario cannot be established, state the uncertainty outside that protocol only when the caller permits it.
