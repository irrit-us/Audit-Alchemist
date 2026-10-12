# Cross-harness baselines

How the built-in auditor compares with four external coding-agent harnesses on
the seven primary `alchemist-dataset-tiny` labels. **All four harnesses run
`deepseek-flash`**, the same model as the built-in agent's blind rounds, and the
case labels are hidden from every harness. Method and scoring are in
[Evaluation](evaluation.md); the recorded run is
[harness-baselines.json](reports/harness-baselines.json).

> **Correction (2026-10-11).** The first published baselines were contaminated:
> the runner staged the audit tree and then wrote the per-case manifest,
> including the `expected` labels, into the agent's working directory. Codex and
> others read it, so results such as "Codex 21/21 exact" were not independent
> discovery. `scripts/external_agent.py --hide-labels` now moves `dataset.json`
> out of the workspace for the duration of each run (the runner passes it by
> default), and a clean verification window showed zero manifest reads. The
> results below are the leak-free rerun; the contaminated numbers are retained
> only in git history.

## Harnesses

| Name | Invocation | Model | Notes |
| --- | --- | --- | --- |
| Codex | `codex exec -m deepseek-flash -c model_provider=deepseek` | `deepseek-flash` | `deepseek` provider + `DS_API_KEY` |
| Claude Code | `claude -p --settings <json>` | `deepseek-flash` | DeepSeek Anthropic-compatible endpoint; token injected by the adapter |
| DSH | `dsh --profile headless` | `deepseek-flash` | profile default model |
| Pi | `pi -p --model deepseek-flash` | `deepseek-flash` | native tools; no adapter-imposed tool budget |

Each harness runs in the audit root with its own native tools and agent loop.
The adapter (`scripts/external_agent.py`) implements the
[Version 1 protocol](protocol.md): it reads the request, sends a fixed audit
brief plus the case instruction, recovers the response object from a per-case
side file or the harness output, normalizes CWE/path/severity form, and never
invents a finding. A missing or unparseable response exits non-zero so the
scorer records a failed invocation rather than a clean empty report. The
adapter also hides the manifest, and its parsing/normalization/label-hiding are
pinned by `HarnessAdapterTests` in `tests/debug_scripts.py`.

## Method

- **Dataset**: the seven primary fixture labels, blind instruction (one generic
  instruction for every case), repo revision pinned in the run manifest.
- **Label isolation**: each case is staged into a fresh copy, and the per-case
  manifest is removed from the agent's working directory while the harness runs.
  Without this, all external results overstate capability.
- **Trials**: three per harness, every trial retained; no best-of selection.
- **Scoring**: exact `(CWE, path, line)` and line `(path, line)` precision,
  recall, and F1; successful/failed invocations and adapter timeouts.
- **Budgets**: benchmark wall-clock 30 min, adapter wall-clock 26 min, a
  15-minute soft in-band deadline, job parallelism 2 per harness.

Reproduce one harness:

```sh
export DS_API_KEY=... AUDIT_HARNESS_CODEX_PROVIDER=deepseek
export AUDIT_HARNESS_CLAUDE_TOKEN=...
python scripts/run_harness_baseline.py --harness codex --model deepseek-flash \
  --blind --trials 3 --jobs 2 --deadline-minutes 15 \
  --timeout-ms 1800000 --adapter-timeout 1560 \
  --output target/harness-baselines/clean-codex
```

## Results (leak-free, three trials)

`P/R/F1` are exact; `line F1` uses `(path, line)` only. `distinct` is how many
of the seven issues were hit exactly at least once.

| Harness | Success | Exact TP/FP/FN | Exact F1 | Line F1 | Distinct | Per-case exact hits (of 3) |
| --- | ---: | --- | ---: | ---: | ---: | --- |
| Pi | 21/21 | 8/19/13 | **.333** | **.417** | 4/7 | ajna 2, filelock 1, fast-jwt 2, zk-email 3 |
| Codex | 21/21 | 4/37/17 | .129 | .197 | 3/7 | fast-jwt 1, pymonocypher 1, zk-email 2 |
| DSH | 21/21 | 4/37/17 | .129 | .161 | 3/7 | ajna 1, fast-jwt 2, h11 1 |
| Claude Code | 21/21 | 1/38/20 | .033 | .172 | 1/7 | fast-jwt 1 |

Built-in reference (`deepseek-flash`, blind, rounds 18-22): pooled 17/140 exact
(12.1%) and 35/140 line (25.0%); exact F1 ranged .057-.125 per configuration and
no configuration exceeded two of the seven distinct issues. With per-case threat
models and two trials (round 16, 18 cases) the same agent reached exact F1 .329 /
line F1 .493. See [Validation](validation.md) and the
[experiment log](experiments.md).

**The built-in agent already matches Codex and DSH on the blind primary labels
and exceeds Claude Code; Pi is the real outlier and the appropriate target.**
The earlier belief that Codex was far ahead was an artifact of the label leak.
A follow-up configuration (minimal prompt, 48 tool calls, high reasoning)
reached exact F1 .408 and 5/7 distinct, exceeding clean Pi; see
[Validation](validation.md#target-pi-optimization-rounds-25-26-2026-10-11).

## Context and task management

- **Exact labeling, not sink discovery, dominates.** Clean runs produced many
  near misses (adjacent lines or alternate CWEs), and 19-38 false positives per
  harness. No harness found `intoiter-drop-panic-double-free` exactly or by line
  in any clean trial; `filelock` and `h11` were found by only one harness each.
- **Pi is the strongest with the same model.** It hit 8/21 exact and 10/21 line
  across four distinct issues, roughly 2.5x Codex/DSH exact F1 and 4x Claude.
- **Codex is fast but not more accurate once labels are hidden.** Its clean F1
  is .129; the 21/21 figure was leaked labels.
- **Completion is no longer the bottleneck** with the soft deadline: all four
  harnesses completed 21/21 clean trials with zero adapter timeouts.
- **Network is uncontrolled.** Codex issued web requests in some sessions. With
  labels hidden those requests did not produce a detection advantage, but a
  strict capability baseline should still pin a no-network policy.

## Constraints and modifications

1. **Labels must not be in the agent workspace.** `--hide-labels` moves the
   manifest out for the duration of each run; verified by `HarnessAdapterTests`
   and a zero-read clean window. The runner enables it by default.
2. **Parallel cases must not share mutable adapter state.** The adapter writes
   `.audit-findings-<case_id>.json`, so concurrent cases cannot read each
   other's answer.
3. **`benchmark --isolate`** exposes the per-case staging used by `evaluate` for
   callers that do not stage themselves.
4. **Same-model selection is harness-specific.** Codex uses
   `-m deepseek-flash -c model_provider=deepseek`; Claude Code needs
   `ANTHROPIC_MODEL`/`ANTHROPIC_SMALL_FAST_MODEL`; DSH reads its profile. The
   adapter's response schema declares `severity` as `string` for DeepSeek's
   structured-output validator.
5. **A soft in-band deadline is safe.** `--deadline-minutes` removed adapter
   timeouts and roughly halved wall-clock in the round-24 experiment.
6. **Network policy and public-CVE recall remain uncontrolled.** These are public
   advisories; training-data and lookup effects cannot be excluded, so do not
   read the numbers as pure reasoning ability.

## Limitations

- Small sample: 21 trials per harness, seven expected issues; differences of one
  or two findings are within provider variance.
- Not budget-matched to the built-in agent (tools, context, wall-clock).
- Pi and Claude Code reach `deepseek-flash` through different front-ends than the
  built-in agent, so wire-level differences remain.
- Exact CWE keys are deliberate tuning choices; line F1 and reviewed findings are
  reported alongside, never folded into exact F1.
- The Rust `--isolate` change was parse- and format-checked with `rustfmt` but
  could not be compiled in this environment (no MSVC/Windows SDK and an
  incomplete GNU toolchain).
