# Cross-harness baselines

How the built-in auditor compares with four external coding-agent harnesses on
the seven primary `alchemist-dataset-tiny` labels. **All four harnesses run
`deepseek-flash`**, the same model as the built-in agent's blind rounds, so the
comparison isolates harness context and task management rather than model
choice. It measures the harness as run on a workstation under one blind
instruction, not a claim about any harness in general. Method and scoring are in
[Evaluation](evaluation.md); the recorded run is
[harness-baselines.json](reports/harness-baselines.json).

## Harnesses

| Name | Invocation | Model | Notes |
| --- | --- | --- | --- |
| Codex | `codex exec -m deepseek-flash -c model_provider=deepseek` | `deepseek-flash` | uses the `deepseek` provider and `DS_API_KEY`; the configured default ChatGPT model is not used here |
| Claude Code | `claude -p --settings <json>` | `deepseek-flash` | DeepSeek's Anthropic-compatible endpoint; the adapter injects `AUDIT_HARNESS_CLAUDE_TOKEN`, `ANTHROPIC_MODEL`, and `ANTHROPIC_SMALL_FAST_MODEL` without editing user settings |
| DSH | `dsh --profile headless` | `deepseek-flash` | the `headless` profile's default model is `deepseek-flash` |
| Pi | `pi -p --model deepseek-flash` | `deepseek-flash` | native tools; no adapter-imposed tool-call budget |

Each harness runs in the audit root with its own native tools and agent loop.
The adapter (`scripts/external_agent.py`) implements the
[Version 1 protocol](protocol.md): it reads the request, sends a fixed audit
brief plus the case instruction, recovers the response object from a per-case
side file or the harness output, normalizes CWE/path/severity form, and never
invents a finding. A missing or unparseable response exits non-zero so the
scorer records a failed invocation rather than a clean empty report. The
adapter's parsing and normalization are pinned by `HarnessAdapterTests` in
`tests/debug_scripts.py`.

## Method

- **Dataset**: the seven primary fixture labels, blind instruction (one generic
  instruction for every case), repo revision pinned in the run manifest.
- **Isolation**: each case is staged into a fresh copy without the label
  manifest, so a coding agent can write files and run commands without mutating
  the fixture. `scripts/run_harness_baseline.py` performs the staging; the
  harness itself can also stage with `benchmark --isolate`.
- **Trials**: three per harness, every trial retained, including failures and
  timeouts; no best-of selection.
- **Scoring**: exact `(CWE, path, line)` and line `(path, line)` precision,
  recall, and F1; successful/failed invocations and adapter timeouts.
- **Budgets**: benchmark wall-clock 30 min, adapter wall-clock 26 min, job
  parallelism 2 per harness.

Reproduce one harness:

```sh
export DS_API_KEY=... AUDIT_HARNESS_CODEX_PROVIDER=deepseek
export AUDIT_HARNESS_CLAUDE_TOKEN=...
python scripts/run_harness_baseline.py --harness codex --model deepseek-flash \
  --blind --trials 3 --jobs 2 --timeout-ms 1800000 --adapter-timeout 1560 \
  --output target/harness-baselines/samemodel-codex
```

Use `--harness claude`, `dsh`, or `pi` for the others; DSH ignores `--model`
because its profile default is already `deepseek-flash`.

## Results

Three trials per harness, seven primary labels, all `deepseek-flash`. `P/R/F1`
are exact; `line F1` uses `(path, line)` only. `distinct` is how many of the
seven issues were hit exactly at least once.

| Harness | Success | Exact TP/FP/FN | Exact F1 | Line F1 | Distinct | Timeouts | Max run |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| Codex | 21/21 | 21/0/0 | **1.000** | 1.000 | 7/7 | 0 | 11.1 min |
| Claude Code | 21/21 | 21/4/0 | .913 | .913 | 7/7 | 0 | 12.2 min |
| DSH | 21/21 | 20/3/1 | .909 | .909 | 7/7 | 0 | 12.6 min |
| Pi | 19/21 | 19/0/2 | .950 | .950 | 7/7 | 2 | 26.0 min |

Built-in reference (`deepseek-flash`, blind, rounds 18-22): pooled 17/140 exact
(12.1%) and 35/140 line (25.0%) over nine configurations; no configuration
exceeded two of the seven distinct issues. With per-case threat models and two
trials (round 16, 18 cases) the same agent reached exact F1 .329 / line F1 .493.
See [Validation](validation.md) and the [experiment log](experiments.md).

## Context and task management

With the model held constant, the harness is the only variable:

- **The same `deepseek-flash` model covers 7/7 issues in every external harness
  and never more than two in the built-in agent blind rounds.** The gap is
  context and task management, not model capability.
- **Exploration depth differs.** In the earlier baseline round Pi used 12-34
  native tool calls per case (33 on Ajna, 34 on `thin-vec`) against a built-in
  evaluation budget of 16 (32 in campaign round 21). The external harnesses
  choose reads, searches, and local execution adaptively; campaign round 21
  showed a larger fixed budget alone does not help.
- **Codex is the most reliable harness.** It was the only one with no failed
  runs across either the mixed-model or same-model rounds, and the only one with
  exact precision 1.000.
- **Pi trades precision for reach.** It produced no false positives but lost two
  of 21 runs to its adapter wall-clock on the largest fixture, so its F1 also
  understates capability.
- **Single trials are not a baseline.** In the first round DSH scored 5/7 then
  19/21, and Pi 7/7 then 18/21. The runner defaults to three trials and records
  per-run elapsed time and timeout counts.

**Optimization round 24.** A 15-minute soft deadline in the adapter brief
(`--deadline-minutes`) removed Pi's two adapter timeouts, kept 7/7 distinct, and
halved total wall-clock (91 to 43 minutes); exact F1 rose .950 to .977. It is
opt-in and recommended for future baselines. See the round notes in
[Validation](validation.md#optimization-round-24-soft-in-band-deadline).

## Constraints and modifications

The baseline surfaced the following constraints; the implemented changes are
listed with them.

1. **External agents must be isolated from labels and source mutation.**
   `evaluate` already staged per case, but `benchmark` did not. `benchmark
   --isolate` is now exposed (the staging path already existed for `evaluate`)
   and covered by `benchmark_isolate_stages_each_case_away_from_the_source_tree`.
   The Python runner stages independently so it does not depend on the flag.
2. **Parallel cases must not share mutable adapter state.** The adapter's fixed
   side-file name caused cross-case contamination under `benchmark --jobs > 1`
   in a shared root. Each request now writes `.audit-findings-<case_id>.json`,
   so concurrent cases cannot read each other's answer.
3. **Different harnesses spell the same model differently.** Codex selects it
   with `-m deepseek-flash -c model_provider=deepseek`; Claude Code needs
   `ANTHROPIC_MODEL`/`ANTHROPIC_SMALL_FAST_MODEL`; DSH reads it from its
   profile. The adapter and runner now expose those knobs so a same-model
   comparison is reproducible. DeepSeek's structured-output endpoint also
   rejects an enum without a `type`, so the adapter's response schema declares
   `severity` as `string`.
4. **Run metadata must be reproducible.** The runner pins harness/dataset
   revisions, binary and adapter hashes, the resolved instruction, per-case
   elapsed time, and adapter timeout counts, and supports `--summarize` to
   rebuild a summary without new model calls.
5. **Network policy is not held constant.** Codex's user config enables network
   access, and these fixtures are public CVEs. No `curl`/`wget` calls were
   observed in the recorded Codex sessions, but a strict capability baseline
   should pin an explicit no-network (or recorded-network) policy. This is a
   requirement for future rounds, not yet enforced.
6. **Public-CVE recall is a confound.** The harnesses may partially recognize
   the upstream advisories from training data. The blind instruction and
   held-out staging reduce leakage, but they do not eliminate model recall. The
   same-model result shows the harness effect is real, but do not read the
   external numbers as pure reasoning ability.

## Limitations

- Small sample: 21 trials per harness, seven expected issues.
- Not budget-matched to the built-in agent (tools, context, or wall-clock).
- Pi and Claude Code reach `deepseek-flash` through different front-ends than the
  built-in agent, so wire-level differences remain even with the model pinned.
- Exact CWE keys are deliberate tuning choices; line F1 and reviewed findings
  are reported alongside, never folded into exact F1.
- The Rust `--isolate` change was parse- and format-checked with `rustfmt` but
  could not be compiled in this environment (no MSVC/Windows SDK and an
  incomplete GNU toolchain); see the round notes in [Validation](validation.md).
