# Validation

## Citation confirmation and model stop telemetry: 2026-10-13

Bounded citation confirmation was adopted as a default-on repair contract at
the user's request. The prior live A/B on four Harbor tasks plus one repeated
Ajna task triggered zero confirmations in all five candidate audits, so it
established no quality or efficiency gain. It uses existing output repair turns
and never accepts a citation without a fresh validated report. The confirmed
source line is treated as untrusted evidence. `--citation-confirmation false`
disables the behavior.

The next experiment adds content-free model stop reasons to ordinary journals.
Its deterministic fixture checks distinguish provider length, incomplete SSE,
stream byte cap, HTTP server failure, and deadline; they validate diagnostic
classification and JSON stdout, not vulnerability discovery. Historical traces
cannot retroactively identify an unrecorded stop cause. The local experiment
plan is retained under `target/model-stop-reasons/plan.md`.

## Practical checks of earlier ambiguities: 2026-10-12

The [round-30 trial records](reports/harbor-round30.json) contain six
adjacent-line near misses: filelock line 44 versus label 41 in all three jobs,
and thin-vec line 2547 versus label 2546 in all three. Three further reports
used the labeled line with a different CWE: fast-jwt, pymonocypher, and
zk-email, once each. These nine instances remain nonmatches in Harbor's exact
score. They are diagnostic cases, not nine additional credited findings.

The earlier filelock symlink probe is recorded below. For thin-vec, a Linux
probe used three elements whose destructors increment separate counters; the
first destructor panicked once while dropping `ThinVec::into_iter()`. The audit
fixture produced drop counts `[2, 2, 2]`. A temporary copy with only the
reference `DropGuard` change to `IntoIter::drop` produced `[1, 1, 1]`. This
reproduces the panic cleanup defect connecting the reported drop call and the
adjacent labeled ownership move. It does not claim a completed exploit or
validate every change in the upstream patch.

An isolated Node probe executed fast-jwt's `validateClaimValues` source
function. A mixed attacker/allowed issuer array was accepted by the vulnerable
`some` check and rejected when that condition was changed to the reference
fix's `every` check; a single allowed issuer remained accepted. This confirms
the source sink shared by the reported and labeled CWEs. It does not reproduce
the dynamic key-fetch exploit or settle the taxonomy choice.

The pymonocypher extension was built from the audit fixture in an isolated
Linux container; its temporary packaging copy supplied the missing README and
build dependencies without changing the audited function. With eight Argon2
blocks it returned a 32-byte hash; with one
block the subprocess aborted at `free(): invalid size`, and with zero blocks it
segfaulted. A temporary copy adding only the reference minimum-block guard
raised `ValueError` for zero and one while eight still worked. This confirms
the missing input bound at the reported and labeled allocation line, not which
of their two CWE names is preferable. The zk-email circuit was not executed in
this pass, so its alternate CWE remains a source-level observation.

Two existing Ajna Harbor traces clarify the completion ambiguity. In the
failed trial, the model used all 32 ordinary calls and two `read_file`
settlement calls, retried three empty completions, then made two final-output
repairs for unobserved citations to `SettlerActions.sol:113`. The last response
consumed exactly 32,768 completion tokens and ended with `finish_reason length`;
its stream contained 10,284,587 bytes. The largest request was 466,748 bytes
against a 2 MiB context cap. Thus the final failure was output exhaustion after
citation repairs, not history pressure. The successful Ajna trial had one
citation repair, then two settlement reads and a valid report. Ordinary traces
do not reveal whether the failed trial saw line 113 through Bash, so the
observation does not establish why the model cited an unregistered line. The
two round-30 Ajna failures lack comparable traces and remain unclassified
beyond their recorded empty-completion errors. Exact observations and limits
are in the [machine-readable review](reports/round31-ambiguity-validation.json).

## Context component evaluation and trace review: 2026-10-12

A provider-free [component evaluation](../examples/context_eval.rs) fixes
`reasoning_effort = "high"` and exercises ordinary history, repeated-output
pressure, and a cap that cannot fit two protected recent turns. At 2 MiB, 16
moderate result turns stayed at 260,171 request bytes with no pruning. A
160-turn repeated-output case fell from 11,239,571 to 1,652,046 bytes after
139 prunes, with one 70,027-byte archive file reused 138 times. At 128 KiB,
four large turns still occupied 143,293 bytes after two eligible results were
pruned. The last case demonstrates how a hard cap can fail even when pruning
works; it does not reconstruct the four individual round-15 failures.

The first performance candidate, selective deserialization of large tool
results, was slower in the pilot and was discarded. The adopted change counts
fixed projection metadata once while searching for a bounded preview. In a
pinned Linux release build, 128 projections of escaped Unicode JSON to 1,024
bytes took 124,687–125,656 microseconds across four candidate samples versus
126,940–130,643 across three fresh baseline samples. Two earlier baselines
were 127,080 and 128,078 microseconds. Each sample is the median of seven
inner rounds. This is a small synthetic component speedup, not an observed
live latency or vulnerability-discovery gain. The exact sample records and
fixture outputs are in the [machine-readable report](reports/context-management-eval.json).

The [trace summary script](../scripts/context_trace_summary.py) inspected two
existing Harbor primary jobs, 14 trials and 212 model turns, at the provider's
default high thinking setting. Median request size was 107,566 bytes, maximum
466,748 bytes, or 22.3% of the 2 MiB cap. No trial reached the 90% pruning
threshold; there were zero prune events or archive reuses and four per-result
projections. One Ajna run failed with `finish_reason length` while its largest
request was 466,748 bytes, so that failure was not a context-cap failure. These
traces predate this optimization and cannot measure its live speed or quality.

The earlier filelock adjacent-line ambiguity was checked in a read-only Linux
container with temporary files. `UnixFileLock` on a symlink reduced its target
to zero bytes; adding the reference fix's `O_NOFOLLOW` flag caused `ELOOP` and
left the target intact. The reported `os.open` sink at line 44 and the labeled
flag assignment at line 41 describe the same defect. This practical check does
not alter Harbor's exact `(CWE, path, line)` reward. The later thin-vec runtime
reproduction is described in the practical checks above.

Formatting, strict Clippy, and all Rust targets passed in the pinned Linux
container. The debug-script suite ran 16 tests with four skips;
the trace summary assertions and new local links also passed.

## Harbor primary audit round 30: 2026-10-12

This was the first live validation of the standard Harbor path, not an A/B
quality claim. The pre-run gate was that exported tasks, the custom agent, and
the delayed verifier run end to end without environment or grading errors.
Seven primary cases used their versioned, case-specific instructions, one trial
per case in each of three independent named jobs (`--n-attempts 1`),
`deepseek-flash` through its chat-completions API, 32 tool calls, a 32,768-token
output cap, and a 900-second CLI deadline. Harbor ran at concurrency 3 with a
5x agent-timeout multiplier. The pinned Linux binary SHA-256 begins `eeb39312`;
the node TOML SHA-256 begins `630b0067`. All 21 trial manifests and all seven
task checksums matched across jobs. Full fingerprints, keys, and per-trial
outcomes are in [the machine-readable report](reports/harbor-round30.json).
The parent Rust source was `f8f3583`; the recorded submodule suite revision is
`0164a8f`. The agent adapter was fixed before the three jobs started.
The task format follows [Harbor's task specification](https://docs.harborframework.com/tasks/overview),
and `deepseek-flash` is the model ID in the [provider's chat API](https://api-docs.deepseek.com/api/create-chat-completion/).

| Measure | Job 1 | Job 2 | Job 3 | Combined |
| --- | ---: | ---: | ---: | ---: |
| Completed | 6/7 | 7/7 | 6/7 | 19/21 |
| Harbor exact reward | 1/7 | 2/7 | 3/7 | 6/21 (.286) |
| Exact F1 | .143 | .235 | .400 | .261 |
| Line F1 | .429 | .353 | .400 | .391 |
| Distinct primary cases hit | | | | 3/7 exact, 4/7 by line |

Combined exact TP/FP/FN were 6/19/15; line TP/FP/FN were 9/16/12. Median
completed CLI time was 83.3 seconds. The two failed trials were both Ajna
provider errors: after bounded attempts the model returned no output text or
tool calls. They count as misses. No task setup or verifier exception occurred.
The local Harbor job records and the committed report were scanned for the
configured API token (268 files); no occurrence was found.

The exact reward hides several candidate near misses without changing the
score. Filelock reported `CWE-59` at the `os.open` call on line 44 in all three
runs; the label is the `O_TRUNC` flag assignment on line 41. Thin-vec reported
`CWE-415` at the drop call on line 2547 in all three runs; the label is the
preceding ownership move on line 2546. Fast-JWT and pymonocypher sometimes
reported the labeled line under a different CWE; one zk-email run did the same.
These are source-location and taxonomy observations, not automatic credit or
proof that every extra finding is valid. The verifier remains exact on
`(CWE, path, line)`; nonmatching claims need independent review.

A single h11 probe at the 4,096-token default stopped with `finish_reason
length` and failed after 29.9 seconds. Changing only the output cap to 32,768
tokens produced a completed, exact hit after 168.7 seconds. This pair supports
the output-cap failure diagnosis for that case, but one stochastic pair cannot
establish a general quality gain. The seven-case jobs also used a longer
deadline; they are not compared causally with the probe. Earlier built-in
rounds 25-29 used different instructions, budgets, and reasoning settings, so
their F1 values are not comparable to this Harbor round. This public suite is
regression/tuning material, not held-out discovery evidence.

The next focused reliability question is why Ajna still produced empty
completions in two of three trials despite the larger output cap. A separate
same-budget run with operational traces should isolate that provider behavior
before any retry or prompt change. The line/CWE near misses warrant a reviewed
rubric alongside, never in place of, the exact Harbor reward.
The later [practical checks](#practical-checks-of-earlier-ambiguities-2026-10-12)
and trace review narrow those questions without changing this round's score.

## Exact archive reuse: 2026-10-12

The non-summarizing context path now reuses a saved file for byte-identical
tool results within a run. A deterministic pressure fixture supplies 160
repeated 70,000-byte results. Pruning more than 120 results represents over
8 MiB of logical output, beyond the old archive quota; the new path keeps one
exact archive file and a request below the 2 MiB hard cap. Separate checks verify
that hash matches compare real bytes and that an externally modified file is
not reused. This establishes archive efficiency and exact recovery, not a
vulnerability-discovery improvement. The prior live context-cap comparison is
recorded under round 15 below.

Verified on Windows/MSVC: formatting, strict Clippy, and all 120 Rust tests
passed. The Linux container test suite also passed. No live provider A/B was
run for this archive-only change.

## Target-Pi optimization rounds 25-28: 2026-10-11

Goal: raise the built-in `deepseek-flash` agent to the leak-free Pi baseline on
the seven primary labels. Model, blind instruction, dataset revision, and
scoring were held fixed. Round 25 changed the system prompt and added one
Pi-like budget/effort variant; round 26 confirmed the winning configuration at
three trials.

| Round | Variant | Config | Trials | Success | Exact TP/FP/FN | Exact F1 | Line F1 | Distinct |
| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: |
| 25 | default | `audit-verbose.txt`, 16 calls, low | 14 | 14 | 3/19/11 | .167 | .278 | 2/7 |
| 25 | minimal | `audit.txt` (then `audit-minimal.txt`), 16 calls, low | 14 | 13 | 3/17/11 | .176 | .364 | 2/7 |
| 25 | pi_like | `audit.txt` (then `audit-minimal.txt`), 48 calls, high | 14 | 13 | 6/16/8 | .333 | .389 | 4/7 |
| 26 | pi_like | `audit.txt` (then `audit-minimal.txt`), 48 calls, high | 21 | 19 | 10/18/11 | **.408** | **.449** | **5/7** |
| 27 | pi_like | `audit.txt`, 48 calls, high | 21 | 17 | 9/58/12 | .205 | .295 | 5/7 (line 6/7) |
| 28 | pi_like | `audit.txt`, 48 calls, high | 21 | 20 | 14/33/7 | .412 | .412 | **6/7 (line 6/7)** |
| 29 | pi_like | current state (provider refactor) | 21 | 19 | 11/29/10 | .361 | .426 | 6/7 (line 6/7) |

Round 26 exceeds the clean Pi baseline (exact F1 .333, line F1 .417, 4/7
distinct) with the same model. Per-case exact hits (of 3): filelock 2, fast-jwt
3, pymonocypher 2, h11 1, zk-email 2; `ajna` and `thin-vec` remain unfound. The
configuration costs ~4.6x tokens (26.7M versus 5.9M for the default variant), so
it is recorded as the recommended evaluation configuration rather than a new
global default. Round 27 (after the concise prompt and tool descriptions became
the default) had a lower exact F1 .205 because the agent enumerated many genuine
but unlabeled wrapper issues, mostly on `pymonocypher`, which the strict
single-label scoring counts as false positives; exact distinct coverage was
still 5/7 and line distinct 6/7, matching or beating Pi. Exact F1 is label-bound
and high-variance; line F1 and distinct coverage are the stable comparison. The
three-variable change (prompt, budget, effort) is not yet isolated.

**Per-round procedure.** Run `cargo test --locked --all-targets`, then the
seven-label blind plan at three trials, and compare exact F1, line F1, and
distinct coverage against the leak-free Pi baseline (.333 / .417 / 4-of-7):
`python -B scripts/evaluate_round.py --plan examples/target-pi-r27.toml
--binary target/debug/alchemist.exe --output reports/rNN`, then summarize with
`--output reports/rNN --summarize docs/reports/tiny-roundNN.json --log
docs/reports/tiny-metrics-log.jsonl --round NN`. Round 28 (current state)
reached the best coverage so far, exact and line distinct 6/7, with only
`thin-vec` still unfound. Round 29 re-ran on the current working tree (which
includes a concurrent provider refactor and reasoning/archive work): exact F1
.361, line F1 .426, exact and line distinct 6/7. Both rounds keep the same
distinct coverage; exact F1 remains the noisier, label-bound metric.

Reports: [round 25](reports/tiny-round25.json),
[round 26](reports/tiny-round26.json), [round 27](reports/tiny-round27.json);
plans `examples/target-pi-r25.toml`, `target-pi-r26.toml`, and
`target-pi-r27.toml`; prompt `prompts/audit.txt` (the concise default,
introduced as `audit-minimal.txt` and promoted in this round; the former verbose
prompt is `prompts/audit-verbose.txt`).

## Cross-harness baselines: 2026-10-11

Same-model comparison of the built-in auditor against four external coding-agent
harnesses on the **seven primary fixture labels**, blind instruction, per-case
staging, all trials retained. **All four harnesses run `deepseek-flash`** and
run with the case labels hidden from the agent workspace. Method, invocation,
and the full context/task analysis are in [Cross-harness baselines](baselines.md);
the raw aggregate is [harness-baselines.json](reports/harness-baselines.json).

**Correction.** The first published baselines leaked the `expected` labels into
the agent working directory (the runner wrote the per-case manifest there), and
Codex and others read it. `--hide-labels` now removes it for the run and a
verification window showed zero manifest reads. The clean rerun below replaces
the contaminated `samemodel-*` numbers (Codex 21/21, Claude 21/21, DSH 20/21,
Pi 19/21); those are retained only in git history.

| Harness (`deepseek-flash`) | Trials | Success | Exact TP/FP/FN | Exact F1 | Line F1 | Distinct | Timeouts |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| Pi | 3 | 21/21 | 8/19/13 | **.333** | **.417** | 4/7 | 0 |
| Codex | 3 | 21/21 | 4/37/17 | .129 | .197 | 3/7 | 0 |
| DSH | 3 | 21/21 | 4/37/17 | .129 | .161 | 3/7 | 0 |
| Claude Code | 3 | 21/21 | 1/38/20 | .033 | .172 | 1/7 | 0 |

Built-in reference (`deepseek-flash`, blind, rounds 18-22): 17/140 exact (12.1%)
and 35/140 line (25.0%); exact F1 .057-.125 per configuration and no
configuration exceeded two of seven distinct issues. **The built-in agent
already matches Codex and DSH on the blind primary labels and exceeds Claude
Code; Pi is the real outlier.** The earlier belief that Codex was far ahead was
an artifact of the label leak. No harness found `intoiter-drop-panic-double-free`
exactly or by line in any clean trial, and most non-matches were adjacent lines
or alternate CWEs, confirming that exact labeling rather than sink discovery
dominates this benchmark.

Constraints implemented from this comparison:

- `benchmark --isolate` now stages each case from the existing `evaluate`
  staging path, so an external agent cannot read the label manifest or mutate
  the source tree. Verified: `cargo fmt --check`, `cargo clippy --locked
  --all-targets -- -D warnings`, and `cargo test --locked --all-targets` pass,
  including `benchmark_isolate_stages_each_case_away_from_the_source_tree`.
- The adapter writes a per-case side file, removing cross-case contamination
  under `benchmark --jobs > 1`.
- `scripts/run_harness_baseline.py` defaults to three trials and records
  per-case elapsed time, adapter timeouts, resolved instructions, and pinned
  revisions, with `--summarize` for no-model re-summaries.
- The adapter now hides the label manifest from the agent workspace
  (`--hide-labels`), removing the leak that produced the first baselines.

Network policy and public-CVE recall remain uncontrolled and are documented as
requirements for the next round, not silently assumed away.

### Optimization round 24: soft in-band deadline

Hypothesis: a soft wall-clock budget in the adapter brief reduces adapter
timeouts. Pi x 7 x 3, same `deepseek-flash`, off vs a 15-minute brief deadline
(measured before the label leak was found, so detection numbers are superseded;
the completion/timeout effect is leak-independent):

| Variant | Success | Timeouts | Total wall-clock |
| --- | ---: | ---: | ---: |
| no deadline | 19/21 | 2 | 5468 s |
| 15 min soft | 21/21 | 0 | 2592 s |

The deadline removed both timeouts and roughly halved total wall-clock; it is
opt-in (`--deadline-minutes`), adds one paragraph to the adapter brief, and is
the recommended configuration for future baselines. Raw metrics are in
`harness-baselines.json` (`optimization_round_24`).

## Optimization campaign rounds 18-22: 2026-10-11

Five rounds testing widely used tuning methods against the **seven primary
fixture labels** (the dataset's intended expected content), under the blind
seven-case instruction. Each round changed one variable; the plan, model,
baseline prompt, and unrelated limits were held fixed and all trials retained.
Model `deepseek-flash`, `--max-tools 16` unless varied, `--max-tokens 32768`,
`--reasoning-effort` per round, 2 trials x 7 cases (round 22 used 4 samples).

| Round | Variable | Config | Exact | Line | Distinct exact | Failures | Tokens |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 18 | reasoning effort | low | 2/14 | 4/14 | 1/7 | 0 | 4.95M |
| 18 | | high | 2/14 | 3/14 | 2/7 | 3 | 5.80M |
| 19 | stream cap | high, 8 MiB | 2/14 | 4/14 | 2/7 | 1 | 5.49M |
| 19 | | high, 32 MiB | 1/14 | 4/14 | 1/7 | 1 | 5.57M |
| 20 | system prompt | `audit.txt` | 2/14 | 4/14 | 1/7 | 2 | 6.25M |
| 20 | | systematic enumeration | 1/14 | 3/14 | 1/7 | 3 | 6.09M |
| 21 | tool budget | high, 16 calls | 1/14 | 3/14 | 1/7 | 0 | 6.44M |
| 21 | | high, 32 calls | 2/14 | 3/14 | 1/7 | 2 | 16.04M |
| 22 | self-consistency | 4 samples | 4/28 | 7/28 | 1/7 | 3 | 12.24M |

Pooled over the nine evaluated configurations, exact detection was 17/140
(12.1%) and line detection 35/140 (25.0%) of the seven expected issues.
Distinct exact coverage never exceeded 2/7 in any configuration and 3/7 across
the union of the whole campaign (`chunked-trailer-not-validated`,
`argon2i32-small-block-count`, `sha256-length-comparator-unconstrained`).
`unsettled-bad-debt-liquidation`, `lock-symlink-truncation`, and
`intoiter-drop-panic-double-free` were never found by exact or line match;
`iss-array-loose-match` was located by line but never labeled correctly.

Higher reasoning effort, a 32 MiB stream cap, systematic enumeration prompt
theme, a doubled tool budget, and four-sample self-consistency did not raise
detection. Higher effort increased cost and introduced execution failures
(`model stream exceeds --max-stream-bytes` and `finish_reason length`) without a
detection gain. Test-time compute, stream budget, prompt strategy, tool budget,
and sampling are not the bottleneck for these seven issues. (An initial round-20
attempt to raise `--max-tokens` to 65536 was rejected by the CLI, whose limit is
1..=32768; that attempt was discarded and the round was repurposed for the
system-prompt variable.) Summaries are in
[round 18](reports/tiny-campaign-round18.json), [19](reports/tiny-campaign-round19.json),
[20](reports/tiny-campaign-round20.json), [21](reports/tiny-campaign-round21.json),
and [22](reports/tiny-campaign-round22.json); plans are `examples/campaign-r18..22.toml`.

## Confirmation and stable-reporting rounds 14-17: 2026-10-10

- **Round 14 - smaller-budget replication (16 vs 12, 7 cases x 3).** The 12-call
  variant cut tokens 32% (8.02M to 5.42M) with exact F1 .041 -> .143 and line F1
  .122 -> .286; the two failures were a provider stream cap and an unobserved-line
  citation, not the budget. Confirms the round-13 cost lever.
- **Round 15 - context cap (2 MiB vs 128 KiB, 7 cases x 2).** Request sizes are
  median ~69 KB and max ~329 KB, and no pruning fired at 2 MiB. The 128 KiB cap
  failed 4/14 runs with `conversation exceeds --max-context-bytes` and dropped
  exact TP to zero, saving ~49% of tokens. Rejected.
- **Round 16 - stable capability report (18 cases x 2).** 36/36 completed, exact
  P/R/F1 .308/.353/.329, line P/R/F1 .462/.529/.493, 27 unexpected findings all
  reviewed, clean control empty, and 6 output repairs fired. The blind budget
  rounds remain the harder setting; per-case threat models explain most of the
  gap.
- **Round 17 - read-only settlement (16 vs 12 calls, 7 cases x 2).** After the
  external-reference review, settlement fired in 17 of 28 runs and used three
  read-only calls to verify citations. The 12-call variant completed 13/14 at
  3.41M tokens versus 14/14 at 5.50M for 16 calls; only the provider stream-cap
  failure remained. This validates the settlement whitelist live.

| Round | Cases x trials | Variant | Success | Exact P/R/F1 | Line P/R/F1 | unexpected valid | Tokens |
| --- | --- | --- | ---: | --- | --- | ---: | ---: |
| 14 | 7 x 3 | 16 tools | 21/21 | .036/.048/.041 | .107/.143/.122 | 21 | 8.02M |
| 14 | 7 x 3 | 12 tools | 19/21 | .143/.143/.143 | .286/.286/.286 | 16 | 5.42M |
| 15 | 7 x 2 | 2 MiB cap | 14/14 | .111/.143/.125 | .167/.214/.188 | 14 | 5.10M |
| 15 | 7 x 2 | 128 KiB cap | 10/14 | .000/.000/.000 | .083/.071/.077 | 11 | 2.59M |
| 16 | 18 x 2 | default | 36/36 | .308/.353/.329 | .462/.529/.493 | 27 | 10.39M |
| 17 | 7 x 2 | 16 calls | 14/14 | .200 | .267 | 11 | 5.50M |
| 17 | 7 x 2 | 12 calls | 13/14 | .200 | .200 | 13 | 3.41M |

The smaller budget is a confirmed cost lever (rounds 13-14); forced context
pruning is rejected (round 15); `update_plan`/`apply_patch` are retired on the
observed tool-error distribution (`bash` 96% of errors, `edit_file` called once).
The global CLI `--max-tool-calls` default stays 32; evaluation plans can use
12-16. Reviews: `round14-reviews.json`, `round15-reviews.json`,
`round16-reviews.json`.

## Optimization and validation rounds 10-13: 2026-10-10

Three further rounds under the same procedure (same provider, model, dataset
revision, and budgets unless stated; all trials retained and reviewed).

- **Round 10 - action-budget A/B (16 vs 24 tool calls, 7 cases x 2).** The
  larger budget did not improve supported findings: exact TP 2 -> 1, F1
  0.114 -> 0.062, unexpected findings 19 -> 17, while tokens rose 5.25M -> 7.33M
  (+40%) and tools 205 -> 282. Increasing the budget is rejected; the default
  stays 16.
- **Round 11 - expanded-dataset validation (18 cases, 1 trial, each case's own
  threat model).** 17/18 completed, 8 exact TPs, 12 unexpected findings reviewed
  as alternate matches or genuine distinct issues, and the clean
  `unsigned-opt-in-control` produced no findings. The one failure was
  `unsettled-bad-debt-liquidation`, which ended with
  `agent exhausted --max-tool-calls without a final report` after a 2-call batch
  arrived with 1 call of budget left.
- **Round 12 - expanded-dataset re-validation after the over-budget fix.** 18/18
  completed, 8 exact TPs, 10 unexpected, clean control still empty. Three output
  repairs fired live. `tool_budget_rejections` was 0 because no run happened to
  over-request; the behavior is covered deterministically by
  `over_budget_batch_is_rejected_then_finalizes_without_mutation`.
- **Round 13 - smaller tool budget (16 vs 12, 7 cases x 2).** The 12-call variant
  cut total tokens 31% (4.77M to 3.30M) and turns 154 to 115 with exact TP
  unchanged (2 vs 2) and exact F1 flat (.121 vs .125). Line TP slipped 4 to 3 and
  one candidate run hit the stream cap unrelated to the budget. Promising, but a
  default change needs a replicated, higher-trial run.

The over-budget fix rejects the whole batch without executing a call, then
removes the tool schemas and forces a final report, so an over-budget turn can no
longer discard an otherwise complete investigation. This preserves the
no-partial-mutation invariant in H04.

| Round | Cases x trials | Variant | Success | Exact TP/FP/FN | F1 | unexpected valid | Repairs | Tokens |
| --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: |
| 10 | 7 x 2 | 16 tools | 14/14 | 2 / 19 / 12 | .114 | 17 | 3 | 5.25M |
| 10 | 7 x 2 | 24 tools | 14/14 | 1 / 17 / 13 | .062 | 15 | 1 | 7.33M |
| 11 | 18 x 1 | default | 17/18 | 8 / 12 / 9 | .432 | 12 | 1 | 5.62M |
| 12 | 18 x 1 | default | 18/18 | 8 / 10 / 9 | .457 | 10 | 3 | 4.95M |
| 13 | 7 x 2 | 16 tools | 14/14 | 2 / 17 / 12 | .121 | 15 | 0 | 4.77M |
| 13 | 7 x 2 | 12 tools | 13/14 | 2 / 16 / 12 | .125 | 16 | 0 | 3.30M |

Rounds 11-12 use per-case threat models, so their exact F1 is higher than the
blind 7-case baseline and is not a blind capability claim. Reviews:
`round10-reviews.json`, `round11-reviews.json`, `round12-reviews.json`. These
remain small samples with provider variance.

## Harness strategy rounds 6-9: 2026-10-10

Implemented and evaluated two recovery strategies selected from well-known
harnesses (`docs/harness-design.md`): bounded final-output repair
(`--max-output-repairs`) and empty-completion retry (a completed stream with no
text or tool calls is retried up to `--max-attempts`). A runner change also
surfaces a failed child's stderr tail into the evaluation `stderr.log`
(redacted), which exposed the failure classes.

| Round | Cases x trials | Variant (repairs) | Success | Output repairs | Empty retries | Failure class seen |
| --- | --- | --- | ---: | ---: | ---: | --- |
| 6 | 7 x 2 | baseline (0) | 10/14 | 0 | 0 | 4 invalid final reports (phase `validating`) |
| 6 | 7 x 2 | candidate (2) | 14/14 | 0 | 0 | none |
| 7 | 4 x 3 | baseline (0) | 12/12 | 0 | 0 | none |
| 7 | 4 x 3 | candidate (2) | 11/12 | 0 | 0 | 1 empty completion |
| 8 | 4 x 3 | baseline (0) | 11/12 | 0 | 0 | 1 unknown `evidence_note` field |
| 8 | 4 x 3 | candidate (2) | 12/12 | 0 | 0 | none |
| 9 | 1 x 6 | baseline (0) | 6/6 | 0 | 0 | none |
| 9 | 1 x 6 | candidate (2) | 6/6 | 2 | 0 | two malformed JSON reports repaired live |

Round 6 used the full seven-fixture plan and was reviewed
(`reports/round6-reviews.json`); rounds 7-9 are targeted strategy experiments
and their non-matching findings are logged unreviewed. The repair path was not
hit in round 6's candidate by chance, so round 9 concentrated six `sha256` trials
on the case that produced the unknown-field failure in round 8. There the
candidate repaired two malformed final reports ("expected `,` or `}`" and
"invalid length 0") that would have failed with repairs disabled. The
empty-completion retry addresses the exact round-7 failure; round 8 produced no
empty completions.

Recovery counters are direct evidence only when the path fires. Rounds 6-9 are
small samples with provider variance; they do not establish a general quality
gain, and the targeted exact-match metrics are too small to compare. Full
reports: [6](reports/tiny-round6.json), [7](reports/tiny-round7.json),
[8](reports/tiny-round8.json), [9](reports/tiny-round9.json); review:
[round 6](reports/round6-reviews.json).

## Paired prompt rounds 4-5: 2026-10-10

Rounds 4 and 5 compare the pre-threshold prompt with the default threshold
prompt on the same seven fixtures, blind instruction, `deepseek-flash`,
`--reasoning-effort low`, `--max-tool-calls 16`, `--max-tokens 32768`, two
trials per variant, and all trials recorded (no best-of selection). Round 4 used
the fixed limit forwarding; round 5 added the forced final-report turn described
below. Full reports: [round 4](reports/tiny-round4.json),
[round 5](reports/tiny-round5.json); per-finding reviews:
[round 4](reports/round4-reviews.json), [round 5](reports/round5-reviews.json).

| Metric (14 trials/variant) | R4 old | R4 threshold | R5 old | R5 threshold |
| --- | ---: | ---: | ---: | ---: |
| Successful trials | 12 | 12 | 12 | 13 |
| Exact TP / FP / misses | 3 / 16 / 11 | 1 / 16 / 13 | 2 / 14 / 12 | 3 / 11 / 11 |
| Exact precision / recall / F1 | .158 / .214 / .182 | .059 / .071 / .065 | .125 / .143 / .133 | .214 / .214 / .214 |
| unexpected_valid / invalid / other | 15 / 0 / 1 | 14 / 2 / 0 | 12 / 2 / 0 | 9 / 1 / 1 |
| Turns / tools / tool errors | 159 / 206 / 32 | 146 / 209 / 27 | 159 / 197 / 24 | 142 / 204 / 36 |
| Total provider tokens | 5,890,648 | 4,266,173 | 5,131,847 | 4,334,057 |

The threshold prompt is consistently cheaper (about 16-28% fewer tokens) and
removes the low-impact class from the default report. Exact F1 is dominated by
alternate sinks and labels: the reviews classify 12/14, 14/16, 12/14, and 9/11
non-exact findings as genuine, so exact precision substantially understates
recovered root causes. Each variant has only 14 trials, so the exact-F1 ordering
is noisy; the review metric `unexpected_valid` is the aggregate to compare.

Round 5 validates one harness fix and one dataset change. First, when the tool
budget is spent the provider no longer sends the tool definitions, so a model
that kept calling tools is forced to return its JSON report instead of ending
with `agent exhausted --max-tool-calls without a final report`. The contract is
covered on all three wires by
`exhausted_budget_forces_a_final_report_without_tools` in `tests/agent_tools.rs`.
Fifteen of the 28 round-5 runs used the forced turn; the threshold variant
completed 13/14 trials versus 12/14 in round 4. The three remaining failures are
final-report validation errors, not budget exhaustion. Second, the reviewed
secondary causes from rounds 1-3 are now cases in the tiny submodule, together
with the `unsigned-opt-in-control` safe control whose expected set is empty.

These are small-sample tuning results; they do not establish general discovery
quality, and the exact keys and severity labels remain deliberate tuning choices.

## Unexpected-finding verification and secondary cases: 2026-10-09

Across rounds 1-3, every non-exact-match finding was checked against the
vendored source and classified in `reports/tiny-unexpected-verification.json`.
Nearly all were genuine: the aggregate unexpected-valid/unexpected-invalid
counts were 3/1 (round 1), 6/0 (round 2), and 16/0 (round 3). They include
alternate sink lines of the target bug (e.g. `thin-vec` line 2547, `h11` line
163), alternate CWE labels at the expected line (`CWE-367` at filelock:41,
`CWE-787` at `c_monocypher.pyx:345`), and genuinely separate issues.

The verified-genuine separate issues were promoted to dataset cases in the
tiny submodule (`e69c8fc`): `blake2b-key-overflow` (`CWE-121`,
`c_monocypher.pyx:281`, unvalidated `len(key)` copied into `key_block[128]`),
`aead-key-length` (`CWE-125`, `c_monocypher.pyx:181`),
`clear-panic-double-free` (`CWE-415`, `src/lib.rs:1084`), and
`empty-signature-accepted` (`CWE-347`, `src/verifier.js:139`, conditional on a
no-key/`none` caller). The default prompt now asks for reachable root causes
that break a security property and omits low-impact hardening. Exact-match
metrics are unchanged; the distinct `unexpected_valid` count and per-case
execution records are logged in `reports/tiny-metrics-log.jsonl`.

## Live tiny-dataset baseline round 3: 2026-10-09

Fix from round 2: the raw-response cap is now `--max-stream-bytes` (default
8 MiB) instead of a fixed 2 MiB. Reasoning models emit far more SSE framing than
assembled text, and the 2 MiB cap aborted three fixtures. Full metrics are in
[the round-3 report](reports/tiny-baseline-round3.json).

| Metric | Round 1 | Round 2 | Round 3 |
| --- | --- | --- | --- |
| Completed cases (best of 2) | 2/7 | 3/7 | 6/7 |
| Raw trial success | 2/7 | 3/12 | 11/14 (79%) |
| Expected-line hits (any CWE) | 1/7 | 3/7 | 2/7 |
| Exact TP / FP / misses | 1 / 3 / 6 | 1 / 6 / 6 | 1 / 8 / 6 |
| Exact precision / recall / F1 | 0.25 / 0.143 / 0.182 | 0.143 / 0.143 / 0.143 | 0.111 / 0.143 / 0.125 |

The stream-cap fix lifted completion from 3/7 to 6/7 and raw trial success to
79%. Exact F1 did not follow because the extra completed runs report more
candidate findings, and each extra candidate counts as a false positive under
exact `(CWE, path, line)` matching. The near misses are close: `thin-vec-uaf`
reports `CWE-415` at line 2547 (expected 2546), `pymonocypher-overflow` reports
the expected line 345 as `CWE-787` (expected `CWE-122`), and `h11` alone stays
exact. `ajna-protocol-compromise-2` now fails at the model/validation phase
rather than the stream cap. The remaining gap is label and extra-finding noise,
not an execution wall; the scoring and label policy needs an explicit decision
before exact F1 is used as the optimization target.

## Live tiny-dataset baseline round 2: 2026-10-09

Two harness fixes from round 1: chat-completions now sets `response_format =
{"type":"json_object"}`, and `--reasoning-effort low` bounds reasoner output.
All Rust tests pass (53 unit, 107 total). Re-ran the same blind instruction and
limits, with up to two trials for cases that failed with an execution error.
Full metrics are in [the round-2 report](reports/tiny-baseline-round2.json).

| Metric | Round 1 | Round 2 |
| --- | --- | --- |
| Successful cases | 2/7 | 3/7 (best of <=2 trials) |
| Expected-line hits (any CWE) | 1/7 | 3/7 |
| Exact TP / FP / misses | 1 / 3 / 6 | 1 / 6 / 6 |
| Exact precision / recall / F1 | 0.25 / 0.143 / 0.182 | 0.143 / 0.143 / 0.143 |

The fixes removed the prose-before-JSON failure and let two more fixtures
complete. Semantic recall improved: `filelock-toctou` now reports the expected
line 41 (as `CWE-367`, not the expected `CWE-59`) and `pymonocypher-overflow`
reports the expected line 345 (as `CWE-476`, not `CWE-122`). Exact F1 did not
improve because those runs also add false positives and the CWE taxonomy
differs; four fixtures (fast-jwt, thin-vec, zk-email, ajna) still had no
successful trial in two attempts. Remaining failures are execution errors at the
model phase (reasoner truncation or a transient stream error), not detection
decisions. This remains a tuning baseline, not a quality claim.

## Live tiny-dataset baseline round 1: 2026-10-09

Ran the built-in agent over the seven real-world fixtures from the `datasets/tiny`
submodule with a blind, hint-free instruction; `evaluate` staging excludes each
manifest, so no case ID or label reached the model. Model `deepseek-flash`
(chat-completions), `--max-tokens 32768`, `--max-tool-calls 16`, one attempt per
case. Full metrics are in [the baseline report](reports/tiny-baseline-round1.json).

| Metric | Value |
| --- | --- |
| Successful cases | 2/7 (`filelock-toctou`, `h11-chunked-framing`) |
| Execution failures | 5/7 |
| True / false positives / misses | 1 / 3 / 6 |
| Precision / recall / F1 | 0.25 / 0.143 / 0.182 |
| Trajectory rounds / tool calls | 53 / 79 |
| Tokens (input / output / reasoning) | 847,227 / 65,179 / 54,676 |

The single exact match was h11 (`CWE-444`, `h11/_readers.py:197`).
`filelock-toctou` was a near miss: three `CWE-59` findings at lines 44/28/22
instead of the expected line 41. The five failures are execution failures, not
detection decisions: `deepseek-flash` is a reasoning model that can exhaust the
output-token cap (`finish_reason: length`), and several runs hit a transient
model-stream error or the tool budget before emitting the required JSON object.
The blind instruction is deliberately unscoped, so this measures a hard setting
and is a tuning baseline, not a quality claim. A `deepseek-chat` probe showed the
same strict-JSON failure mode (prose before the JSON object).

## Caller-side bridge: 2026-10-09

`tests/bridge.rs` drives three `alchemist audit` nodes (discovery, verification,
reporting) through a caller-side bridge against a mock chat-completions provider.
The audited data is the committed Ajna fixture at
`datasets/tiny/ajna-protocol-compromise-2/audit`, staged with the harness's own
`dataset::stage_workspace` so the repository copy stays read-only; the case
target, instruction, and expected finding come from that manifest. The test
asserts that all three requests carry the same `prompts/audit.txt` base prompt,
that each node receives its own brief instruction and no later brief, and that
discovery and verification findings are threaded into the later nodes.
Each node also performs one `read_file` tool call, so the bridge reads that
node's run journal and pushes a metrics record on completion: two trajectory
rounds, one tool call, provider-reported input/output token usage, and result
accuracy (precision/recall/F1 against a one-key expected set). Discovery's
planted false positive drives its precision to 0.5 while verification and
reporting reach 1.0. The pushed records are appended to `metrics.jsonl` per node
and returned to the caller. The `real_world_datasets_validate` harness test loads and validates all seven
fixtures from the submodule. All 105 Rust tests passed (52 unit, 53 integration),
with formatting and strict Clippy clean on `1.95.0-x86_64-pc-windows-msvc` using
the local `.mozbuild` VC tools and Windows SDK 10.0.26100.0. The bridge is
caller-side test code: the harness still owns one bounded node, and no
orchestration or metrics sink was added to `alchemist`. No live model or network
request was used.

## CLI node configuration and MCP: 2026-10-08

All 98 Rust tests passed locally on Windows/MSVC, including real CLI tests for
TOML precedence, config-relative paths, boolean overrides, custom skill loading,
disabled-tool dispatch, evaluation snapshots, MCP continuation on all three
provider wires, and whole-run cancellation during server initialization.
Local MCP fixtures exercise pagination, stderr draining, server requests,
tool errors, malformed/oversized messages, protocol failures, request timeouts,
and descendant cleanup. Formatting and strict Clippy passed. The debugger suite
passed seven checks, with four skips for optional GDB/pwntools/Foundry checks.
The example TOML validates and dry-runs without credentials or MCP startup.
Python 3 is required only for the test fixture and is provisioned in both Rust CI
jobs; the harness gains no Python runtime dependency. No live MCP service or
live-model discovery-quality evaluation was performed in this round.

The first hosted Windows run exposed a fixture timing assumption: the 800 ms
whole-run deadline could expire before Python finished cold startup. The
cancellation fixture now allows startup time, asserts descendant readiness,
and releases a would-be leak only after the CLI has exited. Production deadline
and cleanup code did not change for this correction.

## Windows HTTP fixture correction: 2026-10-08

The first matrix run exposed `WouldBlock` in the Windows mock-provider request
reader. The three HTTP fixtures polled nonblocking listeners but assumed
accepted streams were blocking. They now explicitly restore blocking mode and
set both read and write timeouts. A regression test forces nonblocking mode on
every platform and delays two request fragments until the server is ready.
All 90 Rust tests, formatting, and strict Clippy passed locally on Windows/MSVC.
This changes test infrastructure only; production Bash and provider behavior
are unchanged. See [Winsock accept semantics](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept).

## Process and provider regression coverage: 2026-10-08

All 89 Rust tests passed locally on Windows/MSVC, along with formatting and
strict Clippy. New checks cover cancellation after descendant readiness,
background cleanup after successful Bash completion, simultaneous large stdout
and stderr with retained tails, rejected arguments without file mutations,
duplicate tool IDs on all provider wires, and Unicode SSE data split at every
byte boundary. Subprocess failure checks previously gated to Unix now run on
Windows too. The incomplete-stream fixture now permits its full four-call
batch, ensuring a budget failure cannot hide missing stream validation, and
also covers Responses and Anthropic incomplete turns.

The debugger suite passed nine checks with two local dependency skips (GDB and
pwntools); Node and opt-in Foundry checks ran. Strict dependency mode correctly
failed for those missing tools. No live-model quality evaluation or line-coverage
percentage was measured.

CI now runs independent Linux and Windows Rust jobs, plus a Linux debugger job
that requires Node, GDB, and pwntools. Jobs have wall-clock bounds and read-only
repository permissions; matrix failures do not cancel the other platform's
diagnostics. This follows [GitHub's matrix guidance](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations).
Lifecycle checks exercise the cleanup obligations described in
[Tokio's process documentation](https://docs.rs/tokio/latest/tokio/process/index.html).
Local results above do not assert that a particular hosted CI run passed.

## Debugging skills and concise defaults: 2026-10-08

Validated on Windows with Rust 1.95.0 (MSVC): all 81 Rust tests, formatting,
strict Clippy, and `git diff --check` passed. All ten skills passed frontmatter
validation. Debugger scripts ran 11 checks: nine passed; native GDB and pwntools
checks were skipped because those dependencies were absent. Node Inspector and
opt-in Foundry tests ran, including import-free helpers under Solidity 0.6.12
and 0.8.26 and typed helpers against the local forge-std test checkout. Linux CI
installs GDB and pwntools for its script checks; this record is a local result.

The audit prompt shrank from 3,475 to 1,882 UTF-8 bytes and the compact ten-skill
catalog from 1,863 to 1,195 bytes (about 42% combined). AGENTS.md shrank from
2,506 to 1,293 bytes. Measurements normalize line endings and exclude source
context, tool definitions, provider framing, and on-demand resources. These
are text-size reductions, not tokenizer measurements or demonstrated audit
quality gains. No live-model quality evaluation was performed for this change.

## Tool reliability follow-up: 2026-10-08

The second pass uses the same Windows/MSVC/Git Bash environment and validation
commands below. It adds streaming reads of files over 1 MiB, exact page citation
checks, CRLF/empty/unterminated-line coverage, oversized-line and scan-budget
rejection, UTF-8 capture across buffer boundaries, and bounded head/tail storage.
The timeout fixture now verifies that both partial output streams survive while
the descendant process is still terminated. No live-model quality measurement
was performed in this pass.

All 69 tests passed (41 unit, 28 integration); formatting, strict Clippy, and
`git diff --check` also passed.

## Tool-loop validation: 2026-10-08

Validated locally on Windows with Rust 1.95.0 (MSVC) and Git Bash:

```text
cargo +1.95.0-x86_64-pc-windows-msvc fmt --all -- --check
cargo +1.95.0-x86_64-pc-windows-msvc clippy --locked --all-targets -- -D warnings
cargo +1.95.0-x86_64-pc-windows-msvc test --locked --all-targets
64 tests passed (37 unit, 27 integration)
```

The local HTTP fixtures verify a complete read-file → write-PoC → Bash-execution
→ final-finding exchange for chat-completions, Responses, and Anthropic. Checks
cover fragmented tool arguments, native result IDs, encrypted Responses reasoning,
Anthropic thinking signatures, final-answer phase selection, duplicate-call
rejection, incomplete streams, tool-call limits, paged citation provenance,
nonzero Bash exits, output truncation, timeout descendant cleanup, writable
evaluation isolation, and credential-free directory previews. The exact search
byte-boundary regression is covered. Existing protocol, scoring, provider, and
deterministic smoke tests also pass.

No live-model requests were used for this change. These checks establish tool
and protocol behavior, not improved vulnerability discovery quality or token
efficiency. The Linux-specific process tests were not run on this Windows host.

## Historical live evaluation: 2026-10-07

> Historical record. This run predates the bounded transport retries and the
> Sign In With ChatGPT adapter; it remains the recorded chat-completions smoke
> result.

The live evaluation used credentials from `/home/ubuntu/.codex/deepseek.config.toml`, read privately and passed as `AUDIT_API_KEY` to the harness process. No credential was printed, persisted in this repository, or added to command arguments. The local profile was left unchanged. The model selection was `deepseek-flash`; its provider URL was adapted to `https://api.deepseek.com/chat/completions` for a plain LLM request.

Run configuration:

```sh
./target/debug/audit-harness evaluate \
  --dataset datasets/smoke/dataset.json \
  --endpoint https://api.deepseek.com/chat/completions \
  --model deepseek-flash --jobs 2 --timeout-ms 120000 \
  --output deepseek-evaluation.json
```

The credential environment must be supplied privately before reproducing this command; choose a new output filename because the harness refuses overwrites. Defaults: 256 KiB source context, 4,096 maximum requested output tokens, 1 MiB stdout/stderr limits. Each of the six cases made one request. No retries or output repairs were performed, and the prompt did not include ground truth. The run did not override DeepSeek's default thinking setting.

| Result | Value |
| --- | ---: |
| Successful cases | 6 / 6 |
| Exact-match cases | 6 / 6 |
| True positives | 3 |
| False positives | 0 |
| False negatives | 0 |
| Precision / recall / F1 | 1.0 / 1.0 / 1.0 |
| Total wall-clock duration | 10.702 s |

All three corrected counterparts produced no findings. The unsafe shell, SQL, and eval cases produced the expected CWE, path, and sink line. The full findings and individual timings are in [deepseek-evaluation.json](reports/deepseek-evaluation.json).

This is one run on six small handcrafted cases with three vulnerability families. It establishes working provider integration and correct results on the supplied smoke set. It does not establish general vulnerability discovery effectiveness, repeatability, calibrated severity, or robustness to prompt injection. A broader held-out dataset and repeated measurements remain the appropriate next validation step. Token usage and cost were not captured.

Local checks passed with stable Rust 1.99.0:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
11 integration tests passed
```

Tests cover strict response schemas, matching and duplicate suppression, failed-case scoring, dataset validity, source bounds, nested symlink exclusion, report overwrite protection, process failures and excessive output, deadline/cancellation descendant cleanup on Linux, deterministic demo evaluation, HTTP authentication/request scoping, API failures, truncated completions, and out-of-snapshot findings.

SHA-256 fingerprints at validation:

```text
f0b9d369fab9d6983948c48604e5b1ee7f84b73e5ce4ef8fe2b57fb1d5d67b98  Cargo.lock
e5a232d5710d050ed6090c5f3f9888ccc1b4d905fcfb45da174986e81ef20d52  prompts/audit.txt
78ad6f862ea38f31ebced76663fed2483c3856990829e2cdf0ce765d4e1e49db  datasets/smoke/dataset.json
aae6cc3c771f9ed152b4e44ab5bfe1b89c8abdbd2e770b448aaf6ea52f9967a1  datasets/smoke/sources/command_safe.py
0bddaa2baf3f9d6b80270ad8927d9ac01b0ebec1f879bb153b1614df8e780575  datasets/smoke/sources/command_unsafe.py
9ce6d0974781dcb7840c2e08ed60b2a6faf1c4ea2109690dd4fee9a8747c0597  datasets/smoke/sources/eval_unsafe.py
4983c0ca231983478b4b0d43127a5ef159f5df5c1ed0ef6ecbfdeb630ce66b9b  datasets/smoke/sources/literal_safe.py
eb22131678fc7dca12d25da9f4cfc9a640bdec081eae2f9f38a297ee5ef7b9ad  datasets/smoke/sources/sql_safe.py
65ebcd527f8cd77f70ccaa8c0fd000b845713d3c27fbaadcd5c922ebead89a43  datasets/smoke/sources/sql_unsafe.py
```
