# Cross-harness baseline data

Authoritative leak-free baseline for the seven primary `alchemist-dataset-tiny`
labels. All four harnesses run `deepseek-flash`; each case is staged and the
label manifest is hidden from the agent. See
[Cross-harness baselines](../../baselines.md) for method and interpretation and
[harness-baselines.json](../harness-baselines.json) for the machine-readable
aggregate.

Layout per harness (`codex/`, `claude/`, `dsh/`, `pi/`):

| File | Contents |
| --- | --- |
| `manifest.json` | pinned harness revision, dataset revision, binary/adapter hashes, limits, case list |
| `summary.json` | exact/line metrics, distinct hits, elapsed time, adapter timeouts |
| `records.json` | per-trial records used to rebuild `summary.json` |
| `<case>-<trial>/report.json` | the `alchemist benchmark` report for one case |
| `<case>-<trial>/stderr.log` | redacted adapter and harness diagnostics |

Results (3 trials each):

| Harness | Success | Exact TP/FP/FN | Exact F1 | Line F1 | Distinct |
| --- | ---: | --- | ---: | ---: | ---: |
| Pi | 21/21 | 8/19/13 | .333 | .417 | 4/7 |
| Codex | 21/21 | 4/37/17 | .129 | .197 | 3/7 |
| DSH | 21/21 | 4/37/17 | .129 | .161 | 3/7 |
| Claude Code | 21/21 | 1/38/20 | .033 | .172 | 1/7 |

`harness-baselines-2026-10-11-full.tar.gz` at `docs/reports/` also contains the
superseded runs (the label-leaking `blind-*`/`validate-*`/`samemodel-*` phases
and the smoke/round-24 experiments) so the correction is auditable. Those runs
are not valid for detection: the per-case manifest with `expected` labels was in
the agent workspace. Only the `clean-*` directories above are authoritative.
