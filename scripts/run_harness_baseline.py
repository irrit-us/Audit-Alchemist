#!/usr/bin/env python3
"""Run a reproducible external-harness baseline over the audit datasets.

Unlike ``alchemist benchmark``, this runner stages a fresh copy of each fixture's
``audit/`` tree per case (excluding the label manifest and build/dependency
directories) so a coding-agent harness can write files and run commands without
mutating the repository or reading labels. It then invokes the tested
``alchemist benchmark`` scorer with ``scripts/external_agent.py`` as the agent.

Every trial is retained, including failures. Output layout::

    <output>/
      manifest.json          inputs, revisions, binary/plan hashes
      summary.json           exact/line metrics per case and aggregate
      <case>-<trial>/
        report.json          benchmark report (one case)
        stderr.log           redacted adapter log

Usage::

    python scripts/run_harness_baseline.py --harness codex \\
        --output /tmp/baseline-codex --trials 1
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile

# The seven primary fixture labels: the dataset's intended expected content.
PRIMARY_CASES = [
    ("datasets/tiny/ajna-protocol-compromise-2/audit/dataset.json", "unsettled-bad-debt-liquidation"),
    ("datasets/tiny/filelock-toctou/audit/dataset.json", "lock-symlink-truncation"),
    ("datasets/tiny/fast-jwt-iss/audit/dataset.json", "iss-array-loose-match"),
    ("datasets/tiny/thin-vec-uaf/audit/dataset.json", "intoiter-drop-panic-double-free"),
    ("datasets/tiny/pymonocypher-overflow/audit/dataset.json", "argon2i32-small-block-count"),
    ("datasets/tiny/h11-chunked-framing/audit/dataset.json", "chunked-trailer-not-validated"),
    ("datasets/tiny/zk-email-sha256/audit/dataset.json", "sha256-length-comparator-unconstrained"),
]

BLIND_INSTRUCTION = (
    "Audit the target for exploitable security vulnerabilities. Report concrete "
    "root causes with exact source lines and explain how an attacker reaches "
    "each unsafe operation."
)

IGNORE = shutil.ignore_patterns("dataset.json", "node_modules", "target", ".git", "reference")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def load_primary(root: Path, only: set[str] | None):
    cases = []
    for relative, case_id in PRIMARY_CASES:
        if only and case_id not in only:
            continue
        manifest = root / relative
        data = json.loads(manifest.read_text(encoding="utf-8"))
        case = next((c for c in data["cases"] if c["id"] == case_id), None)
        if case is None:
            raise SystemExit(f"case {case_id} not found in {relative}")
        cases.append((manifest, data["name"], case))
    return cases


def run_case(args, root: Path, output: Path, manifest: Path, dataset_name: str, case: dict, trial: int):
    run_id = f"{case['id']}-{trial}"
    run_dir = output / run_id
    run_dir.mkdir()
    request_case = dict(case)
    if args.blind:
        request_case["instruction"] = BLIND_INSTRUCTION
    with tempfile.TemporaryDirectory(prefix="alchemist-baseline-") as temp:
        staged = Path(temp) / "audit"
        shutil.copytree(manifest.parent, staged, ignore=IGNORE)
        write_json(
            staged / "dataset.json",
            {"schema_version": 1, "name": dataset_name, "cases": [request_case]},
        )
        report = run_dir / "report.json"
        command = [
            str(args.binary),
            "benchmark",
            "--dataset",
            str(staged / "dataset.json"),
            "--agent",
            sys.executable,
            "--agent-arg",
            str(args.adapter),
            "--agent-arg",
            "--harness",
            "--agent-arg",
            args.harness,
            "--timeout-ms",
            str(args.timeout_ms),
            "--max-output-bytes",
            str(args.max_output_bytes),
            "--jobs",
            "1",
            "--output",
            str(report),
        ]
        if args.model:
            command += ["--agent-arg", "--model", "--agent-arg", args.model]
        if args.harness == "dsh" and args.profile:
            command += ["--agent-arg", "--profile", "--agent-arg", args.profile]
        if args.adapter_timeout:
            command += ["--agent-arg", "--timeout-seconds", "--agent-arg", str(args.adapter_timeout)]
        if args.deadline_minutes:
            command += ["--agent-arg", "--deadline-minutes", "--agent-arg", str(args.deadline_minutes)]
        command += ["--agent-arg", "--hide-labels"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        adapter_log = staged / ".audit-adapter.log"
        adapter_text = adapter_log.read_text(encoding="utf-8", errors="replace") if adapter_log.is_file() else ""
    stderr = result.stderr.decode("utf-8", errors="replace") + adapter_text
    for name in ("AUDIT_HARNESS_CLAUDE_TOKEN", "AUDIT_API_KEY", "DS_API_KEY"):
        secret = os.environ.get(name)
        if secret:
            stderr = stderr.replace(secret, "[REDACTED]")
    (run_dir / "stderr.log").write_text(stderr, encoding="utf-8")
    record = {
        "run": run_id,
        "case_id": case["id"],
        "trial": trial,
        "harness": args.harness,
        "exit_code": result.returncode,
        "expected": len(case["expected"]),
        "instruction": request_case["instruction"],
        "report": None,
        "outcome": "missing_report",
    }
    if report.is_file() and report.stat().st_size:
        payload = json.loads(report.read_bytes())
        run = payload["cases"][0]["run"]
        record["report"] = report.relative_to(output).as_posix()
        record["outcome"] = run["outcome"]
        record["elapsed_ms"] = run["elapsed_ms"]
        record["agent_exit_code"] = run["exit_code"]
    return record


def summarize(output: Path, records: list[dict]) -> dict:
    cases = []
    totals = {"tp": 0, "fp": 0, "fn": 0, "line_tp": 0, "line_fp": 0, "line_fn": 0}
    success = failed = adapter_timeouts = 0
    durations: list[int] = []
    exact_hits: set[str] = set()
    line_hits: set[str] = set()
    for record in records:
        case = {
            "run": record["run"],
            "case_id": record["case_id"],
            "trial": record["trial"],
            "instruction": record["instruction"],
            "outcome": record["outcome"],
            "tp": 0, "fp": 0, "fn": record["expected"],
            "line_tp": 0, "line_fp": 0, "line_fn": record["expected"],
            "findings": [],
            "error": None,
            "elapsed_ms": record.get("elapsed_ms"),
        }
        if record["report"]:
            payload = json.loads((output / record["report"]).read_bytes())
            report = payload["cases"][0]
            run = report["run"]
            case["error"] = run.get("error")
            case["elapsed_ms"] = run["elapsed_ms"]
            durations.append(run["elapsed_ms"])
            case["findings"] = [
                {"cwe": f["cwe"], "path": f["path"], "line": f["line"]} for f in run["findings"]
            ]
            if run["outcome"] == "success":
                success += 1
            else:
                failed += 1
                # The adapter exits 3 on its own timeout; provider exit codes differ.
                if run["outcome"] == "nonzero_exit" and run.get("exit_code") == 3:
                    adapter_timeouts += 1
            case["tp"] = len(report["matched"])
            case["fp"] = len(report["unexpected"])
            case["fn"] = len(report["missed"])
            expected_lines = {(f["path"], f["line"]) for f in report["matched"] + report["missed"]}
            reported_lines = {(f["path"], f["line"]) for f in run["findings"]}
            case["line_tp"] = len(expected_lines & reported_lines)
            case["line_fp"] = len(reported_lines - expected_lines)
            case["line_fn"] = len(expected_lines - reported_lines)
            if case["tp"]:
                exact_hits.add(record["case_id"])
            if case["line_tp"]:
                line_hits.add(record["case_id"])
        else:
            failed += 1
        for name in totals:
            totals[name] += case[name]
        cases.append(case)

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    return {
        "schema_version": 1,
        "harness": records[0]["harness"] if records else None,
        "trials": len(records),
        "success": success,
        "failed": failed,
        "adapter_timeouts": adapter_timeouts,
        "elapsed_ms": {
            "mean": statistics.mean(durations) if durations else None,
            "max": max(durations) if durations else None,
            "total": sum(durations),
        },
        "exact": {
            **totals,
            "precision": ratio(totals["tp"], totals["tp"] + totals["fp"]),
            "recall": ratio(totals["tp"], totals["tp"] + totals["fn"]),
            "f1": ratio(2 * totals["tp"], 2 * totals["tp"] + totals["fp"] + totals["fn"]),
            "distinct_hits": sorted(exact_hits),
        },
        "line": {
            "line_tp": totals["line_tp"],
            "line_fp": totals["line_fp"],
            "line_fn": totals["line_fn"],
            "precision": ratio(totals["line_tp"], totals["line_tp"] + totals["line_fp"]),
            "recall": ratio(totals["line_tp"], totals["line_tp"] + totals["line_fn"]),
            "f1": ratio(2 * totals["line_tp"], 2 * totals["line_tp"] + totals["line_fp"] + totals["line_fn"]),
            "distinct_hits": sorted(line_hits),
        },
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", choices=["codex", "claude", "dsh", "pi"])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summarize", type=Path, help="rebuild summary.json from records.json in this run directory")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout-ms", type=int, default=900_000)
    parser.add_argument("--adapter-timeout", type=int, default=840)
    parser.add_argument("--deadline-minutes", type=int, default=0,
                        help="soft in-band time budget forwarded to the adapter; 0 disables it")
    parser.add_argument("--max-output-bytes", type=int, default=4_194_304)
    parser.add_argument("--model", default=None)
    parser.add_argument("--profile", default=os.environ.get("AUDIT_HARNESS_DSH_PROFILE", "headless"))
    parser.add_argument("--blind", action="store_true", help="use one blind instruction for every case")
    parser.add_argument("--case", action="append", default=[], help="restrict to a primary case id")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--adapter", type=Path, default=None)
    args = parser.parse_args()

    if args.summarize:
        output = args.summarize.resolve()
        records = json.loads((output / "records.json").read_text(encoding="utf-8"))
        summary = summarize(output, records)
        (output / "summary.json").unlink(missing_ok=True)
        write_json(output / "summary.json", summary)
        print(json.dumps({"harness": summary["harness"], **summary["exact"],
                          "adapter_timeouts": summary["adapter_timeouts"]}, indent=2))
        return 0
    if not args.harness or not args.output:
        parser.error("--harness and --output are required unless --summarize is used")

    args.root = args.root.resolve()
    args.output = args.output.resolve()
    args.binary = (args.binary or args.root / "target/debug/alchemist.exe").resolve()
    args.adapter = (args.adapter or args.root / "scripts/external_agent.py").resolve()
    if not args.binary.is_file():
        args.binary = (args.root / "target/debug/alchemist").resolve()
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    args.output.mkdir(parents=True)
    args.adapter_timeout = args.adapter_timeout or None

    only = set(args.case) or None
    cases = load_primary(args.root, only)
    manifest = {
        "schema_version": 1,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "harness_revision": git(args.root, "rev-parse", "HEAD"),
        "working_diff_sha256": digest(subprocess.check_output(["git", "-C", str(args.root), "diff", "HEAD"])),
        "binary": str(args.binary),
        "binary_sha256": digest(args.binary.read_bytes()),
        "adapter": str(args.adapter),
        "adapter_sha256": digest(args.adapter.read_bytes()),
        "dataset_revision": git(args.root / "datasets/tiny", "rev-parse", "HEAD"),
        "harness": args.harness,
        "model": args.model,
        "profile": args.profile if args.harness == "dsh" else None,
        "trials": args.trials,
        "blind": args.blind,
        "timeout_ms": args.timeout_ms,
        "adapter_timeout": args.adapter_timeout,
        "deadline_minutes": args.deadline_minutes,
        "selection": "all trials, including failures; no best-of selection",
        "cases": [case["id"] for _, _, case in cases],
    }
    write_json(args.output / "manifest.json", manifest)

    jobs = [(trial, manifest_path, name, case)
            for trial in range(1, args.trials + 1)
            for manifest_path, name, case in cases]
    records = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [
            pool.submit(run_case, args, args.root, args.output, manifest_path, name, case, trial)
            for trial, manifest_path, name, case in jobs
        ]
        for future in as_completed(futures):
            record = future.result()
            records.append(record)
            print(record["run"], record["outcome"], flush=True)
    records.sort(key=lambda r: (r["trial"], r["case_id"]))
    write_json(args.output / "records.json", records)
    summary = summarize(args.output, records)
    write_json(args.output / "summary.json", summary)
    print(json.dumps(summary["exact"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
