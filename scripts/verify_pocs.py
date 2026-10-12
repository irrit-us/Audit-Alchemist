#!/usr/bin/env python3
"""Run per-case PoC oracles in fresh staged fixtures and record verification.

Each defined oracle is a fixed, bounded local reproduction of the labeled root
cause. It runs in a fresh copy of the fixture's ``audit/`` tree (excluding the
label manifest and ``reference/``), never in the agent workspace, so it verifies
that the vulnerability is *demonstrable* independently of what the agent
reported. Results are a separate metric from exact/line detection and are never
folded into it. A missing oracle records ``defined: false`` rather than a pass.

Usage::

    python scripts/verify_pocs.py --output reports/rNN/poc-verification.json
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

SKIP = shutil.ignore_patterns(
    "dataset.json", "reference", "node_modules", "target", ".git", "__pycache__", ".venv", "vendor"
)


def stage(fixture: Path, destination: Path) -> None:
    shutil.copytree(fixture, destination, ignore=SKIP)


def run_oracle(repo: Path, oracle: dict) -> dict:
    """Run one oracle in a throwaway staged copy; never mutate the repository."""
    fixture = (repo / oracle["fixture"]).resolve()
    if not fixture.is_dir():
        return {"defined": True, "verified": False, "error": f"fixture missing: {fixture}"}
    script = (repo / oracle["script"]).resolve() if oracle.get("script") else None
    timeout = oracle.get("timeout_ms", 60_000) / 1000
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="poc-oracle-") as temp:
        staged = Path(temp) / "audit"
        stage(fixture, staged)
        if script is not None:
            shutil.copy2(script, staged / script.name)
        try:
            process = subprocess.run(
                list(oracle["argv"]),
                cwd=staged,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {"defined": True, "verified": False, "error": "timeout",
                    "timeout_ms": oracle.get("timeout_ms"), "elapsed_ms": int((time.monotonic() - started) * 1000)}
        except OSError as error:
            return {"defined": True, "verified": False, "error": str(error)}
    expected_exit = oracle.get("expect_exit", 0)
    contains = oracle.get("expect_stdout_contains")
    verified = process.returncode == expected_exit and (contains is None or contains in process.stdout)
    return {
        "defined": True,
        "verified": verified,
        "exit_code": process.returncode,
        "expected_exit": expected_exit,
        "stdout_tail": process.stdout[-500:],
        "stderr_tail": process.stderr[-500:],
        "error": None,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracles", type=Path,
                        default=Path(__file__).resolve().parent / "poc_oracles.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()

    repo = args.repo.resolve()
    data = json.loads(args.oracles.read_text(encoding="utf-8"))
    selected = set(args.case) or None
    results = {}
    for case_id, oracle in data["oracles"].items():
        if selected and case_id not in selected:
            continue
        if not oracle.get("defined", True):
            results[case_id] = {"defined": False, "verified": False,
                                "reason": oracle.get("reason", "not defined")}
            print(f"{case_id}: not defined")
            continue
        result = run_oracle(repo, oracle)
        results[case_id] = result
        print(f"{case_id}: verified={result['verified']}"
              + (f" error={result['error']}" if result.get("error") else ""), flush=True)

    defined = [r for r in results.values() if r["defined"]]
    report = {
        "schema_version": 1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "oracles": str(args.oracles.resolve()),
        "note": "Fixture-level reproduction verification; independent of the agent and of exact/line scoring.",
        "summary": {
            "cases": len(results),
            "defined": len(defined),
            "verified": sum(1 for r in defined if r["verified"]),
            "failed": sum(1 for r in defined if not r["verified"]),
            "not_defined": len(results) - len(defined),
        },
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
