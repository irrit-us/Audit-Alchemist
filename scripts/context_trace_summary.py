"""Summarize context pressure from ordinary agent traces in Harbor jobs.

Run with one or more completed job directories. Reads only operational events;
does not copy model messages, tool output, or credentials into the summary.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from statistics import median


def summarize(jobs: list[Path]) -> dict:
    rows = []
    for job in jobs:
        traces = sorted(job.glob("*/agent/traces/*.jsonl"))
        if not traces:
            raise ValueError(f"no operational traces in {job}")
        for trace in traces:
            requests = []
            limits = set()
            pruned = 0
            prune_events = 0
            projected = 0
            archive_reuses = 0
            ended = False
            for line in trace.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)["event"]
                if event.get("type") != "operation":
                    continue
                name = event.get("name")
                details = event.get("details", {})
                if name == "turn_start":
                    requests.append(details["request_bytes"])
                    limits.add(details["context_limit_bytes"])
                elif name == "context_pruned":
                    prune_events += 1
                    pruned += details["pruned_results"]
                    archive_reuses = max(
                        archive_reuses, details.get("archive", {}).get("reused_outputs", 0)
                    )
                elif name == "tool_output_projected":
                    projected += 1
                    archive_reuses = max(
                        archive_reuses, details.get("archive", {}).get("reused_outputs", 0)
                    )
                elif name == "run_end":
                    ended = True
            if not requests or len(limits) != 1 or not ended:
                raise ValueError(f"incomplete context trace: {trace}")
            report = json.loads((trace.parent.parent / "report.json").read_text(encoding="utf-8"))
            rows.append({
                "job": job.name,
                "trial": trace.parents[2].name,
                "turns": len(requests),
                "max_request_bytes": max(requests),
                "context_limit_bytes": limits.pop(),
                "prune_events": prune_events,
                "pruned_results": pruned,
                "projected_results": projected,
                "archive_reuses": archive_reuses,
                "outcome": report.get("outcome", "unknown"),
                "request_bytes": requests,
            })
    all_requests = [size for row in rows for size in row["request_bytes"]]
    return {
        "schema_version": 1,
        "jobs": [job.name for job in jobs],
        "trials": len(rows),
        "turns": len(all_requests),
        "median_request_bytes": median(all_requests),
        "max_request_bytes": max(all_requests),
        "trials_above_90_percent": sum(
            row["max_request_bytes"] > row["context_limit_bytes"] * 0.9
            for row in rows
        ),
        "prune_events": sum(row["prune_events"] for row in rows),
        "pruned_results": sum(row["pruned_results"] for row in rows),
        "projected_results": sum(row["projected_results"] for row in rows),
        "archive_reuses": sum(row["archive_reuses"] for row in rows),
        "outcomes": dict(sorted(Counter(row["outcome"] for row in rows).items())),
        "per_trial": [
            {key: value for key, value in row.items() if key != "request_bytes"}
            for row in rows
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", type=Path, action="append", required=True)
    args = parser.parse_args()
    print(json.dumps(summarize(args.job), indent=2))


if __name__ == "__main__":
    main()
