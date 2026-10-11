#!/usr/bin/env python3
"""Version 1 protocol adapter for external agent harnesses.

Audit Alchemist's ``benchmark`` command invokes one external executable per case,
writes a Version 1 request to its stdin, and reads exactly one Version 1 response
from its stdout (see docs/protocol.md and docs/api.md). The agent CLIs available
on a workstation (Codex, Claude Code, DeepSeek Harness, Pi) are *coding* agents,
not audit-native protocol servers, so this adapter bridges the two:

1. read the request from stdin;
2. send a fixed audit brief plus the case instruction to the selected harness,
   with the current directory as the audit root;
3. recover the response object from either a side file the brief asks the agent
   to write (``.audit-findings.json``) or the last balanced JSON object in the
   harness output;
4. normalize finding fields to the protocol contract and emit one response.

Normalization is deliberately conservative: it fixes form (CWE spelling, path
separators, severity vocabulary) but never invents a finding. Entries without a
parseable CWE, a relative path, or a positive line are dropped and counted on
stderr. The adapter exits non-zero for spawn errors, harness errors, timeouts,
and missing/unparseable responses so the harness records a failed invocation
instead of a clean "no findings" run.

Credentials are inherited from the environment; nothing is written to disk beyond
temporary schema/output files and the side file in the audit root. Use
``AUDIT_HARNESS_CLAUDE_TOKEN`` to override an invalid Claude Code token without
editing the user's settings.

Usage (normally through ``scripts/run_harness_baseline.py``)::

    printf '%s' '{"schema_version":1,...}' | \\
        python scripts/external_agent.py --harness codex --model gpt-5.6-sol
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

VERSION = 1
LOG_FILE = ".audit-adapter.log"
SEVERITIES = {"info", "low", "medium", "high", "critical"}
DEFAULT_CODEX_MODEL = "gpt-5.6-sol"

RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "findings"],
    "properties": {
        "schema_version": {"type": "integer", "const": VERSION},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["cwe", "path", "line", "severity", "title", "evidence"],
                "properties": {
                    "cwe": {"type": "string"},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "severity": {"type": "string", "enum": sorted(SEVERITIES)},
                    "title": {"type": "string"},
                    "evidence": {"type": "string"},
                },
            },
        },
    },
}


def log(message: str) -> None:
    line = f"[external_agent] {message}"
    print(line, file=sys.stderr, flush=True)
    try:
        with Path(LOG_FILE).open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
    except OSError:
        pass


def brief(target: str, instruction: str, side_file: str, deadline_minutes: int = 0) -> str:
    """Fixed audit brief. Keep it short; the case instruction carries scope."""
    text = (
        "You are auditing source code in the current working directory for "
        "concrete, reachable security vulnerabilities.\n"
        f"Primary target: {target}\n"
        f"Task: {instruction}\n\n"
        "Use your native tools to read the target and follow the data flow to "
        "the sink. Follow the task's scope boundary exactly: do not claim an "
        "end-to-end exploit when the task says the precondition is narrower, and "
        "do not report intended or documented behavior as a vulnerability.\n\n"
    )
    if deadline_minutes > 0:
        text += (
            f"Time budget: aim to write {side_file} within {deadline_minutes} "
            "minutes of wall-clock time. If you are still investigating as that "
            "budget approaches, stop exploring and report the confirmed findings "
            "you have rather than continuing.\n\n"
        )
    return text + (
        "Report every root cause you are confident in. Write your final answer "
        f"to the file {side_file} in the current directory, and also print the "
        "same object as your final message. The answer must be exactly one JSON "
        "object of this shape and nothing else:\n"
        '{"schema_version": 1, "findings": [{"cwe": "CWE-<number>", '
        '"path": "<path relative to the current directory, forward slashes>", '
        '"line": <1-based sink line>, '
        '"severity": "info|low|medium|high|critical", '
        '"title": "<short title>", '
        '"evidence": "<why the root cause is reachable and unsafe>"}]}\n'
        'Use {"schema_version": 1, "findings": []} when you find nothing. '
        "Do not wrap the JSON in markdown or add prose around it.\n"
    )


def balanced_objects(text: str) -> list[str]:
    """Return every balanced-brace substring, in document order."""
    objects: list[str] = []
    i = 0
    while i < len(text):
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        in_string = False
        escaped = False
        start = i
        j = i
        while j < len(text):
            char = text[j]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    objects.append(text[start : j + 1])
                    break
            j += 1
        i = j + 1
    return objects


def extract_response(text: str):
    """Find the last JSON object that looks like a Version 1 response."""
    candidates = [text.strip()] if text.strip().startswith("{") else []
    candidates.extend(balanced_objects(text))
    for candidate in reversed(candidates):
        try:
            value = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict) and "findings" in value:
            return value
    return None


def normalize_path(value: str, root: Path) -> str | None:
    path = str(value or "").strip().replace("\\", "/")
    root_posix = root.resolve().as_posix().rstrip("/")
    if path.startswith(root_posix + "/"):
        path = path[len(root_posix) + 1 :]
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def normalize_finding(raw: dict, root: Path):
    cwe = str(raw.get("cwe", "")).strip().upper().replace(" ", "-").replace("_", "-")
    cwe = cwe if cwe.startswith("CWE-") else "CWE-" + cwe
    match = re.fullmatch(r"CWE-0*(\d{1,6})", cwe)
    if not match:
        return None
    cwe = f"CWE-{int(match.group(1))}"
    path = normalize_path(raw.get("path", ""), root)
    if path is None:
        return None
    try:
        line = int(raw.get("line", 0))
    except (TypeError, ValueError):
        return None
    if line <= 0:
        return None
    severity = str(raw.get("severity", "medium")).strip().lower()
    if severity not in SEVERITIES:
        severity = "medium"
    title = str(raw.get("title", "")).strip() or cwe
    evidence = str(raw.get("evidence", "")).strip() or title
    return {
        "cwe": cwe,
        "path": path,
        "line": line,
        "severity": severity,
        "title": title[:1024],
        "evidence": evidence[:16384],
    }


def read_side_file(root: Path, name: str):
    path = root / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def hide_labels(root: Path, names=("dataset.json",)):
    """Move label manifests out of the agent workspace for the duration of a run.

    The harness needs the manifest on disk to load and score the case, but the
    agent must not read it. The manifest is moved to a private temporary
    directory (outside the workspace) and restored afterwards.
    """
    backup = Path(tempfile.mkdtemp(prefix="audit-labels-"))
    hidden = []
    for name in names:
        source = root / name
        if source.is_file():
            destination = backup / name
            shutil.move(str(source), str(destination))
            hidden.append((source, destination))
    return hidden


def restore_labels(hidden) -> None:
    for source, destination in hidden:
        if destination.is_file() and not source.exists():
            shutil.move(str(destination), str(source))


def run_process(command: list[str], cwd: Path, prompt_text: str | None, timeout: int):
    """Run a child, bounding it and killing its process tree on timeout."""
    kwargs = {
        "cwd": str(cwd),
        "stdin": subprocess.PIPE if prompt_text is not None else subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(command, **kwargs)
    try:
        stdout, stderr = process.communicate(input=prompt_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_tree(process)
        process.communicate()
        return None, None, "timeout"
    return process.returncode, stdout or "", stderr or ""


def kill_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except (OSError, ProcessLookupError):
        process.kill()


def read_last_message(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def invoke_codex(root: Path, prompt_text: str, model: str, timeout: int, work: Path):
    schema_file = work / "response.schema.json"
    schema_file.write_text(json.dumps(RESPONSE_SCHEMA), encoding="utf-8")
    last_file = work / "last-message.json"
    provider = os.environ.get("AUDIT_HARNESS_CODEX_PROVIDER")
    command = [
        "codex",
        "exec",
        "--skip-git-repo-check",
        "-C",
        str(root),
        "-m",
        model,
    ]
    if provider:
        command += ["-c", f"model_provider={provider}"]
    command += [
        "--dangerously-bypass-approvals-and-sandbox",
        "--output-schema",
        str(schema_file),
        "-o",
        str(last_file),
        "-",
    ]
    code, stdout, stderr = run_process(command, root, prompt_text, timeout)
    return code, stdout, stderr, [read_last_message(last_file), stdout]


def invoke_claude(root: Path, prompt_text: str, model: str | None, timeout: int, work: Path):
    overrides: dict[str, str] = {}
    token = os.environ.get("AUDIT_HARNESS_CLAUDE_TOKEN")
    if token:
        overrides["ANTHROPIC_AUTH_TOKEN"] = token
    if model:
        overrides["ANTHROPIC_MODEL"] = model
        overrides["ANTHROPIC_SMALL_FAST_MODEL"] = model
    command = [
        "claude",
        "-p",
        "--dangerously-skip-permissions",
        "--output-format",
        "json",
    ]
    if overrides:
        command += ["--settings", json.dumps({"env": overrides})]
    command.append(prompt_text)
    code, stdout, stderr = run_process(command, root, None, timeout)
    text = stdout or ""
    try:
        envelope = json.loads(text)
        if isinstance(envelope, dict) and isinstance(envelope.get("result"), str):
            text = envelope["result"]
    except (ValueError, TypeError):
        pass
    return code, stdout, stderr, [text, stdout]


def invoke_dsh(root: Path, prompt_text: str, profile: str, timeout: int, work: Path):
    command = ["dsh", "--profile", profile, "-"]
    code, stdout, stderr = run_process(command, root, prompt_text, timeout)
    return code, stdout, stderr, [stdout]


def invoke_pi(root: Path, prompt_text: str, model: str | None, timeout: int, work: Path):
    command = ["pi", "-p", "--no-context-files"]
    if model:
        command += ["--model", model]
    command.append(prompt_text)
    code, stdout, stderr = run_process(command, root, None, timeout)
    return code, stdout, stderr, [stdout]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", required=True, choices=["codex", "claude", "dsh", "pi"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--profile", default=os.environ.get("AUDIT_HARNESS_DSH_PROFILE", "headless"))
    parser.add_argument("--deadline-minutes", type=int, default=0,
                        help="soft in-band time budget; 0 disables it")
    parser.add_argument("--hide-labels", action="store_true",
                        help="move dataset.json out of the workspace while the harness runs")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    try:
        request = json.loads(sys.stdin.read())
    except ValueError as error:
        log(f"invalid request on stdin: {error}")
        return 2
    root = Path.cwd()
    case_id = str(request.get("case_id", ""))
    safe_case = re.sub(r"[^A-Za-z0-9_-]", "_", case_id)[:64] or "case"
    side_name = f".audit-findings-{safe_case}.json"
    try:
        prompt_text = brief(str(request["target"]), str(request["instruction"]), side_name,
                            args.deadline_minutes)
    except KeyError as error:
        log(f"request missing field: {error}")
        return 2

    # A stale side file from a previous run must never be mistaken for this one.
    side = root / side_name
    if side.exists():
        side.unlink()
    for stale in (root / LOG_FILE,):
        if stale.exists():
            stale.unlink()

    started = time.monotonic()
    hidden = hide_labels(root) if args.hide_labels else []
    try:
        with tempfile.TemporaryDirectory(prefix="audit-harness-") as temp:
            work = Path(temp)
            if args.harness == "codex":
                code, stdout, stderr, extra = invoke_codex(
                    root, prompt_text, args.model or DEFAULT_CODEX_MODEL, args.timeout_seconds, work
                )
            elif args.harness == "claude":
                code, stdout, stderr, extra = invoke_claude(
                    root, prompt_text, args.model, args.timeout_seconds, work
                )
            elif args.harness == "dsh":
                code, stdout, stderr, extra = invoke_dsh(
                    root, prompt_text, args.profile, args.timeout_seconds, work
                )
            else:
                code, stdout, stderr, extra = invoke_pi(
                    root, prompt_text, args.model, args.timeout_seconds, work
                )
    finally:
        restore_labels(hidden)

    elapsed = time.monotonic() - started
    if code is None:
        log(f"{args.harness} timed out after {elapsed:.0f}s")
        return 3

    raw = read_side_file(root, side_name)
    sources = ["side-file"] if raw is not None else []
    if raw is None:
        for text in extra:
            raw = extract_response(text or "")
            if raw is not None:
                sources.append("output")
                break
    if raw is None:
        tail = (stderr or "").strip().splitlines()[-5:]
        log(f"no response object found (exit {code}, {elapsed:.0f}s); stderr tail: {tail}")
        return 4
    if code != 0:
        log(f"harness exited {code} but produced a response; accepting it")

    findings, dropped = [], 0
    for item in raw.get("findings") or []:
        if not isinstance(item, dict):
            dropped += 1
            continue
        normalized = normalize_finding(item, root)
        if normalized is None:
            dropped += 1
            continue
        findings.append(normalized)
    if dropped:
        log(f"dropped {dropped} non-conforming finding(s)")
    response = {"schema_version": VERSION, "findings": findings}
    sys.stdout.write(json.dumps(response))
    sys.stdout.write("\n")
    log(
        f"{args.harness}: {len(findings)} finding(s), source={','.join(sources) or 'unknown'}, "
        f"exit={code}, elapsed={elapsed:.0f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
