mod support;
use audit_harness::{config::FileConfig, mcp::McpTools};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn cli(root: &Path, command: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_alchemist"));
    cmd.current_dir(root)
        .arg(command)
        .arg("--config")
        .arg(root.join("node.toml"));
    cmd.env("AUDIT_API_KEY", "fixture-key");
    cmd
}
fn config(root: &Path, extra: &str) {
    std::fs::write(
        root.join("node.toml"),
        format!("schema_version = 1\n{extra}"),
    )
    .unwrap();
}
fn success(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn mcp_config(root: &Path, mode: &str) -> String {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp_server.py");
    // Windows CI can take several seconds to launch Python while other Rust
    // integration tests start child processes. Keep deliberate hang fixtures
    // short, but give successful startup and tool calls room to complete.
    let timeout = match mode {
        "hang_init" => 1500,
        "echo" | "pages" => 15_000,
        _ => 5000,
    };
    format!("[mcp.fixture]\nenabled = true\ncommand = {:?}\nargs = [{:?}, {:?}, {:?}]\ntimeout_ms = {timeout}\ntools = [\"echo\"]\n", if cfg!(windows) { "python" } else { "python3" }, fixture.to_string_lossy(), mode, root.join("mcp.jsonl").to_string_lossy())
}
fn final_turn() -> String {
    format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"choices":[{"delta":{"content":json!({"schema_version":1,"findings":[]}).to_string()},"finish_reason":"stop"}]})
    )
}

#[test]
fn tui_requires_terminal_without_writing_json_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("entry.py"), "pass\n").unwrap();
    config(
        root,
        "[cli]\nmodel = 'fixture'\ntarget = 'entry.py'\nendpoint = 'http://127.0.0.1:1/v1/chat/completions'\n",
    );
    let output = cli(root, "audit").arg("--tui").output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--tui requires a terminal"));
}

#[test]
fn audit_output_format_and_verbose_follow_config_and_cli_override() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("entry.py"), "pass\n").unwrap();
    let (endpoint, _rx, server) = server(vec![final_turn(), final_turn()]);
    config(
        root,
        &format!(
            "[cli]\nmodel = 'fixture'\ntarget = 'entry.py'\nendpoint = {endpoint:?}\nformat = 'table'\nverbose = true\ntui_view = 'answer'\n"
        ),
    );
    let verbose = cli(root, "audit").output().unwrap();
    let verbose_stderr = String::from_utf8_lossy(&verbose.stderr).into_owned();
    assert_eq!(success(verbose)["outcome"], "success");
    assert!(verbose_stderr.contains("[run_start]"));
    assert!(verbose_stderr.contains("No findings."));

    let compact = cli(root, "audit").arg("--verbose=false").output().unwrap();
    let compact_stderr = String::from_utf8_lossy(&compact.stderr).into_owned();
    assert_eq!(success(compact)["outcome"], "success");
    assert!(!compact_stderr.contains("[run_start]"));
    assert!(compact_stderr.contains("No findings."));
    server.join().unwrap();
}

fn finding_turn(path: &str) -> String {
    let answer = json!({"schema_version":1,"findings":[{"cwe":"CWE-78","path":path,"line":2,"severity":"high","title":"Sink","evidence":"Input reaches sink"}]}).to_string();
    format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"choices":[{"delta":{"content":answer},"finish_reason":"stop"}]})
    )
}

#[test]
fn citation_confirmation_requires_a_new_report_and_exposes_exact_source() {
    for configured in [Some(false), Some(true), None] {
        let enabled = configured.unwrap_or(true);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("entry.py"), "pass\n").unwrap();
        std::fs::create_dir_all(root.join("pkg/sub")).unwrap();
        std::fs::write(root.join("pkg/sub/a.py"), "first\nsink()\n").unwrap();
        let (endpoint, rx, server) =
            server(vec![finding_turn("sub/a.py"), finding_turn("pkg/sub/a.py")]);
        let citation_setting = configured
            .map(|value| format!("citation_confirmation = {value}\n"))
            .unwrap_or_default();
        config(root, &format!(
            "[cli]\nmodel = 'fixture'\ntarget = 'entry.py'\nendpoint = {endpoint:?}\nmax_output_repairs = 1\n{citation_setting}trace_dir = 'traces'\nformat = 'quiet'\n"
        ));
        let output = cli(root, "audit").output().unwrap();
        server.join().unwrap();
        assert_eq!(
            output.status.success(),
            enabled,
            "configured={configured:?}, stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let first = rx.recv().unwrap();
        assert!(!first.to_string().contains("sink()"));
        let second = rx.recv().unwrap();
        let second_text = second.to_string();
        assert_eq!(second_text.contains("sink()"), enabled);
        assert_eq!(second_text.contains("pkg/sub/a.py"), enabled);
        let trace = std::fs::read_to_string(
            std::fs::read_dir(root.join("traces"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .unwrap();
        assert_eq!(
            trace.contains("\"name\":\"citation_confirmation\""),
            enabled
        );
    }
}

#[test]
fn standalone_config_paths_overrides_and_lazy_skills() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("entry.py"), "print('fixture')\n").unwrap();
    std::fs::write(root.join("guide.md"), "CUSTOM_BODY_NOT_PRELOADED").unwrap();
    config(
        root,
        &format!(
            r#"
[cli]
model = "from-file"
target = "entry.py"
root = "."
max_tool_calls = 3
context_policy = "fail"
context_keep_turns = 4
max_tool_output_bytes = 4096
dry_run = true
agent_arg = ["--fixture-option", "literal with spaces", "$(literal)"]
[prompts]
append = "Focus on the current task."
[tools]
enabled = ["bash", "read_file", "load_skill"]
[skills]
enabled = ["local-guide"]
[[skills.custom]]
name = "local-guide"
description = "Local guidance"
file = "guide.md"
[skills.custom.resources]
"scripts/check.sh" = "printf checked\n"
{}
"#,
            mcp_config(root, "echo")
        ),
    );
    let checked = success(cli(root, "check-config").output().unwrap());
    assert_eq!(checked["mcp_servers"], json!(["fixture"]));
    let preview = success(
        cli(root, "audit")
            .current_dir(std::env::temp_dir())
            .args(["--model", "override", "--max-tool-calls", "7"])
            .output()
            .unwrap(),
    );
    assert_eq!(preview["model"], "override");
    assert_eq!(preview["max_tool_calls"], 7);
    assert_eq!(preview["context_policy"], "fail");
    assert_eq!(preview["context_keep_turns"], 4);
    assert_eq!(preview["max_tool_output_bytes"], 4096);
    assert_eq!(preview["files"], 1);
    assert_eq!(preview["tools"], json!(["load_skill", "bash", "read_file"]));
    assert_eq!(preview["skills"].as_array().unwrap().len(), 1);
    assert!(!preview.to_string().contains("CUSTOM_BODY"));
    assert!(!root.join("mcp.jsonl").exists());
    let guide = success(cli(root, "skills").arg("local-guide").output().unwrap());
    assert_eq!(guide["content"], "CUSTOM_BODY_NOT_PRELOADED");
    assert!(!cli(root, "skills")
        .arg("poc-validation")
        .output()
        .unwrap()
        .status
        .success());
    let resource = success(
        cli(root, "skills")
            .args(["local-guide", "--resource", "scripts/check.sh"])
            .output()
            .unwrap(),
    );
    assert_eq!(resource["content"], "printf checked\n");
}

#[test]
fn optional_security_skills_are_selectable_and_lazy_through_cli_config() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    config(
        root,
        "[tools]\nenabled = ['load_skill']\n[skills]\nenabled = ['cvss', 'nvd-cve', 'gh-advisory', 'audit-context-building']\n",
    );
    let checked = success(cli(root, "check-config").output().unwrap());
    let catalog = checked["skills"].as_array().unwrap();
    assert_eq!(catalog.len(), 4);
    assert!(catalog.iter().all(|entry| entry.get("content").is_none()));
    for (name, resource) in [
        ("cvss", "references/scoring.md"),
        ("nvd-cve", "references/api.md"),
        ("gh-advisory", "references/api.md"),
        ("audit-context-building", "references/analysis-format.md"),
    ] {
        assert!(catalog.iter().any(|entry| entry["name"] == name));
        let body = success(cli(root, "skills").arg(name).output().unwrap());
        assert_eq!(body["name"], name);
        assert!(body["available_resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|available| available == resource));
        let reference = success(
            cli(root, "skills")
                .args([name, "--resource", resource])
                .output()
                .unwrap(),
        );
        assert_eq!(reference["resource"], resource);
    }
    let domain = success(
        cli(root, "skills")
            .args([
                "audit-context-building",
                "--resource",
                "references/domain-notes.md",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(domain["resource"], "references/domain-notes.md");
    assert!(!cli(root, "skills")
        .arg("poc-validation")
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn circom_auditor_is_selectable_and_loads_only_exact_resources() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    config(
        root,
        "[tools]\nenabled = ['load_skill']\n[skills]\nenabled = ['circom-auditor']\n",
    );
    let checked = success(cli(root, "check-config").output().unwrap());
    let catalog = checked["skills"].as_array().unwrap();
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog[0]["name"], "circom-auditor");
    assert!(catalog[0].get("content").is_none());

    let body = success(cli(root, "skills").arg("circom-auditor").output().unwrap());
    assert_eq!(body["resource"], "SKILL.md");
    let resources = body["available_resources"].as_array().unwrap();
    assert_eq!(resources.len(), 8);
    for resource in [
        "references/vector-index.md",
        "references/validation.md",
        "references/attack-vectors/signal-field.md",
        "references/attack-vectors/range.md",
        "references/attack-vectors/selector-accumulator.md",
        "references/attack-vectors/binding-1.md",
        "references/attack-vectors/binding-2.md",
        "references/attack-vectors/regex-language.md",
    ] {
        assert!(resources.iter().any(|available| available == resource));
        let loaded = success(
            cli(root, "skills")
                .args(["circom-auditor", "--resource", resource])
                .output()
                .unwrap(),
        );
        assert_eq!(loaded["resource"], resource);
        assert!(loaded["content"]
            .as_str()
            .is_some_and(|content| !content.is_empty()));
    }
    assert!(!cli(root, "skills")
        .args([
            "circom-auditor",
            "--resource",
            "references/orchestration/codex.md"
        ])
        .output()
        .unwrap()
        .status
        .success());
    assert!(!cli(root, "skills")
        .arg("audit-context-building")
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn invalid_configs_fail_before_execution_even_with_overrides() {
    let dir = tempfile::tempdir().unwrap();
    for body in [
        "schema_version = 2",
        "schema_version = 1\nunknown = true",
        "schema_version = 1\n[cli]\nmax_tool_calls = 0",
        "schema_version = 1\n[cli]\nmax_tool_calls = true",
        "schema_version = 1\n[cli]\ncontext_policy = 'summary'",
        "schema_version = 1\n[cli]\ncontext_keep_turns = 0",
        "schema_version = 1\n[cli]\nmax_tool_output_bytes = 1023",
        "schema_version = 1\n[cli]\nmodel_typo = 'x'",
        "schema_version = 1\n[cli]\nheader = ['broken']",
        "schema_version = 1\n[cli]\nformat = 'unknown'",
        "schema_version = 1\n[cli]\ntui_view = 'unknown'",
        "schema_version = 1\n[cli]\nverbose = 'true'",
        "schema_version = 1\n[tools]\nenabled = ['unknown']",
        "schema_version = 1\n[tools]\nenabled = ['bash', 'bash']",
        "schema_version = 1\n[prompts]\nsystem = 'x'\nsystem_file = 'missing'",
        "schema_version = 1\n[skills]\nenabled = ['missing']",
        "schema_version = 1\n[mcp.x]\ncommand = 'x'\ntransport = 'http'",
        "schema_version = 1\n[mcp.x]\ncommand = 'x'\ntimeout_ms = 0",
        "schema_version = 1\n[mcp.x]\ncommand = 'x'\nstartup_timeout_ms = 0",
    ] {
        std::fs::write(dir.path().join("node.toml"), body).unwrap();
        let output = cli(dir.path(), "check-config").output().unwrap();
        assert!(!output.status.success(), "{body}");
        assert!(output.stdout.is_empty());
    }
    config(dir.path(), "[cli]\nmax_tool_calls = 0");
    assert!(!cli(dir.path(), "audit")
        .args([
            "--max-tool-calls",
            "7",
            "--model",
            "x",
            "--target",
            ".",
            "--dry-run"
        ])
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn boolean_cli_override_disables_configured_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("entry.py"), "print('fixture')\n").unwrap();
    let (endpoint, _rx, server) = server(vec![final_turn()]);
    config(dir.path(), &format!("[cli]\nmodel = 'fixture'\ntarget = 'entry.py'\nendpoint = {endpoint:?}\ndry_run = true\n"));
    let result = success(
        cli(dir.path(), "audit")
            .arg("--dry-run=false")
            .output()
            .unwrap(),
    );
    assert_eq!(result["outcome"], "success");
    server.join().unwrap();
}

#[test]
fn mcp_tools_use_native_responses_and_anthropic_continuation() {
    for wire in ["responses", "anthropic"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("entry.py"), "print('fixture')\n").unwrap();
        let sse = |v: Value| format!("data: {v}\n\n");
        let call = if wire == "responses" {
            sse(
                json!({"type":"response.completed","response":{"output":[{"type":"function_call","id":"item-1","call_id":"call-1","name":"mcp_fixture__echo","arguments":"{}","status":"completed"}]}}),
            )
        } else {
            sse(
                json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call-1","name":"mcp_fixture__echo","input":{}}}),
            ) + &sse(
                json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}),
            ) + &sse(json!({"type":"message_delta","delta":{"stop_reason":"tool_use"}}))
                + &sse(json!({"type":"message_stop"}))
        };
        let answer = json!({"schema_version":1,"findings":[]}).to_string();
        let final_body = if wire == "responses" {
            sse(
                json!({"type":"response.completed","response":{"output":[{"type":"message","role":"assistant","phase":"final_answer","content":[{"type":"output_text","text":answer}]}]}}),
            )
        } else {
            sse(json!({"type":"content_block_delta","delta":{"type":"text_delta","text":answer}}))
                + &sse(json!({"type":"message_stop"}))
        };
        let (endpoint, rx, server) = server(vec![call, final_body]);
        config(root, &format!("[cli]\nmodel = 'fixture'\ntarget = 'entry.py'\nendpoint = {endpoint:?}\nwire_api = {wire:?}\n[tools]\nenabled = []\n{}", mcp_config(root, "echo")));
        let result = success(cli(root, "audit").output().unwrap());
        assert_eq!(result["outcome"], "success");
        server.join().unwrap();
        let first = rx.recv().unwrap();
        assert_eq!(first["tools"][0]["name"], "mcp_fixture__echo");
        let second = rx.recv().unwrap();
        if wire == "responses" {
            let item = second["input"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["type"] == "function_call_output")
                .unwrap();
            assert_eq!(item["call_id"], "call-1");
            let output: Value = serde_json::from_str(item["output"].as_str().unwrap()).unwrap();
            assert_eq!(output["content"][0]["text"], "echo");
        } else {
            let messages = second["messages"].as_array().unwrap();
            let item = &messages.last().unwrap()["content"][0];
            assert_eq!(item["tool_use_id"], "call-1");
            let output: Value = serde_json::from_str(item["content"].as_str().unwrap()).unwrap();
            assert_eq!(output["content"][0]["text"], "echo");
        }
    }
}

#[test]
fn cli_agent_runs_mcp_and_custom_skills_with_monitoring() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("entry.py"), "print('fixture')\n").unwrap();
    let calls = [
        ("mcp_fixture__echo", json!({"text":"MCP_OBSERVED"})),
        ("load_skill", json!({"name":"local"})),
        ("bash", json!({"command":"touch should-not-exist"})),
    ];
    let batch: Vec<_> = calls.iter().enumerate().map(|(i, (name,args))| json!({"index":i,"id":format!("call-{i}"),"type":"function","function":{"name":name,"arguments":args.to_string()}})).collect();
    let tool_turn = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"choices":[{"delta":{"tool_calls":batch},"finish_reason":"tool_calls"}]})
    );
    let (endpoint, rx, server) = server(vec![tool_turn, final_turn()]);
    config(
        root,
        &format!(
            r#"
[cli]
model = "fixture"
endpoint = {endpoint:?}
max_attempts = 1
timeout_ms = 30000
trace_dir = "traces"
[prompts]
system = "CONFIGURED_SYSTEM"
append = "CONFIGURED_APPEND"
[tools]
enabled = ["load_skill"]
[skills]
enabled = ["local"]
[[skills.custom]]
name = "local"
description = "Local guidance"
content = "ON_DEMAND_BODY"
{}
[mcp.fixture.env_from]
FIXTURE_MAPPED = "TEST_MCP_SOURCE"
"#,
            mcp_config(root, "pages")
        ),
    );
    let mut child = cli(root, "agent")
        .env("TEST_MCP_SOURCE", "mapped-value")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(json!({"schema_version":1,"case_id":"fixture","target":"entry.py","instruction":"Inspect this task."}).to_string().as_bytes()).unwrap();
    let report = success(child.wait_with_output().unwrap());
    assert_eq!(report["findings"], json!([]));
    server.join().unwrap();
    let first = rx.recv().unwrap();
    assert_eq!(
        first["messages"][0]["content"],
        "CONFIGURED_SYSTEM\n\nCONFIGURED_APPEND"
    );
    assert_eq!(first["tools"].as_array().unwrap().len(), 2);
    assert!(!first.to_string().contains("ON_DEMAND_BODY"));
    assert!(!first.to_string().contains("SERVER_INSTRUCTIONS"));
    let second = rx.recv().unwrap();
    let results: Vec<Value> = second["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["role"] == "tool")
        .map(|v| serde_json::from_str(v["content"].as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(results[0]["content"][0]["text"], "MCP_OBSERVED");
    assert_eq!(
        results[0]["structuredContent"]["mapped_env"],
        "mapped-value"
    );
    assert_eq!(results[1]["content"], "ON_DEMAND_BODY");
    assert!(results[2]["error"].as_str().unwrap().contains("disabled"));
    assert!(!root.join("should-not-exist").exists());
    let log = std::fs::read_to_string(root.join("mcp.jsonl")).unwrap();
    assert!(log.contains("\"closed\": true"));
    assert!(log.contains("-32601"));
    let trace = std::fs::read_dir(root.join("traces"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let journal = std::fs::read_to_string(trace).unwrap();
    assert!(journal.contains("mcp_fixture__echo"));
    assert!(!journal.contains("MCP_OBSERVED"));
}

#[test]
fn evaluate_forwards_resolved_config_into_staged_workspaces() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("entry.py"), "print('fixture')\n").unwrap();
    std::fs::write(root.join("prompt.txt"), "EVALUATION_CONFIG_PROMPT").unwrap();
    std::fs::write(root.join("dataset.json"), json!({"schema_version":1,"name":"config","cases":[{"id":"only","target":"entry.py","instruction":"Inspect.","expected":[]}]}).to_string()).unwrap();
    let (endpoint, rx, server) = server(vec![final_turn()]);
    config(
        root,
        &format!(
            r#"
[cli]
model = "fixture"
endpoint = {endpoint:?}
dataset = "dataset.json"
timeout_ms = 30000
[prompts]
system_file = "prompt.txt"
[tools]
enabled = []
{}
"#,
            mcp_config(root, "echo")
        ),
    );
    let report = success(cli(root, "evaluate").output().unwrap());
    assert_eq!(report["metrics"]["failed_cases"], 0);
    server.join().unwrap();
    let request = rx.recv().unwrap();
    assert_eq!(
        request["messages"][0]["content"],
        "EVALUATION_CONFIG_PROMPT"
    );
    assert_eq!(request["tools"].as_array().unwrap().len(), 1);
    let log = std::fs::read_to_string(root.join("mcp.jsonl")).unwrap();
    let started: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    assert_ne!(Path::new(started["cwd"].as_str().unwrap()), root);
}

#[tokio::test]
async fn mcp_failures_are_bounded_and_poisoned_sessions_are_not_retried() {
    for mode in [
        "bad_version",
        "duplicate",
        "cursor_loop",
        "wrong_id",
        "hang_init",
    ] {
        let dir = tempfile::tempdir().unwrap();
        config(dir.path(), &mcp_config(dir.path(), mode));
        let config = FileConfig::load(&dir.path().join("node.toml")).unwrap();
        let started = Instant::now();
        assert!(
            McpTools::connect(&config.mcp, dir.path()).await.is_err(),
            "{mode}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    for mode in [
        "malformed",
        "bad_result",
        "oversized",
        "hang_call",
        "descendant",
        "tool_error",
    ] {
        let dir = tempfile::tempdir().unwrap();
        config(dir.path(), &mcp_config(dir.path(), mode));
        let config = FileConfig::load(&dir.path().join("node.toml")).unwrap();
        let mut tools = McpTools::connect(&config.mcp, dir.path()).await.unwrap();
        let budget = Duration::from_millis(400);
        let result = tools.execute("mcp_fixture__echo", "{}", budget).await;
        assert!(result.get("error").is_some(), "{mode}: {result}");
        let again = tools.execute("mcp_fixture__echo", "{}", budget).await;
        if mode != "tool_error" {
            assert!(again["error"].as_str().unwrap().contains("unavailable"));
        }
        tools.shutdown().await;
        if mode == "descendant" {
            assert!(dir.path().join("mcp.jsonl.child-ready").exists());
            std::fs::write(dir.path().join("mcp.jsonl.release"), "release").unwrap();
            tokio::time::sleep(Duration::from_millis(1000)).await;
            assert!(!dir.path().join("mcp.jsonl.leaked").exists());
        }
    }
}

#[test]
fn cli_deadline_cancels_mcp_initialization_and_its_descendants() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("entry.py"), "print('fixture')\n").unwrap();
    config(root, &format!("[cli]\nmodel = 'fixture'\ntarget = 'entry.py'\nendpoint = 'http://127.0.0.1:9/unused'\ntimeout_ms = 10000\n{}", mcp_config(root, "cancel_init").replace("timeout_ms = 5000", "timeout_ms = 15000")));
    let start = Instant::now();
    let output = cli(root, "audit").output().unwrap();
    assert!(!output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "timeout", "{result}");
    assert!(start.elapsed() < Duration::from_secs(15));
    let log = std::fs::read_to_string(root.join("mcp.jsonl")).unwrap();
    assert!(log.contains("initialize"));
    assert!(root.join("mcp.jsonl.child-ready").exists());
    std::fs::write(root.join("mcp.jsonl.release"), "release").unwrap();
    thread::sleep(Duration::from_millis(1000));
    assert!(!root.join("mcp.jsonl.leaked").exists());
}
fn bash_turn(id: &str, command: &str) -> String {
    format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":id,"type":"function","function":{"name":"bash","arguments":json!({"command":command}).to_string()}}]},"finish_reason":"tool_calls"}]})
    )
}

#[test]
fn cli_projects_oversized_results_with_status_and_optional_recovery() {
    for policy in ["prune", "fail"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("entry.py"), "print('fixture')\n").unwrap();
        let (endpoint, rx, server) = server(vec![
            bash_turn("large", "printf '%03000d' 0; exit 7"),
            final_turn(),
        ]);
        config(
            root,
            &format!(
                r#"
[cli]
model = "fixture"
target = "entry.py"
endpoint = {endpoint:?}
context_policy = {policy:?}
max_tool_output_bytes = 1024
[tools]
enabled = ["bash"]
[skills]
enabled = []
"#
            ),
        );
        assert_eq!(
            success(cli(root, "audit").output().unwrap())["outcome"],
            "success"
        );
        server.join().unwrap();
        let request = rx.iter().last().unwrap();
        let result = request["messages"].as_array().unwrap().last().unwrap()["content"]
            .as_str()
            .unwrap();
        assert!(result.len() <= 1024);
        let result: Value = serde_json::from_str(result).unwrap();
        assert_eq!(result["exit_code"], 7);
        assert_eq!(result["truncated"], true);
        assert_eq!(result.get("context_archive").is_some(), policy == "prune");
        if policy == "prune" {
            assert!(!Path::new(result["context_archive"]["path"].as_str().unwrap()).exists());
        }
    }
}

#[test]
fn cli_prunes_old_results_and_recovers_without_replaying_mutations() {
    for policy in ["prune", "fail"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("entry.py"), "print('fixture')\n").unwrap();
        let mut turns = vec![
            bash_turn(
                "first",
                "printf 'run\\n' >> executions; printf '%016000d' 0",
            ),
            bash_turn("second", "printf '%03000d' 0"),
            bash_turn("third", "printf '%03000d' 0"),
        ];
        if policy == "prune" {
            turns.extend([final_turn(), final_turn()]);
        }
        let (path_tx, path_rx) = mpsc::channel();
        let (endpoint, rx, server) = server_with(turns, move |index, request| {
            if index != 3 {
                return None;
            }
            let results: Vec<_> = request["messages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["role"] == "tool")
                .collect();
            assert_eq!(results.len(), 3);
            let projected: Value =
                serde_json::from_str(results[0]["content"].as_str().unwrap()).unwrap();
            let path = projected["context_archive"]["path"].as_str().unwrap();
            let saved: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(saved["stdout"].as_str().unwrap().len(), 16000);
            assert_eq!(saved["exit_code"], 0);
            assert_eq!(results[0]["tool_call_id"], "first");
            for recent in &results[1..] {
                let value: Value =
                    serde_json::from_str(recent["content"].as_str().unwrap()).unwrap();
                assert_eq!(value["stdout"].as_str().unwrap().len(), 3000);
                assert!(value.get("context_archive").is_none());
            }
            path_tx.send(path.to_owned()).unwrap();
            Some(bash_turn(
                "recover",
                &format!("head -c 128 -- '{}'", path.replace('\'', "'\\''")),
            ))
        });
        config(
            root,
            &format!(
                r#"
[cli]
model = "fixture"
target = "entry.py"
endpoint = {endpoint:?}
max_attempts = 1
max_context_bytes = 22000
context_policy = {policy:?}
context_keep_turns = 2
reasoning_effort = "high"
trace_dir = "traces"
[prompts]
system = "Return schema_version 1 and findings as JSON."
[tools]
enabled = ["bash"]
[skills]
enabled = []
"#
            ),
        );
        let output = cli(root, "audit").output().unwrap();
        if policy == "prune" {
            assert_eq!(success(output)["outcome"], "success");
            assert!(!Path::new(&path_rx.recv().unwrap()).exists());
        } else {
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stdout).contains("max-context-bytes"));
        }
        server.join().unwrap();
        let requests: Vec<_> = rx.try_iter().collect();
        assert_eq!(requests.len(), if policy == "prune" { 5 } else { 3 });
        assert!(requests
            .iter()
            .all(|r| serde_json::to_vec(r).unwrap().len() <= 22000));
        assert!(requests.iter().all(|r| r["reasoning_effort"] == "high"));
        if policy == "prune" {
            let recovered: Value = serde_json::from_str(
                requests[4]["messages"].as_array().unwrap().last().unwrap()["content"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(recovered["stdout"].as_str().unwrap().len(), 128);
            assert_eq!(recovered["exit_code"], 0);
        }
        assert_eq!(
            std::fs::read_to_string(root.join("executions")).unwrap(),
            "run\n"
        );
        let trace = std::fs::read_dir(root.join("traces"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let journal = std::fs::read_to_string(trace).unwrap();
        assert_eq!(journal.contains("context_pruned"), policy == "prune");
        assert!(!journal.contains(&"0".repeat(256)));
    }
}

fn server(bodies: Vec<String>) -> (String, mpsc::Receiver<Value>, thread::JoinHandle<()>) {
    server_with(bodies, |_, _| None)
}

fn server_with(
    bodies: Vec<String>,
    inspect: impl Fn(usize, &Value) -> Option<String> + Send + 'static,
) -> (String, mpsc::Receiver<Value>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/fixture", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    let task = thread::spawn(move || {
        for (index, body) in bodies.into_iter().enumerate() {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing fixture request");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            support::configure_http_stream(&stream);
            let mut bytes = vec![];
            let mut buffer = [0; 8192];
            let (offset, length) = loop {
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while bytes.len() < offset + length {
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
            }
            let request: Value = serde_json::from_slice(&bytes[offset..offset + length]).unwrap();
            let body = inspect(index, &request).unwrap_or(body);
            tx.send(request).unwrap();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
    });
    (endpoint, rx, task)
}
