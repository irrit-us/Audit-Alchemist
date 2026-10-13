//! CLI provider settings and validation.

use super::{auth, wire::WireApi};
use crate::context::{self, Context};
use anyhow::{ensure, Context as _, Result};
use clap::Args;
use std::path::PathBuf;

/// Default upper bound on a streamed model response. Reasoning models emit a
/// large SSE event stream, so the default leaves headroom above the assembled text.
const DEFAULT_MAX_STREAM_BYTES: u32 = 8 * 1024 * 1024;

/// Which credential source to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AuthKind {
    /// Bearer token from an environment variable.
    ApiKey,
    /// Reuse a Codex CLI ChatGPT login against the Codex responses backend.
    Codex,
}

impl AuthKind {
    /// Stable CLI spelling, matching `clap`'s kebab-case value.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthKind::ApiKey => "api-key",
            AuthKind::Codex => "codex",
        }
    }
}

/// Provider reasoning-effort hint for chat-completions reasoning models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ReasoningEffort {
    Minimal,
    Low,
    Medium,
    High,
}

impl ReasoningEffort {
    pub fn as_str(self) -> &'static str {
        match self {
            ReasoningEffort::Minimal => "minimal",
            ReasoningEffort::Low => "low",
            ReasoningEffort::Medium => "medium",
            ReasoningEffort::High => "high",
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct LlmOptions {
    #[arg(skip)]
    pub settings: crate::config::AgentSettings,
    #[command(flatten)]
    pub monitoring: crate::monitor::MonitorOptions,
    /// Full provider URL: a chat-completions, Responses, or Messages endpoint.
    /// Required with `--auth api-key`; optional override for Codex.
    #[arg(long)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub model: String,
    /// Wire format of the endpoint when `--auth api-key` is used.
    #[arg(long, value_enum, default_value_t = WireApi::ChatCompletions)]
    pub wire_api: WireApi,
    /// Name of the environment variable holding the bearer token.
    #[arg(long, default_value = "AUDIT_API_KEY")]
    pub api_key_env: String,
    /// Credential source.
    #[arg(long, value_enum, default_value_t = AuthKind::ApiKey)]
    pub auth: AuthKind,
    /// Path to the Codex auth.json. Defaults to `$CODEX_HOME/auth.json`.
    #[arg(long)]
    pub codex_auth_file: Option<PathBuf>,
    /// Base URL of the Codex responses backend when `--auth codex` is used.
    #[arg(long, default_value = auth::CODEX_BASE_URL)]
    pub codex_base_url: String,
    #[arg(long, default_value_t = 262_144, value_parser = clap::value_parser!(u32).range(1..=1_048_576))]
    pub max_source_bytes: u32,
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(1..=32_768))]
    pub max_tokens: u32,
    /// Hard byte cap on streamed model output (SSE framing included).
    #[arg(long, default_value_t = DEFAULT_MAX_STREAM_BYTES, value_parser = clap::value_parser!(u32).range(1_048_576..=33_554_432))]
    pub max_stream_bytes: u32,
    /// Optional reasoning-effort hint for reasoning models (chat-completions).
    #[arg(long, value_enum)]
    pub reasoning_effort: Option<ReasoningEffort>,
    /// Optional cap on the estimated context tokens; disabled when unset.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=8_388_608))]
    pub max_source_tokens: Option<u32>,
    /// Total attempts for transient LLM transport failures (1 disables retries).
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..=8))]
    pub max_attempts: u32,
    /// Base delay for exponential retry backoff.
    #[arg(long, default_value_t = 500, value_parser = clap::value_parser!(u64).range(0..=60_000))]
    pub retry_base_ms: u64,
    /// Ceiling for retry backoff and server `Retry-After` hints.
    #[arg(long, default_value_t = 8_000, value_parser = clap::value_parser!(u64).range(0..=600_000))]
    pub retry_max_ms: u64,
    /// Maximum tool executions across the audit (a batch counts each call).
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub max_tool_calls: u32,
    /// Hard byte cap on the serialized model request, including tool history.
    #[arg(long, default_value_t = 2_097_152, value_parser = clap::value_parser!(u32).range(4096..=16_777_216))]
    pub max_context_bytes: u32,
    /// Archive old tool outputs under pressure, or retain history and fail at the cap.
    #[arg(long, value_enum, default_value_t = crate::context::history::ContextPolicy::Prune)]
    pub context_policy: crate::context::history::ContextPolicy,
    /// Complete recent tool turns protected from context pruning.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=32))]
    pub context_keep_turns: u32,
    /// Maximum JSON bytes per model-visible tool result, including truncation metadata.
    #[arg(long, default_value_t = 32768, value_parser = clap::value_parser!(u32).range(1024..=131072))]
    pub max_tool_output_bytes: u32,
    /// Bounded retries when the final report fails JSON or evidence validation.
    /// `0` restores fail-fast behavior; repairs never fabricate a report.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(0..=8))]
    pub max_output_repairs: u32,
    /// Confirm an unobserved cited source line during a bounded final repair.
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    pub citation_confirmation: bool,
    /// Read-only tool executions allowed after the main tool budget is spent,
    /// so a run can still verify a cited line before its final report.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(0..=8))]
    pub max_settlement_calls: u32,
    /// Extra provider request headers, `NAME: VALUE`; repeatable. Intended for
    /// gateway routing, tenant, or tracing headers. The harness's own auth and
    /// `Accept` headers are added after these, so they are not replaced here.
    #[arg(long = "header", value_name = "NAME:VALUE", value_parser = header_arg)]
    pub header: Vec<String>,
}

impl LlmOptions {
    /// Enforce source bounds even for callers supplying an assembled context.
    /// Raw source tokens keep their existing meaning; prompt overhead is
    /// reported separately by `prompt::AuditPrompt::estimated_tokens`.
    pub fn validate_context(&self, context: &Context) -> Result<()> {
        ensure!(
            context.files() <= context::MAX_FILES,
            "audit context must contain at most {} source files",
            context::MAX_FILES
        );
        let bytes = context.sources.iter().try_fold(0usize, |bytes, source| {
            bytes
                .checked_add(source.content.len())
                .context("source byte count overflow")
        })?;
        ensure!(
            bytes <= self.max_source_bytes as usize,
            "source snapshot exceeds byte limit; narrow the target"
        );
        if let Some(max) = self.max_source_tokens {
            ensure!(
                context.estimated_tokens() <= max as usize,
                "estimated context of {} tokens exceeds the {max} token limit; narrow the target",
                context.estimated_tokens()
            );
        }
        Ok(())
    }

    /// The wire format actually used: Codex always speaks the Responses API.
    pub fn effective_wire(&self) -> WireApi {
        match self.auth {
            AuthKind::Codex => WireApi::Responses,
            AuthKind::ApiKey => self.wire_api,
        }
    }

    /// Validate configuration and, where cheap, credential availability.
    ///
    /// This never performs network I/O; token refresh happens later in the
    /// agent process so a stale token does not block argument construction.
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.model.trim().is_empty(), "model is empty");
        let _ = provider_headers(&self.header)?;
        match self.auth {
            AuthKind::ApiKey => {
                let endpoint = self
                    .endpoint
                    .as_deref()
                    .context("--endpoint is required with --auth api-key")?;
                let _ = parse_endpoint(endpoint)?;
                let key = std::env::var(&self.api_key_env).with_context(|| {
                    format!("missing API key environment variable {}", self.api_key_env)
                })?;
                ensure!(!key.trim().is_empty(), "API key is empty");
            }
            AuthKind::Codex => {
                match self.endpoint.as_deref() {
                    Some(endpoint) => {
                        let _ = parse_endpoint(endpoint)?;
                    }
                    None => {
                        let _ = parse_endpoint(&self.codex_base_url)?;
                    }
                }
                if let Some(file) = &self.codex_auth_file {
                    // The agent runs with the source root as its working
                    // directory, so a relative path would resolve differently
                    // in the parent and child processes.
                    ensure!(
                        file.is_absolute(),
                        "--codex-auth-file must be an absolute path"
                    );
                }
                let file = auth::auth_path(self.codex_auth_file.clone())?;
                ensure!(
                    file.is_file(),
                    "Codex auth file not found at {}; run `codex login` to sign in with ChatGPT",
                    file.display()
                );
            }
        }
        Ok(())
    }

    pub fn arguments(&self) -> Result<Vec<String>> {
        let mut args = vec![
            "agent".into(),
            "--model".into(),
            self.model.clone(),
            "--wire-api".into(),
            self.wire_api.as_str().into(),
            "--api-key-env".into(),
            self.api_key_env.clone(),
            "--auth".into(),
            self.auth.as_str().into(),
            "--codex-base-url".into(),
            self.codex_base_url.clone(),
            "--max-source-bytes".into(),
            self.max_source_bytes.to_string(),
            "--max-tokens".into(),
            self.max_tokens.to_string(),
            "--max-stream-bytes".into(),
            self.max_stream_bytes.to_string(),
            "--max-attempts".into(),
            self.max_attempts.to_string(),
            "--retry-base-ms".into(),
            self.retry_base_ms.to_string(),
            "--retry-max-ms".into(),
            self.retry_max_ms.to_string(),
            "--max-tool-calls".into(),
            self.max_tool_calls.to_string(),
            "--max-context-bytes".into(),
            self.max_context_bytes.to_string(),
            "--context-policy".into(),
            self.context_policy.as_str().into(),
            "--context-keep-turns".into(),
            self.context_keep_turns.to_string(),
            "--max-tool-output-bytes".into(),
            self.max_tool_output_bytes.to_string(),
            "--max-output-repairs".into(),
            self.max_output_repairs.to_string(),
            "--max-settlement-calls".into(),
            self.max_settlement_calls.to_string(),
        ];
        if !self.citation_confirmation {
            args.extend(["--citation-confirmation".into(), "false".into()]);
        }
        if let Some(tokens) = self.max_source_tokens {
            args.extend(["--max-source-tokens".into(), tokens.to_string()]);
        }
        if let Some(effort) = self.reasoning_effort {
            args.extend(["--reasoning-effort".into(), effort.as_str().into()]);
        }
        if let Some(endpoint) = &self.endpoint {
            args.extend(["--endpoint".into(), endpoint.clone()]);
        }
        if let Some(file) = &self.codex_auth_file {
            args.extend(["--codex-auth-file".into(), file.display().to_string()]);
        }
        if let Some(path) = &self.monitoring.trace_dir {
            // Resolve before evaluation changes the child working directory.
            let absolute = std::path::absolute(path).context("resolve trace directory")?;
            args.extend(["--trace-dir".into(), absolute.display().to_string()]);
        }
        if self.monitoring.debug_trace {
            args.push("--debug-trace".into());
        }
        for header in &self.header {
            args.extend(["--header".into(), header.clone()]);
        }
        Ok(args)
    }
}

/// Validate an endpoint URL: no embedded credentials, query, or fragment.
fn parse_endpoint(endpoint: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(endpoint).context("invalid endpoint URL")?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "endpoint must not contain credentials, query, or fragment"
    );
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local),
        "endpoint requires HTTPS, except loopback HTTP for local models"
    );
    Ok(url)
}

/// Validate a `NAME: VALUE` header at CLI and configuration parse time.
fn header_arg(raw: &str) -> std::result::Result<String, String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| "header must be NAME: VALUE".to_string())?;
    reqwest::header::HeaderName::from_bytes(name.trim().as_bytes())
        .map_err(|error| format!("invalid header name: {error}"))?;
    reqwest::header::HeaderValue::from_str(value.trim())
        .map_err(|error| format!("invalid header value: {error}"))?;
    Ok(raw.to_string())
}

pub(super) fn provider_headers(raw: &[String]) -> Result<reqwest::header::HeaderMap> {
    let mut headers = reqwest::header::HeaderMap::new();
    for item in raw {
        let (name, value) = item
            .split_once(':')
            .with_context(|| format!("header must be NAME: VALUE, got {item:?}"))?;
        let name = reqwest::header::HeaderName::from_bytes(name.trim().as_bytes())
            .with_context(|| format!("invalid header name {name:?}"))?;
        let value = reqwest::header::HeaderValue::from_str(value.trim())
            .with_context(|| format!("invalid header value for {name}"))?;
        headers.append(name, value);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn evaluation_forwards_an_absolute_trace_path_and_debug_flag() {
        use clap::Parser;
        #[derive(Parser)]
        struct Options {
            #[command(flatten)]
            llm: LlmOptions,
        }
        let options = Options::parse_from([
            "test",
            "--model",
            "fixture",
            "--trace-dir",
            "relative-traces",
            "--debug-trace",
            "--context-policy",
            "fail",
            "--context-keep-turns",
            "5",
            "--max-tool-output-bytes",
            "2048",
        ]);
        let args = options.llm.arguments().unwrap();
        let path = args
            .windows(2)
            .find(|pair| pair[0] == "--trace-dir")
            .unwrap();
        assert_eq!(
            Path::new(&path[1]),
            std::path::absolute("relative-traces").unwrap()
        );
        assert!(args.iter().any(|arg| arg == "--debug-trace"));
        for (flag, value) in [
            ("--context-policy", "fail"),
            ("--context-keep-turns", "5"),
            ("--max-tool-output-bytes", "2048"),
        ] {
            assert!(args
                .windows(2)
                .any(|pair| pair[0] == flag && pair[1] == value));
        }
    }

    #[test]
    fn endpoint_validation_rejects_credentials_and_plain_http() {
        assert!(parse_endpoint("https://api.example.com/v1").is_ok());
        assert!(parse_endpoint("http://127.0.0.1:8080/v1").is_ok());
        assert!(parse_endpoint("http://api.example.com/v1").is_err());
        assert!(parse_endpoint("https://user:pass@api.example.com/v1").is_err());
        assert!(parse_endpoint("https://api.example.com/v1?x=1").is_err());
    }

    #[test]
    fn auth_kind_and_wire_spellings_match_clap() {
        assert_eq!(AuthKind::ApiKey.as_str(), "api-key");
        assert_eq!(AuthKind::Codex.as_str(), "codex");
        assert_eq!(WireApi::ChatCompletions.as_str(), "chat-completions");
        assert_eq!(WireApi::Responses.as_str(), "responses");
        assert_eq!(WireApi::Anthropic.as_str(), "anthropic");
    }
}
