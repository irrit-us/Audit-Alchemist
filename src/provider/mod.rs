//! Model adapters for mainstream LLM API shapes.
//!
//! The adapter runs a bounded tool loop for the selected [`wire::WireApi`], streams each
//! response, normalizes deltas into [`StreamEvent`]s for the console/TUI
//! sink, and returns the same versioned JSON findings as before. Credentials
//! are resolved through [`auth`] and are never logged or written to reports.
//!
//! Supported wires: OpenAI-compatible chat completions, the OpenAI Responses
//! API (also used by the Codex backend), and the Anthropic Messages API.

pub mod auth;
pub mod conversation;
pub mod events;
mod options;
pub mod prompt;
pub mod retry;
mod session;
pub mod sse;
mod transport;
pub mod wire;

use crate::{
    context::{self, Context, ContextBudget},
    protocol::{Request, Response},
};
use anyhow::{ensure, Result};
use std::{
    path::Path,
    time::{Duration, Instant},
};

use self::events::{EventSink, StreamEvent};

pub use crate::context::{snapshot, Source};
pub use options::{AuthKind, LlmOptions, ReasoningEffort};
pub use prompt::SYSTEM_PROMPT;
pub(crate) use transport::session_id;

/// Stable, non-cryptographic fingerprint for run-manifest identity. It records
/// that a prompt or instruction changed without storing the text itself.
fn fingerprint(bytes: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Audit one case, building context from `root`. Used by the `agent` adapter.
pub async fn audit(
    options: &LlmOptions,
    request: &Request,
    root: &Path,
    timeout: Duration,
) -> Result<Response> {
    options.validate()?;
    ensure!(
        !request.instruction.trim().is_empty() && request.instruction.len() <= 65_536,
        "invalid instruction"
    );
    let context = context::initial(
        root,
        &request.target,
        &ContextBudget::new(options.max_source_bytes as usize),
    )?;
    audit_with(options, request, &context, root, timeout, &mut ()).await
}

/// Audit one case using an already-assembled context, streaming to `sink`.
pub async fn audit_with(
    options: &LlmOptions,
    request: &Request,
    context: &Context,
    root: &Path,
    timeout: Duration,
    sink: &mut dyn EventSink,
) -> Result<Response> {
    let mut monitor =
        crate::monitor::Monitor::new(&options.monitoring, &options.api_key_env, sink)?;
    let manifest = crate::monitor::RunManifest {
        harness_version: env!("CARGO_PKG_VERSION").into(),
        system_prompt_sha256: fingerprint(options.settings.system_prompt().as_bytes()),
        instruction_sha256: fingerprint(request.instruction.as_bytes()),
        tools: options
            .settings
            .definitions()
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect(),
        max_tool_calls: options.max_tool_calls,
        max_tokens: options.max_tokens,
        max_context_bytes: options.max_context_bytes,
        context_policy: options.context_policy.as_str().into(),
        max_output_repairs: options.max_output_repairs,
        citation_confirmation: options.citation_confirmation,
        max_settlement_calls: options.max_settlement_calls,
    };
    monitor.start_with_manifest(
        &options.model,
        options.effective_wire().as_str(),
        timeout.as_millis() as u64,
        &request.case_id,
        &request.target,
        &manifest,
    );
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut queue = crate::monitor::QueueSink(sender);
    let began = Instant::now();
    let mut result = {
        let session = session::audit_session(options, request, context, root, timeout, &mut queue);
        tokio::pin!(session);
        let timer = tokio::time::sleep(timeout);
        tokio::pin!(timer);
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(5),
            Duration::from_secs(5),
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                result = &mut session => break result,
                _ = &mut timer => break Err(anyhow::Error::new(AuditTimeout)),
                Some(event) = receiver.recv() => monitor.on_event(&event),
                _ = heartbeat.tick() => monitor.heartbeat(),
            }
        }
    };
    if began.elapsed() >= timeout {
        result = Err(AuditTimeout.into());
    }
    while let Ok(event) = receiver.try_recv() {
        monitor.on_event(&event);
    }
    let outcome = match &result {
        Ok(_) => "success",
        Err(error) if error.is::<AuditTimeout>() => "timeout",
        Err(_) => "error",
    };
    if let Err(error) = &result {
        debug_capture(options, &mut monitor, "error", || format!("{error:#}"));
    }
    monitor.finish(outcome)?;
    result
}

#[derive(Debug)]
pub struct AuditTimeout;
impl std::fmt::Display for AuditTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("audit exceeded wall-clock deadline")
    }
}
impl std::error::Error for AuditTimeout {}

fn debug_capture(
    options: &LlmOptions,
    sink: &mut dyn EventSink,
    stage: &str,
    content: impl FnOnce() -> String,
) {
    if options.monitoring.debug_trace {
        let key = std::env::var(&options.api_key_env)
            .ok()
            .filter(|s| !s.is_empty());
        sink.on_event(&StreamEvent::Debug {
            stage: stage.into(),
            content: crate::monitor::debug_payload(&content(), key.as_deref()),
        });
    }
}
