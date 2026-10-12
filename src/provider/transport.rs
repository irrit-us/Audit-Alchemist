//! Credentialed HTTP requests, retry policy, and streamed turn decoding.

use super::{
    auth,
    conversation::{Turn, TurnDecoder},
    events::EventSink,
    options::{provider_headers, AuthKind, LlmOptions},
    retry,
    sse::SseLines,
    wire::WireApi,
};
use anyhow::{ensure, Context as _, Result};
use serde_json::Value;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(super) fn client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build HTTP client")
}

fn retry_policy(options: &LlmOptions) -> retry::RetryPolicy {
    retry::RetryPolicy::from_millis(
        options.max_attempts,
        options.retry_base_ms,
        options.retry_max_ms,
    )
}

pub(super) fn remaining(deadline: Instant) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1))
}

fn has_time(deadline: Instant, wait: Duration) -> bool {
    Instant::now()
        .checked_add(wait)
        .is_some_and(|wake| wake < deadline)
}

fn retryable_transport(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(retry::parse_retry_after)
}

/// Send a request, retrying only transient transport failures within `deadline`.
///
/// Any HTTP response is returned as-is so the caller can inspect the status
/// (for example to re-authenticate on 401); only connection, TLS, and timeout
/// errors become `Err`. Retries stop before the overall deadline rather than
/// sleeping past it, and a final attempt always returns its result unchanged.
async fn send_retrying(
    policy: retry::RetryPolicy,
    deadline: Instant,
    sink: &mut dyn EventSink,
    mut build: impl FnMut() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    let mut attempt = 0u32;
    loop {
        let final_attempt = !policy.allows_retry(attempt);
        match build().send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                sink.on_event(&crate::monitor::operation(
                    "http_response",
                    serde_json::json!({"attempt":attempt+1,"status":status}),
                ));
                if final_attempt || !retry::retryable_status(status) {
                    return Ok(response);
                }
                let wait = retry::backoff(
                    &policy,
                    attempt,
                    retry_after(response.headers()),
                    retry::seed(),
                );
                if !has_time(deadline, wait) {
                    return Ok(response);
                }
                tracing::warn!(
                    attempt = attempt + 1,
                    status,
                    delay_ms = wait.as_millis() as u64,
                    "retrying transient LLM API response"
                );
                sink.on_event(&crate::monitor::operation("retry", serde_json::json!({
                    "attempt":attempt + 1,"next_attempt":attempt + 2,"delay_ms":wait.as_millis() as u64,
                    "reason":"transient_http","status":status
                })));
                tokio::time::sleep(wait).await;
                attempt += 1;
            }
            Err(error) => {
                if final_attempt || !retryable_transport(&error) {
                    return Err(error)
                        .context("LLM API request failed (connection, TLS, or deadline)");
                }
                let wait = retry::backoff(&policy, attempt, None, retry::seed());
                if !has_time(deadline, wait) {
                    return Err(error)
                        .context("LLM API request failed (connection, TLS, or deadline)");
                }
                tracing::warn!(
                    attempt = attempt + 1,
                    delay_ms = wait.as_millis() as u64,
                    "retrying LLM API connection failure"
                );
                sink.on_event(&crate::monitor::operation("retry", serde_json::json!({
                    "attempt":attempt + 1,"next_attempt":attempt + 2,"delay_ms":wait.as_millis() as u64,
                    "reason":"transport"
                })));
                tokio::time::sleep(wait).await;
                attempt += 1;
            }
        }
    }
}

/// Send one streaming request and return the accumulated answer text.
pub(super) async fn complete(
    options: &LlmOptions,
    client: &reqwest::Client,
    body: &Value,
    deadline: Instant,
    sink: &mut dyn EventSink,
) -> Result<Turn> {
    let wire = options.effective_wire();
    let policy = retry_policy(options);
    let headers = provider_headers(&options.header)?;

    let turn = match options.auth {
        AuthKind::ApiKey => {
            let url = options
                .endpoint
                .as_deref()
                .context("--endpoint is required with --auth api-key")?;
            let key = std::env::var(&options.api_key_env)?;
            let response = send_retrying(policy, deadline, sink, || {
                api_key_request(client, wire, url, &key, body, deadline, &headers)
            })
            .await?;
            ensure!(
                response.status().is_success(),
                "LLM API returned HTTP {}",
                response.status().as_u16()
            );
            read_stream(response, wire, sink, options.max_stream_bytes as usize).await?
        }
        AuthKind::Codex => {
            let url = options.endpoint.clone().unwrap_or_else(|| {
                format!("{}/responses", options.codex_base_url.trim_end_matches('/'))
            });
            let mode = auth::AuthMode::Codex {
                auth_file: options.codex_auth_file.clone(),
            };
            let credentials = auth::resolve(&mode).await?;
            let response = send_retrying(policy, deadline, sink, || {
                codex_request(client, &url, &credentials, body, deadline, &headers)
            })
            .await?;
            let response = if response.status().as_u16() == 401 {
                // The token can expire between our proactive check and the
                // request; refresh once and retry a single time. This is
                // authentication recovery, not a retry of a failed model call.
                let fresh = auth::resolve_fresh(&mode).await?;
                send_retrying(policy, deadline, sink, || {
                    codex_request(client, &url, &fresh, body, deadline, &headers)
                })
                .await?
            } else {
                response
            };
            ensure!(
                response.status().is_success(),
                "Codex responses returned HTTP {}",
                response.status().as_u16()
            );
            read_stream(
                response,
                WireApi::Responses,
                sink,
                options.max_stream_bytes as usize,
            )
            .await?
        }
    };

    let usage = turn.usage;
    if !usage.is_empty() {
        tracing::info!(
            prompt_tokens = usage.prompt_tokens,
            completion_tokens = usage.completion_tokens,
            total_tokens = usage.total_tokens,
            reasoning_tokens = usage.reasoning_tokens,
            "model usage"
        );
    }
    Ok(turn)
}

fn api_key_request(
    client: &reqwest::Client,
    wire: WireApi,
    url: &str,
    key: &str,
    body: &Value,
    deadline: Instant,
    headers: &reqwest::header::HeaderMap,
) -> reqwest::RequestBuilder {
    let request = client
        .post(url)
        .timeout(remaining(deadline))
        .headers(headers.clone())
        .header("Accept", "text/event-stream");
    let request = match wire {
        WireApi::Anthropic => request
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01"),
        WireApi::ChatCompletions | WireApi::Responses => request.bearer_auth(key),
    };
    request.json(body)
}

fn codex_request(
    client: &reqwest::Client,
    url: &str,
    credentials: &auth::Credentials,
    body: &Value,
    deadline: Instant,
    headers: &reqwest::header::HeaderMap,
) -> reqwest::RequestBuilder {
    let mut request = client
        .post(url)
        .timeout(remaining(deadline))
        .headers(headers.clone())
        .header("Accept", "text/event-stream")
        .header("OpenAI-Beta", "responses=experimental")
        .header("originator", "codex_cli_rs")
        .header("session_id", session_id())
        .bearer_auth(&credentials.bearer)
        .json(body);
    if let Some(account_id) = &credentials.account_id {
        request = request.header("chatgpt-account-id", account_id);
    }
    request
}

/// Read a streaming response, emitting normalized events into `sink`.
async fn read_stream(
    mut response: reqwest::Response,
    wire: WireApi,
    sink: &mut dyn EventSink,
    max_bytes: usize,
) -> Result<Turn> {
    let mut lines = SseLines::new();
    let mut stream = TurnDecoder::new(wire);
    let mut total = 0usize;
    let started = Instant::now();
    while let Some(chunk) = response.chunk().await.context("read model stream")? {
        if total == 0 && !chunk.is_empty() {
            sink.on_event(&crate::monitor::operation(
                "stream_start",
                serde_json::json!({"after_headers_ms":started.elapsed().as_millis() as u64}),
            ));
        }
        total += chunk.len();
        ensure!(total <= max_bytes, "model stream exceeds {max_bytes} bytes");
        for data in lines.push(&chunk)? {
            stream.handle_data(&data, sink)?;
        }
    }
    for data in lines.finish()? {
        stream.handle_data(&data, sink)?;
    }
    sink.on_event(&crate::monitor::operation(
        "stream_end",
        serde_json::json!({"bytes":total,"elapsed_ms":started.elapsed().as_millis() as u64}),
    ));
    stream.finish()
}

/// A best-effort unique identifier for the `session_id` header.
pub(crate) fn session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:032x}{:08x}{:08x}", nanos, std::process::id(), counter)
}
