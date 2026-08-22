//! Claude integration: credential resolution via the `ant` CLI, and streaming
//! calls to the Messages API.
//!
//! Auth deliberately defers to `ant auth login` rather than collecting a key
//! in-app, mirroring how this app already defers cluster auth to
//! `kubelogin`/`az` instead of implementing Azure AD itself. The browser-based
//! OAuth flow means the app never handles the user's credential, and the
//! README's "stores no credentials of its own" stays true.
//!
//! There is no official Anthropic Rust SDK, so the API is called over raw HTTP.

use crate::models::{ClaudeAuthState, ClaudeCredential};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// `ant auth login` waits on a human completing a browser flow, so it needs a
/// far longer ceiling than a cluster call. Still bounded, so a user who
/// abandons the browser tab doesn't leave the command pending forever.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
/// Status/credential lookups are local and should be near-instant.
const CLI_TIMEOUT: Duration = Duration::from_secs(15);

async fn run_ant(args: &[&str], timeout: Duration) -> Result<std::process::Output, String> {
    let mut cmd = Command::new("ant");
    cmd.args(args).stdin(Stdio::null());
    match tokio::time::timeout(timeout, cmd.output()).await {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("The `ant` CLI is not installed or not on PATH.".to_string())
        }
        Ok(Err(e)) => Err(format!("Failed to run `ant {}`: {e}", args.join(" "))),
        Err(_) => Err(format!(
            "`ant {}` did not finish within {}s.",
            args.join(" "),
            timeout.as_secs()
        )),
    }
}

fn ant_is_installed() -> bool {
    // `Command::new("ant")` failing with NotFound is the authoritative signal,
    // but checking PATH up front lets `auth_status` distinguish "not installed"
    // from "installed but not signed in" without running anything.
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path).any(|dir| {
                let candidate = dir.join("ant");
                candidate.is_file()
            })
        })
        .unwrap_or(false)
}

/// An env-var key short-circuits the CLI entirely, so CI and power users can
/// bypass `ant` — matching the SDKs' own precedence, where `ANTHROPIC_API_KEY`
/// outranks a stored profile.
fn env_api_key() -> Option<String> {
    for var in ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"] {
        if let Ok(value) = std::env::var(var) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

pub async fn auth_status() -> ClaudeAuthState {
    if env_api_key().is_some() {
        return ClaudeAuthState {
            cli_installed: ant_is_installed(),
            signed_in: true,
            source: Some("environment variable".to_string()),
            detail: Some("Using ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN from the environment.".to_string()),
        };
    }

    if !ant_is_installed() {
        return ClaudeAuthState {
            cli_installed: false,
            signed_in: false,
            source: None,
            detail: Some("Install the Anthropic CLI, then sign in.".to_string()),
        };
    }

    // Whether a credential can actually be *obtained* is the only sound
    // signal. `ant auth status` reports status for humans and is explicitly
    // documented as unsuitable as a health check — keying off its exit code
    // risks showing "connected" while every API call 401s.
    let signed_in = match run_ant(&["auth", "print-credentials", "--access-token"], CLI_TIMEOUT).await {
        Ok(out) => out.status.success() && !String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        Err(_) => false,
    };

    // Its human-readable output is still the best thing to show: it names the
    // winning credential source, profile and workspace. Best-effort only.
    let detail = match run_ant(&["auth", "status"], CLI_TIMEOUT).await {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let text = if text.is_empty() {
                String::from_utf8_lossy(&out.stderr).trim().to_string()
            } else {
                text
            };
            (!text.is_empty()).then_some(text)
        }
        Err(e) => Some(e),
    };

    ClaudeAuthState {
        cli_installed: true,
        signed_in,
        source: signed_in.then(|| "ant CLI profile".to_string()),
        detail: detail.or_else(|| {
            (!signed_in).then(|| "Not signed in. Run sign-in to open a browser.".to_string())
        }),
    }
}

/// Runs `ant auth login`, which opens the user's browser. The app never sees
/// the credential — only whether the flow succeeded.
pub async fn sign_in() -> Result<ClaudeAuthState, String> {
    if !ant_is_installed() {
        return Err("The `ant` CLI is not installed. Install it, then sign in.".to_string());
    }
    let out = run_ant(&["auth", "login"], SIGN_IN_TIMEOUT).await?;
    let state = auth_status().await;
    // Trust the resulting credential over the exit code: a cancelled browser
    // flow can still exit cleanly, and a successful one is only meaningful if
    // a token actually landed.
    if !state.signed_in {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            "Sign-in did not complete — no credential was stored.".to_string()
        } else {
            stderr
        });
    }
    Ok(state)
}

pub async fn sign_out() -> Result<ClaudeAuthState, String> {
    if ant_is_installed() {
        // Failure here is non-fatal: there may simply have been nothing to log
        // out of, and reporting the resulting state is more useful than an error.
        let _ = run_ant(&["auth", "logout"], CLI_TIMEOUT).await;
    }
    Ok(auth_status().await)
}

/// Resolves whatever credential is available into the header form the Messages
/// API expects. An API key goes on `x-api-key`; an OAuth access token goes on
/// `Authorization: Bearer` and additionally requires the `oauth-2025-04-20`
/// beta header — converting between the two is a header change, not just a
/// value swap, which is why the distinction is modelled rather than flattened
/// into a single string.
pub async fn resolve_credential() -> Result<ClaudeCredential, String> {
    if let Some(key) = env_api_key() {
        return Ok(ClaudeCredential::ApiKey(key));
    }
    if !ant_is_installed() {
        return Err("Not signed in to Claude, and the `ant` CLI is not installed.".to_string());
    }
    let out = run_ant(&["auth", "print-credentials", "--access-token"], CLI_TIMEOUT).await?;
    if !out.status.success() {
        return Err("Not signed in to Claude. Sign in from the Claude panel first.".to_string());
    }
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if token.is_empty() {
        return Err("The `ant` CLI returned an empty access token.".to_string());
    }
    Ok(ClaudeCredential::OAuth(token))
}

// ---------------------------------------------------------------------------
// Messages API (streaming)
// ---------------------------------------------------------------------------

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";
const MODEL: &str = "claude-opus-5";

/// Opt into server-side refusal fallbacks. Infrastructure debugging brushes
/// against the `cyber` refusal category more than most workloads, so a decline
/// here is a realistic outcome; with fallbacks the API re-runs the request on
/// another model inside the same call instead of just stopping.
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
/// Required alongside `Authorization: Bearer` when the credential came from an
/// `ant auth login` profile rather than an API key.
const OAUTH_BETA: &str = "oauth-2025-04-20";

/// Generous for an explanation that should run a few paragraphs, while staying
/// far from the point where a truncated answer is likely. Streaming means the
/// large ceiling costs nothing in timeout risk.
const EXPLAIN_MAX_TOKENS: u32 = 16_000;

/// The whole request is one short string in, prose out — `medium` keeps it
/// quick without the terseness `low` brings to a diagnostic explanation.
/// Raise to `high` if explanations start missing root causes.
const EXPLAIN_EFFORT: &str = "medium";

const EXPLAIN_SYSTEM: &str = "\
You explain Kubernetes, Helm, and ArgoCD error messages to an experienced SRE.

Given one error message, respond with:
1. What the error actually means, in plain language.
2. The most likely cause, and why.
3. Concrete next steps — the specific file, field, or command to check.

Be direct and concise; assume fluency with kubectl and Helm. Do not restate the \
error back. If the message is too ambiguous to diagnose confidently, say what \
additional information would settle it rather than guessing.";

/// Streams an explanation of a single error message, emitting text deltas on
/// `on_token` as they arrive.
///
/// Only the error string leaves the machine — no logs, manifests, or cluster
/// identifiers — which is what makes this the lowest-exposure Claude feature
/// in the app.
pub async fn explain_error(error_text: &str, on_token: tauri::ipc::Channel<String>) -> Result<(), String> {
    let credential = resolve_credential().await?;

    let mut betas = vec![FALLBACK_BETA];
    let mut request = reqwest::Client::new()
        .post(API_URL)
        .header("anthropic-version", API_VERSION)
        .header("content-type", "application/json");

    request = match &credential {
        ClaudeCredential::ApiKey(key) => request.header("x-api-key", key),
        ClaudeCredential::OAuth(token) => {
            // OAuth tokens ride on Authorization, not x-api-key, and need
            // their own beta flag — the two credential shapes are not
            // interchangeable at the header level.
            betas.push(OAUTH_BETA);
            request.header("authorization", format!("Bearer {token}"))
        }
    };
    request = request.header("anthropic-beta", betas.join(","));

    let body = serde_json::json!({
        "model": MODEL,
        "max_tokens": EXPLAIN_MAX_TOKENS,
        "stream": true,
        // Adaptive is the only thinking mode on Opus 5; `budget_tokens` was
        // removed and would be rejected with a 400.
        "thinking": { "type": "adaptive" },
        "output_config": { "effort": EXPLAIN_EFFORT },
        "fallbacks": "default",
        "system": EXPLAIN_SYSTEM,
        "messages": [{ "role": "user", "content": error_text }],
    });

    let response = request
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Could not reach the Claude API: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        // Surface the API's own error message — it names the offending
        // parameter, which a generic status line would hide.
        let detail = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.pointer("/error/message").and_then(|m| m.as_str()).map(str::to_string))
            .unwrap_or_else(|| text.chars().take(400).collect());
        return Err(match status.as_u16() {
            401 | 403 => format!("Claude rejected the credential ({status}). Try signing in again. {detail}"),
            429 => format!("Rate limited by the Claude API. {detail}"),
            _ => format!("Claude API error {status}: {detail}"),
        });
    }

    stream_sse(response, on_token).await
}

/// What one `data:` payload means to the caller.
#[derive(Debug, PartialEq)]
enum SseEvent {
    Text(String),
    Done,
    Failed(String),
    /// Framing or metadata the caller doesn't act on (message_start, ping,
    /// thinking deltas, unparseable payloads).
    Ignored,
}

/// Classifies a single SSE `data:` payload. Split out from `stream_sse` so the
/// event handling is testable without a live HTTP response.
fn classify_sse_event(payload: &str) -> SseEvent {
    let Ok(event) = serde_json::from_str::<serde_json::Value>(payload) else {
        return SseEvent::Ignored;
    };
    match event.get("type").and_then(|t| t.as_str()) {
        Some("content_block_delta") => {
            // Thinking deltas arrive on this same event type; only text is
            // forwarded. Thinking display defaults to omitted on Opus 5 so
            // those carry no text anyway, but branching on the delta type
            // keeps this correct if display is ever turned on.
            if event.pointer("/delta/type").and_then(|t| t.as_str()) == Some("text_delta") {
                if let Some(text) = event.pointer("/delta/text").and_then(|t| t.as_str()) {
                    return SseEvent::Text(text.to_string());
                }
            }
            SseEvent::Ignored
        }
        Some("message_delta") => {
            if event.pointer("/delta/stop_reason").and_then(|s| s.as_str()) == Some("refusal") {
                let category = event
                    .pointer("/delta/stop_details/category")
                    .and_then(|c| c.as_str())
                    .unwrap_or("unspecified");
                return SseEvent::Failed(format!(
                    "Claude declined to answer this one (category: {category}). Asking about the \
                     underlying Kubernetes behaviour rather than the raw message usually works."
                ));
            }
            SseEvent::Ignored
        }
        Some("error") => SseEvent::Failed(format!(
            "Claude stream error: {}",
            event
                .pointer("/error/message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown streaming error")
        )),
        Some("message_stop") => SseEvent::Done,
        _ => SseEvent::Ignored,
    }
}

/// Consumes an SSE body, forwarding text deltas to `on_token`.
///
/// Hand-rolled rather than pulling an SSE crate: the only stream this parses is
/// Anthropic's, and the framing needed is a small, stable subset (`data:` lines
/// terminated by a blank line). Chunk boundaries fall anywhere, so lines are
/// reassembled from a running buffer rather than parsed per-chunk.
async fn stream_sse(response: reqwest::Response, on_token: tauri::ipc::Channel<String>) -> Result<(), String> {
    use futures_util::StreamExt;

    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Claude stream interrupted: {e}"))?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        // Process only complete lines; whatever trails stays buffered.
        while let Some(newline) = buffer.find('\n') {
            let line = buffer[..newline].trim_end_matches('\r').to_string();
            buffer.drain(..=newline);

            let Some(payload) = line.strip_prefix("data:") else { continue };
            let payload = payload.trim();
            if payload.is_empty() {
                continue;
            }
            match classify_sse_event(payload) {
                SseEvent::Text(text) => {
                    if on_token.send(text).is_err() {
                        return Ok(()); // receiver went away (panel closed)
                    }
                }
                SseEvent::Done => return Ok(()),
                SseEvent::Failed(message) => return Err(message),
                SseEvent::Ignored => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both cases live in one test on purpose: env vars are process-global and
    /// Rust runs tests in parallel threads, so two separate tests mutating
    /// `ANTHROPIC_API_KEY` race and read each other's values.
    #[test]
    fn env_api_key_distinguishes_blank_from_real_values() {
        // Blank or whitespace-only is not a credential — treating it as one
        // would send an empty `x-api-key` and fail confusingly at the API
        // instead of prompting a sign-in.
        temp_env_var("ANTHROPIC_API_KEY", Some("   "), || assert_eq!(env_api_key(), None));
        temp_env_var("ANTHROPIC_API_KEY", Some(""), || assert_eq!(env_api_key(), None));
        temp_env_var("ANTHROPIC_API_KEY", None, || assert_eq!(env_api_key(), None));

        // A real value comes back trimmed.
        temp_env_var("ANTHROPIC_API_KEY", Some("  sk-test-123  "), || {
            assert_eq!(env_api_key().as_deref(), Some("sk-test-123"));
        });
    }

    /// Payload shapes taken from the Messages API streaming format.
    #[test]
    fn sse_classifier_forwards_only_text_deltas() {
        assert_eq!(
            classify_sse_event(r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#),
            SseEvent::Text("Hello".to_string())
        );
        // Thinking deltas must not reach the panel as answer text.
        assert_eq!(
            classify_sse_event(r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}"#),
            SseEvent::Ignored
        );
    }

    #[test]
    fn sse_classifier_recognises_completion_and_framing() {
        assert_eq!(classify_sse_event(r#"{"type":"message_stop"}"#), SseEvent::Done);
        for framing in [
            r#"{"type":"message_start","message":{"id":"msg_1"}}"#,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            r#"{"type":"ping"}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#,
        ] {
            assert_eq!(classify_sse_event(framing), SseEvent::Ignored, "framing: {framing}");
        }
    }

    #[test]
    fn sse_classifier_surfaces_errors_and_refusals() {
        let err = classify_sse_event(r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#);
        assert!(matches!(&err, SseEvent::Failed(m) if m.contains("Overloaded")), "got {err:?}");

        let refusal = classify_sse_event(
            r#"{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber"}}}"#,
        );
        assert!(matches!(&refusal, SseEvent::Failed(m) if m.contains("cyber")), "got {refusal:?}");
    }

    /// Malformed or truncated payloads must be skipped, not crash the stream —
    /// a partial chunk can produce an incomplete JSON line.
    #[test]
    fn sse_classifier_ignores_unparseable_payloads() {
        for junk in ["", "not json", r#"{"type":"#, "[]"] {
            assert_eq!(classify_sse_event(junk), SseEvent::Ignored, "junk: {junk:?}");
        }
    }

    /// Sets one env var for the duration of the closure, restoring it after, so
    /// these tests don't leak state into each other or the rest of the suite.
    fn temp_env_var(key: &str, value: Option<&str>, f: impl FnOnce()) {
        let previous = std::env::var(key).ok();
        // Both auth vars must be cleared, since `env_api_key` checks them in
        // order and an ambient ANTHROPIC_AUTH_TOKEN would mask the assertion.
        let previous_token = std::env::var("ANTHROPIC_AUTH_TOKEN").ok();
        std::env::remove_var("ANTHROPIC_AUTH_TOKEN");
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match previous {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        if let Some(v) = previous_token {
            std::env::set_var("ANTHROPIC_AUTH_TOKEN", v);
        }
    }
}
