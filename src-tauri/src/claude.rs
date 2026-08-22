//! Claude integration: API-key storage and streaming calls to the Messages API.
//!
//! Auth is an API key held in the OS keychain (or an `ANTHROPIC_API_KEY` env
//! var). Browser/OAuth sign-in via the `ant` CLI was deliberately dropped: it
//! only completes for an account an organization already admits, so it
//! dead-ends while a join request awaits admin approval — and a key needs no
//! org membership and no CLI at all.
//!
//! There is no official Anthropic Rust SDK, so the API is called over raw HTTP.

use crate::models::ClaudeAuthState;
use keyring::v1::Entry;

/// Keychain coordinates for the API key. Deliberately the OS keychain rather
/// than localStorage (plaintext inside the WebView) or a file this app owns —
/// the key is then protected by the OS, and other apps can't read it.
const KEYCHAIN_SERVICE: &str = "io.github.aavishay.aks-fleet-dashboard";
const KEYCHAIN_ACCOUNT: &str = "anthropic-api-key";

fn keychain_entry() -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).map_err(|e| format!("Keychain unavailable: {e}"))
}

/// Stores a pasted key. Trimmed because pasting from a browser or password
/// manager very often carries a trailing newline, which would otherwise travel
/// in the `x-api-key` header and fail authentication for a non-obvious reason.
pub fn set_api_key(key: &str) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("The API key is empty.".to_string());
    }
    keychain_entry()?
        .set_password(key)
        .map_err(|e| format!("Could not save to the Keychain: {e}"))
}

pub fn clear_api_key() -> Result<(), String> {
    match keychain_entry()?.delete_credential() {
        Ok(()) => Ok(()),
        // Nothing stored is the desired end state, not a failure.
        Err(keyring::v1::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Could not remove the key from the Keychain: {e}")),
    }
}

fn keychain_api_key() -> Option<String> {
    let key = keychain_entry().ok()?.get_password().ok()?;
    let key = key.trim().to_string();
    (!key.is_empty()).then_some(key)
}

/// Last four characters, for confirming *which* key is stored without
/// displaying it.
fn key_hint(key: &str) -> String {
    let tail: String = key.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{tail}")
}

/// An env var wins over the keychain, matching the SDKs' own precedence and
/// letting CI or a power user override without touching the UI.
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

pub fn auth_status() -> ClaudeAuthState {
    if env_api_key().is_some() {
        return ClaudeAuthState {
            signed_in: true,
            source: Some("environment variable".to_string()),
            detail: Some("Using ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN from the environment.".to_string()),
        };
    }
    match keychain_api_key() {
        Some(key) => ClaudeAuthState {
            signed_in: true,
            source: Some("API key (Keychain)".to_string()),
            detail: Some(format!("Using the API key stored in your Keychain ({}).", key_hint(&key))),
        },
        None => ClaudeAuthState {
            signed_in: false,
            source: None,
            detail: None,
        },
    }
}

fn resolve_api_key() -> Result<String, String> {
    env_api_key()
        .or_else(keychain_api_key)
        .ok_or_else(|| "No Claude API key configured. Paste one in the Claude panel (✦).".to_string())
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
    let api_key = resolve_api_key()?;

    let request = reqwest::Client::new()
        .post(API_URL)
        .header("anthropic-version", API_VERSION)
        .header("content-type", "application/json")
        .header("x-api-key", api_key)
        .header("anthropic-beta", FALLBACK_BETA);

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

    #[test]
    fn key_hint_shows_only_the_tail() {
        assert_eq!(key_hint("sk-ant-api03-abcdefgh"), "…efgh");
        // Must not leak more than the tail even for a very short value.
        assert_eq!(key_hint("ab"), "…ab");
        assert_eq!(key_hint(""), "…");
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
