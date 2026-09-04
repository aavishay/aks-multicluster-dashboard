//! Which model answers, where its credentials live, and how its stream is read.
//!
//! Three providers with three wire formats. What they share is the shape of a
//! request — a system prompt, one user turn, a token ceiling, a stream of text
//! deltas — so that shape is the seam, and each provider supplies only the
//! parts that genuinely differ: the URL, the auth header, the request body,
//! and how one chunk of its stream turns into text.
//!
//! There is no official Rust SDK for any of them, so all three are called over
//! raw HTTP.

use keyring::v1::Entry;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Claude,
    Gemini,
    Ollama,
}

impl Provider {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "claude" => Ok(Provider::Claude),
            "gemini" => Ok(Provider::Gemini),
            "ollama" => Ok(Provider::Ollama),
            other => Err(format!("Unknown AI provider '{other}'")),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Provider::Claude => "Claude",
            Provider::Gemini => "Gemini",
            Provider::Ollama => "Ollama",
        }
    }

    /// Keychain account for this provider's key. Ollama has none — it is a
    /// local server, and inventing a credential for it would only add a step.
    fn keychain_account(self) -> Option<&'static str> {
        match self {
            Provider::Claude => Some("anthropic-api-key"),
            Provider::Gemini => Some("gemini-api-key"),
            Provider::Ollama => None,
        }
    }

    /// Env vars that override the keychain, matching each vendor's own SDK
    /// precedence so CI or a power user can override without touching the UI.
    fn env_vars(self) -> &'static [&'static str] {
        match self {
            Provider::Claude => &["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
            Provider::Gemini => &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
            Provider::Ollama => &[],
        }
    }

    pub fn needs_api_key(self) -> bool {
        self.keychain_account().is_some()
    }

    /// A starting point, not a promise. Model names move faster than releases
    /// of this app, so every one of these is editable in the AI panel — and a
    /// wrong one fails with the provider naming it, which is self-explanatory.
    pub fn default_model(self) -> &'static str {
        match self {
            Provider::Claude => "claude-opus-5",
            Provider::Gemini => "gemini-2.5-pro",
            Provider::Ollama => "llama3.1",
        }
    }

    /// Whether the endpoint is yours to move. Claude and Gemini are hosted
    /// services at fixed addresses; Ollama is a server you run, so where it
    /// listens is genuinely a setting.
    fn base_url_is_configurable(self) -> bool {
        matches!(self, Provider::Ollama)
    }

    /// Whether the model name becomes part of the request URL. Gemini puts it
    /// in the path; the other two send it in the body.
    fn model_goes_in_url(self) -> bool {
        matches!(self, Provider::Gemini)
    }

    pub fn default_base_url(self) -> &'static str {
        match self {
            Provider::Claude => "https://api.anthropic.com",
            Provider::Gemini => "https://generativelanguage.googleapis.com",
            Provider::Ollama => "http://localhost:11434",
        }
    }

    /// Claude and Gemini frame their streams as SSE `data:` lines; Ollama
    /// writes bare newline-delimited JSON.
    fn framing(self) -> Framing {
        match self {
            Provider::Claude | Provider::Gemini => Framing::Sse,
            Provider::Ollama => Framing::Ndjson,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Framing {
    Sse,
    Ndjson,
}

/// The selected provider and its two editable knobs.
///
/// Held in memory and pushed from the frontend at startup, which is where the
/// preference is persisted — same as the theme and zoom level. The API keys
/// are the part that must not live there, and they don't: they stay in the OS
/// keychain, reachable only through the commands below.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AiSettings {
    pub provider: Provider,
    pub model: String,
    pub base_url: String,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            provider: Provider::Claude,
            model: Provider::Claude.default_model().to_string(),
            base_url: Provider::Claude.default_base_url().to_string(),
        }
    }
}

static SETTINGS: Mutex<Option<AiSettings>> = Mutex::new(None);

pub fn settings() -> AiSettings {
    SETTINGS.lock().ok().and_then(|s| s.clone()).unwrap_or_default()
}

/// Characters that would let a model name escape its path segment.
///
/// Only checked for providers that interpolate the model into the request URL
/// — which is Gemini alone. Claude and Ollama send it in the JSON body, where
/// these are harmless, and for Ollama one of them is required: its tag syntax
/// is `llama3.1:8b`, so rejecting `:` everywhere would lock out the ordinary
/// way of naming an Ollama model.
const URL_UNSAFE_IN_MODEL: &[char] = &['?', '#', '/', '\\', '&', ':', '@'];

fn validate_model(provider: Provider, model: &str) -> Result<(), String> {
    // Never legitimate anywhere, and a stray newline in a header or URL is
    // its own kind of problem.
    if let Some(bad) = model.chars().find(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("A model name cannot contain whitespace (found {bad:?})."));
    }
    if provider.model_goes_in_url() {
        if let Some(bad) = model.chars().find(|c| URL_UNSAFE_IN_MODEL.contains(c)) {
            return Err(format!("A {} model name cannot contain '{bad}'.", provider.label()));
        }
    }
    Ok(())
}

pub fn set_settings(provider: &str, model: &str, base_url: &str) -> Result<AiSettings, String> {
    let provider = Provider::parse(provider)?;
    let model = model.trim();
    let base_url = base_url.trim().trim_end_matches('/');

    validate_model(provider, model)?;

    let next = AiSettings {
        provider,
        model: if model.is_empty() { provider.default_model().to_string() } else { model.to_string() },
        // A hosted provider's address is not a setting, whatever the caller
        // sends — the panel doesn't offer the field, and this is what makes
        // that true rather than merely displayed.
        base_url: match (provider.base_url_is_configurable(), base_url.is_empty()) {
            (true, false) => base_url.to_string(),
            _ => provider.default_base_url().to_string(),
        },
    };
    if let Ok(mut guard) = SETTINGS.lock() {
        *guard = Some(next.clone());
    }
    Ok(next)
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Deliberately the OS keychain rather than localStorage (plaintext inside the
/// WebView) or a file this app owns — the key is then protected by the OS, and
/// other apps can't read it.
const KEYCHAIN_SERVICE: &str = "io.github.aavishay.aks-fleet-dashboard";

fn keychain_entry(provider: Provider) -> Result<Entry, String> {
    let account = provider
        .keychain_account()
        .ok_or_else(|| format!("{} does not use an API key.", provider.label()))?;
    Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| format!("Keychain unavailable: {e}"))
}

/// Stores a pasted key. Trimmed because pasting from a browser or password
/// manager very often carries a trailing newline, which would otherwise travel
/// in the auth header and fail for a non-obvious reason.
pub fn set_api_key(provider: &str, key: &str) -> Result<(), String> {
    let provider = Provider::parse(provider)?;
    let key = key.trim();
    if key.is_empty() {
        return Err("The API key is empty.".to_string());
    }
    keychain_entry(provider)?
        .set_password(key)
        .map_err(|e| format!("Could not save the key to the Keychain: {e}"))
}

pub fn clear_api_key(provider: &str) -> Result<(), String> {
    let provider = Provider::parse(provider)?;
    match keychain_entry(provider)?.delete_credential() {
        Ok(()) => Ok(()),
        // Already absent is the state the caller wanted.
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Could not remove the key from the Keychain: {e}")),
    }
}

fn keychain_api_key(provider: Provider) -> Option<String> {
    keychain_entry(provider).ok()?.get_password().ok().map(|k| k.trim().to_string()).filter(|k| !k.is_empty())
}

fn env_api_key(provider: Provider) -> Option<String> {
    for var in provider.env_vars() {
        if let Ok(value) = std::env::var(var) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Enough of the key to recognise which one is in use, and not enough to use.
fn key_hint(key: &str) -> String {
    let tail: String = key.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{tail}")
}

fn resolve_api_key(provider: Provider) -> Result<String, String> {
    env_api_key(provider).or_else(|| keychain_api_key(provider)).ok_or_else(|| {
        format!("No {} API key configured. Paste one in the AI panel.", provider.label())
    })
}

#[derive(Serialize, Clone, Debug)]
pub struct AiAuthState {
    pub provider: String,
    pub label: String,
    pub model: String,
    pub base_url: String,
    pub needs_api_key: bool,
    /// Whether this provider is ready to be called at all.
    pub signed_in: bool,
    pub source: Option<String>,
    pub detail: Option<String>,
}

pub fn auth_status() -> AiAuthState {
    let s = settings();
    let p = s.provider;

    // Ollama runs on your own machine and takes no credential, so there is
    // nothing to be signed in to — being configured *is* being ready. Whether
    // it is actually running is answered by the first call, not here.
    let (signed_in, source, detail) = if !p.needs_api_key() {
        (
            true,
            Some("local".to_string()),
            Some(format!("Talking to {} at {}. No API key needed.", p.label(), s.base_url)),
        )
    } else if let Some(key) = env_api_key(p) {
        (
            true,
            Some("environment variable".to_string()),
            Some(format!("Using {} from the environment ({}).", p.env_vars().join(" / "), key_hint(&key))),
        )
    } else if let Some(key) = keychain_api_key(p) {
        (
            true,
            Some("API key (Keychain)".to_string()),
            Some(format!("Using the {} key stored in your Keychain ({}).", p.label(), key_hint(&key))),
        )
    } else {
        (false, None, None)
    };

    AiAuthState {
        provider: format!("{:?}", p).to_lowercase(),
        label: p.label().to_string(),
        model: s.model,
        base_url: s.base_url,
        needs_api_key: p.needs_api_key(),
        signed_in,
        source,
        detail,
    }
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/// Opt into server-side refusal fallbacks (Claude only). Infrastructure
/// debugging brushes against topics a refusal classifier can misread.
const CLAUDE_FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
const CLAUDE_API_VERSION: &str = "2023-06-01";

/// What one payload from a provider's stream means to the caller.
#[derive(Debug, PartialEq)]
pub enum StreamEvent {
    Text(String),
    Done,
    Failed(String),
    /// Framing or metadata the caller doesn't act on.
    Ignored,
}

/// One streaming call. Every AI feature goes through here, so auth, error
/// mapping and stream handling exist once regardless of who answers.
pub async fn stream(
    user_content: &str,
    system: &str,
    max_tokens: u32,
    effort: &str,
    on_token: tauri::ipc::Channel<String>,
) -> Result<(), String> {
    let s = settings();
    let p = s.provider;

    let mut request = reqwest::Client::new()
        .post(endpoint(&s))
        .header("content-type", "application/json")
        .json(&request_body(&s, user_content, system, max_tokens, effort));

    if p.needs_api_key() {
        let key = resolve_api_key(p)?;
        request = match p {
            Provider::Claude => request
                .header("x-api-key", key)
                .header("anthropic-version", CLAUDE_API_VERSION)
                .header("anthropic-beta", CLAUDE_FALLBACK_BETA),
            // Header rather than the `?key=` query parameter Gemini also
            // accepts: a URL carrying a credential ends up in logs, proxies
            // and error messages.
            Provider::Gemini => request.header("x-goog-api-key", key),
            Provider::Ollama => request,
        };
    }

    let response = request
        .send()
        .await
        .map_err(|e| match p {
            // The overwhelmingly likely cause for a local server, and worth
            // saying outright rather than surfacing a bare connection error.
            Provider::Ollama => format!("Could not reach Ollama at {}. Is it running? ({e})", s.base_url),
            _ => format!("Could not reach the {} API: {e}", p.label()),
        })?;

    if !response.status().is_success() {
        return Err(describe_http_error(p, response).await);
    }

    consume(p, response, on_token).await
}

fn endpoint(s: &AiSettings) -> String {
    match s.provider {
        Provider::Claude => format!("{}/v1/messages", s.base_url),
        // `alt=sse` switches Gemini from a JSON array to SSE framing; without
        // it the body only completes at the end, which is not a stream.
        Provider::Gemini => {
            format!("{}/v1beta/models/{}:streamGenerateContent?alt=sse", s.base_url, s.model)
        }
        Provider::Ollama => format!("{}/api/chat", s.base_url),
    }
}

fn request_body(s: &AiSettings, user_content: &str, system: &str, max_tokens: u32, effort: &str) -> serde_json::Value {
    match s.provider {
        Provider::Claude => serde_json::json!({
            "model": s.model,
            "max_tokens": max_tokens,
            "stream": true,
            // Adaptive is the only thinking mode on Opus 5; `budget_tokens`
            // was removed and would be rejected with a 400.
            "thinking": { "type": "adaptive" },
            "output_config": { "effort": effort },
            "fallbacks": "default",
            "system": system,
            "messages": [{ "role": "user", "content": user_content }],
        }),
        Provider::Gemini => serde_json::json!({
            "systemInstruction": { "parts": [{ "text": system }] },
            "contents": [{ "role": "user", "parts": [{ "text": user_content }] }],
            "generationConfig": { "maxOutputTokens": max_tokens },
        }),
        Provider::Ollama => serde_json::json!({
            "model": s.model,
            "stream": true,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user_content },
            ],
            "options": { "num_predict": max_tokens },
        }),
    }
}

/// Surface the provider's own message — it names the offending parameter or
/// the missing model, which a bare status line would hide.
async fn describe_http_error(p: Provider, response: reqwest::Response) -> String {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            // Each vendor buries it somewhere different.
            for path in ["/error/message", "/error", "/message"] {
                if let Some(m) = v.pointer(path).and_then(|m| m.as_str()) {
                    return Some(m.to_string());
                }
            }
            None
        })
        .unwrap_or_else(|| text.chars().take(400).collect());

    match status.as_u16() {
        401 | 403 => format!("{} rejected the API key ({status}). Check it in the AI panel. {detail}", p.label()),
        404 if p == Provider::Ollama => {
            format!("Ollama has no such model ({status}). Pull it first, e.g. `ollama pull <model>`. {detail}")
        }
        404 => format!("{} has no such model ({status}). {detail}", p.label()),
        429 => format!("Rate limited by the {} API. {detail}", p.label()),
        _ => format!("{} API error {status}: {detail}", p.label()),
    }
}

/// Turns one payload into an event, per provider.
///
/// Split out from the read loop so every provider's framing can be tested
/// against real captured payloads without a live HTTP response.
pub fn classify(provider: Provider, payload: &str) -> StreamEvent {
    let Ok(event) = serde_json::from_str::<serde_json::Value>(payload) else {
        return StreamEvent::Ignored;
    };
    match provider {
        Provider::Claude => classify_claude(&event),
        Provider::Gemini => classify_gemini(&event),
        Provider::Ollama => classify_ollama(&event),
    }
}

fn classify_claude(event: &serde_json::Value) -> StreamEvent {
    match event.get("type").and_then(|t| t.as_str()) {
        Some("content_block_delta") => {
            // Thinking deltas arrive on this same event type; only text is
            // forwarded.
            if event.pointer("/delta/type").and_then(|t| t.as_str()) == Some("text_delta") {
                if let Some(text) = event.pointer("/delta/text").and_then(|t| t.as_str()) {
                    return StreamEvent::Text(text.to_string());
                }
            }
            StreamEvent::Ignored
        }
        Some("message_delta") => {
            if event.pointer("/delta/stop_reason").and_then(|s| s.as_str()) == Some("refusal") {
                let category =
                    event.pointer("/delta/stop_details/category").and_then(|c| c.as_str()).unwrap_or("unspecified");
                return StreamEvent::Failed(format!(
                    "Claude declined to answer this one (category: {category}). Asking about the \
                     underlying Kubernetes behaviour rather than the raw message usually works."
                ));
            }
            StreamEvent::Ignored
        }
        Some("error") => StreamEvent::Failed(format!(
            "Claude stream error: {}",
            event.pointer("/error/message").and_then(|m| m.as_str()).unwrap_or("unknown streaming error")
        )),
        Some("message_stop") => StreamEvent::Done,
        _ => StreamEvent::Ignored,
    }
}

fn classify_gemini(event: &serde_json::Value) -> StreamEvent {
    // A prompt blocked by safety filters returns no candidate at all, only
    // this — without special-casing it the stream would end silently and look
    // like an empty answer.
    if let Some(reason) = event.pointer("/promptFeedback/blockReason").and_then(|r| r.as_str()) {
        return StreamEvent::Failed(format!(
            "Gemini blocked this prompt ({reason}). Asking about the underlying Kubernetes \
             behaviour rather than the raw message usually works."
        ));
    }
    if let Some(text) = event.pointer("/candidates/0/content/parts/0/text").and_then(|t| t.as_str()) {
        return StreamEvent::Text(text.to_string());
    }
    // A finishReason with no text is the end of the answer. SAFETY and
    // RECITATION mean it was cut short, which is worth saying.
    match event.pointer("/candidates/0/finishReason").and_then(|r| r.as_str()) {
        Some("STOP") | Some("MAX_TOKENS") => StreamEvent::Done,
        Some(other) => StreamEvent::Failed(format!("Gemini stopped early ({other}).")),
        None => StreamEvent::Ignored,
    }
}

fn classify_ollama(event: &serde_json::Value) -> StreamEvent {
    if let Some(err) = event.get("error").and_then(|e| e.as_str()) {
        return StreamEvent::Failed(format!("Ollama error: {err}"));
    }
    // Text first: the final chunk carries `done: true` *and* can carry the
    // last of the content, so checking `done` first would drop it.
    if let Some(text) = event.pointer("/message/content").and_then(|t| t.as_str()) {
        if !text.is_empty() {
            return StreamEvent::Text(text.to_string());
        }
    }
    if event.get("done").and_then(|d| d.as_bool()) == Some(true) {
        return StreamEvent::Done;
    }
    StreamEvent::Ignored
}

/// Consumes a response body, forwarding text to `on_token`.
///
/// Hand-rolled rather than pulling an SSE crate: the framing needed is a small
/// stable subset, and Ollama isn't SSE at all. Chunk boundaries fall anywhere,
/// so lines are reassembled from a running buffer rather than parsed per-chunk.
async fn consume(
    provider: Provider,
    response: reqwest::Response,
    on_token: tauri::ipc::Channel<String>,
) -> Result<(), String> {
    use futures_util::StreamExt;

    let framing = provider.framing();
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("{} stream interrupted: {e}", provider.label()))?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        // Process only complete lines; whatever trails stays buffered.
        while let Some(newline) = buffer.find('\n') {
            let line = buffer[..newline].trim_end_matches('\r').to_string();
            buffer.drain(..=newline);

            let payload = match framing {
                Framing::Sse => match line.strip_prefix("data:") {
                    Some(rest) => rest.trim(),
                    None => continue,
                },
                Framing::Ndjson => line.trim(),
            };
            if payload.is_empty() || payload == "[DONE]" {
                continue;
            }

            match classify(provider, payload) {
                StreamEvent::Text(text) => {
                    if on_token.send(text).is_err() {
                        return Ok(()); // receiver went away (panel closed)
                    }
                }
                StreamEvent::Done => return Ok(()),
                StreamEvent::Failed(message) => return Err(message),
                StreamEvent::Ignored => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(e: StreamEvent) -> Option<String> {
        match e {
            StreamEvent::Text(t) => Some(t),
            _ => None,
        }
    }

    #[test]
    fn claude_stream_yields_text_and_stops() {
        assert_eq!(
            text_of(classify(
                Provider::Claude,
                r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}"#
            )),
            Some("hello".into())
        );
        // Thinking deltas ride the same event type and must not be forwarded.
        assert_eq!(
            classify(Provider::Claude, r#"{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"x"}}"#),
            StreamEvent::Ignored
        );
        assert_eq!(classify(Provider::Claude, r#"{"type":"message_stop"}"#), StreamEvent::Done);
        assert!(matches!(
            classify(Provider::Claude, r#"{"type":"error","error":{"message":"boom"}}"#),
            StreamEvent::Failed(_)
        ));
    }

    #[test]
    fn gemini_stream_yields_text_and_reports_a_blocked_prompt() {
        assert_eq!(
            text_of(classify(
                Provider::Gemini,
                r#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}"#
            )),
            Some("hi".into())
        );
        assert_eq!(
            classify(Provider::Gemini, r#"{"candidates":[{"content":{"parts":[]},"finishReason":"STOP"}]}"#),
            StreamEvent::Done
        );
        // No candidate at all — without this the stream ends looking empty.
        assert!(matches!(
            classify(Provider::Gemini, r#"{"promptFeedback":{"blockReason":"SAFETY"}}"#),
            StreamEvent::Failed(_)
        ));
        assert!(matches!(
            classify(Provider::Gemini, r#"{"candidates":[{"finishReason":"RECITATION"}]}"#),
            StreamEvent::Failed(_)
        ));
    }

    /// The final Ollama chunk carries `done: true` *and* can carry the last of
    /// the content. Checking `done` first would silently truncate every answer.
    #[test]
    fn ollama_last_chunk_keeps_its_text() {
        assert_eq!(
            text_of(classify(Provider::Ollama, r#"{"message":{"content":"tail"},"done":true}"#)),
            Some("tail".into())
        );
        assert_eq!(
            text_of(classify(Provider::Ollama, r#"{"message":{"content":"mid"},"done":false}"#)),
            Some("mid".into())
        );
        assert_eq!(classify(Provider::Ollama, r#"{"message":{"content":""},"done":true}"#), StreamEvent::Done);
        assert!(matches!(classify(Provider::Ollama, r#"{"error":"model not found"}"#), StreamEvent::Failed(_)));
    }

    #[test]
    fn endpoints_and_auth_differ_per_provider() {
        let gemini = AiSettings {
            provider: Provider::Gemini,
            model: "gemini-2.5-pro".into(),
            base_url: "https://generativelanguage.googleapis.com".into(),
        };
        let url = endpoint(&gemini);
        assert!(url.contains("streamGenerateContent"), "{url}");
        assert!(url.contains("alt=sse"), "must ask for SSE framing, got {url}");
        // The key travels in a header, never the URL.
        assert!(!url.contains("key="), "{url}");

        let ollama =
            AiSettings { provider: Provider::Ollama, model: "llama3.1".into(), base_url: "http://localhost:11434".into() };
        assert_eq!(endpoint(&ollama), "http://localhost:11434/api/chat");
        assert!(!Provider::Ollama.needs_api_key());
        assert!(Provider::Claude.needs_api_key() && Provider::Gemini.needs_api_key());
    }

    #[test]
    fn settings_fall_back_to_defaults_and_trim_a_trailing_slash() {
        let s = set_settings("ollama", "  ", "http://localhost:11434/").unwrap();
        assert_eq!(s.model, "llama3.1", "blank model falls back to the default");
        assert_eq!(s.base_url, "http://localhost:11434", "trailing slash would double up in the path");

        assert!(Provider::parse("gpt4").is_err());
        // Leave the shared slot as the app starts, so test order can't matter.
        set_settings("claude", "", "").unwrap();
    }

    /// The model is a path segment in Gemini's URL, so a name carrying a URL
    /// delimiter could append a query parameter instead of naming a model.
    #[test]
    fn a_gemini_model_name_cannot_escape_its_url_segment() {
        for bad in ["gemini?key=leaked", "a/b", "a#f", "a:b", "a@b", "a&b", "a\\b"] {
            assert!(set_settings("gemini", bad, "").is_err(), "{bad} must be rejected");
        }
        assert!(set_settings("gemini", "gemini-2.5-pro", "").is_ok());
        set_settings("claude", "", "").unwrap();
    }

    /// `llama3.1:8b` is the ordinary way to name an Ollama model. The colon is
    /// only dangerous where the model lands in a URL, which for Ollama it
    /// never does — rejecting it everywhere would lock out normal use.
    #[test]
    fn an_ollama_tag_keeps_its_colon() {
        let s = set_settings("ollama", "llama3.1:8b", "").unwrap();
        assert_eq!(s.model, "llama3.1:8b");
        assert_eq!(set_settings("claude", "claude-opus-5", "").unwrap().model, "claude-opus-5");
        // Whitespace stays out everywhere: it is never part of a model name.
        assert!(set_settings("ollama", "llama 3", "").is_err());
        set_settings("claude", "", "").unwrap();
    }

    /// Claude and Gemini are hosted at fixed addresses. The panel doesn't offer
    /// the field; this is what makes that true rather than merely displayed.
    #[test]
    fn only_ollama_can_be_pointed_somewhere_else() {
        let s = set_settings("claude", "", "https://evil.example").unwrap();
        assert_eq!(s.base_url, "https://api.anthropic.com");
        let s = set_settings("gemini", "", "https://evil.example").unwrap();
        assert_eq!(s.base_url, "https://generativelanguage.googleapis.com");
        let s = set_settings("ollama", "", "http://192.168.1.5:11434").unwrap();
        assert_eq!(s.base_url, "http://192.168.1.5:11434", "Ollama is a server you run");
        set_settings("claude", "", "").unwrap();
    }

    /// A partial chunk can produce an incomplete JSON line; skipping it must
    /// not take the stream down with it.
    #[test]
    fn unparseable_payloads_are_skipped_on_every_provider() {
        for p in [Provider::Claude, Provider::Gemini, Provider::Ollama] {
            assert_eq!(classify(p, "{not json"), StreamEvent::Ignored, "{p:?}");
            assert_eq!(classify(p, ""), StreamEvent::Ignored, "{p:?}");
        }
    }

    /// Both cases live in one test on purpose: env vars are process-global and
    /// Rust runs tests in parallel threads, so two separate tests mutating the
    /// same var race and read each other's values.
    #[test]
    fn env_api_key_distinguishes_blank_from_real_values() {
        temp_env_var("ANTHROPIC_API_KEY", Some("   "), || {
            assert_eq!(env_api_key(Provider::Claude), None, "whitespace is not a key");
        });
        temp_env_var("ANTHROPIC_API_KEY", Some(" sk-real "), || {
            assert_eq!(env_api_key(Provider::Claude), Some("sk-real".to_string()), "must be trimmed");
        });
        // Gemini reads its own vars, and must not pick up Anthropic's.
        temp_env_var("ANTHROPIC_API_KEY", Some("sk-real"), || {
            temp_env_var("GEMINI_API_KEY", None, || {
                assert_eq!(env_api_key(Provider::Gemini), None);
            });
        });
    }

    /// Sets one env var for the duration of the closure, restoring it after, so
    /// these tests don't leak state into each other or the rest of the suite.
    fn temp_env_var(key: &str, value: Option<&str>, f: impl FnOnce()) {
        let previous = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match previous {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn key_hint_shows_only_the_tail() {
        let hint = key_hint("sk-ant-secret-abcd");
        assert_eq!(hint, "…abcd");
        assert!(!hint.contains("secret"));
    }
}
