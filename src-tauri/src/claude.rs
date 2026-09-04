//! What the AI features ask, and what they are allowed to send.
//!
//! The prompts and the diagnosis payload live here; which model answers them,
//! and how its stream is read, is `ai`. The split is deliberate — the payload
//! builder is the security-relevant half (it decides what leaves the machine,
//! and runs everything through `redact`) and it should not change when a
//! provider is added.

use crate::ai;
use crate::models::ClaudeDiagnosisPayload;
use crate::{k8s, redact};

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

// ---------------------------------------------------------------------------
// Pod diagnosis
// ---------------------------------------------------------------------------

/// Log lines included in a diagnosis. Enough for a crashloop's story without
/// dominating the payload — and the trim is always disclosed, never silent.
const DIAGNOSE_LOG_LINES: usize = 200;
/// Fetched before trimming, so `tail_lines` has a real tail to choose from.
const DIAGNOSE_LOG_FETCH_LINES: i64 = 400;
/// Diagnosis reasons over several documents at once, so it gets more headroom
/// than the one-string explain path.
const DIAGNOSE_MAX_TOKENS: u32 = 32_000;
/// Root-causing a crashloop is the intelligence-sensitive case in this app;
/// terser settings produce plausible-but-shallow answers here.
const DIAGNOSE_EFFORT: &str = "high";

const DIAGNOSE_SYSTEM: &str = "\
You diagnose failing Kubernetes pods for an experienced SRE.

You are given a pod's status, its recent events, its manifest, and recent \
container logs. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the event, log line, or \
manifest field.
3. Concrete next steps: the exact command to run or field to change.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over a \
list of possibilities. If the evidence is genuinely insufficient, say so and \
name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

/// Assembles everything a diagnosis needs, redacted and trimmed.
///
/// Returned to the frontend *before* being sent, so the exact text leaving the
/// machine is inspectable rather than implied. Every document goes through
/// `redact` — logs and manifests both, since a manifest's env values are as
/// likely to hold a secret as a log line.
pub async fn build_diagnosis_payload(
    context_name: &str,
    namespace: &str,
    pod_name: &str,
    container: &str,
) -> Result<ClaudeDiagnosisPayload, String> {
    // Independent reads, issued concurrently — the same reasoning as the
    // tokio::join! conversions in k8s.rs, and it matters more here because a
    // private-link cluster costs tens of seconds per round trip.
    let (pods, events, manifest, logs) = tokio::join!(
        k8s::get_pods(context_name, Some(namespace.to_string())),
        k8s::get_pod_events(context_name, namespace, pod_name),
        k8s::get_pod_manifest(context_name, namespace, pod_name),
        k8s::get_pod_logs(context_name, namespace, pod_name, container, true, DIAGNOSE_LOG_FETCH_LINES),
    );

    let status = pods
        .ok()
        .and_then(|list| list.into_iter().find(|p| p.name == pod_name))
        .map(|p| {
            format!(
                "phase: {}\nready: {}\nrestarts: {}\nnode: {}\nowner: {}\nage: {}s\nreason: {}",
                p.phase,
                p.ready,
                p.restarts,
                p.node.unwrap_or_else(|| "(unscheduled)".to_string()),
                match (p.owner_kind, p.owner_name) {
                    (Some(k), Some(n)) => format!("{k}/{n}"),
                    _ => "(none)".to_string(),
                },
                p.age_seconds,
                p.status_reason.unwrap_or_else(|| "(none)".to_string()),
            )
        })
        .unwrap_or_else(|| "(pod status unavailable)".to_string());

    let events_text = match events {
        Ok(list) if list.is_empty() => "(no events for this pod)".to_string(),
        Ok(list) => list
            .iter()
            .take(25)
            .map(|e| format!("[{}] {} — {} (×{})", e.event_type, e.reason, e.message, e.count))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("(events unavailable: {e})"),
    };

    // Managed fields are pure server bookkeeping — omitting them removes a
    // large share of the manifest's tokens with no diagnostic loss.
    let manifest_text = match manifest {
        Ok(m) => m.yaml_without_managed_fields,
        Err(e) => format!("(manifest unavailable: {e})"),
    };

    let (logs_text, log_note) = match logs {
        Ok(text) if text.trim().is_empty() => ("(container produced no log output)".to_string(), None),
        Ok(text) => redact::tail_lines(&text, DIAGNOSE_LOG_LINES),
        Err(e) => (format!("(logs unavailable: {e})"), None),
    };

    // Redact each document, then merge the findings so the summary reflects the
    // whole payload rather than one part of it.
    let status = redact::redact(&status);
    let events_r = redact::redact(&events_text);
    let manifest_r = redact::redact(&manifest_text);
    let logs_r = redact::redact(&logs_text);

    let redaction_summary = redact::Redacted::merge([&status, &events_r, &manifest_r, &logs_r]).summary();

    let prompt = format!(
        "Pod {namespace}/{pod_name}, container {container}.\n\n\
         ## Status\n{}\n\n\
         ## Events\n{}\n\n\
         ## Manifest\n```yaml\n{}\n```\n\n\
         ## Logs{}\n```\n{}\n```",
        status.text,
        events_r.text,
        manifest_r.text,
        log_note.as_ref().map(|n| format!(" ({n})")).unwrap_or_default(),
        logs_r.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note,
    })
}

/// Rough token estimate for the payload preview — ~4 characters per token.
///
/// Deliberately not a call to `/v1/messages/count_tokens`: that would send the
/// payload to the API *before* the user has approved it, which is precisely
/// what the preview exists to prevent. An estimate is enough to convey scale.
fn approx_tokens(text: &str) -> u32 {
    (text.chars().count() as f64 / 4.0).ceil() as u32
}

/// Streams a diagnosis for an already-built payload.
///
/// Takes the assembled prompt rather than re-gathering, so what is sent is
/// exactly what the user was shown — re-fetching could send something different
/// from the preview.
pub async fn diagnose(prompt: &str, on_token: tauri::ipc::Channel<String>) -> Result<(), String> {
    ai::stream(prompt, DIAGNOSE_SYSTEM, DIAGNOSE_MAX_TOKENS, DIAGNOSE_EFFORT, on_token).await
}

/// Streams an explanation of a single error message, emitting text deltas on
/// `on_token` as they arrive.
///
/// Only the error string leaves the machine — no logs, manifests, or cluster
/// identifiers — which is what makes this the lowest-exposure Claude feature
/// in the app.
pub async fn explain_error(error_text: &str, on_token: tauri::ipc::Channel<String>) -> Result<(), String> {
    ai::stream(error_text, EXPLAIN_SYSTEM, EXPLAIN_MAX_TOKENS, EXPLAIN_EFFORT, on_token).await
}
