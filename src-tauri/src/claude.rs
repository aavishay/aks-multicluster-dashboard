//! What the AI features ask, and what they are allowed to send.
//!
//! The prompts and the diagnosis payload live here; which model answers them,
//! and how its stream is read, is `ai`. The split is deliberate — the payload
//! builder is the security-relevant half (it decides what leaves the machine,
//! and runs everything through `redact`) and it should not change when a
//! provider is added.

use crate::ai;
use crate::models::{ClaudeDiagnosisPayload, PodInfo};
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

const DIAGNOSE_WORKLOAD_SYSTEM: &str = "\
You diagnose failing Kubernetes workloads (Deployments, StatefulSets, \
DaemonSets) for an experienced SRE.

You are given the controller's replica counts, its recent events, its \
manifest, a table of every pod it owns, and the events and recent logs of \
the pod least likely to be healthy. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the event, log line, pod \
row, or manifest field.
3. Concrete next steps: the exact command to run or field to change.

Distinguish a controller-level problem from a pod-level one. If every pod \
fails the same way the cause is usually the template or an admission \
policy; if one pod differs, look at its node or its scheduling. A rollout \
that is stuck with updated below desired is a different failure from one \
where pods are crashlooping after a successful rollout — say which you are \
looking at.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over \
a list of possibilities. If the evidence is genuinely insufficient, say so \
and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

/// Ranks a workload's pods worst-first, so the logs in the payload come from
/// the instance most likely to explain the trouble.
///
/// Sorted ascending on the tuple, so `false` — not running, not fully ready —
/// comes first, and the negated restart count puts the most-restarted pod
/// ahead of the rest. A healthy workload has no clear worst pod and simply
/// yields its first, which is the right answer when nothing is wrong.
fn diagnosis_pod_priority(p: &PodInfo) -> (bool, bool, i32) {
    let all_ready = match p.ready.split_once('/') {
        Some((r, t)) => r.trim() == t.trim(),
        None => true,
    };
    (p.phase == "Running", all_ready, -p.restarts)
}

/// Assembles everything a workload diagnosis needs, redacted and trimmed.
///
/// Shaped like `build_diagnosis_payload` but a controller sees a different
/// failure surface: the interesting signal is usually the spread across its
/// pods — all of them failing identically points at the template, one of them
/// at that pod's node — so the pod table is the part a pod-level diagnosis
/// cannot provide.
pub async fn build_workload_diagnosis_payload(
    context_name: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<ClaudeDiagnosisPayload, String> {
    // Independent reads issued together, as in the pod path — it matters more
    // here because there are four of them before the dependent log fetch.
    let (workloads, events, manifest, pods) = tokio::join!(
        k8s::get_workloads(context_name),
        k8s::get_workload_events(context_name, kind, namespace, name),
        k8s::get_workload_manifest(context_name, kind, namespace, name),
        k8s::get_pods(context_name, Some(namespace.to_string())),
    );

    let status = workloads
        .ok()
        .and_then(|list| list.into_iter().find(|w| w.kind == kind && w.name == name && w.namespace == namespace))
        .map(|w| {
            format!(
                "kind: {}\ndesired: {}\nready: {}\nupdated: {}\navailable: {}\nhealthy: {}\nage: {}s\nversion: {} ({})\nimages: {}",
                w.kind,
                w.desired,
                w.ready,
                w.updated,
                w.available,
                w.healthy,
                w.age_seconds,
                w.version,
                if w.version_from_label { "from label" } else { "from image tag" },
                w.images.join(", "),
            )
        })
        .unwrap_or_else(|| "(workload status unavailable)".to_string());

    let owned: Vec<PodInfo> = pods
        .map(|list| {
            let mut owned: Vec<PodInfo> = list
                .into_iter()
                .filter(|p| p.owner_kind.as_deref() == Some(kind) && p.owner_name.as_deref() == Some(name))
                .collect();
            owned.sort_by_key(diagnosis_pod_priority);
            owned
        })
        .unwrap_or_default();

    let pods_text = if owned.is_empty() {
        "(this workload currently owns no pods)".to_string()
    } else {
        // Worst-first, so a truncated table keeps the pods worth reading.
        let rows = owned
            .iter()
            .take(20)
            .map(|p| {
                format!(
                    "{}  phase={} ready={} restarts={} node={} reason={}",
                    p.name,
                    p.phase,
                    p.ready,
                    p.restarts,
                    p.node.as_deref().unwrap_or("(unscheduled)"),
                    p.status_reason.as_deref().unwrap_or("(none)"),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        if owned.len() > 20 {
            format!("{rows}\n(… {} more pods, worst-first)", owned.len() - 20)
        } else {
            rows
        }
    };

    let events_text = match events {
        Ok(list) if list.is_empty() => "(no events for this workload)".to_string(),
        Ok(list) => list
            .iter()
            .take(25)
            .map(|e| format!("[{}] {} — {} (×{})", e.event_type, e.reason, e.message, e.count))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("(events unavailable: {e})"),
    };

    let (manifest_text, container) = match manifest {
        Ok(m) => {
            let container = m.containers.first().cloned().unwrap_or_default();
            (m.yaml_without_managed_fields, container)
        }
        Err(e) => (format!("(manifest unavailable: {e})"), String::new()),
    };

    // Dependent on the pod list, so it cannot join the batch above. Only the
    // worst pod's logs: a Deployment's pods are usually near-identical, so
    // every pod's logs would multiply the payload to say the same thing.
    let (logs_text, log_note, log_source) = match (owned.first(), container.is_empty()) {
        (Some(worst), false) => {
            let fetched = k8s::get_workload_logs(
                context_name,
                namespace,
                std::slice::from_ref(&worst.name),
                &container,
                true,
                DIAGNOSE_LOG_FETCH_LINES,
            )
            .await;
            match fetched {
                Ok(text) if text.trim().is_empty() => {
                    ("(container produced no log output)".to_string(), None, Some(worst.name.clone()))
                }
                Ok(text) => {
                    let (t, n) = redact::tail_lines(&text, DIAGNOSE_LOG_LINES);
                    (t, n, Some(worst.name.clone()))
                }
                Err(e) => (format!("(logs unavailable: {e})"), None, Some(worst.name.clone())),
            }
        }
        _ => ("(no pod available to read logs from)".to_string(), None, None),
    };

    // The worst pod's own events, because a controller rarely has any of its
    // own: Kubernetes attaches BackOff, Failed and Unhealthy to the pod, so a
    // workload-only view of a crashlooping Deployment reads "(no events)" while
    // the pod underneath it carries "BackOff ×945" — the single most diagnostic
    // line available. Verified against a real crashlooping Deployment.
    let pod_events_text = match owned.first() {
        Some(worst) => match k8s::get_pod_events(context_name, namespace, &worst.name).await {
            Ok(list) if list.is_empty() => format!("(no events for pod {})", worst.name),
            Ok(list) => list
                .iter()
                .take(15)
                .map(|e| format!("[{}] {} — {} (×{})", e.event_type, e.reason, e.message, e.count))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(e) => format!("(pod events unavailable: {e})"),
        },
        None => "(no pod to read events from)".to_string(),
    };

    let status = redact::redact(&status);
    let pods_r = redact::redact(&pods_text);
    let events_r = redact::redact(&events_text);
    let pod_events_r = redact::redact(&pod_events_text);
    let manifest_r = redact::redact(&manifest_text);
    let logs_r = redact::redact(&logs_text);

    let redaction_summary =
        redact::Redacted::merge([&status, &pods_r, &events_r, &pod_events_r, &manifest_r, &logs_r]).summary();

    let log_heading = match (&log_source, &container) {
        (Some(pod), c) if !c.is_empty() => format!(" (pod {pod}, container {c})"),
        _ => String::new(),
    };

    let prompt = format!(
        "{kind} {namespace}/{name}.\n\n\
         ## Status\n{}\n\n\
         ## Pods (worst first)\n{}\n\n\
         ## Events ({kind})\n{}\n\n\
         ## Events (worst pod{})\n{}\n\n\
         ## Manifest\n```yaml\n{}\n```\n\n\
         ## Logs{}{}\n```\n{}\n```",
        status.text,
        pods_r.text,
        events_r.text,
        log_source.as_ref().map(|p| format!(" {p}")).unwrap_or_default(),
        pod_events_r.text,
        manifest_r.text,
        log_heading,
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
pub async fn diagnose(prompt: &str, kind: &str, on_token: tauri::ipc::Channel<String>) -> Result<(), String> {
    // Chosen here rather than passed in from the frontend: the system prompt is
    // the instruction the model actually follows, so it stays on this side of
    // the IPC boundary where the payload preview cannot misrepresent it.
    let system = if kind == "Pod" { DIAGNOSE_SYSTEM } else { DIAGNOSE_WORKLOAD_SYSTEM };
    ai::stream(prompt, system, DIAGNOSE_MAX_TOKENS, DIAGNOSE_EFFORT, on_token).await
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(name: &str, phase: &str, ready: &str, restarts: i32) -> PodInfo {
        PodInfo {
            name: name.into(),
            namespace: "prod".into(),
            node: Some("aks-general-1".into()),
            phase: phase.into(),
            ready: ready.into(),
            restarts,
            age_days: 1,
            age_seconds: 86_400,
            owner_kind: Some("Deployment".into()),
            owner_name: Some("api".into()),
            cpu_usage_millicores: None,
            memory_usage_ki: None,
            status_reason: None,
        }
    }

    fn ranked(mut pods: Vec<PodInfo>) -> Vec<String> {
        pods.sort_by_key(diagnosis_pod_priority);
        pods.into_iter().map(|p| p.name).collect()
    }

    #[test]
    fn the_worst_pod_is_the_one_whose_logs_go_in_the_payload() {
        // Pending outranks everything: a pod that never started explains a
        // stuck rollout better than one that is merely restarting.
        assert_eq!(
            ranked(vec![
                pod("healthy", "Running", "1/1", 0),
                pod("restarting", "Running", "1/1", 14),
                pod("pending", "Pending", "0/1", 0),
            ]),
            vec!["pending", "restarting", "healthy"]
        );
    }

    #[test]
    fn a_running_but_unready_pod_outranks_a_ready_one() {
        // Running with a failing readiness probe is the classic "rollout says
        // it worked, nothing serves traffic" case, so it must beat a ready pod
        // even when the ready pod has restarted more.
        assert_eq!(
            ranked(vec![
                pod("ready-but-flappy", "Running", "2/2", 9),
                pod("running-unready", "Running", "1/2", 0),
            ]),
            vec!["running-unready", "ready-but-flappy"]
        );
    }

    #[test]
    fn among_equals_the_most_restarted_pod_wins() {
        assert_eq!(
            ranked(vec![
                pod("calm", "Running", "1/1", 1),
                pod("crashy", "Running", "1/1", 57),
                pod("quiet", "Running", "1/1", 0),
            ]),
            vec!["crashy", "calm", "quiet"]
        );
    }

    #[test]
    fn a_malformed_ready_string_is_treated_as_ready() {
        // `ready` is rendered by the pod reader, not parsed from the API, but
        // an unexpected shape must not silently promote a healthy pod to
        // "worst" and send its logs instead of the crashlooping one's.
        assert_eq!(
            ranked(vec![
                pod("odd-ready", "Running", "unknown", 0),
                pod("crashy", "Running", "1/1", 33),
            ]),
            vec!["crashy", "odd-ready"]
        );
    }
}
