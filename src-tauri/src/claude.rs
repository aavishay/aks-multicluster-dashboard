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

const DIAGNOSE_GITOPS_SYSTEM: &str = "\
You diagnose failing ArgoCD Applications for an experienced SRE.

You are given the Application's sync and health status, where it syncs from, \
its recent events, its manifest, and — for an app that has drifted — a diff \
per resource between what was last applied and what is live in the cluster. \
Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the drifted field, the \
event, or the manifest setting.
3. Concrete next steps: the exact command to run or field to change.

Separate the two failure modes rather than blurring them. OutOfSync means the \
cluster no longer matches Git, and the diff says which fields; Degraded means \
the resources synced but are not working, and the events and the resource \
health say why. An app can be both, and then the order matters: say which one \
caused the other.

The diff is drift against the last applied configuration, not against Git. A \
field changed by a mutating webhook, an autoscaler, or a controller shows up \
here exactly like a hand edit does, so do not assume a human changed it — \
name the likely writer.

Be direct; assume fluency with kubectl and ArgoCD. Prefer one well-supported \
cause over a list of possibilities. If the evidence is genuinely \
insufficient, say so and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

const DIAGNOSE_HELM_SYSTEM: &str = "\
You diagnose Helm releases for an experienced SRE.

You are given the release's current status and chart, its user-supplied \
values, an inventory of the resources it renders, and its revision history \
with the description Helm recorded for each one. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the failing revision's \
description, the value that was set, or the resource named in the error.
3. Concrete next steps: the exact command to run or value to change.

Read the history, not just the status. A release shows `deployed` the moment \
one upgrade succeeds, so a release that has failed repeatedly and then been \
rolled back or fixed looks healthy in its current revision while the actual \
problem is still there. Repeated identical failures are collapsed with a \
count and a time range; a failure recurring on a fixed interval usually means \
an operator or CI job is retrying, not that a person tried that many times.

Helm's own failure and the workload's failure are different things. A failed \
or pending revision means Helm could not apply the chart — the description \
names the object and the reason. A `deployed` release whose pods are broken \
is not a Helm problem, and this payload deliberately carries nothing about \
pod health: say so and point at the workload rather than guessing.

The rendered manifest is not included — for large charts it runs to megabytes \
of CRD schemas. You get the resource inventory instead, which is enough to \
place the object an error names. Ask for a specific resource if you need its \
body.

Be direct; assume fluency with kubectl and helm. Prefer one well-supported \
cause over a list of possibilities. If the evidence is genuinely \
insufficient, say so and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

/// How many drifted resources go into a diagnosis.
///
/// An app with dozens of drifted resources is usually drifted the same way in
/// all of them, so the first few carry the story and the rest would crowd out
/// the events and the manifest.
const DIAGNOSE_DIFF_RESOURCES: usize = 5;

/// Hard ceiling on how many not-Synced resources a diagnosis will read.
///
/// `DIAGNOSE_DIFF_RESOURCES` alone does not bound the cluster work: an app
/// whose resources are all OutOfSync but applied server-side yields no drift
/// however many are read, so the "enough drifted" stop never fires and the
/// scan would walk every one of them — sequentially, inside the same deadline
/// the status, events and manifest fetches share.
///
/// Above the display cap on purpose. The budget is spent on *candidates*, and
/// an uncomparable or unchanged one consumes a slot without producing an
/// example, so a ceiling equal to the cap would routinely send fewer than
/// five diffs when five were available.
///
/// Measured against both fleets on 2026-09-23: dev-weu's 116 Applications had
/// no not-Synced resources at all, and prod-weu's 68 had thirteen between
/// them, the worst single app carrying nine. So twenty clears today's real
/// worst case twice over and never engages — which is what a ceiling should
/// look like. It is insurance against an app that drifts wholesale, not a
/// routine trimmer, and the `enough` stop is what does the everyday work.
const DIAGNOSE_DIFF_READS: usize = 20;

/// Renders the drift section of a GitOps diagnosis.
///
/// Pure, and separate from the payload builder, because the distinction it
/// draws is the testable part: "drifted", "could not be compared" and "could
/// not be read" are three different statements about the cluster, and a
/// payload that collapses them tells a model reasoning about cluster state
/// something untrue. A read failure reported as server-side apply is the
/// worst of the three — it turns a gap in what we know into a design choice.
fn render_diff_section(scan: &k8s::GitOpsDiffScan) -> String {
    let drifted: Vec<_> = scan.diffs.iter().filter(|d| d.has_drift()).collect();
    // No last-applied-configuration to compare against. Normal, not a
    // failure: that is what server-side apply looks like from here.
    let uncomparable = scan.diffs.iter().filter(|d| !d.desired_available && d.error.is_none()).count();
    // Could not be read at all — RBAC, or deleted since ArgoCD looked.
    let unreadable: Vec<_> = scan.diffs.iter().filter_map(|d| d.error.as_deref()).collect();

    let mut out = if drifted.is_empty() {
        "(no resource drift detected)".to_string()
    } else {
        let shown = drifted.len().min(DIAGNOSE_DIFF_RESOURCES);
        let mut rendered = drifted
            .iter()
            .take(DIAGNOSE_DIFF_RESOURCES)
            .map(|d| {
                format!(
                    "### {}/{} {} ({})\n--- last applied\n{}\n--- live\n{}",
                    if d.namespace.is_empty() { "cluster" } else { &d.namespace },
                    d.name,
                    d.kind,
                    d.sync_status,
                    d.desired_yaml,
                    d.live_yaml,
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        if drifted.len() > shown {
            rendered.push_str(&format!("\n\n(… {} more drifted resource(s))", drifted.len() - shown));
        }
        rendered
    };

    if uncomparable > 0 {
        out.push_str(&format!(
            "\n\n({uncomparable} resource(s) could not be compared: applied server-side, so they carry no last-applied-configuration. This is not a fault and says nothing about whether they drifted.)"
        ));
    }
    if let Some(first) = unreadable.first() {
        out.push_str(&format!(
            "\n\n({} resource(s) could not be read at all, so any drift in them is invisible here — e.g. {first})",
            unreadable.len()
        ));
    }
    if scan.examined < scan.candidates {
        out.push_str(&format!(
            "\n\n(scan stopped after {} of {} not-Synced resources; the drift above is a sample, not its full extent)",
            scan.examined, scan.candidates
        ));
    }
    out
}

/// Cuts a `&str` to at most `max` bytes without splitting a character.
///
/// `&s[..max]` panics mid-character. It was written for the live probe, whose
/// own caveat lines are full of `—` and `…`; it is production code now because
/// a release's values YAML is arbitrary user text, and truncating it is a
/// thing the payload builder does on every large release rather than a thing a
/// developer opts into.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// How many resources from a release's inventory go into a diagnosis.
///
/// The inventory is cheap — one short line each, 66 for the largest release
/// measured — so this is a guard against a pathological chart rather than a
/// routine trim.
const DIAGNOSE_INVENTORY_RESOURCES: usize = 80;

/// How many failed revisions to open for their descriptions.
///
/// Failures repeat: one release had fifteen, all carrying the same RBAC
/// denial an hour apart. Identical descriptions collapse below, so a handful
/// is enough to establish both the error and that it is recurring, and each
/// one costs a decode of a payload that can run to megabytes.
const DIAGNOSE_HELM_FAILURES: usize = 6;

/// How much of a release's values YAML to send.
const DIAGNOSE_VALUES_CHARS: usize = 8000;

/// How much of one revision's description to send.
///
/// Helm concatenates every per-resource failure into a single description
/// with ` && `. One real release's webhook outage produced a description
/// naming forty resources, each with its own admission URL: 65 kB of one
/// sentence repeated, which took the whole payload to 18k tokens while the
/// first clause already said what went wrong. The cap is on the description
/// rather than the payload because that is where the pathology is.
const DIAGNOSE_DESCRIPTION_CHARS: usize = 1200;

/// Renders a release's revision history, collapsing repeats.
///
/// Pure, and separate, because the collapsing is the part worth testing: a
/// release that failed fifteen times with the same message should read as one
/// recurring failure with a count and a span, not as fifteen entries that
/// crowd out everything else in the payload.
fn render_helm_history(revisions: &[crate::models::HelmRevisionInfo]) -> String {
    if revisions.is_empty() {
        return "(no revision history)".to_string();
    }
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < revisions.len() {
        let here = &revisions[i];
        let mut j = i + 1;
        // Only consecutive runs collapse. A failure that recurs either side of
        // a success is a different story from one continuous outage, and
        // merging them across the success would hide the success.
        while j < revisions.len()
            && revisions[j].status == here.status
            && revisions[j].description == here.description
        {
            j += 1;
        }
        let last = &revisions[j - 1];
        let when = match (&here.deployed_at, &last.deployed_at) {
            (Some(newest), Some(oldest)) if j - i > 1 => format!(" between {oldest} and {newest}"),
            (Some(newest), _) => format!(" at {newest}"),
            _ => String::new(),
        };
        let span = if j - i > 1 {
            format!("v{}–v{} ({}× {}){when}", last.revision, here.revision, j - i, here.status)
        } else {
            format!("v{} ({}){when}", here.revision, here.status)
        };
        // An unread run collapses on an empty description, which would let a
        // reader take it for a repeat of the failure above. Say which it is:
        // these were not opened, so nothing is known about whether they match.
        let description = if here.description.is_empty() {
            format!(
                "(not opened — only the {DIAGNOSE_HELM_FAILURES} most recent failures are read, so whether these match the above is unknown)"
            )
        } else if here.description.len() > DIAGNOSE_DESCRIPTION_CHARS {
            format!(
                "{}\n  … (description truncated; {} chars in total, and Helm joins one clause per failing resource with ` && `)",
                truncate_on_char_boundary(&here.description, DIAGNOSE_DESCRIPTION_CHARS),
                here.description.len()
            )
        } else {
            here.description.clone()
        };
        out.push(format!("{span}\n  {description}"));
        i = j;
    }
    out.join("\n")
}

/// Assembles everything a Helm release diagnosis needs, redacted.
///
/// The revision history is the part no other subject has, and it is the part
/// the release's own status hides: Helm marks a release `deployed` as soon as
/// one upgrade succeeds, so a chart that has failed fifteen times and then
/// been rolled back presents as healthy.
pub async fn build_helm_diagnosis_payload(
    context_name: &str,
    namespace: &str,
    name: &str,
) -> Result<ClaudeDiagnosisPayload, String> {
    let snapshot =
        crate::helm::get_helm_release_diagnostics(context_name, namespace, name, DIAGNOSE_HELM_FAILURES).await?;
    let r = &snapshot.release;
    // No `description` here. It is the current revision's, so the history
    // below already carries it as its first entry — and carries it *capped*,
    // where this copy was raw: a current revision that failed the way vmks did
    // would have put 65 kB of it in the status block alone.
    let status = format!(
        "status: {}\nchart: {} {}\napp version: {}\ncurrent revision: {}\nrevisions stored: {} ({} failed)\nlast deployed: {}\nfirst deployed: {}",
        r.status,
        r.chart_name,
        r.chart_version,
        if r.app_version.is_empty() { "(none)" } else { &r.app_version },
        r.revision,
        r.revision_count,
        r.failed_revisions,
        r.last_deployed.clone().unwrap_or_else(|| "(unknown)".to_string()),
        r.first_deployed.clone().unwrap_or_else(|| "(unknown)".to_string()),
    );

    let history_text = render_helm_history(&snapshot.history);

    let values_text = if snapshot.values_yaml.is_empty() {
        "(installed with no value overrides)".to_string()
    } else if snapshot.values_yaml.len() > DIAGNOSE_VALUES_CHARS {
        let cut = truncate_on_char_boundary(&snapshot.values_yaml, DIAGNOSE_VALUES_CHARS);
        format!("{cut}\n… (values truncated; {} chars in total)", snapshot.values_yaml.len())
    } else {
        snapshot.values_yaml.clone()
    };

    let shown = snapshot.inventory.len().min(DIAGNOSE_INVENTORY_RESOURCES);
    let mut inventory_text = if snapshot.inventory.is_empty() {
        "(the rendered manifest lists no resources)".to_string()
    } else {
        snapshot.inventory.iter().take(DIAGNOSE_INVENTORY_RESOURCES).cloned().collect::<Vec<_>>().join("\n")
    };
    if snapshot.inventory.len() > shown {
        inventory_text.push_str(&format!("\n… and {} more", snapshot.inventory.len() - shown));
    }
    inventory_text.push_str(&format!(
        "\n\n(the rendered manifest itself is {} chars and is not included)",
        snapshot.manifest_chars
    ));

    let status = redact::redact(&status);
    let history_r = redact::redact(&history_text);
    let values_r = redact::redact(&values_text);
    let inventory_r = redact::redact(&inventory_text);

    let redaction_summary =
        redact::Redacted::merge([&status, &history_r, &values_r, &inventory_r]).summary();

    let prompt = format!(
        "Helm release {namespace}/{name}.\n\n\
         ## Status\n{}\n\n\
         ## Revision history (newest first)\n{}\n\n\
         ## Values (user-supplied)\n```yaml\n{}\n```\n\n\
         ## Resources this release renders\n{}",
        status.text, history_r.text, values_r.text, inventory_r.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note: None,
    })
}

/// Assembles everything an ArgoCD Application diagnosis needs, redacted.
///
/// The drift diff is the part no other subject has. For an OutOfSync app the
/// whole question is *which fields* stopped matching, and that is exactly what
/// `get_gitops_diff` computes — so this reuses it rather than sending the
/// model two manifests to compare itself.
pub async fn build_gitops_diagnosis_payload(
    context_name: &str,
    namespace: &str,
    name: &str,
) -> Result<ClaudeDiagnosisPayload, String> {
    let (apps, events, manifest, diffs) = tokio::join!(
        k8s::get_gitops_apps(context_name),
        k8s::get_gitops_events(context_name, namespace, name),
        k8s::get_gitops_manifest(context_name, namespace, name),
        k8s::get_gitops_diff_scan(
            context_name,
            namespace,
            name,
            Some(k8s::DiffScanLimit { max_reads: DIAGNOSE_DIFF_READS, enough: DIAGNOSE_DIFF_RESOURCES }),
        ),
    );

    let status = apps
        .ok()
        .and_then(|r| r.apps.into_iter().find(|a| a.name == name && a.namespace == namespace))
        .map(|a| {
            format!(
                "sync: {}\nhealth: {}\ndestination namespace: {}\nrepo: {}\npath: {}\ntarget revision: {}\nlive revision: {}\nlast synced: {}\nage: {}s",
                a.sync_status,
                a.health_status,
                a.destination_namespace,
                a.repo_url,
                a.path,
                a.target_revision,
                a.revision,
                a.last_synced_at.unwrap_or_else(|| "(never)".to_string()),
                a.age_seconds,
            )
        })
        .unwrap_or_else(|| "(application status unavailable)".to_string());

    let events_text = match events {
        Ok(list) if list.is_empty() => "(no events for this application)".to_string(),
        Ok(list) => list
            .iter()
            .take(25)
            .map(|e| format!("[{}] {} — {} (×{})", e.event_type, e.reason, e.message, e.count))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("(events unavailable: {e})"),
    };

    let manifest_text = match manifest {
        Ok(m) => m.yaml_without_managed_fields,
        Err(e) => format!("(manifest unavailable: {e})"),
    };

    let diff_text = match diffs {
        Ok(scan) => render_diff_section(&scan),
        Err(e) => format!("(diff unavailable: {e})"),
    };

    let status = redact::redact(&status);
    let events_r = redact::redact(&events_text);
    let manifest_r = redact::redact(&manifest_text);
    let diff_r = redact::redact(&diff_text);

    let redaction_summary = redact::Redacted::merge([&status, &events_r, &manifest_r, &diff_r]).summary();

    let prompt = format!(
        "ArgoCD Application {namespace}/{name}.\n\n\
         ## Status\n{}\n\n\
         ## Events\n{}\n\n\
         ## Drift (last applied vs live)\n{}\n\n\
         ## Manifest\n```yaml\n{}\n```",
        status.text, events_r.text, diff_r.text, manifest_r.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note: None,
    })
}

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

    // Both of these depend on the worst pod and on nothing else, so they go out
    // together rather than one after the other. They cannot join the batch
    // above — which pod is worst is only known once the pod list has arrived —
    // but serialising them here would add a whole round trip to every workload
    // preview, and on a private-link cluster that is tens of seconds. Worse,
    // the log fetch is the one that can sit on a timeout, and awaiting it first
    // would make the events wait behind precisely the slowest call.
    //
    // Only the worst pod's logs: a Deployment's pods are usually near-identical,
    // so every pod's logs would multiply the payload to say the same thing.
    //
    // Its *events* are here because a controller rarely has any of its own:
    // Kubernetes attaches BackOff, Failed and Unhealthy to the pod, so a
    // workload-only view of a crashlooping Deployment reads "(no events)" while
    // the pod underneath carries "BackOff ×945" — the single most diagnostic
    // line available. Verified against a real crashlooping Deployment.
    let worst = owned.first();
    let (logs, pod_events) = match worst {
        Some(worst) => {
            // `container` is empty only when the manifest read failed, in which
            // case there is nothing to ask the log endpoint for.
            let logs_fut = async {
                if container.is_empty() {
                    None
                } else {
                    Some(
                        k8s::get_workload_logs(
                            context_name,
                            namespace,
                            std::slice::from_ref(&worst.name),
                            &container,
                            true,
                            DIAGNOSE_LOG_FETCH_LINES,
                        )
                        .await,
                    )
                }
            };
            let events_fut = k8s::get_pod_events(context_name, namespace, &worst.name);
            let (logs, events) = tokio::join!(logs_fut, events_fut);
            (logs, Some(events))
        }
        None => (None, None),
    };

    let (logs_text, log_note, log_source) = match (worst, logs) {
        (Some(worst), Some(Ok(text))) if text.trim().is_empty() => {
            ("(container produced no log output)".to_string(), None, Some(worst.name.clone()))
        }
        (Some(worst), Some(Ok(text))) => {
            let (t, n) = redact::tail_lines(&text, DIAGNOSE_LOG_LINES);
            (t, n, Some(worst.name.clone()))
        }
        (Some(worst), Some(Err(e))) => {
            (format!("(logs unavailable: {e})"), None, Some(worst.name.clone()))
        }
        _ => ("(no pod available to read logs from)".to_string(), None, None),
    };

    let pod_events_text = match (worst, pod_events) {
        (Some(worst), Some(Ok(list))) if list.is_empty() => format!("(no events for pod {})", worst.name),
        (_, Some(Ok(list))) => list
            .iter()
            .take(15)
            .map(|e| format!("[{}] {} — {} (×{})", e.event_type, e.reason, e.message, e.count))
            .collect::<Vec<_>>()
            .join("\n"),
        (_, Some(Err(e))) => format!("(pod events unavailable: {e})"),
        _ => "(no pod to read events from)".to_string(),
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
    // The container can be empty when Diagnose is reached from a table row for
    // a pod-level failure: an evicted pod belongs to no container, and asking
    // the log endpoint for one named "" is an error rather than a default.
    // `None` means there was no container to ask, which is a different fact
    // from a container that answered with nothing — and the prompt has to say
    // which, or it asserts that a container produced no output when none was
    // ever read.
    let logs_fut = async {
        if container.is_empty() {
            None
        } else {
            Some(k8s::get_pod_logs(context_name, namespace, pod_name, container, true, DIAGNOSE_LOG_FETCH_LINES).await)
        }
    };

    let (pods, events, manifest, logs) = tokio::join!(
        k8s::get_pods(context_name, Some(namespace.to_string())),
        k8s::get_pod_events(context_name, namespace, pod_name),
        k8s::get_pod_manifest(context_name, namespace, pod_name),
        logs_fut,
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
        // An evicted pod belongs to no container, so nothing was asked for
        // logs. Saying so is not the same as saying a container was silent.
        None => (
            "(this is a pod-level failure with no container to read logs from)".to_string(),
            None,
        ),
        Some(Ok(text)) if text.trim().is_empty() => ("(container produced no log output)".to_string(), None),
        Some(Ok(text)) => redact::tail_lines(&text, DIAGNOSE_LOG_LINES),
        Some(Err(e)) => (format!("(logs unavailable: {e})"), None),
    };

    // Redact each document, then merge the findings so the summary reflects the
    // whole payload rather than one part of it.
    let status = redact::redact(&status);
    let events_r = redact::redact(&events_text);
    let manifest_r = redact::redact(&manifest_text);
    let logs_r = redact::redact(&logs_text);

    let redaction_summary = redact::Redacted::merge([&status, &events_r, &manifest_r, &logs_r]).summary();

    let container_note = if container.is_empty() {
        String::new()
    } else {
        format!(", container {container}")
    };

    let prompt = format!(
        "Pod {namespace}/{pod_name}{container_note}.\n\n\
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
    let system = match kind {
        "Pod" => DIAGNOSE_SYSTEM,
        "Application" => DIAGNOSE_GITOPS_SYSTEM,
        "Release" => DIAGNOSE_HELM_SYSTEM,
        _ => DIAGNOSE_WORKLOAD_SYSTEM,
    };
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
    use crate::models::GitOpsResourceDiff;

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
            failure_container: None,
            failure_message: None,
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

    fn diff_entry(name: &str, desired: &str, live: &str, desired_available: bool, error: Option<&str>) -> GitOpsResourceDiff {
        GitOpsResourceDiff {
            group: String::new(),
            version: "v1".into(),
            kind: "ConfigMap".into(),
            namespace: "ns".into(),
            name: name.into(),
            sync_status: "OutOfSync".into(),
            desired_yaml: desired.into(),
            live_yaml: live.into(),
            live_yaml_full: live.into(),
            suppressed_lines: 0,
            desired_available,
            error: error.map(str::to_string),
        }
    }

    fn scan(diffs: Vec<GitOpsResourceDiff>) -> k8s::GitOpsDiffScan {
        let n = diffs.len();
        k8s::GitOpsDiffScan { diffs, candidates: n, examined: n }
    }

    #[test]
    fn a_resource_that_could_not_be_read_is_not_reported_as_server_side_apply() {
        // The distinction this whole function exists for. Both entries have
        // `desired_available: false`, and calling both "applied server-side"
        // would turn a permissions failure into a design choice — the model
        // would then have no reason to suspect its view is incomplete.
        let out = render_diff_section(&scan(vec![
            diff_entry("ssa", "", "a: 1", false, None),
            diff_entry("denied", "", "", false, Some("Failed to get Secret/tls: forbidden")),
        ]));
        assert!(out.contains("1 resource(s) could not be compared"), "{out}");
        assert!(out.contains("1 resource(s) could not be read at all"), "{out}");
        assert!(out.contains("forbidden"), "{out}");
    }

    #[test]
    fn caveats_survive_alongside_real_drift() {
        // They used to print only when nothing had drifted, so the case where
        // the model most needs to know its diff is partial — it has some real
        // evidence and will reason from it — was the one case that hid it.
        let out = render_diff_section(&scan(vec![
            diff_entry("drifted", "replicas: 1", "replicas: 3", true, None),
            diff_entry("denied", "", "", false, Some("forbidden")),
        ]));
        assert!(out.contains("### ns/drifted"), "{out}");
        assert!(out.contains("could not be read at all"), "{out}");
    }

    #[test]
    fn an_unreadable_resource_is_not_counted_as_drift() {
        // Its yamls differ from nothing to nothing, but `has_drift` gates on
        // `desired_available` — otherwise every unreadable resource would
        // arrive as a phantom drift with two empty sides.
        let out = render_diff_section(&scan(vec![diff_entry("ssa", "", "a: 1", false, None)]));
        assert!(out.starts_with("(no resource drift detected)"), "{out}");
    }

    #[test]
    fn a_bounded_scan_says_it_stopped_early() {
        let mut s = scan(vec![diff_entry("d", "a: 1", "a: 2", true, None)]);
        s.candidates = 60;
        s.examined = 5;
        let out = render_diff_section(&s);
        assert!(out.contains("scan stopped after 5 of 60"), "{out}");
        // ... and an unbounded one does not.
        assert!(!render_diff_section(&scan(vec![diff_entry("d", "a: 1", "a: 2", true, None)])).contains("scan stopped"));
    }

    #[test]
    fn truncating_the_probe_output_never_splits_a_character() {
        // An em dash straddling the cut: `&s[..max]` panics on exactly this,
        // and the caveat lines this probe prints are written with em dashes,
        // so whether it aborted came down to which application was passed in.
        let s = format!("{}—tail", "a".repeat(10));
        let max = 11; // one byte into the three-byte dash
        assert!(!s.is_char_boundary(max), "the test string must actually straddle the cut");

        let cut = truncate_on_char_boundary(&s, max);
        assert_eq!(cut, "a".repeat(10));
        assert!(cut.len() <= max);

        // Shorter than the limit is returned whole, and a cut that already
        // lands on a boundary is taken as-is.
        assert_eq!(truncate_on_char_boundary("short", 4000), "short");
        assert_eq!(truncate_on_char_boundary(&s, 10), "a".repeat(10));
    }

    #[tokio::test]
    #[ignore = "needs a reachable cluster; set HELM_DIAG_TEST_* to run"]
    async fn helm_diagnosis_against_a_live_cluster() {
        let (Ok(context), Ok(namespace), Ok(release)) = (
            std::env::var("HELM_DIAG_TEST_CONTEXT"),
            std::env::var("HELM_DIAG_TEST_NS"),
            std::env::var("HELM_DIAG_TEST_RELEASE"),
        ) else {
            eprintln!("HELM_DIAG_TEST_* not set — skipping");
            return;
        };

        let started = std::time::Instant::now();
        let snapshot =
            crate::helm::get_helm_release_diagnostics(&context, &namespace, &release, DIAGNOSE_HELM_FAILURES)
                .await
                .expect("diagnostics");
        eprintln!(
            "fetch in {}ms: {} {} rev {} ({}), {} revisions, {} failed | manifest {} chars -> {} inventory lines | values {} chars",
            started.elapsed().as_millis(),
            snapshot.release.chart_name,
            snapshot.release.chart_version,
            snapshot.release.revision,
            snapshot.release.status,
            snapshot.release.revision_count,
            snapshot.release.failed_revisions,
            snapshot.manifest_chars,
            snapshot.inventory.len(),
            snapshot.values_yaml.len(),
        );

        let started = std::time::Instant::now();
        let payload = build_helm_diagnosis_payload(&context, &namespace, &release)
            .await
            .expect("payload should build");
        eprintln!(
            "\npayload: {} bytes / {} chars, ~{} tokens, built in {}ms\nredaction: {}",
            payload.prompt.len(),
            payload.prompt.chars().count(),
            payload.approx_tokens,
            started.elapsed().as_millis(),
            payload.redaction_summary
        );

        let head = payload.prompt.split("## Values").next().unwrap_or(&payload.prompt);
        eprintln!("\n--- status and history ---\n{}", truncate_on_char_boundary(head, 3500));
    }

    #[tokio::test]
    #[ignore = "needs a reachable cluster; set GITOPS_DIAG_TEST_* to run"]
    async fn gitops_diagnosis_against_a_live_cluster() {
        let (Ok(context), Ok(namespace), Ok(app)) = (
            std::env::var("GITOPS_DIAG_TEST_CONTEXT"),
            std::env::var("GITOPS_DIAG_TEST_NS"),
            std::env::var("GITOPS_DIAG_TEST_APP"),
        ) else {
            eprintln!("GITOPS_DIAG_TEST_* not set — skipping");
            return;
        };

        // The scan on its own first, so the payload's diff section can be read
        // against what the cluster actually held.
        let started = std::time::Instant::now();
        let bounded = k8s::get_gitops_diff_scan(
            &context,
            &namespace,
            &app,
            Some(k8s::DiffScanLimit { max_reads: DIAGNOSE_DIFF_READS, enough: DIAGNOSE_DIFF_RESOURCES }),
        )
        .await
        .expect("scan");
        let bounded_ms = started.elapsed().as_millis();

        let started = std::time::Instant::now();
        let unbounded = k8s::get_gitops_diff_scan(&context, &namespace, &app, None).await.expect("scan");
        let unbounded_ms = started.elapsed().as_millis();

        eprintln!(
            "candidates={} | bounded examined={} ({bounded_ms}ms) | unbounded examined={} ({unbounded_ms}ms)",
            bounded.candidates, bounded.examined, unbounded.examined
        );
        // Both lists, labelled. The counts alone cannot show *which* resources
        // the diagnosis actually looked at, and the whole point of comparing
        // the two scans is that the bounded one may have stopped somewhere
        // specific — reading that off requires seeing its rows.
        for (label, scan) in [("bounded", &bounded), ("unbounded", &unbounded)] {
            eprintln!("  --- {label} ({} resource(s)) ---", scan.diffs.len());
            for d in &scan.diffs {
                eprintln!(
                    "    {}/{} {} drift={} desired_available={} error={:?}",
                    if d.namespace.is_empty() { "cluster" } else { &d.namespace },
                    d.name,
                    d.kind,
                    d.has_drift(),
                    d.desired_available,
                    d.error
                );
            }
        }

        let started = std::time::Instant::now();
        let payload = build_gitops_diagnosis_payload(&context, &namespace, &app)
            .await
            .expect("payload should build");
        eprintln!(
            "\npayload: {} bytes / {} chars, ~{} tokens, built in {}ms\nredaction: {}",
            payload.prompt.len(),
            payload.prompt.chars().count(),
            payload.approx_tokens,
            started.elapsed().as_millis(),
            payload.redaction_summary
        );

        // Status, events and drift — the manifest would bury them.
        let head = payload.prompt.split("## Manifest").next().unwrap_or(&payload.prompt);
        eprintln!("\n--- payload (manifest omitted) ---\n{}", truncate_on_char_boundary(head, 4000));
    }

    fn rev(revision: i64, status: &str, description: &str, at: &str) -> crate::models::HelmRevisionInfo {
        crate::models::HelmRevisionInfo {
            revision,
            status: status.into(),
            description: description.into(),
            deployed_at: Some(at.into()),
        }
    }

    #[test]
    fn a_failure_that_repeats_collapses_into_one_entry_with_a_span() {
        // The real shape this exists for: one release had fifteen identical
        // RBAC denials an hour apart. Listed individually they would crowd the
        // values and the inventory out of the payload while saying one thing.
        let out = render_helm_history(&[
            rev(75, "failed", "Upgrade failed: forbidden", "2026-08-24T15:19:28Z"),
            rev(74, "failed", "Upgrade failed: forbidden", "2026-08-24T14:19:09Z"),
            rev(73, "failed", "Upgrade failed: forbidden", "2026-08-24T13:18:50Z"),
        ]);
        assert!(out.contains("v73–v75 (3× failed)"), "{out}");
        assert!(out.contains("between 2026-08-24T13:18:50Z and 2026-08-24T15:19:28Z"), "{out}");
        assert_eq!(out.matches("Upgrade failed: forbidden").count(), 1, "{out}");
    }

    #[test]
    fn a_success_between_failures_is_not_collapsed_away() {
        // Two outages either side of a working release is a different story
        // from one continuous outage, and merging them would delete the
        // evidence that it ever worked.
        let out = render_helm_history(&[
            rev(4, "failed", "Upgrade failed: forbidden", "d"),
            rev(3, "deployed", "Upgrade complete", "c"),
            rev(2, "failed", "Upgrade failed: forbidden", "b"),
            rev(1, "deployed", "Install complete", "a"),
        ]);
        assert_eq!(out.matches("Upgrade failed: forbidden").count(), 2, "{out}");
        assert!(out.contains("v4 (failed)") && out.contains("v2 (failed)"), "{out}");
        assert!(!out.contains("×"), "nothing should collapse here: {out}");
    }


    #[test]
    fn a_description_naming_every_failing_resource_is_capped() {
        // Helm joins one clause per resource with ` && `. A webhook outage on
        // a large chart produced 65 kB of the same sentence with forty
        // different resource names, which alone took the payload to 18k
        // tokens — the cap is on the description because that is where the
        // pathology is, not in the payload as a whole.
        // Clause length matters as much as the count: the real ones carry a
        // full admission URL, which is most of the 65 kB.
        let clause = "cannot patch \"vmks-victoria-metrics-k8s-stack-etcd\" with kind VMRule: Internal error \
occurred: failed calling webhook \"vmrules.operator.victoriametrics.com\": failed to call webhook: Post \
\"https://vmks-victoria-metrics-operator.vmks.svc:9443/validate-operator-victoriametrics-com-v1beta1-vmrule?timeout=10s\": \
no endpoints available for service \"vmks-victoria-metrics-operator\"";
        let huge = std::iter::repeat(clause).take(40).collect::<Vec<_>>().join(" && ");
        assert!(huge.len() > DIAGNOSE_DESCRIPTION_CHARS * 4, "the fixture must actually be oversized");

        let out = render_helm_history(&[rev(9, "failed", &huge, "t")]);
        assert!(out.len() < huge.len() / 2, "should be much shorter: {} vs {}", out.len(), huge.len());
        assert!(out.contains("description truncated"), "{out}");
        assert!(out.contains(&format!("{} chars in total", huge.len())), "{out}");
        // The cause survives the cut.
        assert!(out.contains("failed calling webhook"), "{out}");
    }

    #[test]
    fn revisions_whose_payload_was_not_opened_say_so() {
        // Only the newest revision and the newest failures are decoded, so a
        // superseded success has no description. Blank would read as "Helm
        // recorded nothing", which is a different claim.
        let out = render_helm_history(&[crate::models::HelmRevisionInfo {
            revision: 9,
            status: "superseded".into(),
            description: String::new(),
            deployed_at: None,
        }]);
        assert!(out.contains("not opened"), "{out}");
        // Says why, rather than leaving a blank that reads as "Helm recorded
        // nothing" or as a repeat of the failure printed above it.
        assert!(out.contains("unknown"), "{out}");
    }

    #[test]
    fn an_empty_history_does_not_render_as_nothing() {
        assert_eq!(render_helm_history(&[]), "(no revision history)");
    }
}
