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

// ---------------------------------------------------------------------------
// Pod diagnosis
// ---------------------------------------------------------------------------

/// Log lines included in a diagnosis. Enough for a crashloop's story without
/// dominating the payload — and the trim is always disclosed, never silent.
const DIAGNOSE_LOG_LINES: usize = 200;
/// Fetched before trimming, so `tail_lines` has a real tail to choose from.
const DIAGNOSE_LOG_FETCH_LINES: i64 = 400;
/// Diagnosis reasons over several documents at once — status, events,
/// manifest and logs — so it gets generous headroom. Streaming means the large
/// ceiling costs nothing in timeout risk.
const DIAGNOSE_MAX_TOKENS: u32 = 32_000;
/// Root-causing a crashloop is the intelligence-sensitive case in this app;
/// terser settings produce plausible-but-shallow answers here.
const DIAGNOSE_EFFORT: &str = "high";

const DIAGNOSE_SYSTEM: &str = "\
You diagnose failing Kubernetes pods for an experienced SRE.

You are given a pod's status, its recent events, its manifest, recent \
container logs, and — when the container has restarted — the logs of its \
previous instance, which is usually where the crash itself is written. \
Respond with:
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
the pod least likely to be healthy — with its previous instance's logs when \
it has restarted, usually where the crash itself is written. Respond with:
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

const DIAGNOSE_NODE_SYSTEM: &str = "\
You diagnose Kubernetes nodes for an experienced SRE.

You are given the node's identity and capacity, every condition the cluster \
reports on it, its taints, its recent events, the pods it is holding, and its \
manifest. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the condition message, the \
event, or the taint.
3. Concrete next steps: the exact command to run or setting to change.

`Ready` is the only condition where True is good. Every other one — \
MemoryPressure, DiskPressure, KernelDeadlock, FrequentKubeletRestart, \
VMEventScheduled and the rest — reports a problem when True. Conditions that \
are False are listed by name only, because their messages are boilerplate; \
that they were checked and are clear is the useful part.

Separate a node fault from a workload fault. A node whose kubelet, disk, \
kernel or underlying VM is unwell is a node problem, and the condition \
message usually names it. A Ready node holding crashing pods is not: the pods \
are listed here so you can see that is the case, and the answer is to \
diagnose the workload rather than the node.

A cordoned or draining node whose pods will not leave is usually held by a \
PodDisruptionBudget or a do-not-disrupt annotation, and the events name the \
pod responsible. Say which one, not just that draining is blocked.

There are no live CPU or memory readings here. The pressure conditions are \
the cluster's own answer to that question, so use them rather than \
speculating about utilisation.

`status.images` is omitted from the manifest — it is the node's image cache, \
and on a real node it is nearly half the object.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over \
a list of possibilities. If the evidence is genuinely insufficient, say so \
and name what would settle it.

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

const DIAGNOSE_NAP_SYSTEM: &str = "\
You diagnose Karpenter NodePools (AKS Node Auto Provisioning) for an \
experienced SRE.

You are given the pool's policy and status — requirements, limits and how \
much of them is provisioned, disruption settings and budgets — its \
conditions, every NodeClaim it owns with the state of each claim's node, the \
events on the pool and on its claims and nodes, the scheduling failures \
Karpenter reported against this pool, the node class it launches from, and \
its manifest. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the condition, the claim, \
the event, or the field.
3. Concrete next steps: the exact command to run or field to change.

Say which failure you are looking at, because each has a different fix:
- Not provisioning: pods stay pending. Karpenter's scheduling failures say \
why — the requirements exclude what the pod asks for, a limit is reached \
(compare provisioned with the limit), or no instance type fits. Azure \
refusing the VM — quota, a size unavailable in the zone, a subnet out of \
addresses — shows as a claim that never reaches Launched, and in its events.
- Not becoming ready: a claim launched but never Registered or Initialized. \
That is node bootstrap, networking or the image, and the claim's and the \
node class's conditions usually say which.
- Not disrupting: drift, expiry or consolidation is due but nodes are held — \
a budget of zero for that reason, a do-not-disrupt annotation, or a \
PodDisruptionBudget. Karpenter names the blocker in DisruptionBlocked and \
Unconsolidatable events; name it too.
- Churning: nodes replaced over and over — consolidation fighting a workload \
that scales, or an expireAfter too short for what runs there.

On the pool, its node class and its claims, True is healthy for Ready, \
Launched, Registered, Initialized and the other *Ready and *Succeeded \
conditions. Drifted, Empty, Consolidatable and Expired being True marks a \
claim for replacement: routine on a healthy pool, a problem only when the \
claim stays that way.

Provisioned is the capacity of the nodes the pool owns, which is what its \
limits bound — not utilisation. There are no CPU or memory readings here. \
Pending pods whose failures do not name this pool are not listed, so an empty \
scheduling section means Karpenter has not blamed this pool for any pod.

Be direct; assume fluency with kubectl and Karpenter. Prefer one \
well-supported cause over a list of possibilities. If the evidence is \
genuinely insufficient, say so and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

const DIAGNOSE_HPA_SYSTEM: &str = "\
You diagnose Kubernetes HorizontalPodAutoscalers for an experienced SRE.

You are given the HPA's replica bounds and counts, its conditions, each \
metric against its target, its scaling behavior, its events, the object it \
scales, the requests and live usage of every container in the pods it \
averages over, whether the metrics APIs it reads from are available, and its \
manifest. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the condition message, the \
event, the container, or the field.
3. Concrete next steps: the exact command to run or field to change.

Say which of these you are looking at, because the fixes differ:
- Cannot read a metric (ScalingActive False, a metric with no reading): a \
utilization target needs a request for that resource on every container in \
every pod, sidecars included — one injected by a webhook is not in the \
workload's template, so the template looking right does not settle it; read \
the container table. Otherwise the metrics API serving it is unavailable or \
the metric does not exist under that name or selector.
- At a bound (ScalingLimited True): it wants more or fewer replicas than \
min or max allow. Say which, and whether the bound or the load is wrong.
- Scaling, but not as expected: the behavior's stabilization windows and \
policies are slowing or capping it, or the target is computed over pods that \
are not ready.
- Fighting something: another controller — a second HPA, KEDA, or a \
GitOps tool resetting replicas — writes the same field.

An HPA owned by a KEDA ScaledObject is generated from it; the fix belongs in \
the ScaledObject, not the HPA.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over \
a list of possibilities. If the evidence is genuinely insufficient, say so \
and name what would settle it.

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
/// Measured against both fleets on 2026-09-23: example-dev-ns's 116 Applications had
/// no not-Synced resources at all, and example-prod-ns's 68 had thirteen between
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

/// How many of a node's pods go into a diagnosis, worst first.
const DIAGNOSE_NODE_PODS: usize = 25;

/// Splits a node's conditions into the ones reporting a problem and the names
/// of the ones that are clear.
///
/// Pure, because the polarity is the part worth pinning down: `Ready` is the
/// only condition where True is the good state, and getting that backwards
/// would either drop the one condition that matters or report every healthy
/// node as broken. Both mistakes look plausible in a diff.
fn split_node_conditions(
    conditions: &[k8s_openapi::api::core::v1::NodeCondition],
) -> (Vec<String>, Vec<String>) {
    let mut problems = Vec::new();
    let mut clear = Vec::new();
    for c in conditions {
        let reports_problem = if c.type_ == "Ready" { c.status != "True" } else { c.status == "True" };
        if reports_problem {
            let mut line = format!("{}={}", c.type_, c.status);
            if let Some(reason) = c.reason.as_deref().filter(|r| !r.is_empty()) {
                line.push_str(&format!(" ({reason})"));
            }
            if let Some(at) = c.last_transition_time.as_ref() {
                line.push_str(&format!(" since {}", at.0.to_rfc3339()));
            }
            if let Some(message) = c.message.as_deref().filter(|m| !m.is_empty()) {
                line.push_str(&format!("\n  {message}"));
            }
            problems.push(line);
        } else {
            clear.push(c.type_.clone());
        }
    }
    (problems, clear)
}

/// Renders the pods a node is holding.
///
/// Pure, and separate, because of the distinction it has to keep: a node whose
/// pods could not be listed is not a node with no pods. Collapsing the two —
/// which is what `unwrap_or_default` did here — hands the model "no pods on
/// this node" as a fact when the truth is that nobody looked, and a node
/// holding a crashing workload would then read as idle.
fn render_node_pods(pods: &Result<Vec<crate::k8s::NodePodSummary>, String>) -> String {
    let pods = match pods {
        Ok(pods) => pods,
        Err(e) => return format!("(pods unavailable: {e})"),
    };
    if pods.is_empty() {
        return "(no pods on this node)".to_string();
    }
    let unhealthy = pods.iter().filter(|p| !p.healthy).count();
    let mut out = format!(
        "{} pod(s), {unhealthy} not running cleanly. Worst first:\n{}",
        pods.len(),
        pods.iter()
            .take(DIAGNOSE_NODE_PODS)
            .map(|p| format!("{}/{}  {}  ready {}  restarts {}", p.namespace, p.name, p.phase, p.ready, p.restarts))
            .collect::<Vec<_>>()
            .join("\n")
    );
    if pods.len() > DIAGNOSE_NODE_PODS {
        out.push_str(&format!("\n… and {} more", pods.len() - DIAGNOSE_NODE_PODS));
    }
    out
}

/// Assembles everything a node diagnosis needs, redacted.
///
/// The conditions are the part no other subject has, and on a real fleet they
/// are the *only* part that moves: across 185 nodes every one was `Ready`, and
/// the single node worth looking at was flagged by `VMEventScheduled` — a
/// scheduled Azure redeploy after a VM fault, invisible in readiness.
pub async fn build_node_diagnosis_payload(
    context_name: &str,
    node_name: &str,
) -> Result<ClaudeDiagnosisPayload, String> {
    let d = crate::k8s::get_node_diagnostics(context_name, node_name).await?;

    let spec = d.node.spec.clone().unwrap_or_default();
    let node_status = d.node.status.clone().unwrap_or_default();
    let info = node_status.node_info.clone();
    let label = |key: &str| {
        d.node
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(key))
            .cloned()
            .unwrap_or_else(|| "(none)".to_string())
    };
    let quantity = |map: &Option<std::collections::BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>>, key: &str| {
        map.as_ref().and_then(|m| m.get(key)).map(|q| q.0.clone()).unwrap_or_else(|| "(unknown)".to_string())
    };

    let status = format!(
        "schedulable: {}\nkubelet: {}\nOS image: {}\ncontainer runtime: {}\ninstance type: {}\nnode pool: {}\nzone: {}\ncpu capacity/allocatable: {} / {}\nmemory capacity/allocatable: {} / {}\npods on this node: {}",
        if spec.unschedulable.unwrap_or(false) { "no (cordoned)" } else { "yes" },
        info.as_ref().map(|i| i.kubelet_version.clone()).unwrap_or_default(),
        info.as_ref().map(|i| i.os_image.clone()).unwrap_or_default(),
        info.as_ref().map(|i| i.container_runtime_version.clone()).unwrap_or_default(),
        label("node.kubernetes.io/instance-type"),
        label("karpenter.sh/nodepool"),
        label("topology.kubernetes.io/zone"),
        quantity(&node_status.capacity, "cpu"),
        quantity(&node_status.allocatable, "cpu"),
        quantity(&node_status.capacity, "memory"),
        quantity(&node_status.allocatable, "memory"),
        match &d.pods {
            Ok(pods) => pods.len().to_string(),
            Err(_) => "(could not be listed)".to_string(),
        },
    );

    let (problems, clear) = split_node_conditions(node_status.conditions.as_deref().unwrap_or_default());
    let mut conditions_text = if problems.is_empty() {
        "(no condition reports a problem)".to_string()
    } else {
        problems.join("\n")
    };
    if !clear.is_empty() {
        conditions_text.push_str(&format!("\n\nchecked and clear: {}", clear.join(", ")));
    }

    let taints = spec.taints.unwrap_or_default();
    let taints_text = if taints.is_empty() {
        "(none)".to_string()
    } else {
        taints
            .iter()
            .map(|t| format!("{}={} :{}", t.key, t.value.clone().unwrap_or_default(), t.effect))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let events_text = match &d.events {
        Ok(list) if list.is_empty() => "(no events for this node)".to_string(),
        Ok(list) => list
            .iter()
            .take(25)
            .map(|e| format!("[{}] {} — {} (×{})", e.event_type, e.reason, e.message, e.count))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("(events unavailable: {e})"),
    };

    let pods_text = render_node_pods(&d.pods);

    let manifest_text = node_manifest_without_images(&d.node)?;

    let status = redact::redact(&status);
    let conditions_r = redact::redact(&conditions_text);
    let taints_r = redact::redact(&taints_text);
    let events_r = redact::redact(&events_text);
    let pods_r = redact::redact(&pods_text);
    let manifest_r = redact::redact(&manifest_text);

    let redaction_summary =
        redact::Redacted::merge([&status, &conditions_r, &taints_r, &events_r, &pods_r, &manifest_r]).summary();

    let prompt = format!(
        "Node {node_name}.\n\n\
         ## Status\n{}\n\n\
         ## Conditions\n{}\n\n\
         ## Taints\n{}\n\n\
         ## Events\n{}\n\n\
         ## Pods on this node\n{}\n\n\
         ## Manifest (managed fields and status.images omitted)\n```yaml\n{}\n```",
        status.text, conditions_r.text, taints_r.text, events_r.text, pods_r.text, manifest_r.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note: None,
    })
}

/// The node as YAML, without managed fields or the image cache.
///
/// `status.images` is every container image the kubelet has pulled, with all
/// of its digests: 6,528 of one real node's 15,089 characters. It says
/// nothing about why a node is unwell, and dropping it is most of the reason
/// this payload stays small enough to include the manifest at all.
fn node_manifest_without_images(node: &k8s_openapi::api::core::v1::Node) -> Result<String, String> {
    let mut value = serde_json::to_value(node).map_err(|e| format!("Failed to serialise node: {e}"))?;
    if let Some(metadata) = value.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        metadata.remove("managedFields");
    }
    if let Some(status) = value.get_mut("status").and_then(|m| m.as_object_mut()) {
        status.remove("images");
    }
    if let Some(object) = value.as_object_mut() {
        object.insert("apiVersion".to_string(), serde_json::json!("v1"));
        object.insert("kind".to_string(), serde_json::json!("Node"));
    }
    serde_yaml::to_string(&value).map_err(|e| format!("Failed to render node YAML: {e}"))
}

/// How many NodeClaims go into a NodePool diagnosis, worst first.
///
/// The healthy rest are counted, not listed: a pool of ninety Ready claims
/// says the same thing in one line as in ninety.
const DIAGNOSE_NAP_CLAIMS: usize = 30;

/// How many events from the pool's claims and nodes go in, newest first.
const DIAGNOSE_NAP_MEMBER_EVENTS: usize = 30;

/// How many distinct scheduling failures go in.
///
/// Karpenter writes one per pending pod per attempt, near-identical, so they
/// are collapsed on the message first and this caps the distinct ones.
const DIAGNOSE_NAP_SCHEDULING: usize = 12;

/// How much of one scheduling failure's message to send. Karpenter appends
/// the pod's requests and every requirement it compared, which runs long.
const DIAGNOSE_NAP_MESSAGE_CHARS: usize = 800;

/// Karpenter conditions where True marks a claim for replacement rather than
/// saying it is healthy. Every other condition — Ready, Launched,
/// Registered, Initialized, the pool's and the node class's — is healthy
/// when True, which is also the safer reading of one this list has not
/// heard of.
const KARPENTER_MARKING_CONDITIONS: [&str; 5] = ["Drifted", "Empty", "Consolidatable", "Expired", "Disrupting"];

/// A Karpenter object's conditions, split into the ones to read and the ones
/// that are clear — the same split as `split_node_conditions`, with
/// Karpenter's polarity.
fn split_karpenter_conditions(obj: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let mut notable = Vec::new();
    let mut clear = Vec::new();
    let conditions = obj.pointer("/status/conditions").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    for c in &conditions {
        let field = |k: &str| c.get(k).and_then(|v| v.as_str()).unwrap_or_default();
        let (kind, status) = (field("type"), field("status"));
        let marks = KARPENTER_MARKING_CONDITIONS.contains(&kind);
        if (marks && status != "True") || (!marks && status == "True") {
            clear.push(kind.to_string());
            continue;
        }
        let mut line = format!("{kind}={status}");
        if !field("reason").is_empty() {
            line.push_str(&format!(" ({})", field("reason")));
        }
        if !field("lastTransitionTime").is_empty() {
            line.push_str(&format!(" since {}", field("lastTransitionTime")));
        }
        if !field("message").is_empty() {
            line.push_str(&format!("\n  {}", field("message")));
        }
        notable.push(line);
    }
    (notable, clear)
}

fn render_karpenter_conditions(obj: &serde_json::Value) -> String {
    let (notable, clear) = split_karpenter_conditions(obj);
    let mut out = if notable.is_empty() { "(no condition reports a problem)".to_string() } else { notable.join("\n") };
    if !clear.is_empty() {
        out.push_str(&format!("\n\nchecked and clear: {}", clear.join(", ")));
    }
    out
}

/// A pool resource as a reader would say it: cores, GiB, or a count.
fn render_nap_quantity(unit: &str, value: i64) -> String {
    match unit {
        "millicores" => format!("{} cores", trim_decimal(value as f64 / 1000.0)),
        "ki" => format!("{} GiB", trim_decimal(value as f64 / 1_048_576.0)),
        _ => value.to_string(),
    }
}

fn trim_decimal(v: f64) -> String {
    let s = format!("{v:.1}");
    s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
}

/// The pool's policy, as the facts a diagnosis turns on.
fn render_nap_status(detail: &crate::models::NapDetail, nodes: i64) -> String {
    let or_none = |v: &[String]| if v.is_empty() { "(none)".to_string() } else { v.join(", ") };
    let mut lines = vec![format!("nodes owned: {nodes}")];
    for r in &detail.resources {
        let limit = r.limit.map(|l| render_nap_quantity(&r.unit, l)).unwrap_or_else(|| "no limit".to_string());
        lines.push(format!("{} provisioned / limit: {} / {limit}", r.name, render_nap_quantity(&r.unit, r.used)));
    }
    lines.push(format!("weight: {}", detail.weight.map(|w| w.to_string()).unwrap_or_else(|| "(none)".to_string())));
    lines.push(format!("node class: {} {}", detail.node_class_kind, detail.node_class_name));
    lines.push("requirements:".to_string());
    if detail.requirements.is_empty() {
        lines.push("  (none)".to_string());
    }
    for r in &detail.requirements {
        let min = r.min_values.map(|m| format!(" (at least {m} values)")).unwrap_or_default();
        lines.push(format!("  {} {} [{}]{min}", r.key, r.operator, r.values.join(", ")));
    }
    lines.push(format!("taints: {}", or_none(&detail.taints)));
    lines.push(format!("startup taints: {}", or_none(&detail.startup_taints)));
    lines.push(format!("expire after: {}", detail.expire_after));
    lines.push(format!(
        "termination grace period: {}",
        if detail.termination_grace_period.is_empty() { "(none — a drain may wait forever)" } else { &detail.termination_grace_period }
    ));
    lines.push(format!(
        "consolidation: {}{}",
        detail.consolidation_policy,
        if detail.consolidate_after.is_empty() { String::new() } else { format!(" after {}", detail.consolidate_after) }
    ));
    lines.push(format!("disruption budgets{}:", if detail.budgets_default { " (none set; Karpenter's default)" } else { "" }));
    for b in &detail.budgets {
        let mut line = format!("  nodes {}", b.nodes);
        if !b.reasons.is_empty() {
            line.push_str(&format!(" for {}", b.reasons.join(", ")));
        }
        if !b.schedule.is_empty() {
            line.push_str(&format!(", schedule {} for {}", b.schedule, b.duration));
        }
        lines.push(line);
    }
    lines.join("\n")
}

/// The pool's NodeClaims, worst first, each with the state of its node.
///
/// Pure, and separate, because the ordering is the point: a pool's one stuck
/// claim must not sit below thirty healthy ones and fall off the cap.
fn render_nap_claims(
    claims: &Result<Vec<kube::api::DynamicObject>, String>,
    nodes: &Result<Vec<k8s_openapi::api::core::v1::Node>, String>,
) -> String {
    let claims = match claims {
        Ok(c) if c.is_empty() => return "(this pool owns no NodeClaims)".to_string(),
        Ok(c) => c,
        Err(e) => return format!("(NodeClaims unavailable: {e})"),
    };
    let node_state = |name: &str| -> String {
        let nodes = match nodes {
            Ok(n) => n,
            Err(_) => return "node state unknown (nodes could not be listed)".to_string(),
        };
        let Some(node) = nodes.iter().find(|n| n.metadata.name.as_deref() == Some(name)) else {
            return format!("node {name} not found");
        };
        let ready = node
            .status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .and_then(|c| c.iter().find(|c| c.type_ == "Ready"))
            .map(|c| c.status.as_str())
            .unwrap_or("Unknown");
        let mut parts = vec![format!("node {name} Ready={ready}")];
        let spec = node.spec.as_ref();
        if spec.and_then(|s| s.unschedulable).unwrap_or(false) {
            parts.push("cordoned".to_string());
        }
        for t in spec.and_then(|s| s.taints.as_ref()).into_iter().flatten() {
            if t.key.starts_with("karpenter.sh/") {
                parts.push(format!("tainted {}:{}", t.key, t.effect));
            }
        }
        parts.join(", ")
    };

    let mut rows: Vec<(u8, String)> = claims
        .iter()
        .map(|c| {
            let v = serde_json::to_value(c).unwrap_or_default();
            let label = |k: &str| c.metadata.labels.as_ref().and_then(|l| l.get(k)).cloned().unwrap_or_default();
            let (notable, _) = split_karpenter_conditions(&v);
            let ready = v
                .pointer("/status/conditions")
                .and_then(|c| c.as_array())
                .and_then(|c| c.iter().find(|c| c.get("type").and_then(|t| t.as_str()) == Some("Ready")))
                .and_then(|c| c.get("status").and_then(|s| s.as_str()))
                == Some("True");
            let deleting = c.metadata.deletion_timestamp.as_ref().map(|t| t.0.to_rfc3339());
            let mut line = format!(
                "{}  {}  {}  {}",
                c.metadata.name.clone().unwrap_or_default(),
                label("node.kubernetes.io/instance-type"),
                label("karpenter.sh/capacity-type"),
                label("topology.kubernetes.io/zone"),
            );
            if let Some(created) = c.metadata.creation_timestamp.as_ref() {
                line.push_str(&format!("  created {}", created.0.to_rfc3339()));
            }
            if let Some(at) = &deleting {
                line.push_str(&format!("  TERMINATING since {at}"));
            }
            match v.pointer("/status/nodeName").and_then(|n| n.as_str()).filter(|n| !n.is_empty()) {
                Some(n) => line.push_str(&format!("\n  {}", node_state(n))),
                None => line.push_str("\n  no node registered"),
            }
            for n in &notable {
                line.push_str(&format!("\n  {}", n.replace('\n', "\n  ")));
            }
            // Worst first: not Ready, then terminating, then marked, then fine.
            let rank = if !ready { 0 } else if deleting.is_some() { 1 } else if !notable.is_empty() { 2 } else { 3 };
            (rank, line)
        })
        .collect();
    rows.sort_by_key(|(rank, _)| *rank);

    let count = |r: u8| rows.iter().filter(|(rank, _)| *rank == r).count();
    let mut out = format!(
        "{} claim(s): {} not Ready, {} terminating, {} marked for replacement, {} Ready with nothing pending",
        rows.len(),
        count(0),
        count(1),
        count(2),
        count(3)
    );
    for (_, line) in rows.iter().take(DIAGNOSE_NAP_CLAIMS) {
        out.push_str(&format!("\n{line}"));
    }
    if rows.len() > DIAGNOSE_NAP_CLAIMS {
        out.push_str(&format!("\n… and {} more, all Ready with nothing pending", rows.len() - DIAGNOSE_NAP_CLAIMS));
    }
    out
}

fn render_nap_events(events: &Result<Vec<crate::models::EventInfo>, String>, empty: &str, with_object: bool, cap: usize) -> String {
    match events {
        Ok(list) if list.is_empty() => empty.to_string(),
        Ok(list) => {
            let mut out = list
                .iter()
                .take(cap)
                .map(|e| {
                    let object = if with_object { format!(" {}", e.involved_object) } else { String::new() };
                    format!("[{}] {}{object} — {} (×{})", e.event_type, e.reason, e.message, e.count)
                })
                .collect::<Vec<_>>()
                .join("\n");
            if list.len() > cap {
                out.push_str(&format!("\n… and {} older", list.len() - cap));
            }
            out
        }
        Err(e) => format!("(events unavailable: {e})"),
    }
}

/// Karpenter's scheduling failures against this pool, collapsed on the message.
///
/// One pending pod produces one event per attempt and a scaled-out workload
/// produces one per pod, all saying the same thing; listed as they come, the
/// first dozen would be one failure repeated. Collapsed, they read as which
/// failures there are and how many pods each holds back.
fn render_nap_scheduling(events: &Result<Vec<crate::models::EventInfo>, String>) -> String {
    let list = match events {
        Ok(list) if list.is_empty() => return "(Karpenter reports no pod it could not place on this pool)".to_string(),
        Ok(list) => list,
        Err(e) => return format!("(scheduling failures unavailable: {e})"),
    };
    // (message, pods, latest, example pod), in order of first sighting — the
    // list is newest first, so that is also newest first.
    let mut groups: Vec<(String, std::collections::BTreeSet<String>, Option<String>, String)> = Vec::new();
    for e in list {
        let pod = format!("{}/{}", e.object_namespace, e.object_name);
        match groups.iter_mut().find(|g| g.0 == e.message) {
            Some(g) => {
                g.1.insert(pod);
            }
            None => groups.push((e.message.clone(), std::iter::once(pod.clone()).collect(), e.last_seen.clone(), pod)),
        }
    }
    let mut out = groups
        .iter()
        .take(DIAGNOSE_NAP_SCHEDULING)
        .map(|(message, pods, latest, example)| {
            let message = if message.len() > DIAGNOSE_NAP_MESSAGE_CHARS {
                format!("{} …", truncate_on_char_boundary(message, DIAGNOSE_NAP_MESSAGE_CHARS))
            } else {
                message.clone()
            };
            format!(
                "{} pod(s), e.g. {example}{}:\n  {message}",
                pods.len(),
                latest.as_ref().map(|t| format!(", latest {t}")).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    if groups.len() > DIAGNOSE_NAP_SCHEDULING {
        out.push_str(&format!("\n… and {} more distinct failures", groups.len() - DIAGNOSE_NAP_SCHEDULING));
    }
    out
}

/// Assembles everything a NodePool diagnosis needs, redacted.
///
/// A pool's own status is the part least likely to explain anything: it
/// stays Ready while every claim it launches fails to register, and its
/// limits are reached silently. The claims and Karpenter's scheduling
/// failures are where provisioning problems show, so they carry the weight.
pub async fn build_nap_diagnosis_payload(context_name: &str, name: &str) -> Result<ClaudeDiagnosisPayload, String> {
    let d = k8s::get_nap_diagnostics(context_name, name).await?;
    let detail = crate::nap_detail::nap_detail(&d.pool);
    let pool_value = serde_json::to_value(&d.pool).map_err(|e| format!("Failed to serialise NodePool: {e}"))?;
    let nodes_owned = pool_value
        .pointer("/status/resources/nodes")
        .and_then(|n| n.as_str())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);

    let status = render_nap_status(&detail, nodes_owned);
    let conditions = render_karpenter_conditions(&pool_value);
    let claims = render_nap_claims(&d.claims, &d.nodes);
    let pool_events = render_nap_events(&d.pool_events, "(no events for this NodePool)", false, 25);
    let member_events = render_nap_events(
        &d.member_events,
        "(no events on this pool's claims or nodes)",
        true,
        DIAGNOSE_NAP_MEMBER_EVENTS,
    );
    let scheduling = render_nap_scheduling(&d.pod_events);
    let (node_class_heading, node_class_text) = match d.node_class {
        Ok(Some(nc)) => {
            let value = serde_json::to_value(&nc).unwrap_or_default();
            let heading = format!("{} {}", detail.node_class_kind, detail.node_class_name);
            let yaml = k8s::object_manifest(nc)
                .map(|m| m.yaml_without_managed_fields)
                .unwrap_or_else(|e| format!("(could not be rendered: {e})"));
            (heading, format!("{}\n\n```yaml\n{yaml}\n```", render_karpenter_conditions(&value)))
        }
        Ok(None) => ("".to_string(), "(the pool names no node class)".to_string()),
        Err(e) => (
            format!("{} {}", detail.node_class_kind, detail.node_class_name),
            format!("(node class unavailable: {e})"),
        ),
    };
    let manifest = k8s::object_manifest(d.pool)?.yaml_without_managed_fields;

    let status = redact::redact(&status);
    let conditions_r = redact::redact(&conditions);
    let claims_r = redact::redact(&claims);
    let pool_events_r = redact::redact(&pool_events);
    let member_events_r = redact::redact(&member_events);
    let scheduling_r = redact::redact(&scheduling);
    let node_class_r = redact::redact(&node_class_text);
    let manifest_r = redact::redact(&manifest);

    let redaction_summary = redact::Redacted::merge([
        &status,
        &conditions_r,
        &claims_r,
        &pool_events_r,
        &member_events_r,
        &scheduling_r,
        &node_class_r,
        &manifest_r,
    ])
    .summary();

    let prompt = format!(
        "NodePool {name}.\n\n\
         ## Policy and status\n{}\n\n\
         ## Conditions\n{}\n\n\
         ## NodeClaims (worst first)\n{}\n\n\
         ## Events (NodePool)\n{}\n\n\
         ## Events (its claims and nodes)\n{}\n\n\
         ## Pods Karpenter could not place on this pool\n{}\n\n\
         ## Node class{}\n{}\n\n\
         ## Manifest (managed fields omitted)\n```yaml\n{}\n```",
        status.text,
        conditions_r.text,
        claims_r.text,
        pool_events_r.text,
        member_events_r.text,
        scheduling_r.text,
        if node_class_heading.is_empty() { String::new() } else { format!(" ({node_class_heading})") },
        node_class_r.text,
        manifest_r.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note: None,
    })
}

/// How many pods of an HPA's target go into its container table.
///
/// The table is per container across pods, so this only bounds the work; a
/// webhook-injected sidecar is on every pod, and the first few show it.
const DIAGNOSE_HPA_PODS: usize = 50;

/// One utilization target's need for a request: on every container, or on
/// the one a ContainerResource metric names.
struct RequestNeed {
    resource: String,
    container: Option<String>,
    metric: String,
}

/// The requests the HPA's utilization targets need.
///
/// Only a percentage target needs one: utilization is usage over request, and
/// the HPA refuses to compute it for a pod missing the request on any
/// container. An AverageValue target compares raw usage and needs none.
fn hpa_request_needs(metrics: &[crate::models::HpaMetricRow]) -> Vec<RequestNeed> {
    metrics
        .iter()
        .filter(|m| m.target.ends_with('%'))
        .filter_map(|m| match m.kind.as_str() {
            "Resource" => Some(RequestNeed { resource: m.name.clone(), container: None, metric: format!("{} {}", m.name, m.target) }),
            "ContainerResource" => m.name.split_once('/').map(|(c, r)| RequestNeed {
                resource: r.to_string(),
                container: Some(c.to_string()),
                metric: format!("{} {}", m.name, m.target),
            }),
            _ => None,
        })
        .collect()
}

/// Every container in the HPA's pods, with its requests and usage, and which
/// ones lack a request a utilization target needs.
///
/// Read from the pods, not the workload's template, because the two differ
/// exactly where it matters: a sidecar injected by a mutating webhook — a
/// service mesh proxy, a config reloader — is on every pod and in no
/// template, and the HPA fails on it all the same. Per container across pods
/// rather than per pod, since the pods of one workload repeat each other.
fn render_hpa_containers(
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
    usage: &Result<std::collections::HashMap<(String, String), (i64, i64)>, String>,
    needs: &[RequestNeed],
) -> String {
    let pods = match pods {
        Ok(p) if p.is_empty() => return "(the target's selector matches no pods)".to_string(),
        Ok(p) => p,
        Err(e) => return format!("(pods unavailable: {e})"),
    };
    let ready = pods
        .iter()
        .filter(|p| {
            p.status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .is_some_and(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
        })
        .count();

    // (name, sidecar, pods seen in, cpu requests, memory requests, usage samples)
    struct Row {
        name: String,
        sidecar: bool,
        pods: usize,
        cpu: Vec<String>,
        memory: Vec<String>,
        usage: Vec<(i64, i64)>,
    }
    let mut rows: Vec<Row> = Vec::new();
    for pod in pods.iter().take(DIAGNOSE_HPA_PODS) {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let spec = pod.spec.clone().unwrap_or_default();
        // Native sidecars — init containers that keep running — count towards
        // the HPA's requests like any container; one-shot init containers do not.
        let sidecars = spec.init_containers.unwrap_or_default().into_iter().filter(|c| c.restart_policy.as_deref() == Some("Always"));
        let all = spec.containers.into_iter().map(|c| (c, false)).chain(sidecars.map(|c| (c, true)));
        for (c, sidecar) in all {
            let request = |k: &str| {
                c.resources
                    .as_ref()
                    .and_then(|r| r.requests.as_ref())
                    .and_then(|r| r.get(k))
                    .map(|q| q.0.clone())
                    .unwrap_or_else(|| "none".to_string())
            };
            let row = match rows.iter_mut().position(|r| r.name == c.name) {
                Some(i) => &mut rows[i],
                None => {
                    rows.push(Row { name: c.name.clone(), sidecar, pods: 0, cpu: vec![], memory: vec![], usage: vec![] });
                    rows.last_mut().unwrap()
                }
            };
            row.pods += 1;
            row.cpu.push(request("cpu"));
            row.memory.push(request("memory"));
            if let Ok(u) = usage {
                if let Some(sample) = u.get(&(pod_name.clone(), c.name.clone())) {
                    row.usage.push(*sample);
                }
            }
        }
    }
    let sampled = pods.len().min(DIAGNOSE_HPA_PODS);

    // "50m", or "50m in 2, none in 1" when the pods disagree mid-rollout.
    let tally = |values: &[String]| -> String {
        let mut distinct: Vec<(String, usize)> = Vec::new();
        for v in values {
            match distinct.iter_mut().find(|d| &d.0 == v) {
                Some(d) => d.1 += 1,
                None => distinct.push((v.clone(), 1)),
            }
        }
        if distinct.len() == 1 {
            distinct[0].0.clone()
        } else {
            distinct.iter().map(|(v, n)| format!("{v} in {n}")).collect::<Vec<_>>().join(", ")
        }
    };

    let mut out = format!("{} pod(s) matched, {ready} Ready", pods.len());
    if pods.len() > sampled {
        out.push_str(&format!("; containers read from the first {sampled}"));
    }
    if !needs.is_empty() {
        let list = needs
            .iter()
            .map(|n| match &n.container {
                Some(c) => format!("{} on {c} ({})", n.resource, n.metric),
                None => format!("{} on every container ({})", n.resource, n.metric),
            })
            .collect::<Vec<_>>()
            .join("; ");
        out.push_str(&format!("\nutilization targets need a request for: {list}"));
    }
    if let Err(e) = usage {
        out.push_str(&format!("\nusage unavailable: {e}"));
    }
    for r in &rows {
        let mut line = format!(
            "\n{}{} — in {}/{sampled} pods; requests cpu {}, memory {}",
            r.name,
            if r.sidecar { " (native sidecar)" } else { "" },
            r.pods,
            tally(&r.cpu),
            tally(&r.memory)
        );
        if r.usage.is_empty() && usage.is_ok() {
            line.push_str("; metrics-server reports no usage for it in any pod");
        } else if !r.usage.is_empty() {
            let n = r.usage.len() as i64;
            let (cpu, mem) = r.usage.iter().fold((0, 0), |(a, b), (c, m)| (a + c, b + m));
            line.push_str(&format!(
                "; average usage cpu {}m, memory {}Mi over {n} pod(s)",
                cpu / n,
                mem / n / 1024
            ));
        }
        for need in needs.iter().filter(|n| n.container.as_ref().is_none_or(|c| c == &r.name)) {
            let values = if need.resource == "cpu" { &r.cpu } else if need.resource == "memory" { &r.memory } else { continue };
            let missing = values.iter().filter(|v| *v == "none").count();
            if missing > 0 {
                line.push_str(&format!(
                    "\n  MISSING {} request in {missing}/{} pods — the {} target cannot be computed",
                    need.resource, r.pods, need.metric
                ));
            }
        }
        out.push_str(&line);
    }
    // A ContainerResource metric naming a container no pod has fails too.
    for need in needs {
        if let Some(c) = &need.container {
            if !rows.iter().any(|r| &r.name == c) {
                out.push_str(&format!("\nno pod has a container named {c}, which the {} target reads", need.metric));
            }
        }
    }
    out
}

/// The object the HPA scales: its replica counts as the controller reports them.
fn render_hpa_target(target: &Result<kube::api::DynamicObject, String>, selector: &Result<String, String>) -> String {
    let mut out = match target {
        Ok(t) => {
            let v = |p: &str| t.data.pointer(p).and_then(|v| v.as_i64()).map(|n| n.to_string()).unwrap_or_else(|| "(unset)".to_string());
            format!(
                "spec.replicas {}; status: replicas {}, ready {}, updated {}, available {}",
                v("/spec/replicas"),
                v("/status/replicas"),
                v("/status/readyReplicas"),
                v("/status/updatedReplicas"),
                v("/status/availableReplicas"),
            )
        }
        Err(e) => format!("(target unavailable: {e})"),
    };
    match selector {
        Ok(s) => out.push_str(&format!("\nselector (from its scale subresource): {s}")),
        Err(e) => out.push_str(&format!("\nselector unavailable: {e}")),
    }
    out
}

/// Whether each metrics API this HPA reads from is registered and available.
fn render_hpa_metrics_apis(
    metrics: &[crate::models::HpaMetricRow],
    services: &Result<Vec<k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService>, String>,
) -> String {
    let mut groups: Vec<(&str, Vec<String>)> = Vec::new();
    for m in metrics {
        let g = k8s::metrics_api_group(&m.kind);
        match groups.iter_mut().find(|(group, _)| *group == g) {
            Some((_, kinds)) => {
                if !kinds.contains(&m.kind) {
                    kinds.push(m.kind.clone())
                }
            }
            None => groups.push((g, vec![m.kind.clone()])),
        }
    }
    if groups.is_empty() {
        return "(the HPA declares no metrics)".to_string();
    }
    let services = match services {
        Ok(s) => s,
        Err(e) => return format!("(APIServices unavailable: {e})"),
    };
    groups
        .iter()
        .map(|(group, kinds)| {
            let registered: Vec<String> = services
                .iter()
                .filter(|s| s.spec.as_ref().and_then(|sp| sp.group.as_deref()) == Some(*group))
                .map(|s| {
                    let available = s
                        .status
                        .as_ref()
                        .and_then(|st| st.conditions.as_ref())
                        .and_then(|c| c.iter().find(|c| c.type_ == "Available"));
                    let backend = s
                        .spec
                        .as_ref()
                        .and_then(|sp| sp.service.as_ref())
                        .map(|svc| format!(", served by {}/{}", svc.namespace.clone().unwrap_or_default(), svc.name.clone().unwrap_or_default()))
                        .unwrap_or_default();
                    match available {
                        Some(c) if c.status == "True" => format!("{} Available{backend}", s.metadata.name.clone().unwrap_or_default()),
                        Some(c) => format!(
                            "{} Available={} ({}){backend}\n  {}",
                            s.metadata.name.clone().unwrap_or_default(),
                            c.status,
                            c.reason.clone().unwrap_or_default(),
                            c.message.clone().unwrap_or_default()
                        ),
                        None => format!("{} (no Available condition reported){backend}", s.metadata.name.clone().unwrap_or_default()),
                    }
                })
                .collect();
            let state = if registered.is_empty() { "NOT REGISTERED — nothing on the cluster serves it".to_string() } else { registered.join("\n  ") };
            format!("{group} (for {} metrics): {state}", kinds.join(", "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Other HPAs scaling the same object. Two controllers writing one replica
/// count is its own failure — the HPA controller reports it as
/// AmbiguousSelector and stops — and the usual pair is a KEDA-generated HPA
/// beside a hand-written one.
fn render_hpa_siblings(siblings: &Result<Vec<(String, String)>, String>) -> String {
    match siblings {
        Ok(list) if list.is_empty() => "(none — this is the only HPA scaling it)".to_string(),
        Ok(list) => list
            .iter()
            .map(|(name, owner)| if owner.is_empty() { name.clone() } else { format!("{name} (owned by {owner})") })
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("(other HPAs unavailable: {e})"),
    }
}

/// The HPA's own state: bounds, counts, owner, conditions, metrics, behavior.
fn render_hpa_status(d: &crate::models::HpaDetail) -> String {
    let mut lines = vec![
        format!("scales: {}/{}", d.target_kind, d.target_name),
        format!(
            "replicas: min {}, max {}, current {}, desired {}",
            d.min_replicas, d.max_replicas, d.current_replicas, d.desired_replicas
        ),
        format!("last scaled: {}", d.last_scale_at.as_deref().unwrap_or("never")),
    ];
    if !d.owner_kind.is_empty() {
        lines.push(format!("owned by: {}/{}", d.owner_kind, d.owner_name));
    }
    lines.push("metrics (current / target):".to_string());
    if d.metrics.is_empty() {
        lines.push("  (none declared)".to_string());
    }
    for m in &d.metrics {
        lines.push(format!("  {} {}: {} / {}", m.kind, m.name, m.current, m.target));
    }
    lines.push(format!("behavior{}:", if d.behavior_is_default { " (not set; Kubernetes' defaults)" } else { "" }));
    lines.push(format!("  scale up: {}", d.scale_up.join("; ")));
    lines.push(format!("  scale down: {}", d.scale_down.join("; ")));
    lines.join("\n")
}

/// An HPA's conditions: AbleToScale and ScalingActive report a problem when
/// False, ScalingLimited when True.
fn render_hpa_conditions(conditions: &[crate::models::PodConditionInfo]) -> String {
    let mut notable = Vec::new();
    let mut clear = Vec::new();
    for c in conditions {
        let problem = if c.condition_type == "ScalingLimited" { c.status == "True" } else { c.status != "True" };
        if !problem {
            clear.push(c.condition_type.clone());
            continue;
        }
        let mut line = format!("{}={}", c.condition_type, c.status);
        if !c.reason.is_empty() {
            line.push_str(&format!(" ({})", c.reason));
        }
        if let Some(at) = &c.last_transition {
            line.push_str(&format!(" since {at}"));
        }
        if !c.message.is_empty() {
            line.push_str(&format!("\n  {}", c.message));
        }
        notable.push(line);
    }
    let mut out = if conditions.is_empty() {
        "(none reported yet)".to_string()
    } else if notable.is_empty() {
        "(no condition reports a problem)".to_string()
    } else {
        notable.join("\n")
    };
    if !clear.is_empty() {
        out.push_str(&format!("\n\nchecked and clear: {}", clear.join(", ")));
    }
    out
}

/// Assembles everything an HPA diagnosis needs, redacted.
///
/// The HPA's own message usually names the failure — "missing request for
/// memory in container X" — but not why that container has no request or
/// whether every pod is affected. The container table answers that from the
/// pods themselves, and the metrics APIs answer the other common case: the
/// API the metric comes from is down.
pub async fn build_hpa_diagnosis_payload(
    context_name: &str,
    namespace: &str,
    name: &str,
) -> Result<ClaudeDiagnosisPayload, String> {
    let d = k8s::get_hpa_diagnostics(context_name, namespace, name).await?;
    let needs = hpa_request_needs(&d.detail.metrics);

    let status = render_hpa_status(&d.detail);
    let conditions = render_hpa_conditions(&d.detail.conditions);
    let events = render_nap_events(&d.events, "(no events for this HPA)", false, 25);
    let target = render_hpa_target(&d.target, &d.selector);
    let containers = render_hpa_containers(&d.pods, &d.usage, &needs);
    let apis = render_hpa_metrics_apis(&d.detail.metrics, &d.metrics_apis);
    let siblings = render_hpa_siblings(&d.siblings);

    let status = redact::redact(&status);
    let conditions_r = redact::redact(&conditions);
    let events_r = redact::redact(&events);
    let target_r = redact::redact(&target);
    let containers_r = redact::redact(&containers);
    let apis_r = redact::redact(&apis);
    let siblings_r = redact::redact(&siblings);
    let manifest_r = redact::redact(&d.manifest);

    let redaction_summary = redact::Redacted::merge([
        &status,
        &conditions_r,
        &events_r,
        &target_r,
        &siblings_r,
        &containers_r,
        &apis_r,
        &manifest_r,
    ])
    .summary();

    let prompt = format!(
        "HorizontalPodAutoscaler {namespace}/{name}.\n\n\
         ## Status\n{}\n\n\
         ## Conditions\n{}\n\n\
         ## Events\n{}\n\n\
         ## Target ({}/{})\n{}\n\n\
         ## Other HPAs scaling the same target\n{}\n\n\
         ## Containers in the target's pods\n{}\n\n\
         ## Metrics APIs\n{}\n\n\
         ## Manifest (managed fields omitted)\n```yaml\n{}\n```",
        status.text,
        conditions_r.text,
        events_r.text,
        d.detail.target_kind,
        d.detail.target_name,
        target_r.text,
        siblings_r.text,
        containers_r.text,
        apis_r.text,
        manifest_r.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note: None,
    })
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
    // where this copy was raw: a current revision that failed the way example-metrics did
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

    let (manifest_text, first_container) = match manifest {
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
    // The worst pod's failing container, not the template's first: with a
    // healthy sidecar listed first, its logs explain nothing and it has no
    // previous instance, so a crash in the app container would read as "has
    // not restarted". The first container only for a pod with nothing failing.
    let container = worst
        .and_then(|w| w.failure_container.clone())
        .filter(|c| !c.is_empty())
        .unwrap_or(first_container);
    let (logs, previous, pod_events) = match worst {
        Some(worst) => {
            // `container` is empty only when the pod names no failing container
            // and the manifest read failed, in which case there is nothing to
            // ask the log endpoint for.
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
            let previous_fut = async {
                if container.is_empty() {
                    None
                } else {
                    Some(k8s::get_previous_pod_logs(context_name, namespace, &worst.name, &container, DIAGNOSE_LOG_FETCH_LINES).await)
                }
            };
            let events_fut = k8s::get_pod_events(context_name, namespace, &worst.name);
            let (logs, previous, events) = tokio::join!(logs_fut, previous_fut, events_fut);
            (logs, previous, Some(events))
        }
        None => (None, None, None),
    };
    let previous_logs = previous.map(previous_logs_section);

    let (logs_text, current_note, log_source) = match (worst, logs) {
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
    let previous_r = previous_logs.as_ref().map(|p| redact::redact(&p.text));

    let mut parts = vec![&status, &pods_r, &events_r, &pod_events_r, &manifest_r, &logs_r];
    parts.extend(previous_r.as_ref());
    let redaction_summary = redact::Redacted::merge(parts).summary();
    let log_note = combine_log_notes(current_note.clone(), previous_logs.as_ref());

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
         ## Logs{}{}\n```\n{}\n```{}",
        status.text,
        pods_r.text,
        events_r.text,
        log_source.as_ref().map(|p| format!(" {p}")).unwrap_or_default(),
        pod_events_r.text,
        manifest_r.text,
        log_heading,
        current_note.as_ref().map(|n| format!(" ({n})")).unwrap_or_default(),
        logs_r.text,
        previous_logs
            .as_ref()
            .zip(previous_r.as_ref())
            .map(|(p, r)| previous_logs_markdown(p, r, None))
            .unwrap_or_default(),
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
    // Alongside, not after: whether there is a previous instance is only known
    // by asking, and a crash loop's current instance may hold nothing yet.
    let previous_fut = async {
        if container.is_empty() {
            None
        } else {
            Some(k8s::get_previous_pod_logs(context_name, namespace, pod_name, container, DIAGNOSE_LOG_FETCH_LINES).await)
        }
    };

    let (pods, events, manifest, logs, previous) = tokio::join!(
        k8s::get_pods(context_name, Some(namespace.to_string())),
        k8s::get_pod_events(context_name, namespace, pod_name),
        k8s::get_pod_manifest(context_name, namespace, pod_name),
        logs_fut,
        previous_fut,
    );
    // How the previous instance ended, for its section's heading.
    let last_exit = manifest.as_ref().ok().and_then(|m| {
        m.detail
            .containers
            .iter()
            .chain(m.detail.init_containers.iter())
            .find(|c| c.name == container)
            .map(|c| last_exit_text(&c.last_reason, c.last_exit_code, c.last_finished.as_deref()))
    });

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
    let previous_logs = previous.map(previous_logs_section);

    let (logs_text, current_note) = match logs {
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
    let previous_r = previous_logs.as_ref().map(|p| redact::redact(&p.text));

    let mut parts = vec![&status, &events_r, &manifest_r, &logs_r];
    parts.extend(previous_r.as_ref());
    let redaction_summary = redact::Redacted::merge(parts).summary();
    let log_note = combine_log_notes(current_note.clone(), previous_logs.as_ref());

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
         ## Logs{}\n```\n{}\n```{}",
        status.text,
        events_r.text,
        manifest_r.text,
        current_note.as_ref().map(|n| format!(" ({n})")).unwrap_or_default(),
        logs_r.text,
        previous_logs
            .as_ref()
            .zip(previous_r.as_ref())
            .map(|(p, r)| previous_logs_markdown(p, r, last_exit.as_deref()))
            .unwrap_or_default(),
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note,
    })
}

/// How a container's previous instance ended: `OOMKilled, exit code 137, 2026-10-12T08:00:00Z`.
fn last_exit_text(reason: &str, code: Option<i32>, finished: Option<&str>) -> String {
    [
        Some(reason.to_string()).filter(|r| !r.is_empty()),
        code.map(|c| format!("exit code {c}")),
        finished.map(|f| format!("finished {f}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(", ")
}

/// The previous instance's logs, trimmed like the current ones, or why there are none.
struct PreviousLogs {
    text: String,
    /// The trim, when there was one.
    note: Option<String>,
    /// There was a previous instance to read.
    present: bool,
}

fn previous_logs_section(fetched: Result<Option<String>, String>) -> PreviousLogs {
    match fetched {
        Ok(None) => PreviousLogs { text: "(no previous instance — the container has not restarted)".to_string(), note: None, present: false },
        Ok(Some(t)) if t.trim().is_empty() => PreviousLogs { text: "(the previous instance produced no log output)".to_string(), note: None, present: true },
        Ok(Some(t)) => {
            let (text, note) = redact::tail_lines(&t, DIAGNOSE_LOG_LINES);
            PreviousLogs { text, note, present: true }
        }
        Err(e) => PreviousLogs { text: format!("(previous logs unavailable: {e})"), note: None, present: false },
    }
}

fn previous_logs_markdown(p: &PreviousLogs, redacted: &redact::Redacted, last_exit: Option<&str>) -> String {
    let exit = last_exit.filter(|e| !e.is_empty()).map(|e| format!(" — it ended: {e}")).unwrap_or_default();
    let trim = p.note.as_ref().map(|n| format!(" ({n})")).unwrap_or_default();
    format!("\n\n## Logs of the previous instance{exit}{trim}\n```\n{}\n```", redacted.text)
}

/// The preview's one line about logs, covering both instances.
fn combine_log_notes(current: Option<String>, previous: Option<&PreviousLogs>) -> Option<String> {
    let previous = previous.filter(|p| p.present).map(|p| match &p.note {
        Some(n) => format!("previous instance included, {n}"),
        None => "previous instance included".to_string(),
    });
    match (current, previous) {
        (Some(c), Some(p)) => Some(format!("{c}; {p}")),
        (c, p) => c.or(p),
    }
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
        "Node" => DIAGNOSE_NODE_SYSTEM,
        "NodePool" => DIAGNOSE_NAP_SYSTEM,
        "HorizontalPodAutoscaler" => DIAGNOSE_HPA_SYSTEM,
        _ => DIAGNOSE_WORKLOAD_SYSTEM,
    };
    ai::stream(prompt, system, DIAGNOSE_MAX_TOKENS, DIAGNOSE_EFFORT, on_token).await
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
            created_at: None,
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
    #[ignore = "needs a reachable cluster; set NODE_DIAG_TEST_* to run"]
    async fn node_diagnosis_against_a_live_cluster() {
        let (Ok(context), Ok(node)) = (
            std::env::var("NODE_DIAG_TEST_CONTEXT"),
            std::env::var("NODE_DIAG_TEST_NODE"),
        ) else {
            eprintln!("NODE_DIAG_TEST_* not set — skipping");
            return;
        };

        let started = std::time::Instant::now();
        let payload = build_node_diagnosis_payload(&context, &node).await.expect("payload should build");
        eprintln!(
            "payload: {} bytes / {} chars, ~{} tokens, built in {}ms\nredaction: {}",
            payload.prompt.len(),
            payload.prompt.chars().count(),
            payload.approx_tokens,
            started.elapsed().as_millis(),
            payload.redaction_summary
        );

        let head = payload.prompt.split("## Manifest").next().unwrap_or(&payload.prompt);
        eprintln!("\n--- payload (manifest omitted) ---\n{}", truncate_on_char_boundary(head, 3500));
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
        let clause = "cannot patch \"example-metrics-victoria-metrics-k8s-stack-etcd\" with kind VMRule: Internal error \
occurred: failed calling webhook \"vmrules.operator.victoriametrics.com\": failed to call webhook: Post \
\"https://example-metrics-victoria-metrics-operator.example-metrics.svc:9443/validate-operator-victoriametrics-com-v1beta1-vmrule?timeout=10s\": \
no endpoints available for service \"example-metrics-victoria-metrics-operator\"";
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

    fn cond(type_: &str, status: &str, reason: &str, message: &str) -> k8s_openapi::api::core::v1::NodeCondition {
        k8s_openapi::api::core::v1::NodeCondition {
            type_: type_.into(),
            status: status.into(),
            reason: if reason.is_empty() { None } else { Some(reason.into()) },
            message: if message.is_empty() { None } else { Some(message.into()) },
            last_heartbeat_time: None,
            last_transition_time: None,
        }
    }

    #[test]
    fn ready_is_the_one_condition_where_true_is_good() {
        // Getting this backwards fails in both directions and looks plausible
        // either way: treat Ready like the rest and every healthy node reports
        // a problem; treat the rest like Ready and the only node worth looking
        // at reports none.
        let (problems, clear) = split_node_conditions(&[
            cond("Ready", "True", "KubeletReady", "kubelet is posting ready status"),
            cond("MemoryPressure", "False", "KubeletHasSufficientMemory", "kubelet has sufficient memory"),
        ]);
        assert!(problems.is_empty(), "a healthy node has no problems: {problems:?}");
        assert_eq!(clear, vec!["Ready".to_string(), "MemoryPressure".to_string()]);

        let (problems, _) = split_node_conditions(&[cond("Ready", "Unknown", "NodeStatusUnknown", "kubelet stopped posting")]);
        assert_eq!(problems.len(), 1, "Ready=Unknown is a problem: {problems:?}");
        assert!(problems[0].contains("Ready=Unknown"), "{problems:?}");
    }

    #[test]
    fn a_flagged_condition_carries_its_message_and_a_clear_one_does_not() {
        // The real case this exists for: a node Azure had scheduled for
        // redeploy after a VM fault, which `Ready=True` hides entirely. The
        // message is the whole diagnosis, and the seventeen boilerplate
        // "kubelet has sufficient X" messages are what would bury it.
        let (problems, clear) = split_node_conditions(&[
            cond("Ready", "True", "KubeletReady", "kubelet is posting ready status"),
            cond("DiskPressure", "False", "KubeletHasNoDiskPressure", "kubelet has no disk pressure"),
            cond("VMEventScheduled", "True", "VMEventScheduled", "Redeploy Scheduled: Sun, 27 Sep 2026. Virtual machine has encountered a failure."),
        ]);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("VMEventScheduled=True (VMEventScheduled)"), "{problems:?}");
        assert!(problems[0].contains("Virtual machine has encountered a failure"), "{problems:?}");
        assert_eq!(clear, vec!["Ready".to_string(), "DiskPressure".to_string()]);
        // The boilerplate messages do not travel.
        assert!(!problems.concat().contains("no disk pressure"));
    }

    #[test]
    fn the_node_manifest_drops_the_image_cache() {
        // 6,528 of one real node's 15,089 characters. It is a list of pulled
        // images with digests and says nothing about why a node is unwell.
        let node: k8s_openapi::api::core::v1::Node = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "n1", "managedFields": [{ "manager": "kubelet" }] },
            "status": {
                "images": [{ "names": ["registry.io/a@sha256:deadbeef"], "sizeBytes": 1 }],
                "capacity": { "cpu": "8" }
            }
        }))
        .expect("node fixture");

        let yaml = node_manifest_without_images(&node).expect("yaml");
        assert!(!yaml.contains("sha256:deadbeef"), "{yaml}");
        assert!(!yaml.contains("managedFields"), "{yaml}");
        // and keeps what a diagnosis needs
        assert!(yaml.contains("cpu: '8'") || yaml.contains("cpu: \"8\"") || yaml.contains("cpu: 8"), "{yaml}");
        assert!(yaml.contains("kind: Node"), "{yaml}");
    }

    fn pod_summary(name: &str, phase: &str, healthy: bool, restarts: i32) -> crate::k8s::NodePodSummary {
        crate::k8s::NodePodSummary {
            namespace: "ns".into(),
            name: name.into(),
            phase: phase.into(),
            ready: "1/1".into(),
            restarts,
            healthy,
        }
    }

    #[test]
    fn pods_that_could_not_be_listed_are_not_reported_as_no_pods() {
        // The distinction this function exists for. A 403 or a timeout used to
        // collapse to an empty list, so the payload told the model "no pods on
        // this node" — and a node holding a crashing workload read as idle.
        let unavailable = render_node_pods(&Err("Failed to list pods on 'n1': forbidden".to_string()));
        assert!(unavailable.starts_with("(pods unavailable:"), "{unavailable}");
        assert!(unavailable.contains("forbidden"), "{unavailable}");

        let genuinely_empty = render_node_pods(&Ok(vec![]));
        assert_eq!(genuinely_empty, "(no pods on this node)");
        assert_ne!(unavailable, genuinely_empty);
    }

    #[test]
    fn the_pod_list_counts_the_unhealthy_ones_and_caps_the_rest() {
        let mut pods = vec![pod_summary("crashing", "CrashLoopBackOff", false, 7)];
        pods.extend((0..DIAGNOSE_NODE_PODS).map(|i| pod_summary(&format!("ok-{i}"), "Running", true, 0)));

        let out = render_node_pods(&Ok(pods));
        assert!(out.starts_with(&format!("{} pod(s), 1 not running cleanly", DIAGNOSE_NODE_PODS + 1)), "{out}");
        assert!(out.contains("ns/crashing  CrashLoopBackOff"), "{out}");
        assert!(out.contains("… and 1 more"), "{out}");
    }

    #[test]
    fn the_kubelets_no_previous_instance_reply_is_recognised() {
        assert!(k8s::is_no_previous_instance(r#"previous terminated container "api" in pod "api-x" not found"#));
        assert!(!k8s::is_no_previous_instance("container \"api\" in pod \"api-x\" is waiting to start: ContainerCreating"));
    }

    #[test]
    fn the_previous_instance_is_described_by_how_it_ended() {
        assert_eq!(last_exit_text("OOMKilled", Some(137), Some("2026-10-12T08:00:00Z")), "OOMKilled, exit code 137, finished 2026-10-12T08:00:00Z");
        assert_eq!(last_exit_text("", Some(1), None), "exit code 1");
        assert_eq!(last_exit_text("", None, None), "");
    }

    #[test]
    fn a_previous_instance_is_trimmed_and_disclosed_and_an_absent_one_said_so() {
        let long: String = (1..=500).map(|i| format!("line {i}\n")).collect();
        let p = previous_logs_section(Ok(Some(long)));
        assert!(p.present);
        assert_eq!(p.text.lines().count(), DIAGNOSE_LOG_LINES);
        assert!(p.text.ends_with("line 500"));
        assert_eq!(combine_log_notes(None, Some(&p)).as_deref(), Some("previous instance included, showing the last 200 of 500 lines"));

        let none = previous_logs_section(Ok(None));
        assert!(!none.present);
        assert!(none.text.contains("has not restarted"));
        // No previous instance adds nothing to the preview's note.
        assert_eq!(combine_log_notes(Some("showing the last 200 of 400 lines".into()), Some(&none)).as_deref(), Some("showing the last 200 of 400 lines"));

        let md = previous_logs_markdown(&p, &redact::redact(&p.text), Some("OOMKilled, exit code 137"));
        assert!(md.starts_with("\n\n## Logs of the previous instance — it ended: OOMKilled, exit code 137 (showing the last 200 of 500 lines)"), "{md}");
    }

    fn claim(name: &str, conditions: serde_json::Value, node: Option<&str>, deleting: bool) -> kube::api::DynamicObject {
        let mut obj: kube::api::DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "karpenter.sh/v1",
            "kind": "NodeClaim",
            "metadata": {
                "name": name,
                "labels": {
                    "node.kubernetes.io/instance-type": "Standard_D4s_v5",
                    "karpenter.sh/capacity-type": "spot",
                    "topology.kubernetes.io/zone": "westeurope-1"
                }
            },
            "status": { "conditions": conditions, "nodeName": node }
        }))
        .unwrap();
        if deleting {
            obj.metadata.deletion_timestamp =
                Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(chrono::Utc::now()));
        }
        obj
    }

    fn node(name: &str, ready: &str, cordoned: bool) -> k8s_openapi::api::core::v1::Node {
        serde_json::from_value(serde_json::json!({
            "metadata": { "name": name },
            "spec": {
                "unschedulable": cordoned,
                "taints": [{ "key": "karpenter.sh/disrupted", "effect": "NoSchedule" }]
            },
            "status": { "conditions": [{ "type": "Ready", "status": ready }] }
        }))
        .unwrap()
    }

    #[test]
    fn karpenter_conditions_read_marking_conditions_the_other_way_round() {
        let (notable, clear) = split_karpenter_conditions(&serde_json::json!({ "status": { "conditions": [
            { "type": "Ready", "status": "True" },
            { "type": "Initialized", "status": "False", "reason": "NotInitialized", "message": "kubelet never reported" },
            { "type": "Drifted", "status": "True", "reason": "NodeClassDrift" },
            { "type": "Empty", "status": "False" },
            { "type": "SomethingNew", "status": "True" },
        ]}}));
        assert_eq!(clear, ["Ready", "Empty", "SomethingNew"]);
        assert_eq!(notable.len(), 2);
        assert!(notable[0].starts_with("Initialized=False (NotInitialized)") && notable[0].ends_with("\n  kubelet never reported"));
        assert!(notable[1].starts_with("Drifted=True (NodeClassDrift)"));
    }

    #[test]
    fn a_pools_stuck_claim_is_listed_before_its_healthy_ones() {
        let ready = serde_json::json!([{ "type": "Ready", "status": "True" }]);
        let mut claims: Vec<_> = (0..DIAGNOSE_NAP_CLAIMS + 5).map(|i| claim(&format!("ok-{i}"), ready.clone(), Some(&format!("n-{i}")), false)).collect();
        claims.push(claim("stuck", serde_json::json!([{ "type": "Launched", "status": "False", "reason": "LaunchFailed", "message": "SKU not available" }, { "type": "Ready", "status": "Unknown" }]), None, false));
        claims.push(claim("leaving", ready.clone(), Some("n-leaving"), true));
        let nodes = Ok(vec![node("n-leaving", "True", true)]);
        let out = render_nap_claims(&Ok(claims), &nodes);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with(&format!("{} claim(s): 1 not Ready, 1 terminating, 0 marked", DIAGNOSE_NAP_CLAIMS + 7)), "{}", lines[0]);
        assert!(lines[1].starts_with("stuck  Standard_D4s_v5  spot  westeurope-1"));
        assert_eq!(lines[2], "  no node registered");
        assert!(out.contains("Launched=False (LaunchFailed)\n    SKU not available"), "{out}");
        let leaving = out.find("leaving").unwrap();
        assert!(out[leaving..].contains("TERMINATING since"));
        assert!(out.contains("node n-leaving Ready=True, cordoned, tainted karpenter.sh/disrupted:NoSchedule"));
        assert!(out.contains("node n-0 not found"));
        assert!(out.ends_with("… and 7 more, all Ready with nothing pending"), "{out}");
    }

    #[test]
    fn claims_that_could_not_be_read_are_not_reported_as_none() {
        assert_eq!(render_nap_claims(&Ok(vec![]), &Ok(vec![])), "(this pool owns no NodeClaims)");
        assert_eq!(render_nap_claims(&Err("forbidden".into()), &Ok(vec![])), "(NodeClaims unavailable: forbidden)");
        let ready = serde_json::json!([{ "type": "Ready", "status": "True" }]);
        let out = render_nap_claims(&Ok(vec![claim("c", ready, Some("n"), false)]), &Err("forbidden".into()));
        assert!(out.contains("node state unknown (nodes could not be listed)"));
    }

    #[test]
    fn scheduling_failures_collapse_on_the_message_and_count_pods() {
        let event = |ns: &str, pod: &str, message: &str, seen: &str| crate::models::EventInfo {
            object_namespace: ns.into(),
            object_name: pod.into(),
            message: message.into(),
            last_seen: Some(seen.into()),
            ..Default::default()
        };
        let limit = "all available instance types exceed limits for nodepool: \"gpu\"";
        let out = render_nap_scheduling(&Ok(vec![
            event("ml", "train-1", limit, "2026-10-20T10:00:00Z"),
            event("ml", "train-2", limit, "2026-10-20T09:59:00Z"),
            event("ml", "train-1", limit, "2026-10-20T09:58:00Z"),
            event("web", "api-1", &"x".repeat(DIAGNOSE_NAP_MESSAGE_CHARS + 50), "2026-10-20T09:00:00Z"),
        ]));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "2 pod(s), e.g. ml/train-1, latest 2026-10-20T10:00:00Z:");
        assert_eq!(lines[1], format!("  {limit}"));
        assert_eq!(lines[2], "1 pod(s), e.g. web/api-1, latest 2026-10-20T09:00:00Z:");
        assert!(lines[3].ends_with(" …") && lines[3].len() < DIAGNOSE_NAP_MESSAGE_CHARS + 10);
        assert_eq!(render_nap_scheduling(&Ok(vec![])), "(Karpenter reports no pod it could not place on this pool)");
    }

    #[test]
    fn a_pools_status_reads_in_cores_and_gib_and_says_when_a_drain_can_wait_forever() {
        let detail = crate::models::NapDetail {
            node_class_kind: "AKSNodeClass".into(),
            node_class_name: "default".into(),
            requirements: vec![crate::models::NapRequirement {
                key: "karpenter.sh/capacity-type".into(),
                operator: "In".into(),
                values: vec!["spot".into(), "on-demand".into()],
                min_values: None,
            }],
            expire_after: "720h".into(),
            consolidation_policy: "WhenEmptyOrUnderutilized".into(),
            consolidate_after: "0s".into(),
            budgets: vec![crate::models::NapBudget { nodes: "0".into(), reasons: vec!["Drifted".into()], ..Default::default() }],
            resources: vec![
                crate::models::NapResourceUse { name: "cpu".into(), unit: "millicores".into(), used: 48_000, limit: Some(64_000) },
                crate::models::NapResourceUse { name: "memory".into(), unit: "ki".into(), used: 201_326_592, limit: None },
            ],
            ..Default::default()
        };
        let out = render_nap_status(&detail, 12);
        assert!(out.starts_with("nodes owned: 12\ncpu provisioned / limit: 48 cores / 64 cores\nmemory provisioned / limit: 192 GiB / no limit"), "{out}");
        assert!(out.contains("  karpenter.sh/capacity-type In [spot, on-demand]"));
        assert!(out.contains("termination grace period: (none — a drain may wait forever)"));
        assert!(out.ends_with("disruption budgets:\n  nodes 0 for Drifted"), "{out}");
    }

    fn hpa_metric(kind: &str, name: &str, target: &str) -> crate::models::HpaMetricRow {
        crate::models::HpaMetricRow { kind: kind.into(), name: name.into(), target: target.into(), current: "<unknown>".into() }
    }

    fn hpa_pod(name: &str, containers: serde_json::Value, sidecars: serde_json::Value, ready: bool) -> k8s_openapi::api::core::v1::Pod {
        serde_json::from_value(serde_json::json!({
            "metadata": { "name": name },
            "spec": { "containers": containers, "initContainers": sidecars },
            "status": { "conditions": [{ "type": "Ready", "status": if ready { "True" } else { "False" } }] }
        }))
        .unwrap()
    }

    #[test]
    fn only_utilization_targets_need_requests() {
        let needs = hpa_request_needs(&[
            hpa_metric("Resource", "memory", "80%"),
            hpa_metric("Resource", "cpu", "500m"),
            hpa_metric("ContainerResource", "app/cpu", "60%"),
            hpa_metric("External", "queue_length", "30"),
        ]);
        let got: Vec<_> = needs.iter().map(|n| (n.resource.as_str(), n.container.as_deref(), n.metric.as_str())).collect();
        assert_eq!(got, [("memory", None, "memory 80%"), ("cpu", Some("app"), "app/cpu 60%")]);
    }

    #[test]
    fn a_sidecar_without_a_memory_request_is_named_as_the_reason_memory_cannot_be_computed() {
        let containers = serde_json::json!([
            { "name": "grafana", "resources": { "requests": { "cpu": "100m", "memory": "256Mi" } } },
            { "name": "grafana-sc-alerts", "resources": { "requests": { "cpu": "50m" } } },
        ]);
        let sidecars = serde_json::json!([
            { "name": "proxy", "restartPolicy": "Always", "resources": { "requests": { "cpu": "10m", "memory": "64Mi" } } },
            { "name": "migrate" },
        ]);
        let pods = Ok(vec![
            hpa_pod("g-1", containers.clone(), sidecars.clone(), true),
            hpa_pod("g-2", containers.clone(), sidecars.clone(), true),
            hpa_pod("g-3", containers, sidecars, false),
        ]);
        let usage = Ok([(("g-1".to_string(), "grafana".to_string()), (40, 204_800)), (("g-2".to_string(), "grafana".to_string()), (20, 102_400))]
            .into_iter()
            .collect());
        let needs = hpa_request_needs(&[hpa_metric("Resource", "memory", "80%"), hpa_metric("Resource", "cpu", "60%")]);
        let out = render_hpa_containers(&pods, &usage, &needs);
        assert!(out.starts_with("3 pod(s) matched, 2 Ready\nutilization targets need a request for: memory on every container (memory 80%); cpu on every container (cpu 60%)"), "{out}");
        assert!(out.contains("\ngrafana — in 3/3 pods; requests cpu 100m, memory 256Mi; average usage cpu 30m, memory 150Mi over 2 pod(s)"), "{out}");
        assert!(out.contains("\ngrafana-sc-alerts — in 3/3 pods; requests cpu 50m, memory none; metrics-server reports no usage for it in any pod\n  MISSING memory request in 3/3 pods — the memory 80% target cannot be computed"), "{out}");
        assert!(out.contains("\nproxy (native sidecar) — in 3/3 pods"));
        assert!(!out.contains("migrate"), "a one-shot init container does not count: {out}");
        assert_eq!(out.matches("MISSING").count(), 1);
    }

    #[test]
    fn requests_that_differ_mid_rollout_are_tallied_and_a_missing_named_container_is_said() {
        let pods = Ok(vec![
            hpa_pod("a", serde_json::json!([{ "name": "app", "resources": { "requests": { "cpu": "100m" } } }]), serde_json::json!([]), true),
            hpa_pod("b", serde_json::json!([{ "name": "app" }]), serde_json::json!([]), true),
        ]);
        let needs = hpa_request_needs(&[hpa_metric("ContainerResource", "app/cpu", "60%"), hpa_metric("ContainerResource", "worker/cpu", "60%")]);
        let out = render_hpa_containers(&pods, &Err("metrics.k8s.io: 503".into()), &needs);
        assert!(out.contains("usage unavailable: metrics.k8s.io: 503"));
        assert!(out.contains("requests cpu 100m in 1, none in 1"), "{out}");
        assert!(out.contains("MISSING cpu request in 1/2 pods — the app/cpu 60% target cannot be computed"));
        assert!(out.ends_with("no pod has a container named worker, which the worker/cpu 60% target reads"), "{out}");
        assert_eq!(render_hpa_containers(&Ok(vec![]), &Ok(Default::default()), &[]), "(the target's selector matches no pods)");
        let quiet = render_hpa_containers(
            &Ok(vec![hpa_pod("a", serde_json::json!([{ "name": "app" }]), serde_json::json!([]), true)]),
            &Ok(Default::default()),
            &[],
        );
        assert!(quiet.ends_with("app — in 1/1 pods; requests cpu none, memory none; metrics-server reports no usage for it in any pod"), "{quiet}");
        assert_eq!(
            render_hpa_siblings(&Ok(vec![("api-hpa".into(), String::new()), ("keda-hpa-api".into(), "ScaledObject/api".into())])),
            "api-hpa\nkeda-hpa-api (owned by ScaledObject/api)"
        );
    }

    #[test]
    fn a_metrics_api_that_is_missing_or_down_is_said_per_metric_type() {
        let svc: k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "v1beta1.metrics.k8s.io" },
            "spec": { "group": "metrics.k8s.io", "version": "v1beta1", "groupPriorityMinimum": 100, "versionPriority": 100,
                      "service": { "namespace": "kube-system", "name": "metrics-server" } },
            "status": { "conditions": [{ "type": "Available", "status": "False", "reason": "FailedDiscoveryCheck", "message": "no response" }] }
        }))
        .unwrap();
        let out = render_hpa_metrics_apis(
            &[hpa_metric("Resource", "cpu", "60%"), hpa_metric("ContainerResource", "app/cpu", "60%"), hpa_metric("External", "q", "5")],
            &Ok(vec![svc]),
        );
        assert_eq!(
            out,
            "metrics.k8s.io (for Resource, ContainerResource metrics): v1beta1.metrics.k8s.io Available=False (FailedDiscoveryCheck), served by kube-system/metrics-server\n  no response\n\
             external.metrics.k8s.io (for External metrics): NOT REGISTERED — nothing on the cluster serves it"
        );
    }

    #[test]
    fn hpa_conditions_read_scaling_limited_the_other_way_round() {
        let c = |t: &str, s: &str, m: &str| crate::models::PodConditionInfo {
            condition_type: t.into(),
            status: s.into(),
            reason: String::new(),
            message: m.into(),
            last_transition: None,
        };
        let out = render_hpa_conditions(&[c("AbleToScale", "True", ""), c("ScalingActive", "False", "missing request"), c("ScalingLimited", "True", "at max")]);
        assert_eq!(out, "ScalingActive=False\n  missing request\nScalingLimited=True\n  at max\n\nchecked and clear: AbleToScale");
        assert_eq!(render_hpa_conditions(&[]), "(none reported yet)");
    }

    /// Builds real pod diagnoses for restarted and never-restarted pods and
    /// checks the previous instance's section. Prints counts only — no
    /// names, logs or prompt text.
    ///
    ///   POD_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml pod_diagnosis_previous_logs_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set POD_DIAG_TEST_CONTEXT to run"]
    async fn pod_diagnosis_previous_logs_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("POD_DIAG_TEST_CONTEXT") else { return };
        let pods = k8s::get_pods(&ctx, None).await.expect("pods");
        let (mut restarted_with_section, mut restarted_without, mut fresh_said_so, mut fresh_wrong) = (0, 0, 0, 0);
        let restarted = pods.iter().filter(|p| p.restarts > 0).take(5);
        let fresh = pods.iter().filter(|p| p.restarts == 0 && p.phase == "Running").take(3);
        for p in restarted.chain(fresh) {
            let manifest = k8s::get_pod_manifest(&ctx, &p.namespace, &p.name).await.expect("manifest");
            // The container that restarted, else the first.
            let container = manifest
                .detail
                .containers
                .iter()
                .find(|c| c.restart_count > 0)
                .or(manifest.detail.containers.first())
                .map(|c| c.name.clone())
                .unwrap_or_default();
            let restarted = manifest.detail.containers.iter().any(|c| c.name == container && c.restart_count > 0);
            let payload = build_diagnosis_payload(&ctx, &p.namespace, &p.name, &container).await.expect("payload");
            // The header alone proves nothing: it is also written when there is
            // no previous instance or the fetch failed. The note is set only
            // when one was read.
            let has_previous = payload.log_note.as_deref().is_some_and(|n| n.contains("previous instance included"));
            let said_none = payload.prompt.contains("has not restarted");
            if restarted {
                if has_previous { restarted_with_section += 1 } else { restarted_without += 1 }
            } else if said_none {
                fresh_said_so += 1
            } else {
                fresh_wrong += 1
            }
        }
        println!("restarted_with_previous_logs={restarted_with_section} restarted_without={restarted_without} fresh_said_none={fresh_said_so} fresh_wrong={fresh_wrong}");
        assert!(restarted_with_section > 0, "no restarted pod to check");
        assert!(fresh_said_so > 0, "no never-restarted pod to check");
        assert_eq!(restarted_without, 0);
        assert_eq!(fresh_wrong, 0);
    }

    /// Builds a diagnosis for every NodePool on a cluster and checks each
    /// section was read rather than reported unavailable. Prints counts only —
    /// no names, messages or prompt text.
    ///
    ///   NAP_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml nap_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster with NAP; set NAP_DIAG_TEST_CONTEXT to run"]
    async fn nap_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("NAP_DIAG_TEST_CONTEXT") else { return };
        let pools = k8s::get_nap_node_pools(&ctx).await.expect("pools").node_pools;
        let (mut built, mut unavailable, mut claim_count_differs, mut with_scheduling, mut largest) = (0, 0, 0, 0, 0);
        for p in &pools {
            let payload = build_nap_diagnosis_payload(&ctx, &p.name).await.expect("payload");
            built += 1;
            unavailable += payload.prompt.matches("unavailable: ").count();
            // The pool's own node count against the claims listed by label.
            let claims = payload
                .prompt
                .split("## NodeClaims (worst first)\n")
                .nth(1)
                .and_then(|s| s.split(" claim(s)").next())
                .and_then(|n| n.parse::<i64>().ok())
                .unwrap_or(0);
            if claims != p.nodes {
                claim_count_differs += 1
            }
            if !payload.prompt.contains("(Karpenter reports no pod it could not place") {
                with_scheduling += 1
            }
            largest = largest.max(payload.approx_tokens);
        }
        println!("pools={} built={built} unavailable_sections={unavailable} claim_count_differs={claim_count_differs} with_scheduling_failures={with_scheduling} largest_tokens={largest}", pools.len());
        assert!(built > 0, "no NodePool to diagnose");
        assert_eq!(unavailable, 0);
    }

    /// Builds a diagnosis for every HPA on a cluster, and checks that each one
    /// whose own message blames a missing request has that container flagged
    /// in the payload. Prints counts only.
    ///
    ///   HPA_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml hpa_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set HPA_DIAG_TEST_CONTEXT to run"]
    async fn hpa_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("HPA_DIAG_TEST_CONTEXT") else { return };
        let hpas = k8s::get_hpas(&ctx).await.expect("hpas");
        let (mut built, mut unavailable, mut missing_request, mut flagged, mut largest) = (0, 0, 0, 0, 0);
        let (mut with_usage, mut flagged_any, mut apis_not_available, mut not_active) = (0, 0, 0, 0);
        let (mut ambiguous, mut ambiguous_listed, mut no_metrics, mut no_metrics_said) = (0, 0, 0, 0);
        for h in &hpas {
            let payload = build_hpa_diagnosis_payload(&ctx, &h.namespace, &h.name).await.expect("payload");
            built += 1;
            unavailable += payload.prompt.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            with_usage += payload.prompt.contains("average usage cpu") as usize;
            flagged_any += payload.prompt.contains("MISSING ") as usize;
            apis_not_available += (payload.prompt.contains("NOT REGISTERED") || payload.prompt.contains("Available=False")) as usize;
            not_active += !h.scaling_active as usize;
            // Two HPAs on one target: the payload should name the other one.
            if h.condition_reason.starts_with("AmbiguousSelector") {
                ambiguous += 1;
                ambiguous_listed += !payload.prompt.contains("(none — this is the only HPA scaling it)") as usize;
            }
            // metrics-server returned nothing: some container should say so.
            if h.condition_reason.contains("no metrics returned") {
                no_metrics += 1;
                no_metrics_said += (payload.prompt.contains("reports no usage for it")
                    || payload.prompt.contains("usage unavailable")
                    || payload.prompt.contains("matches no pods")) as usize;
            }
            // "missing request for memory in container X of Pod Y"
            if let Some(rest) = h.condition_reason.split("missing request for ").nth(1) {
                missing_request += 1;
                let resource = rest.split_whitespace().next().unwrap_or_default();
                let container = rest.split("in container ").nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or_default();
                let section = payload.prompt.split("## Containers in the target's pods\n").nth(1).unwrap_or_default();
                let row = section.split("\n").position(|l| l.starts_with(&format!("{container} ")) || l.starts_with(&format!("{container} (")));
                let lines: Vec<&str> = section.lines().collect();
                let notes = row.map(|i| lines.iter().skip(i + 1).take_while(|l| l.starts_with("  ")).copied().collect::<Vec<_>>()).unwrap_or_default();
                if notes.iter().any(|l| l.contains(&format!("MISSING {resource} request"))) {
                    flagged += 1
                }
            }
        }
        println!("hpas={} built={built} unavailable_sections={unavailable} blamed_missing_request={missing_request} flagged={flagged} largest_tokens={largest} with_usage={with_usage} any_missing_flag={flagged_any} metrics_api_down={apis_not_available} not_scaling_active={not_active} ambiguous={ambiguous}/{ambiguous_listed} no_metrics={no_metrics}/{no_metrics_said}", hpas.len());
        assert!(built > 0, "no HPA to diagnose");
        assert_eq!(flagged, missing_request);
        assert_eq!(ambiguous_listed, ambiguous);
        // `no_metrics` is printed, not asserted: the HPA's condition is from its
        // last sync and the usage from this read, so a pod whose metrics come
        // and go between the two makes the pair disagree for a moment.
    }

    /// Builds workload diagnoses for unhealthy workloads and checks the logs
    /// come from the worst pod's failing container, not the template's first.
    /// Prints counts only.
    ///
    ///   WORKLOAD_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml workload_diagnosis_reads_the_failing_container_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set WORKLOAD_DIAG_TEST_CONTEXT to run"]
    async fn workload_diagnosis_reads_the_failing_container_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("WORKLOAD_DIAG_TEST_CONTEXT") else { return };
        let (workloads, pods) = tokio::join!(k8s::get_workloads(&ctx), k8s::get_pods(&ctx, None));
        let (workloads, pods) = (workloads.expect("workloads"), pods.expect("pods"));
        let (mut checked, mut matched, mut not_first, mut wrong) = (0, 0, 0, 0);
        for w in workloads.iter().filter(|w| !w.healthy).take(10) {
            let payload = build_workload_diagnosis_payload(&ctx, &w.kind, &w.namespace, &w.name).await.expect("payload");
            // "## Logs (pod <pod>, container <container>)"
            let Some(heading) = payload.prompt.lines().find(|l| l.starts_with("## Logs (pod ")) else { continue };
            let Some((pod, rest)) = heading["## Logs (pod ".len()..].split_once(", container ") else { continue };
            let container = rest.split(')').next().unwrap_or_default();
            let Some(failing) = pods
                .iter()
                .find(|p| p.namespace == w.namespace && p.name == pod)
                .and_then(|p| p.failure_container.as_deref())
            else {
                continue;
            };
            checked += 1;
            if container == failing {
                matched += 1;
                let manifest = k8s::get_workload_manifest(&ctx, &w.kind, &w.namespace, &w.name).await.expect("manifest");
                if manifest.containers.first().map(String::as_str) != Some(failing) {
                    not_first += 1
                }
            } else {
                wrong += 1
            }
        }
        println!("checked={checked} matched={matched} failing_was_not_first={not_first} wrong={wrong}");
        assert!(checked > 0, "no unhealthy workload with a failing container to check");
        assert_eq!(wrong, 0);
    }
}
