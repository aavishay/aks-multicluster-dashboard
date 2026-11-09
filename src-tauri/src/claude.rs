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

const DIAGNOSE_STATEFULSET_SYSTEM: &str = "\
You diagnose failing Kubernetes StatefulSets for an experienced SRE.

You are given the StatefulSet's replica counts, revisions and update \
strategy; its pods by ordinal, with the revision each runs and the state of \
the node under any that is stuck; the claims its volumeClaimTemplates make \
for each ordinal; its governing Service; the PodDisruptionBudgets over its \
pods; its events and manifest; a table of its pods worst first; and the \
events and recent logs of the pod least likely to be healthy, with its \
previous instance's logs when it has restarted. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the ordinal, the claim, \
the event, the log line, or the field.
3. Concrete next steps: the exact command to run or field to change.

Say which of these you are looking at, because the fixes differ:
- An ordinal that will not start: its claim is Pending (no class, a \
provisioner failing, a zone it cannot use) or its pod crashes. With \
OrderedReady, every ordinal above it waits, so name the lowest one stuck.
- A rollout that has stopped: a pod on the new revision is not ready. It \
may only be starting; if the new template is broken, correct or revert it \
first. With OrderedReady the controller does not replace a pod that is not \
ready, so a pod left on a broken revision after the template is corrected \
has to be deleted; with Parallel the controller replaces it. A partition or \
OnDelete that holds pods on the old revision is by design, not a fault.
- A pod stuck terminating on a node that is NotReady or gone: the \
StatefulSet never runs two pods with one identity, so it waits until the \
pod object is gone. Force-deleting is safe only once the node is confirmed \
down, since the old pod may still be writing to its volume.
- A volume problem: a claim smaller than the template (template changes do \
not resize existing claims), or a volume pinned to a zone with no \
schedulable node.
- Peers that cannot find each other: no governing Service, one that is not \
headless, or one whose selector misses the pods. A Service with no selector \
has endpoints managed by hand, which you are not shown.
- Drains blocked by a PodDisruptionBudget that allows no disruption (it \
stops the eviction of healthy pods; whether an unready pod can go depends \
on its unhealthyPodEvictionPolicy), or by more than one budget over the \
same pod.

If the StatefulSet is healthy, say so plainly rather than inventing a \
problem.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over \
a list of possibilities. If the evidence is genuinely insufficient, say so \
and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

const DIAGNOSE_DAEMONSET_SYSTEM: &str = "\
You diagnose failing Kubernetes DaemonSets for an experienced SRE.

You are given the DaemonSet's node counts, latest revision and update \
strategy; which nodes should run its pod, worked out from its nodeSelector, \
required node affinity and tolerations (including those the controller adds \
to every DaemonSet pod), with the reasons the others are excluded; the nodes \
that should run one but do not; its pods that are not ready, with their node, \
revision and scheduling message; its events and manifest; a table of its pods \
worst first; and the events and recent logs of the pod least likely to be \
healthy, with its previous instance's logs when it has restarted. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the node, the pod, the \
taint, the event, the log line, or the field.
3. Concrete next steps: the exact command to run or field to change.

Say which of these you are looking at, because the fixes differ:
- Nodes that should run a pod and have none: the controller makes one per \
node, so when it has not, its events say why (FailedCreate: quota, an \
admission webhook, a policy).
- Nodes deliberately left out: a taint it does not tolerate, or a \
nodeSelector or affinity it does not match. That is by design unless the \
user expects the pod there; then the fix is a toleration or a selector, not \
the node.
- A pod that cannot fit on its node: a DaemonSet pod runs only on its own \
node, so it waits for room there. Insufficient CPU or memory means the \
node's other pods have it; it can preempt them only if its priority is \
higher than theirs and its preemptionPolicy is not Never. A host port already in use means \
another pod on that node holds it.
- A rollout that has stopped: pods on the latest revision that are not ready \
count as unavailable, and once the nodes without an available pod reach \
maxUnavailable (with no surge), the controller replaces no more old pods. \
Below that it carries on, so check the counts before calling it stuck. The \
new pods may only be starting; if the new template is broken, correct or \
revert it, and the controller then replaces them, as it replaces any \
unavailable pod on an older revision. OnDelete moves a pod only when it is \
deleted, by design.
- A pod that fails on some nodes only: compare those nodes — their pool, \
OS, kernel or architecture — with the nodes where it is ready.
- A pod stuck terminating on a node that is NotReady or gone: the kubelet \
there cannot confirm it stopped. Force-delete only once the node is \
confirmed down.
- A misscheduled pod: one on a node it no longer fits, which the controller \
deletes.

If the DaemonSet is healthy, say so plainly rather than inventing a problem.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over \
a list of possibilities. If the evidence is genuinely insufficient, say so \
and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

const DIAGNOSE_DEPLOYMENT_SYSTEM: &str = "\
You diagnose failing Kubernetes Deployments for an experienced SRE.

You are given the Deployment's replica counts, strategy and conditions; its \
ReplicaSets newest first, with the pods each holds and the events of the \
newest; the HorizontalPodAutoscalers that target it; the \
PodDisruptionBudgets over its pods; its events and manifest; a table of its \
pods worst first; and the events and recent logs of the pod least likely to \
be healthy, with its previous instance's logs when it has restarted. \
Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the condition, the \
ReplicaSet, the event, the log line, or the field.
3. Concrete next steps: the exact command to run or field to change.

Say which of these you are looking at, because the fixes differ:
- Pods that are never created: the newest ReplicaSet reports ReplicaFailure \
or FailedCreate events — a ResourceQuota, a LimitRange, Pod Security \
admission or a webhook refusing them. Nothing crashes, so there are no logs; \
the message names the cause.
- A rollout that is not finishing: the newest ReplicaSet's pods are not \
ready while older ReplicaSets still hold pods. The controller scales the old \
ones down only as new pods become available, within maxUnavailable and \
maxSurge, so the old version keeps serving. The new pods may only be \
starting; if the new template is broken, `kubectl rollout undo` or a \
corrected template replaces them. ProgressDeadlineExceeded marks the \
rollout failed; the controller still keeps trying.
- A paused Deployment: changes to its template do not roll out until it is \
resumed.
- Pods that fail after a rollout completed: every pod on the current \
ReplicaSet failing the same way points at the template or its \
configuration; one pod differing points at its node.
- Replica counts that do not stick: an HPA owns them, so a change to \
spec.replicas is overwritten; more than one HPA on it fight each other.
- Drains blocked by a PodDisruptionBudget that allows no disruption, often a \
single replica with minAvailable 1.
- With the Recreate strategy every old pod is stopped before a new one \
starts, so a failing new template leaves nothing serving.

If the Deployment is healthy, say so plainly rather than inventing a problem.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over \
a list of possibilities. If the evidence is genuinely insufficient, say so \
and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

const DIAGNOSE_PDB_SYSTEM: &str = "\
You diagnose Kubernetes PodDisruptionBudgets for an experienced SRE.

You are given the budget with its counts, its eviction policy and \
conditions; the pods it covers with their readiness and the state of their \
nodes; the controllers behind those pods and how many pods each asks for; \
the other budgets that cover any of the same pods; its events and manifest. \
Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the count, the pod, the \
node, the controller, or the field.
3. Concrete next steps: the exact command to run or field to change.

Say which of these you are looking at, because the fixes differ:
- A drain or node upgrade that is waiting on it: the budget allows no \
disruption while pods it covers sit on cordoned nodes. Say whether the pods \
are unhealthy (fix them, or the unhealthyPodEvictionPolicy decides whether \
they can go) or the budget is simply as tight as the replicas.
- A budget that can never allow a disruption: minAvailable at or above the \
replicas its pods' controller asks for, or maxUnavailable 0 — the classic \
single replica with minAvailable 1. The fix is more replicas or a looser \
budget, not retrying the drain.
- More than one budget over the same pod: the eviction API refuses to evict \
it at all, whatever either budget allows.
- A budget that selects no pods: it protects nothing; compare its selector \
with the pods' labels.
- Pods with no controller: an evicted one is not recreated.

If the budget is healthy and allows disruptions, say so plainly rather than \
inventing a problem.

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

const DIAGNOSE_KEDA_SYSTEM: &str = "\
You diagnose KEDA ScaledObjects and ScaledJobs for an experienced SRE.

You are given the object's settings and conditions, each trigger with KEDA's \
health for it, where every credential a trigger uses comes from — checked \
against the Secrets and ConfigMaps it names, by key name only — the KEDA \
operator's own log lines about this object, its events, the HPA KEDA \
generated (for a ScaledObject) or the Jobs it created (for a ScaledJob), the \
workload it scales, the state of KEDA itself, and the manifest. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the log line, the \
condition, the credential, or the field.
3. Concrete next steps: the exact command to run or field to change.

The operator's log is usually where the actual error is: a query that fails, \
a connection refused, an authentication error from the event source. Quote \
the error and say what it means for this trigger.

Say which of these you are looking at:
- The scaler cannot read its source: wrong address, query or metadata, the \
source is down, or the credential is wrong or missing — a FromEnv variable \
not defined on the container, a Secret or key that does not exist, or a pod \
identity that is not federated or lacks the role.
- KEDA itself is unwell: the operator or the metrics apiserver is not ready, \
or external.metrics.k8s.io is unavailable — then every ScaledObject fails \
alike, and fixing this one object will not help.
- It works but scales wrongly: the threshold, activation threshold, min/max, \
cooldown or polling interval, or the generated HPA's behavior, explain it.
- It is paused, or in fallback because a scaler kept failing.

Active=False is not a failure: it means no trigger is above its activation \
threshold, so KEDA is holding the workload at its minimum (or zero).

Be direct; assume fluency with kubectl and KEDA. Prefer one well-supported \
cause over a list of possibilities. If the evidence is genuinely \
insufficient, say so and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

const DIAGNOSE_SERVICE_SYSTEM: &str = "\
You diagnose Kubernetes Services for an experienced SRE.

You are given the Service's spec, its endpoints as the EndpointSlices \
report them, the pods its selector matches — or, when it matches none, the \
pods and workloads that nearly match and the label that keeps each out — \
whether its target ports exist on those pods, the events of a matching pod \
that is not ready, the Ingresses routing to it, its events, and its \
manifest. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the pod, the label, the \
port, the event, or the field.
3. Concrete next steps: the exact command to run or field to change.

Say which of these you are looking at, because the fixes differ:
- The selector matches no pods: a label that differs from the pods' (read \
the near misses), a workload scaled to zero or deleted, or a selector for \
something that does not run in this cluster at all — on a managed control \
plane such as AKS, etcd, kube-scheduler and kube-controller-manager have no \
pods, so a Service selecting them (often created by a monitoring chart) is \
empty by design and the fix is to stop creating it, not to fix the cluster.
- Pods match but are not ready: the readiness probe is failing, the \
container is crashing or still starting, or the pod is not scheduled. The \
pod's events usually say which.
- Endpoints are ready but traffic still fails: a target port that is not \
the one the process listens on, or a named target port no container \
declares.
- A LoadBalancer with no address: the cloud provider could not create it; \
its events and the service.beta.kubernetes.io annotations say why.
- No selector: its endpoints are written by hand or by another controller, \
and that is where to look.

If the Service is healthy, say so plainly rather than inventing a problem.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over \
a list of possibilities. If the evidence is genuinely insufficient, say so \
and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

const DIAGNOSE_INGRESS_SYSTEM: &str = "\
You diagnose Kubernetes Ingresses for an experienced SRE.

You are given the Ingress's routes, TLS and address; whether its class \
exists and which controller serves it; the controller's workloads and its \
own log lines from the last hour about this Ingress, its Services and its \
Secrets; each backend Service with its port and ready endpoints; each TLS \
Secret, checked by key name and by the public fields of its certificate; \
cert-manager's Certificates for those Secrets; other Ingresses with the same \
hosts; its events; and its manifest. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the log line, the backend, \
the certificate, or the field.
3. Concrete next steps: the exact command to run or field to change.

The controller's log is usually where the actual error is — a rejected \
configuration, a Service with no active endpoint, a certificate it could not \
load. Quote it and say what it means for this Ingress.

Say which of these you are looking at, because the fixes differ:
- Not claimed: no controller serves its class — the class it names has no \
IngressClass and no controller flag names it, it names no class and no \
controller watches class-less Ingresses — or the controller is down or \
rejects it. No published address is a hint, not proof: some controllers \
serve without publishing one, so look for the controller's log and events.
- Admitted but failing requests (502, 503, 404): a backend Service that does \
not exist, a port that is not one of its ports, no ready endpoint behind it, \
or a path or pathType that does not match the requests.
- TLS: the Secret is missing or lacks tls.crt or tls.key, the certificate is \
expired or names other hosts, or cert-manager cannot issue it — then the \
controller serves its default certificate.
- A conflict: another Ingress of the same class claims the same host and \
path.

If the Ingress looks healthy, say so plainly rather than inventing a problem.

Be direct; assume fluency with kubectl. Prefer one well-supported cause over \
a list of possibilities. If the evidence is genuinely insufficient, say so \
and name what would settle it.

Some values are replaced with [REDACTED] before you see them — secrets and \
personal data are stripped deliberately. Do not speculate about redacted \
contents, and do not ask for them.";

const DIAGNOSE_PVC_SYSTEM: &str = "\
You diagnose Kubernetes PersistentVolumeClaims for an experienced SRE.

You are given the claim's phase, size and conditions; its StorageClass, or \
why it has none; the PersistentVolume bound to it and its CSI driver; the \
pods that mount it, and the events of those that are not ready; the \
VolumeAttachments of its volume; how full the volume is; the events of the \
claim and the volume; and the manifest. Respond with:
1. The most likely root cause, stated plainly.
2. The specific evidence that points there — cite the event, the attachment \
error, the class, or the field.
3. Concrete next steps: the exact command to run or field to change.

Say which of these you are looking at, because the fixes differ:
- Pending, never bound: no class and no default, a class that does not \
exist, or a provisioner that refuses — quota, an unsupported SKU or access \
mode (Azure Disk is ReadWriteOnce only), a zone it cannot use. With \
WaitForFirstConsumer, Pending until a pod uses it is normal, not a fault.
- Bound, but its pods cannot use it: a single-node volume wanted on another \
node (Multi-Attach), a volume pinned to a zone the pod's node is not in, a \
node at its attach limit, a CSI driver missing from the node. The pods' \
events and the attachment errors say which. Having no VolumeAttachment is \
not evidence: drivers that skip attach, such as Azure Files, create none.
- A resize that has not finished: the class does not allow expansion, or \
the filesystem resize waits for the pod to restart.
- Full, or out of inodes.
- Lost or released: the volume was deleted, or belongs to another claim.

If the claim is healthy, say so plainly rather than inventing a problem.

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
        // Said from what was cut, not assumed healthy: with more than the cap
        // of stuck claims, the cut includes stuck ones too.
        let omitted = &rows[DIAGNOSE_NAP_CLAIMS..];
        let of = |r: u8| omitted.iter().filter(|(rank, _)| *rank == r).count();
        let parts: Vec<String> = [(0, "not Ready"), (1, "terminating"), (2, "marked for replacement"), (3, "Ready with nothing pending")]
            .into_iter()
            .filter(|(r, _)| of(*r) > 0)
            .map(|(r, label)| format!("{} {label}", of(r)))
            .collect();
        out.push_str(&format!("\n… and {} more: {}", omitted.len(), parts.join(", ")));
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
    // Checked over every pod, not just the ones read above: mid-rename, the
    // new name may only be on pods past the sample.
    let present = |name: &str| {
        pods.iter().any(|p| {
            p.spec.as_ref().is_some_and(|s| {
                s.containers.iter().any(|c| c.name == name)
                    || s.init_containers.iter().flatten().any(|c| c.name == name && c.restart_policy.as_deref() == Some("Always"))
            })
        })
    };
    for need in needs {
        if let Some(c) = &need.container {
            if !present(c) {
                out.push_str(&format!("\nno pod has a container named {c}, which the {} target reads", need.metric));
            }
        }
    }
    out
}

/// The object the HPA scales: its replica counts as the controller reports them.
///
/// The counts come from its scale subresource, which every scalable kind
/// reports the same way — a CRD may keep its own in `spec.size` — and the
/// readiness detail from the object, where a workload kind has it.
fn render_hpa_target(
    target: &Result<kube::api::DynamicObject, String>,
    scale: &Result<k8s_openapi::api::autoscaling::v1::Scale, String>,
    selector: &Result<String, String>,
) -> String {
    let mut out = match scale {
        Ok(sc) => format!(
            "replicas (from its scale subresource): desired {}, current {}",
            sc.spec.as_ref().and_then(|s| s.replicas).map(|n| n.to_string()).unwrap_or_else(|| "(unset)".to_string()),
            sc.status.as_ref().map(|s| s.replicas.to_string()).unwrap_or_else(|| "(unset)".to_string()),
        ),
        Err(e) => read_failure("scale", e),
    };
    match target {
        Ok(t) => {
            let detail: Vec<String> = [("ready", "/status/readyReplicas"), ("updated", "/status/updatedReplicas"), ("available", "/status/availableReplicas")]
                .into_iter()
                .filter_map(|(label, path)| t.data.pointer(path).and_then(|v| v.as_i64()).map(|n| format!("{label} {n}")))
                .collect();
            if !detail.is_empty() {
                out.push_str(&format!("\nstatus: {}", detail.join(", ")));
            }
        }
        // Said once: when the object is missing, so is its scale and selector.
        Err(e) if scale.as_ref().err() == Some(e) => {}
        Err(e) => out.push_str(&format!("\n{}", read_failure("target", e))),
    }
    match selector {
        Ok(s) => out.push_str(&format!("\nselector (from its scale subresource): {s}")),
        Err(_) if target.is_err() && scale.is_err() => {}
        Err(e) => out.push_str(&format!("\nselector unavailable: {e}")),
    }
    out
}

/// A read that failed, said as what it found: an object that does not exist
/// is evidence — a ScaledObject pointing at a deleted Deployment — where any
/// other failure is a gap in what could be seen.
fn read_failure(what: &str, e: &str) -> String {
    if e.ends_with(" does not exist") {
        format!("({e})")
    } else {
        format!("({what} unavailable: {e})")
    }
}

/// One APIService: available, or why not, and what serves it.
fn render_api_service(s: &k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService) -> String {
    let name = s.metadata.name.clone().unwrap_or_default();
    let available = s.status.as_ref().and_then(|st| st.conditions.as_ref()).and_then(|c| c.iter().find(|c| c.type_ == "Available"));
    let backend = s
        .spec
        .as_ref()
        .and_then(|sp| sp.service.as_ref())
        .map(|svc| format!(", served by {}/{}", svc.namespace.clone().unwrap_or_default(), svc.name.clone().unwrap_or_default()))
        .unwrap_or_default();
    match available {
        Some(c) if c.status == "True" => format!("{name} Available{backend}"),
        Some(c) => format!(
            "{name} Available={} ({}){backend}\n  {}",
            c.status,
            c.reason.clone().unwrap_or_default(),
            c.message.clone().unwrap_or_default()
        ),
        None => format!("{name} (no Available condition reported){backend}"),
    }
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
                .map(render_api_service)
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
    let target = render_hpa_target(&d.target, &d.scale, &d.selector);
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

/// How many distinct operator log entries go into a KEDA diagnosis.
const DIAGNOSE_KEDA_LOG_ENTRIES: usize = 15;

/// How much of one operator error to send; Go errors wrap and repeat.
const DIAGNOSE_KEDA_ERROR_CHARS: usize = 600;

/// How many of a ScaledJob's Jobs are listed one by one.
const DIAGNOSE_KEDA_JOBS: usize = 8;

/// A KEDA object's settings and triggers.
fn render_keda_status(d: &crate::models::KedaDetail, kind: &str) -> String {
    let mut lines = Vec::new();
    if kind == "ScaledJob" {
        lines.push(format!("runs: Jobs from its jobTargetRef template, scaling strategy {}", d.scaling_strategy));
    } else {
        lines.push(format!("scales: {}/{}", d.target_kind, d.target_name));
    }
    let idle = d.idle_replicas.map(|i| format!(", idle {i}")).unwrap_or_default();
    lines.push(format!("replicas: min {}, max {}{idle}", d.min_replicas, d.max_replicas));
    lines.push(format!("polling interval: {}s", d.polling_interval));
    if let Some(c) = d.cooldown_period {
        lines.push(format!("cooldown period: {c}s"));
    }
    lines.push(format!("fallback: {}", if d.fallback.is_empty() { "(none)" } else { &d.fallback }));
    if d.paused {
        lines.push(format!(
            "PAUSED{}",
            d.paused_replicas.as_ref().map(|r| format!(" at {r} replicas")).unwrap_or_default()
        ));
    }
    lines.push(format!("last active: {}", d.last_active.as_deref().unwrap_or("never")));
    if !d.hpa_name.is_empty() {
        lines.push(format!("generated HPA: {}", d.hpa_name));
    }
    lines.push("triggers:".to_string());
    if d.triggers.is_empty() {
        lines.push("  (none)".to_string());
    }
    for (i, t) in d.triggers.iter().enumerate() {
        let mut line = format!("  {i}. {}", t.trigger_type);
        if !t.name.is_empty() {
            line.push_str(&format!(" \"{}\"", t.name));
        }
        if !t.metric_type.is_empty() {
            line.push_str(&format!(", metric type {}", t.metric_type));
        }
        match (t.health.as_str(), t.failures) {
            ("", _) => line.push_str(", no health reported"),
            (h, Some(n)) => line.push_str(&format!(", health {h} ({n} failures in a row)")),
            (h, None) => line.push_str(&format!(", health {h}")),
        }
        if !t.auth_ref.is_empty() {
            line.push_str(&format!(", authentication {}", t.auth_ref));
        }
        for m in &t.metadata {
            line.push_str(&format!("\n     {m}"));
        }
        lines.push(line);
    }
    lines.join("\n")
}

/// KEDA's conditions, every one with its message: Ready reports a problem
/// when False, Fallback and Paused when True, and Active is information.
fn render_keda_conditions(conditions: &[crate::models::PodConditionInfo]) -> String {
    if conditions.is_empty() {
        return "(none reported yet)".to_string();
    }
    conditions
        .iter()
        .map(|c| {
            let mut line = format!("{}={}", c.condition_type, c.status);
            if !c.reason.is_empty() {
                line.push_str(&format!(" ({})", c.reason));
            }
            if !c.message.is_empty() {
                line.push_str(&format!(": {}", c.message));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

type KeySets = std::collections::HashMap<(String, String, String), Result<Vec<String>, String>>;

/// Whether `key` is in a Secret or ConfigMap, said without its value.
fn key_presence(key_sets: &KeySets, kind: &str, namespace: &str, name: &str, key: &str) -> String {
    match key_sets.get(&(kind.to_string(), namespace.to_string(), name.to_string())) {
        Some(Ok(keys)) if keys.iter().any(|k| k == key) => format!("{kind} {name} key {key} — present"),
        Some(Ok(keys)) => {
            let mut have: Vec<&str> = keys.iter().map(String::as_str).take(10).collect();
            have.sort_unstable();
            format!("{kind} {name} key {key} — MISSING; it has: {}", if have.is_empty() { "(no keys)".to_string() } else { have.join(", ") })
        }
        Some(Err(e)) => format!("{kind} {name} {e}"),
        None => format!("{kind} {name} (not checked)"),
    }
}

/// Where one environment variable comes from on the container KEDA reads.
///
/// That is the container `only` names or, by KEDA's default, the first one.
/// The kubelet's precedence decides between sources: `env` over `envFrom`,
/// and a later entry over an earlier one, so both are searched last first. A
/// source that could not be read leaves the answer open, and is said to.
fn resolve_env_var(var: &str, containers: &[serde_json::Value], only: Option<&str>, namespace: &str, key_sets: &KeySets) -> String {
    let field = |v: Option<&serde_json::Value>, k: &str| v.and_then(|v| v.get(k)).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let container = match only {
        Some(o) => containers.iter().find(|c| c.get("name").and_then(|n| n.as_str()) == Some(o)),
        None => containers.first(),
    };
    let Some(c) = container else {
        return match only {
            Some(o) => format!("NOT RESOLVABLE — the target has no container {o}"),
            None => "NOT RESOLVABLE — no container to read it from".to_string(),
        };
    };
    let cname = field(Some(c), "name");
    let list = |k: &str| c.get(k).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if let Some(e) = list("env").iter().rev().find(|e| e.get("name").and_then(|n| n.as_str()) == Some(var)) {
        let from = e.get("valueFrom");
        if let Some(r) = from.and_then(|f| f.get("secretKeyRef")) {
            return format!("on container {cname}, from {}", key_presence(key_sets, "Secret", namespace, &field(Some(r), "name"), &field(Some(r), "key")));
        }
        if let Some(r) = from.and_then(|f| f.get("configMapKeyRef")) {
            return format!("on container {cname}, from {}", key_presence(key_sets, "ConfigMap", namespace, &field(Some(r), "name"), &field(Some(r), "key")));
        }
        if from.is_some() {
            return format!("on container {cname}, from a field reference");
        }
        return format!("on container {cname}, set inline in the manifest");
    }
    // Later sources that could not be read, and those that do not exist.
    let (mut unread, mut missing) = (Vec::new(), Vec::new());
    for e in list("envFrom").iter().rev() {
        let prefix = field(Some(e), "prefix");
        let Some(key) = var.strip_prefix(prefix.as_str()) else { continue };
        for (kind, at) in [("Secret", "secretRef"), ("ConfigMap", "configMapRef")] {
            let name = field(e.get(at), "name");
            if name.is_empty() {
                continue;
            }
            match key_sets.get(&(kind.to_string(), namespace.to_string(), name.clone())) {
                Some(Ok(keys)) if keys.iter().any(|k| k == key) => {
                    let mut line = format!("on container {cname}, from all of {kind} {name} (envFrom), key {key} — present");
                    if !unread.is_empty() {
                        line.push_str(&format!(", unless {} (later, so taking precedence) defines it", unread.join(" or ")));
                    }
                    return line;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) if e == "does not exist" => missing.push(format!("{kind} {name}")),
                Some(Err(e)) => unread.push(format!("{kind} {name} ({e})")),
                None => unread.push(format!("{kind} {name} (not checked)")),
            }
        }
    }
    let mut line = if unread.is_empty() {
        format!("NOT DEFINED on container {cname} — KEDA cannot resolve it")
    } else {
        format!("not found on container {cname} in what could be read; it may come from {}", unread.join(" or "))
    };
    if !missing.is_empty() {
        let verb = if missing.len() == 1 { "does" } else { "do" };
        line.push_str(&format!(" (its envFrom names {}, which {verb} not exist)", missing.join(" and ")));
    }
    line
}

/// Where every credential the triggers use comes from, and whether it is there.
///
/// The failures this catches are the common ones and are invisible from the
/// trigger alone: a `connectionFromEnv` naming a variable the container does
/// not have, a Secret that was never created in this namespace, a key spelled
/// differently from the one the reference names. Checked by key name; no value
/// is read into the payload.
fn render_keda_credentials(
    d: &crate::models::KedaDetail,
    object: &serde_json::Value,
    containers: &[serde_json::Value],
    auths: &[(String, Result<kube::api::DynamicObject, String>)],
    key_sets: &KeySets,
    namespace: &str,
    operator_namespace: Option<&str>,
) -> String {
    let only = object
        .pointer("/spec/scaleTargetRef/envSourceContainerName")
        .or_else(|| object.pointer("/spec/envSourceContainerName"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let mut lines = Vec::new();
    for (i, t) in d.triggers.iter().enumerate() {
        for m in &t.metadata {
            let Some((key, var)) = m.split_once('=') else { continue };
            if key.ends_with("FromEnv") {
                lines.push(format!("trigger {i} {key} → env {var}: {}", resolve_env_var(var, containers, only, namespace, key_sets)));
            }
        }
    }
    for (r, auth) in auths {
        let auth = match auth {
            Ok(a) => serde_json::to_value(a).unwrap_or_default(),
            Err(e) => {
                lines.push(format!("{r}: unavailable: {e}"));
                continue;
            }
        };
        let ns = if r.starts_with("ClusterTriggerAuthentication/") { operator_namespace.unwrap_or("keda") } else { namespace };
        let field = |v: &serde_json::Value, k: &str| v.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let spec = auth.get("spec").cloned().unwrap_or_default();
        lines.push(format!("{r}:"));
        if let Some(pi) = spec.get("podIdentity") {
            let id = field(pi, "identityId");
            lines.push(format!(
                "  pod identity: {}{}",
                field(pi, "provider"),
                if id.is_empty() { String::new() } else { format!(", identity {id}") }
            ));
        }
        for t in spec.get("secretTargetRef").and_then(|v| v.as_array()).into_iter().flatten() {
            lines.push(format!("  {} from {}", field(t, "parameter"), key_presence(key_sets, "Secret", ns, &field(t, "name"), &field(t, "key"))));
        }
        for t in spec.get("configMapTargetRef").and_then(|v| v.as_array()).into_iter().flatten() {
            lines.push(format!("  {} from {}", field(t, "parameter"), key_presence(key_sets, "ConfigMap", ns, &field(t, "name"), &field(t, "key"))));
        }
        for t in spec.get("env").and_then(|v| v.as_array()).into_iter().flatten() {
            let only = t.get("containerName").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).or(only);
            lines.push(format!("  {} from env {}: {}", field(t, "parameter"), field(t, "name"), resolve_env_var(&field(t, "name"), containers, only, namespace, key_sets)));
        }
        if let Some(kv) = spec.get("azureKeyVault") {
            let secrets: Vec<String> = kv
                .get("secrets")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .map(|s| format!("{} ← {}", field(s, "parameter"), field(s, "name")))
                .collect();
            lines.push(format!("  Azure Key Vault {}: {}", field(kv, "vaultUri"), secrets.join(", ")));
        }
        if let Some(hv) = spec.get("hashiCorpVault") {
            lines.push(format!("  HashiCorp Vault {} ({} auth)", field(hv, "address"), field(hv, "authentication")));
        }
    }
    if lines.is_empty() {
        "(the triggers name no credentials: no *FromEnv metadata and no authenticationRef)".to_string()
    } else {
        lines.join("\n")
    }
}

/// The operator's log lines about this object, collapsed on what they say.
///
/// A failing scaler logs the same error on every poll — every 30 seconds by
/// default, so a few thousand lines are mostly one error. Collapsed on level,
/// component, message and error, they read as which errors there are, how
/// often, and when last.
fn render_keda_operator_logs(lines: &Result<Vec<String>, String>) -> String {
    let lines = match lines {
        Ok(l) if l.is_empty() => return "(the operator logged nothing about this object in its recent log)".to_string(),
        Ok(l) => l,
        Err(e) => return format!("(operator log unavailable: {e})"),
    };
    // (level, component, message, error) → (count, last time)
    let mut groups: Vec<((String, String, String, String), usize, String)> = Vec::new();
    for line in lines {
        // `time\tLEVEL\t[component\t]message\t{json}`: the controller's own
        // lines carry no component.
        let (head, json) = match line.find("\t{") {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => (line.as_str(), ""),
        };
        let fields: Vec<&str> = head.split('\t').collect();
        let time = fields.first().copied().unwrap_or_default();
        let level = fields.get(1).copied().unwrap_or_default();
        let (component, message) = match fields.len() {
            n if n >= 4 => (fields[2], fields[3..].join(" ")),
            3 => ("", fields[2].to_string()),
            _ => ("", String::new()),
        };
        let error = serde_json::from_str::<serde_json::Value>(json.trim_end())
            .ok()
            .and_then(|j| j.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or_default();
        let key = (level.to_string(), component.to_string(), message, error);
        match groups.iter_mut().find(|g| g.0 == key) {
            Some(g) => {
                g.1 += 1;
                g.2 = time.to_string();
            }
            None => groups.push((key, 1, time.to_string())),
        }
    }
    groups.sort_by(|a, b| b.2.cmp(&a.2));
    let mut out = groups
        .iter()
        .take(DIAGNOSE_KEDA_LOG_ENTRIES)
        .map(|((level, component, message, error), count, last)| {
            let from = if component.is_empty() { String::new() } else { format!(" {component}") };
            let mut line = format!("{level}{from}: {message} (×{count}, last {last})");
            if !error.is_empty() {
                let e = if error.len() > DIAGNOSE_KEDA_ERROR_CHARS {
                    format!("{} …", truncate_on_char_boundary(error, DIAGNOSE_KEDA_ERROR_CHARS))
                } else {
                    error.clone()
                };
                line.push_str(&format!("\n  {e}"));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n");
    if groups.len() > DIAGNOSE_KEDA_LOG_ENTRIES {
        out.push_str(&format!("\n… and {} older distinct entries", groups.len() - DIAGNOSE_KEDA_LOG_ENTRIES));
    }
    out
}

/// KEDA itself: its two Deployments and the external metrics API they serve.
fn render_keda_health(
    operator: &Result<Vec<k8s_openapi::api::apps::v1::Deployment>, String>,
    apis: &Result<Vec<k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService>, String>,
) -> String {
    let mut lines = match operator {
        Ok(d) if d.is_empty() => vec!["no keda-operator or keda-operator-metrics-apiserver Deployment found".to_string()],
        Ok(d) => d
            .iter()
            .map(|d| {
                let status = d.status.clone().unwrap_or_default();
                format!(
                    "{}/{}: ready {}/{}",
                    d.metadata.namespace.clone().unwrap_or_default(),
                    d.metadata.name.clone().unwrap_or_default(),
                    status.ready_replicas.unwrap_or(0),
                    d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1)
                )
            })
            .collect(),
        Err(e) => vec![format!("(KEDA's Deployments unavailable: {e})")],
    };
    lines.push(match apis {
        Ok(s) if s.is_empty() => "external.metrics.k8s.io: NOT REGISTERED — no HPA can read KEDA's metrics".to_string(),
        Ok(s) => format!("external.metrics.k8s.io: {}", s.iter().map(render_api_service).collect::<Vec<_>>().join("\n  ")),
        Err(e) => format!("(APIServices unavailable: {e})"),
    });
    lines.join("\n")
}

/// A ScaledJob's Jobs: counts, then the most recent ones with how they ended.
fn render_keda_jobs(jobs: &Result<Vec<k8s_openapi::api::batch::v1::Job>, String>) -> String {
    let jobs = match jobs {
        Ok(j) if j.is_empty() => return "(it has created no Jobs that still exist)".to_string(),
        Ok(j) => j,
        Err(e) => return format!("(Jobs unavailable: {e})"),
    };
    let finished = |j: &k8s_openapi::api::batch::v1::Job, t: &str| {
        j.status.as_ref().and_then(|s| s.conditions.as_ref()).and_then(|c| c.iter().find(|c| c.type_ == t && c.status == "True")).cloned()
    };
    let (failed, complete) = (jobs.iter().filter(|j| finished(j, "Failed").is_some()).count(), jobs.iter().filter(|j| finished(j, "Complete").is_some()).count());
    let mut out = format!("{} Job(s): {complete} complete, {failed} failed, {} running", jobs.len(), jobs.len() - complete - failed);
    for j in jobs.iter().take(DIAGNOSE_KEDA_JOBS) {
        let created = j.metadata.creation_timestamp.as_ref().map(|t| t.0.to_rfc3339()).unwrap_or_default();
        let state = match (finished(j, "Failed"), finished(j, "Complete")) {
            (Some(c), _) => format!("Failed ({}): {}", c.reason.unwrap_or_default(), c.message.unwrap_or_default()),
            (_, Some(_)) => "Complete".to_string(),
            _ => format!("running, {} active pod(s)", j.status.as_ref().and_then(|s| s.active).unwrap_or(0)),
        };
        out.push_str(&format!("\n{}  created {created}  {state}", j.metadata.name.clone().unwrap_or_default()));
    }
    out
}

/// The HPA KEDA generated: what the HPA controller itself makes of the metrics.
fn render_keda_hpa(hpa: &Result<crate::models::HpaDetail, String>) -> String {
    match hpa {
        Ok(h) => {
            let mut out = format!(
                "replicas: min {}, max {}, current {}, desired {}\nmetrics (current / target):",
                h.min_replicas, h.max_replicas, h.current_replicas, h.desired_replicas
            );
            for m in &h.metrics {
                out.push_str(&format!("\n  {} {}: {} / {}", m.kind, m.name, m.current, m.target));
            }
            out.push_str(&format!("\nconditions:\n{}", render_hpa_conditions(&h.conditions)));
            out
        }
        Err(e) => read_failure("generated HPA", e),
    }
}

/// Assembles everything a KEDA diagnosis needs, redacted.
///
/// The object's own status says *that* a trigger failed and little more; the
/// operator's log says what the event source answered, and the credential
/// check says whether what the trigger needs to authenticate is even there.
pub async fn build_keda_diagnosis_payload(
    context_name: &str,
    namespace: &str,
    kind: &str,
    name: &str,
) -> Result<ClaudeDiagnosisPayload, String> {
    let d = k8s::get_keda_diagnostics(context_name, namespace, kind, name).await?;
    let object_value = serde_json::to_value(&d.object).unwrap_or_default();

    let status = render_keda_status(&d.detail, kind);
    let conditions = render_keda_conditions(&d.detail.conditions);
    let credentials = render_keda_credentials(
        &d.detail,
        &object_value,
        &d.env_containers,
        &d.auths,
        &d.key_sets,
        namespace,
        d.operator_namespace.as_deref(),
    );
    let logs = render_keda_operator_logs(&d.operator_logs);
    let events = render_nap_events(&d.events, &format!("(no events for this {kind})"), false, 25);
    let (scaling_heading, scaling) = match (&d.hpa, &d.jobs) {
        (_, Some(jobs)) => ("Jobs it created".to_string(), render_keda_jobs(jobs)),
        (Some(hpa), _) => (format!("Generated HPA ({})", d.detail.hpa_name), render_keda_hpa(hpa)),
        _ => ("Generated HPA".to_string(), "(KEDA has not reported an HPA for it — status.hpaName is empty)".to_string()),
    };
    let target = match &d.target {
        Some((target, scale)) => {
            let selector = scale.clone().and_then(|s| s.status.and_then(|st| st.selector).ok_or_else(|| "none reported".to_string()));
            Some(render_hpa_target(target, scale, &selector))
        }
        None => None,
    };
    let health = render_keda_health(&d.operator, &d.external_metrics_api);

    let status = redact::redact(&status);
    let conditions_r = redact::redact(&conditions);
    let credentials_r = redact::redact(&credentials);
    let logs_r = redact::redact(&logs);
    let events_r = redact::redact(&events);
    let scaling_r = redact::redact(&scaling);
    let target_r = target.as_deref().map(redact::redact);
    let health_r = redact::redact(&health);
    let manifest_r = redact::redact(&d.manifest);

    let mut parts = vec![&status, &conditions_r, &credentials_r, &logs_r, &events_r, &scaling_r, &health_r, &manifest_r];
    parts.extend(target_r.as_ref());
    let redaction_summary = redact::Redacted::merge(parts).summary();

    let target_section = target_r
        .as_ref()
        .map(|t| format!("## Target ({}/{})\n{}\n\n", d.detail.target_kind, d.detail.target_name, t.text))
        .unwrap_or_default();
    let prompt = format!(
        "{kind} {namespace}/{name}.\n\n\
         ## Settings and triggers\n{}\n\n\
         ## Conditions\n{}\n\n\
         ## Credentials\n{}\n\n\
         ## KEDA operator log about this object\n{}\n\n\
         ## Events\n{}\n\n\
         ## {scaling_heading}\n{}\n\n\
         {target_section}\
         ## KEDA itself\n{}\n\n\
         ## Manifest (managed fields omitted)\n```yaml\n{}\n```",
        status.text, conditions_r.text, credentials_r.text, logs_r.text, events_r.text, scaling_r.text, health_r.text, manifest_r.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note: None,
    })
}

/// How many endpoints, matching pods and near misses are listed one by one.
const DIAGNOSE_SERVICE_ENDPOINTS: usize = 20;
const DIAGNOSE_SERVICE_PODS: usize = 15;
const DIAGNOSE_SERVICE_NEAR_MISSES: usize = 5;

fn int_or_string(v: &k8s_openapi::apimachinery::pkg::util::intstr::IntOrString) -> String {
    match v {
        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(n) => n.to_string(),
        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::String(s) => s.clone(),
    }
}

/// The Service's own spec: what it selects, the ports it maps, and how it is
/// reached.
fn render_service_spec(svc: &k8s_openapi::api::core::v1::Service) -> String {
    let spec = svc.spec.clone().unwrap_or_default();
    let service_type = spec.type_.clone().unwrap_or_else(|| "ClusterIP".to_string());
    let mut lines = vec![format!("type: {service_type}")];
    if service_type == "ExternalName" {
        lines.push(format!(
            "external name: {} (a DNS CNAME; it has no selector, endpoints or ports of its own by design)",
            spec.external_name.unwrap_or_default()
        ));
        return lines.join("\n");
    }
    lines.push(match spec.cluster_ip.as_deref() {
        Some("None") => "cluster IP: None (headless: DNS returns the ready pods' addresses directly)".to_string(),
        Some(ip) => format!("cluster IP: {ip}"),
        None => "cluster IP: (unassigned)".to_string(),
    });
    let selector = spec.selector.clone().unwrap_or_default();
    lines.push(if selector.is_empty() {
        "selector: none — its endpoints are not managed by Kubernetes; they are written by hand or by another controller".to_string()
    } else {
        format!("selector: {}", selector.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", "))
    });
    lines.push("ports:".to_string());
    for p in spec.ports.iter().flatten() {
        let target = p.target_port.as_ref().map(int_or_string).unwrap_or_else(|| format!("{} (defaulted to the port)", p.port));
        let name = p.name.as_deref().map(|n| format!("{n} ")).unwrap_or_default();
        let node_port = p.node_port.map(|n| format!(", node port {n}")).unwrap_or_default();
        let app = p.app_protocol.as_deref().map(|a| format!(", appProtocol {a}")).unwrap_or_default();
        lines.push(format!("  {name}{} → target port {target}/{}{node_port}{app}", p.port, p.protocol.as_deref().unwrap_or("TCP")));
    }
    if spec.publish_not_ready_addresses == Some(true) {
        lines.push("publishNotReadyAddresses: true (pods are published before they are ready)".to_string());
    }
    if let Some(a) = spec.session_affinity.as_deref().filter(|a| *a != "None") {
        lines.push(format!("session affinity: {a}"));
    }
    if let Some(p) = &spec.external_traffic_policy {
        lines.push(format!("external traffic policy: {p}"));
    }
    if let Some(p) = spec.internal_traffic_policy.as_deref().filter(|p| *p != "Cluster") {
        lines.push(format!("internal traffic policy: {p}"));
    }
    if service_type == "LoadBalancer" {
        if let Some(c) = &spec.load_balancer_class {
            lines.push(format!("load balancer class: {c}"));
        }
        let ingress: Vec<String> = svc
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|i| i.ip.clone().or_else(|| i.hostname.clone()))
            .collect();
        lines.push(if ingress.is_empty() {
            "load balancer address: PENDING — none assigned yet".to_string()
        } else {
            format!("load balancer address: {}", ingress.join(", "))
        });
    }
    if let Some(ips) = spec.external_ips.filter(|i| !i.is_empty()) {
        lines.push(format!("external IPs: {}", ips.join(", ")));
    }
    lines.join("\n")
}

/// What the EndpointSlices say is behind it, address by address.
fn render_service_endpoints(slices: &Result<Vec<k8s_openapi::api::discovery::v1::EndpointSlice>, String>, has_selector: bool) -> String {
    let slices = match slices {
        Ok(s) => s,
        Err(e) => return format!("(EndpointSlices unavailable: {e})"),
    };
    let endpoints: Vec<&k8s_openapi::api::discovery::v1::Endpoint> = slices.iter().flat_map(|s| s.endpoints.iter()).collect();
    if endpoints.is_empty() {
        return if slices.is_empty() && !has_selector {
            "(no EndpointSlices: nothing has written any for this selector-less Service, so it routes nowhere)".to_string()
        } else {
            "(no endpoints: nothing is behind it)".to_string()
        };
    }
    let condition = |e: &k8s_openapi::api::discovery::v1::Endpoint, f: fn(&k8s_openapi::api::discovery::v1::EndpointConditions) -> Option<bool>| {
        e.conditions.as_ref().and_then(f)
    };
    let ready = endpoints.iter().filter(|e| condition(e, |c| c.ready).unwrap_or(true)).count();
    let terminating = endpoints.iter().filter(|e| condition(e, |c| c.terminating) == Some(true)).count();
    let ports: Vec<String> = slices
        .iter()
        .flat_map(|s| s.ports.iter().flatten())
        .map(|p| {
            let name = p.name.as_deref().filter(|n| !n.is_empty()).map(|n| format!("{n} ")).unwrap_or_default();
            format!("{name}{}/{}", p.port.map(|n| n.to_string()).unwrap_or_else(|| "(none)".to_string()), p.protocol.as_deref().unwrap_or("TCP"))
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut out = format!("{ready} of {} ready, {terminating} terminating; resolved ports: {}", endpoints.len(), if ports.is_empty() { "(none)".to_string() } else { ports.join(", ") });
    for e in endpoints.iter().take(DIAGNOSE_SERVICE_ENDPOINTS) {
        let state = match (condition(e, |c| c.ready), condition(e, |c| c.terminating)) {
            (_, Some(true)) => "terminating",
            (Some(false), _) => "NOT READY",
            _ => "ready",
        };
        let target = e
            .target_ref
            .as_ref()
            .map(|t| format!(" ({} {})", t.kind.as_deref().unwrap_or("object"), t.name.as_deref().unwrap_or_default()))
            .unwrap_or_default();
        let node = e.node_name.as_deref().map(|n| format!(" on {n}")).unwrap_or_default();
        out.push_str(&format!("\n  {} {state}{target}{node}", e.addresses.join(",")));
    }
    if endpoints.len() > DIAGNOSE_SERVICE_ENDPOINTS {
        out.push_str(&format!("\n  … and {} more", endpoints.len() - DIAGNOSE_SERVICE_ENDPOINTS));
    }
    out
}

fn pod_is_ready(p: &k8s_openapi::api::core::v1::Pod) -> bool {
    p.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
}

/// A probe, said as what it checks: never an exec command, which can carry
/// anything.
fn render_probe(p: &k8s_openapi::api::core::v1::Probe) -> String {
    let what = if let Some(h) = &p.http_get {
        format!("httpGet {}:{}{}", h.scheme.as_deref().unwrap_or("HTTP").to_lowercase(), int_or_string(&h.port), h.path.as_deref().unwrap_or("/"))
    } else if let Some(t) = &p.tcp_socket {
        format!("tcpSocket {}", int_or_string(&t.port))
    } else if let Some(g) = &p.grpc {
        format!("grpc {}", g.port)
    } else if p.exec.is_some() {
        "exec (a command)".to_string()
    } else {
        "(no handler)".to_string()
    };
    format!(
        "{what}, every {}s, fails after {}, first after {}s",
        p.period_seconds.unwrap_or(10),
        p.failure_threshold.unwrap_or(3),
        p.initial_delay_seconds.unwrap_or(0)
    )
}

/// The containers that serve a pod's traffic and count towards its
/// readiness: its containers and its native sidecars — init containers that
/// keep running — but not one-shot init containers.
fn serving_containers(p: &k8s_openapi::api::core::v1::Pod) -> impl Iterator<Item = &k8s_openapi::api::core::v1::Container> {
    p.spec.iter().flat_map(|s| {
        s.containers
            .iter()
            .chain(s.init_containers.iter().flatten().filter(|c| c.restart_policy.as_deref() == Some("Always")))
    })
}

/// One matching pod in a line: whether it is ready and, if not, why.
fn render_service_pod(p: &k8s_openapi::api::core::v1::Pod) -> String {
    let status = p.status.clone().unwrap_or_default();
    let mut line = format!("{}: {}", p.metadata.name.as_deref().unwrap_or_default(), status.phase.as_deref().unwrap_or("Unknown"));
    if p.metadata.deletion_timestamp.is_some() {
        line.push_str(", being deleted");
    }
    match status.conditions.iter().flatten().find(|c| c.type_ == "Ready") {
        Some(c) if c.status == "True" => line.push_str(", ready"),
        Some(c) => {
            line.push_str(", NOT READY");
            if let Some(r) = c.reason.as_deref() {
                line.push_str(&format!(" ({r})"));
            }
        }
        None => line.push_str(", NOT READY (no Ready condition yet)"),
    }
    // Init containers first: one stuck there holds every other container in
    // PodInitializing, which says nothing of why. A one-shot init container
    // that exited 0 is done, not failed; a native sidecar is judged like any
    // container.
    let sidecars: Vec<&str> = p
        .spec
        .iter()
        .flat_map(|s| s.init_containers.iter().flatten())
        .filter(|c| c.restart_policy.as_deref() == Some("Always"))
        .map(|c| c.name.as_str())
        .collect();
    let statuses: Vec<(&k8s_openapi::api::core::v1::ContainerStatus, String, bool)> = status
        .init_container_statuses
        .iter()
        .flatten()
        .map(|c| {
            let sidecar = sidecars.contains(&c.name.as_str());
            (c, format!("{} {}", if sidecar { "sidecar" } else { "init" }, c.name), !sidecar)
        })
        .chain(status.container_statuses.iter().flatten().map(|c| (c, c.name.clone(), false)))
        .collect();
    let restarts: i32 = statuses.iter().map(|(c, _, _)| c.restart_count).sum();
    if restarts > 0 {
        line.push_str(&format!(", {restarts} restarts"));
    }
    for (c, name, one_shot) in &statuses {
        let state = c.state.as_ref();
        if let Some(w) = state.and_then(|s| s.waiting.as_ref()) {
            line.push_str(&format!("; {name} waiting: {}", w.reason.as_deref().unwrap_or("?")));
        } else if let Some(t) = state.and_then(|s| s.terminated.as_ref()) {
            if !(*one_shot && t.exit_code == 0) {
                line.push_str(&format!("; {name} terminated: {} (exit {})", t.reason.as_deref().unwrap_or("?"), t.exit_code));
            }
        } else if !c.ready && !one_shot {
            line.push_str(&format!("; {name} running, not ready"));
        }
    }
    if let Some(n) = p.spec.as_ref().and_then(|s| s.node_name.as_deref()) {
        line.push_str(&format!("; on {n}"));
    }
    line
}

/// The pods behind the Service — or, when the selector matches none, the
/// pods that nearly match and the label that keeps each out.
fn render_service_pods(
    selector: &std::collections::BTreeMap<String, String>,
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
    namespace: &str,
) -> String {
    if selector.is_empty() {
        return "(no selector, so no pods are matched by label)".to_string();
    }
    let pods = match pods {
        Ok(p) => p,
        Err(e) => return format!("(pods unavailable: {e})"),
    };
    let matching: Vec<&k8s_openapi::api::core::v1::Pod> =
        pods.iter().filter(|p| k8s::selector_terms_met(selector, p.metadata.labels.as_ref()) == selector.len()).collect();
    if !matching.is_empty() {
        let ready = matching.iter().filter(|p| pod_is_ready(p)).count();
        let mut out = format!("{} pods match, {ready} ready", matching.len());
        // Unready first: they are the ones the diagnosis is about.
        let mut ordered = matching.clone();
        ordered.sort_by_key(|p| pod_is_ready(p));
        for p in ordered.iter().take(DIAGNOSE_SERVICE_PODS) {
            out.push_str(&format!("\n  {}", render_service_pod(p)));
        }
        if matching.len() > DIAGNOSE_SERVICE_PODS {
            out.push_str(&format!("\n  … and {} more", matching.len() - DIAGNOSE_SERVICE_PODS));
        }
        // Readiness probes, each distinct one once: the pods of one workload
        // repeat each other, but mid-rollout, or across two workloads, one
        // container name can carry two probes. Unready pods first, so theirs lead.
        let mut probes: Vec<(String, String)> = Vec::new();
        for p in &ordered {
            for c in serving_containers(p) {
                let probe = c.readiness_probe.as_ref().map(render_probe).unwrap_or_else(|| "none (ready as soon as it starts)".to_string());
                let entry = (c.name.clone(), probe);
                if !probes.contains(&entry) {
                    probes.push(entry);
                }
            }
        }
        out.push_str("\nreadiness probes:");
        for (n, probe) in probes {
            out.push_str(&format!("\n  {n}: {probe}"));
        }
        return out;
    }

    let mut out = format!("NO POD in namespace {namespace} matches the selector ({} pods in the namespace)", pods.len());
    // Near misses, grouped on what keeps them out: the same mistake usually
    // repeats across every replica of one workload.
    let mut groups: Vec<(String, usize, String)> = Vec::new();
    for p in pods {
        let labels = p.metadata.labels.as_ref();
        if k8s::selector_terms_met(selector, labels) == 0 {
            continue;
        }
        let why: Vec<String> = selector
            .iter()
            .filter_map(|(k, v)| match labels.and_then(|l| l.get(k)) {
                Some(have) if have == v => None,
                Some(have) => Some(format!("{k}={have} where the selector wants {k}={v}")),
                None => Some(format!("no {k} label")),
            })
            .collect();
        let why = why.join("; ");
        match groups.iter_mut().find(|g| g.0 == why) {
            Some(g) => g.1 += 1,
            None => groups.push((why, 1, p.metadata.name.clone().unwrap_or_default())),
        }
    }
    if groups.is_empty() {
        out.push_str("\nno pod in the namespace carries any of the selector's labels");
    } else {
        out.push_str("\nnear misses (pods with some of the selector's labels):");
        for (why, n, example) in groups.iter().take(DIAGNOSE_SERVICE_NEAR_MISSES) {
            out.push_str(&format!("\n  {n} pod(s), e.g. {example}: {why}"));
        }
    }
    out
}

/// Whether each target port exists on the pods: a named one must be declared
/// by a container, or the Service has no port to send to on that pod.
fn render_service_port_check(svc: &k8s_openapi::api::core::v1::Service, pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>) -> String {
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    let spec = svc.spec.clone().unwrap_or_default();
    let selector = spec.selector.clone().unwrap_or_default();
    let Ok(pods) = pods else { return "(not checked: pods unavailable)".to_string() };
    let matching: Vec<&k8s_openapi::api::core::v1::Pod> =
        pods.iter().filter(|p| !selector.is_empty() && k8s::selector_terms_met(&selector, p.metadata.labels.as_ref()) == selector.len()).collect();
    if matching.is_empty() {
        return "(not checked: no matching pods)".to_string();
    }
    // Native sidecars declare ports a Service can target, as containers do.
    let declared = |p: &k8s_openapi::api::core::v1::Pod| -> Vec<k8s_openapi::api::core::v1::ContainerPort> {
        serving_containers(p).flat_map(|c| c.ports.iter().flatten()).cloned().collect()
    };
    let mut lines = Vec::new();
    for port in spec.ports.iter().flatten() {
        let target = port.target_port.clone().unwrap_or(IntOrString::Int(port.port));
        let protocol = port.protocol.as_deref().unwrap_or("TCP");
        let label = format!("port {} → {}", port.port, int_or_string(&target));
        match &target {
            IntOrString::String(name) => {
                // A named port resolves on its name and the Service port's
                // protocol together: `dns` declared for UDP is no target for TCP.
                let resolves = |cp: &k8s_openapi::api::core::v1::ContainerPort| {
                    cp.name.as_deref() == Some(name.as_str()) && cp.protocol.as_deref().unwrap_or("TCP") == protocol
                };
                let missing: Vec<&str> = matching
                    .iter()
                    .filter(|p| !declared(p).iter().any(resolves))
                    .filter_map(|p| p.metadata.name.as_deref())
                    .collect();
                if missing.is_empty() {
                    let numbers: std::collections::BTreeSet<i32> =
                        matching.iter().flat_map(|p| declared(p)).filter(resolves).map(|cp| cp.container_port).collect();
                    lines.push(format!("{label}: named port declared on every matching pod, as {}", numbers.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")));
                } else {
                    lines.push(format!(
                        "{label}: NAMED PORT NOT DECLARED for {protocol} on {} of {} matching pods (e.g. {}) — those endpoints get no port",
                        missing.len(),
                        matching.len(),
                        missing[0]
                    ));
                }
            }
            IntOrString::Int(n) => {
                let any = matching.iter().any(|p| declared(p).iter().any(|cp| cp.container_port == *n));
                lines.push(if any {
                    format!("{label}: declared by a container")
                } else {
                    let have: std::collections::BTreeSet<i32> = matching.iter().flat_map(|p| declared(p)).map(|cp| cp.container_port).collect();
                    format!(
                        "{label}: no container declares it (harmless if the process listens there anyway; declared: {})",
                        if have.is_empty() { "none".to_string() } else { have.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ") }
                    )
                });
            }
        }
    }
    lines.join("\n")
}

/// The workloads whose pods the selector would match, and how many they run:
/// a Deployment scaled to zero is a selector that is right and a Service
/// with nothing behind it all the same.
fn render_service_workloads(selector: &std::collections::BTreeMap<String, String>, workloads: &[k8s::ServiceWorkload], errors: &[String]) -> String {
    if selector.is_empty() {
        return "(no selector)".to_string();
    }
    let unread: String = errors.iter().map(|e| format!("\n(unavailable: {e})")).collect();
    if workloads.is_empty() {
        return format!("(no Deployment, StatefulSet or DaemonSet that could be read has any of the selector's labels on its pod template){unread}");
    }
    let mut full: Vec<String> = Vec::new();
    let mut near: Vec<String> = Vec::new();
    for w in workloads {
        let met = k8s::selector_terms_met(selector, Some(&w.labels));
        if met == 0 {
            continue;
        }
        let line = format!("{}/{}: {} desired, {} ready", w.kind, w.name, w.desired, w.ready);
        if met == selector.len() {
            full.push(line);
        } else {
            let missing: Vec<String> = selector
                .iter()
                .filter(|(k, v)| w.labels.get(*k) != Some(*v))
                .map(|(k, v)| match w.labels.get(k) {
                    Some(have) => format!("{k}={have} not {v}"),
                    None => format!("no {k}"),
                })
                .collect();
            near.push(format!("{line} — template has {}", missing.join(", ")));
        }
    }
    let mut out = if full.is_empty() { "no workload's pod template matches the selector".to_string() } else { format!("matching:\n  {}", full.join("\n  ")) };
    if !near.is_empty() {
        out.push_str(&format!("\nnear misses:\n  {}", near.iter().take(DIAGNOSE_SERVICE_NEAR_MISSES).cloned().collect::<Vec<_>>().join("\n  ")));
    }
    out.push_str(&unread);
    out
}

/// What the nodes say about the control plane, without claiming more: a
/// self-managed cluster may label no node with a role, so only AKS's own
/// node labels settle that etcd and the scheduler run no pods here.
fn render_service_cluster(control_plane: &Result<k8s::ControlPlane, String>) -> String {
    match control_plane {
        Ok(c) if c.aks => format!(
            "AKS: yes — the control plane is managed by Azure, and its components (etcd, kube-scheduler, kube-controller-manager, kube-apiserver) run no pods in this cluster\nnodes labelled control-plane or master: {}",
            c.role_nodes
        ),
        Ok(c) => format!("AKS: no\nnodes labelled control-plane or master: {}", c.role_nodes),
        Err(e) => format!("(nodes unavailable: {e})"),
    }
}

/// The Ingresses that send traffic here, and on which of its ports.
fn render_service_ingresses(name: &str, ingresses: &Result<Vec<k8s_openapi::api::networking::v1::Ingress>, String>) -> String {
    let ingresses = match ingresses {
        Ok(i) if i.is_empty() => return "(no Ingress in the namespace routes to it)".to_string(),
        Ok(i) => i,
        Err(e) => return format!("(Ingresses unavailable: {e})"),
    };
    let port = |b: &k8s_openapi::api::networking::v1::IngressBackend| {
        b.service
            .as_ref()
            .and_then(|s| s.port.as_ref())
            .map(|p| p.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| p.number.map(|n| n.to_string()).unwrap_or_default()))
            .unwrap_or_default()
    };
    let mut lines = Vec::new();
    for i in ingresses {
        let spec = i.spec.clone().unwrap_or_default();
        let iname = i.metadata.name.clone().unwrap_or_default();
        if let Some(b) = spec.default_backend.as_ref().filter(|b| b.service.as_ref().is_some_and(|s| s.name == name)) {
            lines.push(format!("{iname}: default backend → port {}", port(b)));
        }
        for r in spec.rules.iter().flatten() {
            for p in r.http.iter().flat_map(|h| h.paths.iter()) {
                if p.backend.service.as_ref().is_some_and(|s| s.name == name) {
                    lines.push(format!("{iname}: {}{} → port {}", r.host.as_deref().unwrap_or("*"), p.path.as_deref().unwrap_or("/"), port(&p.backend)));
                }
            }
        }
    }
    lines.join("\n")
}

/// Assembles everything a Service diagnosis needs, redacted.
///
/// A Service rarely fails in its own status; it fails in what is behind it.
/// So most of this is the pods: the ones the selector matches and why they
/// are not ready, or — when it matches none — the ones that nearly match and
/// the workloads that would supply them.
pub async fn build_service_diagnosis_payload(context_name: &str, namespace: &str, name: &str) -> Result<ClaudeDiagnosisPayload, String> {
    let d = k8s::get_service_diagnostics(context_name, namespace, name).await?;
    let selector = d.service.spec.as_ref().and_then(|s| s.selector.clone()).unwrap_or_default();

    let spec = redact::redact(&render_service_spec(&d.service));
    let external_name = d.service.spec.as_ref().and_then(|s| s.type_.as_deref()) == Some("ExternalName");
    let endpoints = redact::redact(&if external_name {
        "(none, by design: an ExternalName resolves through a DNS CNAME and has no endpoints)".to_string()
    } else {
        render_service_endpoints(&d.slices, !selector.is_empty())
    });
    let pods = redact::redact(&render_service_pods(&selector, &d.pods, namespace));
    let ports = redact::redact(&render_service_port_check(&d.service, &d.pods));
    let workloads = redact::redact(&render_service_workloads(&selector, &d.workloads.0, &d.workloads.1));
    let unready = redact::redact(&match &d.unready_pod_events {
        Some((pod, events)) => format!("pod {pod}:\n{}", render_nap_events(events, "(no events for it)", false, 15)),
        None => "(every matching pod is ready, or none matches)".to_string(),
    });
    let ingresses = redact::redact(&render_service_ingresses(name, &d.ingresses));
    let events = redact::redact(&render_nap_events(&d.events, "(no events for this Service)", false, 25));
    let cluster = redact::redact(&render_service_cluster(&d.control_plane));
    let manifest = redact::redact(&d.manifest);

    let redaction_summary = redact::Redacted::merge([&spec, &endpoints, &pods, &ports, &workloads, &unready, &ingresses, &events, &cluster, &manifest]).summary();

    let prompt = format!(
        "Service {namespace}/{name}.\n\n\
         ## Spec\n{}\n\n\
         ## Endpoints\n{}\n\n\
         ## Pods\n{}\n\n\
         ## Target ports\n{}\n\n\
         ## Workloads\n{}\n\n\
         ## Events of an unready matching pod\n{}\n\n\
         ## Ingresses routing to it\n{}\n\n\
         ## Events\n{}\n\n\
         ## Cluster\n{}\n\n\
         ## Manifest (managed fields omitted)\n```yaml\n{}\n```",
        spec.text, endpoints.text, pods.text, ports.text, workloads.text, unready.text, ingresses.text, events.text, cluster.text, manifest.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note: None,
    })
}

/// How many distinct controller log entries, and how much of each, go into an
/// Ingress diagnosis.
const DIAGNOSE_INGRESS_LOG_ENTRIES: usize = 15;
const DIAGNOSE_INGRESS_LOG_CHARS: usize = 400;

/// The port an Ingress backend names: its number, or its name.
fn ingress_backend_port(b: &k8s_openapi::api::networking::v1::IngressServiceBackend) -> String {
    b.port
        .as_ref()
        .map(|p| p.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| p.number.map(|n| n.to_string()).unwrap_or_default()))
        .unwrap_or_default()
}

/// Every (Service, port) an Ingress routes to.
fn ingress_backend_refs(ing: &k8s_openapi::api::networking::v1::Ingress) -> Vec<(String, String)> {
    let spec = ing.spec.as_ref();
    let mut refs: Vec<(String, String)> = spec
        .and_then(|s| s.default_backend.as_ref())
        .into_iter()
        .chain(spec.and_then(|s| s.rules.as_ref()).into_iter().flatten().flat_map(|r| r.http.iter().flat_map(|h| h.paths.iter().map(|p| &p.backend))))
        .filter_map(|b| b.service.as_ref().map(|s| (s.name.clone(), ingress_backend_port(s))))
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

/// The Ingress's own spec and status: its class, its routes, its TLS, and
/// whether a controller has given it an address.
fn render_ingress_spec(ing: &k8s_openapi::api::networking::v1::Ingress) -> String {
    let spec = ing.spec.clone().unwrap_or_default();
    let mut lines = vec![match k8s::ingress_class_of(ing) {
        Some(c) => format!("class: {c}"),
        None => "class: (none named)".to_string(),
    }];
    let address: Vec<String> = ing
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|i| i.ip.clone().or_else(|| i.hostname.clone()))
        .collect();
    lines.push(if address.is_empty() {
        "address: none published (a controller may still serve it without publishing one; its log and events say whether it took the Ingress)".to_string()
    } else {
        format!("address: {}", address.join(", "))
    });
    lines.push("routes:".to_string());
    let backend = |b: &k8s_openapi::api::networking::v1::IngressBackend| match (&b.service, &b.resource) {
        (Some(s), _) => format!("Service {}:{}", s.name, ingress_backend_port(s)),
        (None, Some(r)) => format!("{} {} (a resource backend)", r.kind, r.name),
        _ => "(no backend)".to_string(),
    };
    if let Some(b) = &spec.default_backend {
        lines.push(format!("  (default backend) → {}", backend(b)));
    }
    for r in spec.rules.iter().flatten() {
        let host = r.host.clone().filter(|h| !h.is_empty()).unwrap_or_else(|| "*".to_string());
        let paths = r.http.as_ref().map(|h| h.paths.as_slice()).unwrap_or_default();
        if paths.is_empty() {
            lines.push(format!("  {host} (no paths)"));
        }
        for p in paths {
            lines.push(format!("  {host}{} ({}) → {}", p.path.as_deref().unwrap_or("/"), p.path_type, backend(&p.backend)));
        }
    }
    if spec.default_backend.is_none() && spec.rules.as_ref().is_none_or(|r| r.is_empty()) {
        lines.push("  (none: no rules and no default backend)".to_string());
    }
    let tls = spec.tls.clone().unwrap_or_default();
    if tls.is_empty() {
        lines.push("TLS: none (served over plain HTTP only)".to_string());
    } else {
        lines.push("TLS:".to_string());
        for t in &tls {
            lines.push(format!(
                "  {} → Secret {}",
                t.hosts.clone().unwrap_or_default().join(", "),
                t.secret_name.as_deref().filter(|s| !s.is_empty()).unwrap_or("(none: the controller's default certificate)")
            ));
        }
        let covered: Vec<String> = tls.iter().flat_map(|t| t.hosts.clone().unwrap_or_default()).collect();
        let plain: Vec<String> = spec.rules.iter().flatten().filter_map(|r| r.host.clone()).filter(|h| !h.is_empty() && !covered.contains(h)).collect();
        if !plain.is_empty() {
            lines.push(format!("  hosts in the rules but in no TLS entry: {}", plain.join(", ")));
        }
    }
    lines.join("\n")
}

/// Whether the class in effect exists and what controller it is for.
fn render_ingress_class(ing: &k8s_openapi::api::networking::v1::Ingress, classes: &Result<Vec<k8s_openapi::api::networking::v1::IngressClass>, String>) -> String {
    let classes = match classes {
        Ok(c) => c,
        Err(e) => return format!("(IngressClasses unavailable: {e})"),
    };
    let describe = |c: &k8s_openapi::api::networking::v1::IngressClass| {
        let default = c.metadata.annotations.as_ref().and_then(|a| a.get("ingressclass.kubernetes.io/is-default-class")).map(String::as_str) == Some("true");
        format!(
            "{} (controller {}{})",
            c.metadata.name.as_deref().unwrap_or_default(),
            c.spec.as_ref().and_then(|s| s.controller.as_deref()).unwrap_or("(unset)"),
            if default { ", the default" } else { "" }
        )
    };
    let all = if classes.is_empty() { "(none)".to_string() } else { classes.iter().map(describe).collect::<Vec<_>>().join("; ") };
    match k8s::ingress_class_ref(ing) {
        Some((name, legacy)) => match classes.iter().find(|c| c.metadata.name.as_deref() == Some(name.as_str())) {
            Some(c) => format!("named class exists: {}", describe(c)),
            // The annotation predates IngressClass and needs none: a
            // controller started with `--ingress-class={name}` claims it.
            None if legacy => format!(
                "named {name} by the legacy kubernetes.io/ingress.class annotation, which needs no IngressClass object; none exists, so only a controller whose flags name {name} claims it\nclasses on the cluster: {all}"
            ),
            None => format!("NAMED CLASS {name} DOES NOT EXIST — no IngressClass by that name, so no controller claims it through one\nclasses on the cluster: {all}"),
        },
        // A default class is applied when an Ingress is admitted, not after,
        // so one without a class stays without one whatever the default is now.
        None => format!(
            "NO CLASS: it names none, so only a controller set to watch class-less Ingresses claims it (ingress-nginx: --watch-ingress-without-class); a default class does not apply to an Ingress admitted before it was marked default\nclasses on the cluster: {all}"
        ),
    }
}

/// The workloads taken for the controller, and whether they are up.
fn render_ingress_controllers(controllers: &Result<Vec<k8s::IngressControllerWorkload>, String>) -> String {
    match controllers {
        Ok(c) if c.is_empty() => "(no Deployment or DaemonSet names this class or its controller in its args, and none is called ingress)".to_string(),
        Ok(c) => c
            .iter()
            .map(|w| {
                let health = if w.desired == 0 {
                    " — SCALED TO ZERO: nothing is serving this class, and the address in the Ingress's status is left over from when something did"
                } else if w.ready < w.desired {
                    " — NOT ALL READY"
                } else {
                    ""
                };
                format!("{} {}/{}: {} desired, {} ready{health} (matched by {})", w.kind, w.namespace, w.name, w.desired, w.ready, w.matched_by)
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("(controller workloads unavailable: {e})"),
    }
}

/// The controller's log lines about this Ingress, collapsed on what they say.
///
/// ingress-nginx writes klog lines (`W1102 10:00:00.000000 7 file.go:12] msg`),
/// Traefik and others `level=… msg=…` or JSON. The level and message are
/// pulled out of whichever it is, so the same error at a different time
/// counts as one.
fn render_ingress_controller_logs(lines: &Option<Result<(usize, Vec<String>), String>>) -> String {
    let lines = match lines {
        None => return "(no workload's args name this Ingress's class or controller, so there is no controller log to read)".to_string(),
        Some(Ok((0, _))) => return "(the controller has no pods, so there is no log to read)".to_string(),
        Some(Ok((_, l))) if l.is_empty() => return "(the controller logged nothing about this Ingress, its Services or its Secrets in the last hour)".to_string(),
        Some(Ok((_, l))) => l,
        Some(Err(e)) => return format!("(controller log unavailable: {e})"),
    };
    // (level, message) → (count, last time)
    let mut groups: Vec<((String, String), usize, String)> = Vec::new();
    for line in lines {
        let klog = line.len() > 5 && line.as_bytes()[0].is_ascii_alphabetic() && line.as_bytes()[1..5].iter().all(u8::is_ascii_digit);
        let (level, time, message) = if klog {
            let level = match &line[..1] {
                "E" => "ERROR",
                "W" => "WARN",
                "F" => "FATAL",
                _ => "INFO",
            };
            let time = line[1..].split_whitespace().take(2).collect::<Vec<_>>().join(" ");
            let message = line.split_once("] ").map(|(_, m)| m).unwrap_or(line).to_string();
            (level.to_string(), time, message)
        } else if let Ok(j) = serde_json::from_str::<serde_json::Value>(line) {
            let field = |k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let mut message = field("msg");
            let error = field("error");
            if !error.is_empty() {
                message.push_str(&format!(": {error}"));
            }
            (field("level").to_uppercase(), field("time"), message)
        } else {
            // `key=value` or `key="quoted value"`, logfmt as Traefik writes
            // it, with `\"` and `\\` escaped inside the quotes.
            let after = |k: &str| {
                line.split_once(&format!("{k}=")).map(|(_, rest)| match rest.strip_prefix('"') {
                    Some(quoted) => {
                        let mut value = String::new();
                        let mut chars = quoted.chars();
                        while let Some(c) = chars.next() {
                            match c {
                                '\\' => value.extend(chars.next()),
                                '"' => break,
                                c => value.push(c),
                            }
                        }
                        value
                    }
                    None => rest.split_whitespace().next().unwrap_or_default().to_string(),
                })
            };
            match after("msg") {
                Some(msg) => {
                    let mut message = msg;
                    if let Some(e) = after("error") {
                        message.push_str(&format!(": {e}"));
                    }
                    (after("level").unwrap_or_default().to_uppercase(), after("time").unwrap_or_default(), message)
                }
                None => (String::new(), String::new(), line.clone()),
            }
        };
        let message = if message.len() > DIAGNOSE_INGRESS_LOG_CHARS {
            format!("{} …", truncate_on_char_boundary(&message, DIAGNOSE_INGRESS_LOG_CHARS))
        } else {
            message
        };
        let key = (level, message);
        // The latest, not the last seen: the lines come pod by pod, so a
        // second replica's older line can follow a first replica's newer one.
        match groups.iter_mut().find(|g| g.0 == key) {
            Some(g) => {
                g.1 += 1;
                if time > g.2 {
                    g.2 = time;
                }
            }
            None => groups.push((key, 1, time)),
        }
    }
    groups.sort_by(|a, b| b.2.cmp(&a.2));
    let mut out = groups
        .iter()
        .take(DIAGNOSE_INGRESS_LOG_ENTRIES)
        .map(|((level, message), count, last)| {
            let level = if level.is_empty() { String::new() } else { format!("{level} ") };
            let last = if last.is_empty() { String::new() } else { format!(", last {last}") };
            format!("{level}{message} (×{count}{last})")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if groups.len() > DIAGNOSE_INGRESS_LOG_ENTRIES {
        out.push_str(&format!("\n… and {} older distinct entries", groups.len() - DIAGNOSE_INGRESS_LOG_ENTRIES));
    }
    out
}

/// Each backend Service: whether it exists, whether the port the Ingress
/// names is one of its ports, and whether anything ready is behind it.
fn render_ingress_backends(ing: &k8s_openapi::api::networking::v1::Ingress, backends: &[k8s::IngressBackend]) -> String {
    let refs = ingress_backend_refs(ing);
    if refs.is_empty() {
        return "(it routes to no Service)".to_string();
    }
    let mut lines = Vec::new();
    for (svc, port) in refs {
        let Some(b) = backends.iter().find(|b| b.name == svc) else { continue };
        let service = match &b.service {
            Ok(s) => s,
            Err(e) => {
                lines.push(format!("Service {svc}:{port}: {}", read_failure("Service", e)));
                continue;
            }
        };
        let spec = service.spec.clone().unwrap_or_default();
        let ports = spec.ports.clone().unwrap_or_default();
        let found = ports.iter().find(|p| p.name.as_deref() == Some(port.as_str()) || p.port.to_string() == port);
        let have = ports
            .iter()
            .map(|p| match &p.name {
                Some(n) if !n.is_empty() => format!("{}/{n}", p.port),
                _ => p.port.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        let mut line = format!("Service {svc}:{port} ({})", spec.type_.as_deref().unwrap_or("ClusterIP"));
        match found {
            Some(p) => line.push_str(&format!(
                ": port exists, → target port {}",
                p.target_port.as_ref().map(int_or_string).unwrap_or_else(|| p.port.to_string())
            )),
            None => line.push_str(&format!(": PORT {port} IS NOT A PORT OF THE SERVICE (it has {})", if have.is_empty() { "none".to_string() } else { have })),
        }
        if spec.type_.as_deref() == Some("ExternalName") {
            line.push_str(&format!("; an ExternalName to {}", spec.external_name.as_deref().unwrap_or_default()));
        } else {
            match &b.slices {
                Ok(slices) => {
                    // Counted for this Service port: a slice lists the ports
                    // its endpoints serve by the Service port's name, and a
                    // multi-port Service can have endpoints for one and not another.
                    let port_name = found.map(|p| p.name.clone().unwrap_or_default());
                    let serving: Vec<&k8s_openapi::api::discovery::v1::EndpointSlice> = slices
                        .iter()
                        .filter(|s| match &port_name {
                            Some(n) => s.ports.iter().flatten().any(|sp| sp.name.clone().unwrap_or_default() == *n),
                            None => true,
                        })
                        .collect();
                    let endpoints: Vec<&k8s_openapi::api::discovery::v1::Endpoint> = serving.iter().flat_map(|s| s.endpoints.iter()).collect();
                    let ready = endpoints.iter().filter(|e| e.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true)).count();
                    let all: usize = slices.iter().map(|s| s.endpoints.len()).sum();
                    match (ready, endpoints.len()) {
                        (0, 0) if all > 0 => line.push_str(&format!("; NO ENDPOINT SERVES THIS PORT ({all} endpoints serve its other ports — the target port resolves on none of the pods)")),
                        (0, 0) => line.push_str("; NO ENDPOINTS — nothing is behind it"),
                        (0, total) => line.push_str(&format!("; NO READY ENDPOINT (0 of {total})")),
                        (ready, total) => line.push_str(&format!("; {ready} of {total} endpoints ready")),
                    }
                }
                Err(e) => line.push_str(&format!("; endpoints unavailable: {e}")),
            }
        }
        lines.push(line);
    }
    lines.join("\n")
}

/// Whether a certificate name covers a host: exactly, or by a wildcard for
/// one label.
fn san_covers(san: &str, host: &str) -> bool {
    let (san, host) = (san.to_ascii_lowercase(), host.to_ascii_lowercase());
    if san == host {
        return true;
    }
    match san.strip_prefix("*.") {
        Some(suffix) => host.split_once('.').is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
        None => false,
    }
}

/// Each TLS Secret: there, of the right type, with both keys, and holding a
/// certificate that is in date and names every host it serves.
fn render_ingress_tls(
    ing: &k8s_openapi::api::networking::v1::Ingress,
    tls: &[(String, Result<k8s::IngressTlsSecret, String>)],
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let entries = ing.spec.as_ref().and_then(|s| s.tls.clone()).unwrap_or_default();
    if entries.is_empty() {
        return "(no TLS)".to_string();
    }
    let mut lines = Vec::new();
    for t in &entries {
        let hosts = t.hosts.clone().unwrap_or_default();
        let Some(secret) = t.secret_name.as_deref().filter(|s| !s.is_empty()) else {
            lines.push(format!("{}: no Secret named; the controller's default certificate is served", hosts.join(", ")));
            continue;
        };
        let read = match tls.iter().find(|(n, _)| n == secret) {
            Some((_, r)) => r,
            None => continue,
        };
        let s = match read {
            Ok(s) => s,
            Err(e) => {
                lines.push(format!("Secret {secret}: {}", read_failure("Secret", e)));
                continue;
            }
        };
        let mut line = format!("Secret {secret} ({})", s.secret_type);
        let missing: Vec<&str> = ["tls.crt", "tls.key"].into_iter().filter(|k| !s.keys.iter().any(|have| have == k)).collect();
        if !missing.is_empty() {
            line.push_str(&format!(": MISSING KEY {}", missing.join(" and ")));
        }
        match &s.leaf {
            None => line.push_str("\n  no certificate could be read from tls.crt"),
            Some(c) => {
                line.push_str(&format!("\n  certificate: subject {}, issuer {}", c.subject, c.issuer));
                if let Some(after) = c.not_after.as_deref() {
                    // Compared before rounding: a certificate that expired an
                    // hour ago is expired, though zero whole days have passed.
                    match chrono::DateTime::parse_from_rfc3339(after).ok().map(|t| t.with_timezone(&chrono::Utc)) {
                        Some(t) if t <= now => match (now - t).num_days() {
                            0 => line.push_str(&format!("\n  EXPIRED on {after}, less than a day ago")),
                            d => line.push_str(&format!("\n  EXPIRED on {after}, {d} days ago")),
                        },
                        Some(t) => line.push_str(&format!("\n  valid until {after} ({} days left)", (t - now).num_days())),
                        None => line.push_str(&format!("\n  valid until {after}")),
                    }
                }
                for h in &hosts {
                    if !c.sans.iter().any(|san| san_covers(san, h)) {
                        line.push_str(&format!("\n  DOES NOT COVER {h} (it names {})", c.sans.join(", ")));
                    }
                }
            }
        }
        lines.push(line);
    }
    lines.join("\n")
}

/// cert-manager's view of the TLS Secrets, when it issues them.
fn render_ingress_certificates(certificates: &Option<Result<Vec<kube::api::DynamicObject>, String>>) -> String {
    match certificates {
        None => "(cert-manager is not installed, or there is no TLS Secret to issue)".to_string(),
        Some(Err(e)) => format!("(Certificates unavailable: {e})"),
        Some(Ok(c)) if c.is_empty() => "(no cert-manager Certificate writes these Secrets)".to_string(),
        Some(Ok(c)) => c
            .iter()
            .map(|cert| {
                let s = |p: &str| cert.data.pointer(p).and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let ready = cert
                    .data
                    .pointer("/status/conditions")
                    .and_then(|v| v.as_array())
                    .and_then(|cs| cs.iter().find(|c| c.get("type").and_then(|t| t.as_str()) == Some("Ready")))
                    .map(|c| {
                        let f = |k: &str| c.get(k).and_then(|v| v.as_str()).unwrap_or_default();
                        format!("Ready={} ({}): {}", f("status"), f("reason"), f("message"))
                    })
                    .unwrap_or_else(|| "no Ready condition yet".to_string());
                let mut line = format!(
                    "Certificate {} → Secret {}, issuer {} {}: {ready}",
                    cert.metadata.name.as_deref().unwrap_or_default(),
                    s("/spec/secretName"),
                    s("/spec/issuerRef/kind"),
                    s("/spec/issuerRef/name")
                );
                let renewal = s("/status/renewalTime");
                if !renewal.is_empty() {
                    line.push_str(&format!("; renews at {renewal}"));
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Other Ingresses claiming one of this one's hosts. Two Ingresses of one
/// class are merged by the controller; the same host and path in both is a
/// conflict one of them loses, often silently.
fn render_ingress_same_host(ing: &k8s_openapi::api::networking::v1::Ingress, others: &Result<Vec<k8s_openapi::api::networking::v1::Ingress>, String>) -> String {
    let others = match others {
        Ok(o) if o.is_empty() => return "(no other Ingress has any of its hosts)".to_string(),
        Ok(o) => o,
        Err(e) => return format!("(other Ingresses unavailable: {e})"),
    };
    // (host, path, pathType): an Exact and a Prefix rule on one path are two
    // routes a controller serves side by side, not a clash.
    let routes = |i: &k8s_openapi::api::networking::v1::Ingress| -> Vec<(String, String, String)> {
        i.spec
            .iter()
            .flat_map(|s| s.rules.iter().flatten())
            .flat_map(|r| {
                let host = r.host.clone().unwrap_or_default();
                r.http.iter().flat_map(move |h| h.paths.iter().map({
                    let host = host.clone();
                    move |p| (host.clone(), p.path.clone().unwrap_or_else(|| "/".to_string()), p.path_type.clone())
                }))
            })
            .collect()
    };
    let mine = routes(ing);
    let my_class = k8s::ingress_class_of(ing);
    let my_hosts: Vec<&String> = mine.iter().map(|(h, _, _)| h).collect();
    let show = |(h, p, t): &(String, String, String)| format!("{h}{p} ({t})");
    others
        .iter()
        .map(|o| {
            let theirs: Vec<(String, String, String)> = routes(o).into_iter().filter(|(h, _, _)| my_hosts.contains(&h)).collect();
            let class = k8s::ingress_class_of(o);
            let clash: Vec<String> = theirs.iter().filter(|r| mine.contains(r)).map(show).collect();
            let mut line = format!(
                "{}/{} (class {}): {}",
                o.metadata.namespace.as_deref().unwrap_or_default(),
                o.metadata.name.as_deref().unwrap_or_default(),
                class.as_deref().unwrap_or("(none)"),
                theirs.iter().map(show).collect::<Vec<_>>().join(", ")
            );
            if !clash.is_empty() && class == my_class {
                line.push_str(&format!(" — SAME HOST, PATH AND PATH TYPE AS THIS ONE: {}", clash.join(", ")));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Assembles everything an Ingress diagnosis needs, redacted.
///
/// An Ingress is a request to a controller, so most of what can be wrong is
/// outside it: no controller claims its class, the controller is down or
/// rejected it, a backend Service or its port is wrong or has nothing ready
/// behind it, or the TLS Secret is missing, expired or for another name. The
/// controller's own log lines usually say which.
pub async fn build_ingress_diagnosis_payload(context_name: &str, namespace: &str, name: &str) -> Result<ClaudeDiagnosisPayload, String> {
    let d = k8s::get_ingress_diagnostics(context_name, namespace, name).await?;

    let spec = redact::redact(&render_ingress_spec(&d.ingress));
    let class = redact::redact(&render_ingress_class(&d.ingress, &d.classes));
    let controllers = redact::redact(&render_ingress_controllers(&d.controllers));
    let logs = redact::redact(&render_ingress_controller_logs(&d.controller_logs));
    let backends = redact::redact(&render_ingress_backends(&d.ingress, &d.backends));
    let tls = redact::redact(&render_ingress_tls(&d.ingress, &d.tls, chrono::Utc::now()));
    let certificates = redact::redact(&render_ingress_certificates(&d.certificates));
    let same_host = redact::redact(&render_ingress_same_host(&d.ingress, &d.same_host));
    let events = redact::redact(&render_nap_events(&d.events, "(no events for this Ingress)", false, 25));
    let manifest = redact::redact(&d.manifest);

    let redaction_summary =
        redact::Redacted::merge([&spec, &class, &controllers, &logs, &backends, &tls, &certificates, &same_host, &events, &manifest]).summary();

    let prompt = format!(
        "Ingress {namespace}/{name}.\n\n\
         ## Spec\n{}\n\n\
         ## Ingress class\n{}\n\n\
         ## Controller\n{}\n\n\
         ## Controller log (last hour, lines about this Ingress, its Services and Secrets)\n{}\n\n\
         ## Backends\n{}\n\n\
         ## TLS\n{}\n\n\
         ## cert-manager\n{}\n\n\
         ## Other Ingresses with its hosts\n{}\n\n\
         ## Events\n{}\n\n\
         ## Manifest (managed fields omitted)\n```yaml\n{}\n```",
        spec.text, class.text, controllers.text, logs.text, backends.text, tls.text, certificates.text, same_host.text, events.text, manifest.text,
    );

    Ok(ClaudeDiagnosisPayload {
        approx_tokens: approx_tokens(&prompt),
        prompt,
        redaction_summary,
        log_note: None,
    })
}

/// A volume this full is called out: most filesystems slow or fail before 100%.
const DIAGNOSE_PVC_FULL_PERCENT: u64 = 90;

/// Bytes as GiB or MiB, which is how volume sizes are requested.
fn gib(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        format!("{:.1}Gi", bytes as f64 / (1u64 << 30) as f64)
    } else {
        format!("{}Mi", bytes >> 20)
    }
}

/// The claim's own state: phase, size asked for and got, modes, class,
/// volume, and any resize in progress.
fn render_pvc_status(pvc: &k8s_openapi::api::core::v1::PersistentVolumeClaim) -> String {
    let spec = pvc.spec.clone().unwrap_or_default();
    let status = pvc.status.clone().unwrap_or_default();
    let requested = spec.resources.as_ref().and_then(|r| r.requests.as_ref()).and_then(|r| r.get("storage")).map(|q| q.0.clone()).unwrap_or_else(|| "(none)".to_string());
    let capacity = status.capacity.as_ref().and_then(|c| c.get("storage")).map(|q| q.0.clone());
    let mut lines = vec![
        format!("phase: {}", status.phase.as_deref().unwrap_or("(unknown)")),
        format!("requested: {requested}; capacity: {}", capacity.as_deref().unwrap_or("(none yet)")),
        format!("access modes: {}", spec.access_modes.clone().unwrap_or_default().join(", ")),
        format!("volume mode: {}", spec.volume_mode.as_deref().unwrap_or("Filesystem")),
        match spec.storage_class_name.as_deref() {
            None => "storage class: (not set)".to_string(),
            Some("") => "storage class: \"\" (explicitly none: binds only to a pre-created PersistentVolume)".to_string(),
            Some(c) => format!("storage class: {c}"),
        },
        format!("volume: {}", spec.volume_name.as_deref().filter(|v| !v.is_empty()).unwrap_or("(none bound)")),
    ];
    if let Some(ds) = spec.data_source_ref.as_ref().map(|d| (d.kind.clone(), d.name.clone())).or_else(|| spec.data_source.as_ref().map(|d| (d.kind.clone(), d.name.clone()))) {
        lines.push(format!("populated from: {} {}", ds.0, ds.1));
    }
    if let Some(sel) = &spec.selector {
        lines.push(format!("selector for a static volume: {}", k8s::label_selector_query(sel)));
    }
    if let Some(node) = pvc.metadata.annotations.as_ref().and_then(|a| a.get("volume.kubernetes.io/selected-node")) {
        lines.push(format!("selected node (WaitForFirstConsumer): {node}"));
    }
    for (resource, state) in status.allocated_resource_statuses.iter().flatten() {
        lines.push(format!("resize of {resource}: {state}"));
    }
    if let Some(allocated) = status.allocated_resources.as_ref().and_then(|a| a.get("storage")) {
        if capacity.as_deref() != Some(allocated.0.as_str()) {
            lines.push(format!("allocated (resize target): {}", allocated.0));
        }
    }
    for c in status.conditions.iter().flatten() {
        let mut line = format!("condition {}={}", c.type_, c.status);
        if let Some(r) = c.reason.as_deref().filter(|r| !r.is_empty()) {
            line.push_str(&format!(" ({r})"));
        }
        if let Some(m) = c.message.as_deref().filter(|m| !m.is_empty()) {
            line.push_str(&format!(": {m}"));
        }
        lines.push(line);
    }
    lines.join("\n")
}

fn is_default_class(c: &k8s_openapi::api::storage::v1::StorageClass) -> bool {
    let a = c.metadata.annotations.as_ref();
    ["storageclass.kubernetes.io/is-default-class", "storageclass.beta.kubernetes.io/is-default-class"]
        .iter()
        .any(|k| a.and_then(|a| a.get(*k)).map(String::as_str) == Some("true"))
}

/// The StorageClass that provisions it, or why there is none.
///
/// A claim with no class at all is given the default when it is admitted,
/// and since Kubernetes 1.28 one marked default later is also applied to
/// claims still without a class — so a claim with none means there was no
/// default either time. An empty class is different: it asks for no
/// provisioning, only a pre-created volume.
fn render_pvc_storage_class(
    pvc: &k8s_openapi::api::core::v1::PersistentVolumeClaim,
    classes: &Result<Vec<k8s_openapi::api::storage::v1::StorageClass>, String>,
) -> String {
    let classes = match classes {
        Ok(c) => c,
        Err(e) => return format!("(StorageClasses unavailable: {e})"),
    };
    let defaults: Vec<&str> = classes.iter().filter(|c| is_default_class(c)).filter_map(|c| c.metadata.name.as_deref()).collect();
    let all = if classes.is_empty() {
        "(none)".to_string()
    } else {
        classes
            .iter()
            .map(|c| format!("{}{}", c.metadata.name.as_deref().unwrap_or_default(), if is_default_class(c) { " (default)" } else { "" }))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match pvc.spec.as_ref().and_then(|s| s.storage_class_name.as_deref()) {
        None => format!(
            "NO CLASS SET: there was no default class when it was created, and none has been applied since; default classes now: {}\nclasses on the cluster: {all}",
            if defaults.is_empty() { "none".to_string() } else { defaults.join(", ") }
        ),
        Some("") => format!("none, by request: it binds only to a pre-created PersistentVolume with no class\nclasses on the cluster: {all}"),
        Some(name) => match classes.iter().find(|c| c.metadata.name.as_deref() == Some(name)) {
            None => format!("CLASS {name} DOES NOT EXIST — nothing will provision it\nclasses on the cluster: {all}"),
            Some(c) => {
                let mut lines = vec![
                    format!("{name}: provisioner {}", c.provisioner),
                    format!("binding: {}", c.volume_binding_mode.as_deref().unwrap_or("Immediate")),
                    format!("reclaim policy: {}", c.reclaim_policy.as_deref().unwrap_or("Delete")),
                    format!("volume expansion: {}", if c.allow_volume_expansion == Some(true) { "allowed" } else { "NOT ALLOWED" }),
                ];
                let params: Vec<String> = c.parameters.iter().flatten().map(|(k, v)| format!("{k}={v}")).collect();
                if !params.is_empty() {
                    lines.push(format!("parameters: {}", params.join(", ")));
                }
                for t in c.allowed_topologies.iter().flatten() {
                    for e in t.match_label_expressions.iter().flatten() {
                        lines.push(format!("allowed topology: {} in ({})", e.key, e.values.join(",")));
                    }
                }
                lines.join("\n")
            }
        },
    }
}

/// The bound PersistentVolume: its size, where it can attach, and whether
/// it is still this claim's.
fn render_pvc_volume(
    pvc: &k8s_openapi::api::core::v1::PersistentVolumeClaim,
    pv: &Option<Result<k8s_openapi::api::core::v1::PersistentVolume, String>>,
    csi: &Option<Result<k8s::PvcCsiDriver, String>>,
) -> String {
    let mut lines = Vec::new();
    match pv {
        None => lines.push("(no volume bound yet)".to_string()),
        Some(Err(e)) => lines.push(read_failure("volume", e)),
        Some(Ok(pv)) => {
            let spec = pv.spec.clone().unwrap_or_default();
            let status = pv.status.clone().unwrap_or_default();
            lines.push(format!(
                "{}: phase {}, capacity {}, access modes {}, reclaim policy {}",
                pv.metadata.name.as_deref().unwrap_or_default(),
                status.phase.as_deref().unwrap_or("(unknown)"),
                spec.capacity.as_ref().and_then(|c| c.get("storage")).map(|q| q.0.clone()).unwrap_or_default(),
                spec.access_modes.clone().unwrap_or_default().join(", "),
                spec.persistent_volume_reclaim_policy.as_deref().unwrap_or("(unset)")
            ));
            if let Some(m) = status.message.as_deref().filter(|m| !m.is_empty()) {
                lines.push(format!("status: {} {m}", status.reason.as_deref().unwrap_or_default()));
            }
            match spec.claim_ref.as_ref() {
                // Named by the claim's volumeName but not yet bound to it, as
                // when its size, access modes or class do not match the claim.
                None => lines.push("no claimRef: the volume is not bound to any claim yet".to_string()),
                Some(c) if c.name.as_deref() != pvc.metadata.name.as_deref() || c.namespace.as_deref() != pvc.metadata.namespace.as_deref() => {
                    lines.push(format!(
                        "CLAIMED BY ANOTHER: its claimRef is {}/{}",
                        c.namespace.as_deref().unwrap_or("-"),
                        c.name.as_deref().unwrap_or("-")
                    ));
                }
                // A claim deleted and recreated under the same name is a new
                // object; the volume still belongs to the old one.
                Some(c) if c.uid.is_some() && c.uid != pvc.metadata.uid => {
                    lines.push("CLAIMED BY AN EARLIER CLAIM OF THE SAME NAME: its claimRef's uid is not this claim's".to_string());
                }
                Some(_) => {}
            }
            if let Some(c) = &spec.csi {
                lines.push(format!("CSI driver {}, volume handle {}", c.driver, c.volume_handle));
            }
            for term in spec.node_affinity.iter().flat_map(|a| a.required.iter()).flat_map(|r| r.node_selector_terms.iter()) {
                let exprs: Vec<String> = term
                    .match_expressions
                    .iter()
                    .flatten()
                    .map(|e| format!("{} {} ({})", e.key, e.operator, e.values.clone().unwrap_or_default().join(",")))
                    .collect();
                if !exprs.is_empty() {
                    lines.push(format!("attaches only to nodes with: {}", exprs.join(" and ")));
                }
            }
        }
    }
    match csi {
        None => {}
        Some(Err(e)) => lines.push(format!("(CSI driver unavailable: {e})")),
        Some(Ok(d)) => lines.push(format!(
            "CSI driver {}: {}; on {} of {} nodes",
            d.name,
            if d.registered { "registered" } else { "NO CSIDriver OBJECT (not installed, or an in-tree provisioner)" },
            d.on_nodes,
            d.nodes
        )),
    }
    lines.join("\n")
}

/// The pods mounting the claim, and whether a single-node volume is wanted
/// on more than one node.
fn render_pvc_pods(pvc: &k8s_openapi::api::core::v1::PersistentVolumeClaim, pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>) -> String {
    let pods = match pods {
        Ok(p) if p.is_empty() => return "(no pod mounts it)".to_string(),
        Ok(p) => p,
        Err(e) => return format!("(pods unavailable: {e})"),
    };
    let mut lines: Vec<String> = pods
        .iter()
        .map(|p| {
            let status = p.status.clone().unwrap_or_default();
            let mut line = format!(
                "{}: {}{}",
                p.metadata.name.as_deref().unwrap_or_default(),
                status.phase.as_deref().unwrap_or("Unknown"),
                if pod_is_ready(p) { ", ready" } else { ", NOT READY" }
            );
            for c in status.init_container_statuses.iter().flatten().chain(status.container_statuses.iter().flatten()) {
                if let Some(w) = c.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                    line.push_str(&format!("; {} waiting: {}", c.name, w.reason.as_deref().unwrap_or("?")));
                }
            }
            match p.spec.as_ref().and_then(|s| s.node_name.as_deref()) {
                Some(n) => line.push_str(&format!("; on {n}")),
                None => line.push_str("; not scheduled"),
            }
            line
        })
        .collect();
    // A finished pod keeps its claim and node but no longer holds the volume,
    // so only the others can conflict.
    let live: Vec<_> = pods
        .iter()
        .filter(|p| !matches!(p.status.as_ref().and_then(|s| s.phase.as_deref()), Some("Succeeded" | "Failed")))
        .collect();
    let modes = pvc.spec.as_ref().and_then(|s| s.access_modes.clone()).unwrap_or_default();
    let single_node = modes.iter().all(|m| m == "ReadWriteOnce" || m == "ReadWriteOncePod");
    let mut nodes: Vec<&str> = live.iter().filter_map(|p| p.spec.as_ref().and_then(|s| s.node_name.as_deref())).collect();
    nodes.sort_unstable();
    nodes.dedup();
    if single_node && nodes.len() > 1 {
        lines.push(format!("A SINGLE-NODE VOLUME ({}) IS MOUNTED BY PODS ON {} NODES: {}", modes.join(", "), nodes.len(), nodes.join(", ")));
    }
    if modes.iter().any(|m| m == "ReadWriteOncePod") && live.len() > 1 {
        lines.push(format!("ReadWriteOncePod, but {} running pods mount it: only one can", live.len()));
    }
    lines.join("\n")
}

/// Which node has the volume attached, and any attach or detach error.
fn render_pvc_attachments(attachments: &Result<Vec<k8s_openapi::api::storage::v1::VolumeAttachment>, String>, bound: bool) -> String {
    let attachments = match attachments {
        Ok(a) if a.is_empty() => {
            // Drivers that skip attach (Azure Files, NFS) and in-tree plugins
            // create none, so an empty list says nothing about attachment.
            return if bound { "(no VolumeAttachment objects for it)".to_string() } else { "(no volume to attach)".to_string() };
        }
        Ok(a) => a,
        Err(e) => return format!("(VolumeAttachments unavailable: {e})"),
    };
    attachments
        .iter()
        .map(|a| {
            let status = a.status.clone().unwrap_or_default();
            let mut line = format!(
                "on {}: {}{}",
                a.spec.node_name,
                if status.attached { "attached" } else { "NOT ATTACHED" },
                if a.metadata.deletion_timestamp.is_some() { ", being detached" } else { "" }
            );
            for (what, err) in [("attach", &status.attach_error), ("detach", &status.detach_error)] {
                if let Some(e) = err {
                    line.push_str(&format!("\n  {what} error{}: {}", e.time.as_ref().map(|t| format!(" at {}", t.0.to_rfc3339())).unwrap_or_default(), e.message.as_deref().unwrap_or_default()));
                }
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// How full the volume is, as the kubelet sees it.
fn render_pvc_usage(usage: &[Result<Option<k8s::PvcUsage>, String>], has_running_pod: bool) -> String {
    if !has_running_pod {
        return "(no running pod mounts it, so the kubelet reports no usage)".to_string();
    }
    let mut lines = Vec::new();
    for u in usage {
        match u {
            Err(e) => lines.push(format!("(usage unavailable: {e})")),
            Ok(None) => lines.push("(the kubelet reports no stats for it — block volumes and some drivers report none)".to_string()),
            Ok(Some(u)) => {
                let mut line = format!("on {}: ", u.node);
                match (u.used_bytes, u.capacity_bytes) {
                    (Some(used), Some(cap)) if cap > 0 => {
                        let pct = used * 100 / cap;
                        line.push_str(&format!("{} of {} used ({pct}%)", gib(used), gib(cap)));
                        if pct >= DIAGNOSE_PVC_FULL_PERCENT {
                            line.push_str(" — NEARLY FULL");
                        }
                    }
                    _ => line.push_str("bytes not reported"),
                }
                if let (Some(used), Some(total)) = (u.inodes_used, u.inodes) {
                    if total > 0 {
                        let pct = used * 100 / total;
                        line.push_str(&format!("; inodes {used} of {total} ({pct}%)"));
                        if pct >= DIAGNOSE_PVC_FULL_PERCENT {
                            line.push_str(" — INODES NEARLY EXHAUSTED");
                        }
                    }
                }
                lines.push(line);
            }
        }
    }
    lines.join("\n")
}

/// Assembles everything a PersistentVolumeClaim diagnosis needs, redacted.
///
/// A claim fails in one of a few places: before it binds (no class, the
/// provisioner refuses, or it is waiting for a pod by design), when its
/// volume is attached and mounted (on another node, in another zone, a
/// driver missing), while it is resized, or when it fills up. The claim's
/// own events cover only the first; the pods' events and the
/// VolumeAttachments cover the second.
pub async fn build_pvc_diagnosis_payload(context_name: &str, namespace: &str, name: &str) -> Result<ClaudeDiagnosisPayload, String> {
    let d = k8s::get_pvc_diagnostics(context_name, namespace, name).await?;
    let bound = d.pv.as_ref().is_some_and(|p| p.is_ok());
    let running = d.pods.iter().flatten().any(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running"));

    let status = redact::redact(&render_pvc_status(&d.pvc));
    let class = redact::redact(&render_pvc_storage_class(&d.pvc, &d.storage_classes));
    let volume = redact::redact(&render_pvc_volume(&d.pvc, &d.pv, &d.csi_driver));
    let pods = redact::redact(&render_pvc_pods(&d.pvc, &d.pods));
    let pod_events = redact::redact(&if d.pod_events.is_empty() {
        "(every pod that mounts it is ready, or none does)".to_string()
    } else {
        d.pod_events
            .iter()
            .map(|(pod, events)| format!("pod {pod}:\n{}", render_nap_events(events, "(no events for it)", false, 10)))
            .collect::<Vec<_>>()
            .join("\n\n")
    });
    let attachments = redact::redact(&render_pvc_attachments(&d.attachments, bound));
    let usage = redact::redact(&render_pvc_usage(&d.usage, running));
    let events = redact::redact(&render_nap_events(&d.events, "(no events for this claim)", false, 25));
    let pv_events = redact::redact(&match &d.pv_events {
        None => "(no volume bound)".to_string(),
        Some(e) => render_nap_events(e, "(no events for the volume)", false, 15),
    });
    let manifest = redact::redact(&d.manifest);

    let redaction_summary =
        redact::Redacted::merge([&status, &class, &volume, &pods, &pod_events, &attachments, &usage, &events, &pv_events, &manifest]).summary();

    let prompt = format!(
        "PersistentVolumeClaim {namespace}/{name}.\n\n\
         ## Status\n{}\n\n\
         ## Storage class\n{}\n\n\
         ## Volume\n{}\n\n\
         ## Pods mounting it\n{}\n\n\
         ## Events of pods mounting it that are not ready\n{}\n\n\
         ## Volume attachments\n{}\n\n\
         ## Usage\n{}\n\n\
         ## Events\n{}\n\n\
         ## Volume events\n{}\n\n\
         ## Manifest (managed fields omitted)\n```yaml\n{}\n```",
        status.text, class.text, volume.text, pods.text, pod_events.text, attachments.text, usage.text, events.text, pv_events.text, manifest.text,
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

/// A StatefulSet's replica counts, revisions and update strategy, and
/// whether a rollout is under way and what governs its pace.
fn render_sts_spec(sts: &k8s_openapi::api::apps::v1::StatefulSet) -> String {
    let spec = sts.spec.clone().unwrap_or_default();
    let status = sts.status.clone().unwrap_or_default();
    let desired = spec.replicas.unwrap_or(1);
    let mut lines = vec![format!(
        "replicas: desired {desired}, ready {}, current {}, updated {}, available {}",
        status.ready_replicas.unwrap_or(0),
        status.current_replicas.unwrap_or(0),
        status.updated_replicas.unwrap_or(0),
        status.available_replicas.unwrap_or(0)
    )];
    if let Some(start) = spec.ordinals.as_ref().and_then(|o| o.start).filter(|s| *s != 0) {
        lines.push(format!("ordinals start at {start}"));
    }
    let policy = spec.pod_management_policy.clone().unwrap_or_else(|| "OrderedReady".into());
    lines.push(format!("pod management: {policy}"));
    let strategy = spec.update_strategy.clone().unwrap_or_default();
    let kind = strategy.type_.clone().unwrap_or_else(|| "RollingUpdate".into());
    let rolling = strategy.rolling_update.clone().unwrap_or_default();
    let partition = rolling.partition.unwrap_or(0);
    let mut strategy_line = format!("update strategy: {kind}");
    if kind == "RollingUpdate" {
        if partition > 0 {
            strategy_line.push_str(&format!(", partition {partition}"));
        }
        if let Some(m) = &rolling.max_unavailable {
            strategy_line.push_str(&format!(", maxUnavailable {}", int_or_string(m)));
        }
    }
    lines.push(strategy_line);
    if let Some(s) = spec.min_ready_seconds.filter(|s| *s > 0) {
        lines.push(format!("minReadySeconds: {s}"));
    }
    if let Some(r) = &spec.persistent_volume_claim_retention_policy {
        lines.push(format!(
            "claim retention: whenDeleted {}, whenScaled {}",
            r.when_deleted.as_deref().unwrap_or("Retain"),
            r.when_scaled.as_deref().unwrap_or("Retain")
        ));
    }
    let current = status.current_revision.clone().unwrap_or_default();
    let update = status.update_revision.clone().unwrap_or_default();
    lines.push(format!(
        "revisions: current {}, update {}",
        if current.is_empty() { "(none)" } else { &current },
        if update.is_empty() { "(none)" } else { &update }
    ));
    if let (Some(g), Some(o)) = (sts.metadata.generation, status.observed_generation) {
        if g > o {
            lines.push(format!("THE CONTROLLER HAS NOT YET ACTED ON THE LATEST SPEC: generation {g}, observed {o}"));
        }
    }
    let updated = status.updated_replicas.unwrap_or(0);
    if !update.is_empty() && !current.is_empty() && update != current {
        lines.push(if kind == "OnDelete" {
            format!("ON DELETE: a new revision exists, and a pod moves to it only when deleted; {updated} of {desired} are on it")
        } else if partition > 0 {
            format!("ROLLOUT PARTITIONED AT {partition}: only ordinals {partition} and above move to the new revision; {updated} of {desired} are on it")
        } else {
            format!("ROLLOUT IN PROGRESS: {updated} of {desired} pods on the new revision; it replaces pods from the highest ordinal down")
        });
    }
    lines.join("\n")
}

/// The desired ordinals: from `ordinals.start`, `replicas` of them.
fn sts_ordinals(sts: &k8s_openapi::api::apps::v1::StatefulSet) -> std::ops::Range<i32> {
    let spec = sts.spec.as_ref();
    let start = spec.and_then(|s| s.ordinals.as_ref()).and_then(|o| o.start).unwrap_or(0);
    start..start + spec.and_then(|s| s.replicas).unwrap_or(1)
}

/// Each desired ordinal's pod: missing, or its state, revision and node; then
/// what is holding the controller back.
fn render_sts_ordinals(
    sts: &k8s_openapi::api::apps::v1::StatefulSet,
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
    nodes: &[(String, Result<Option<bool>, String>)],
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let pods = match pods {
        Ok(p) => p,
        Err(e) => return format!("(pods unavailable: {e})"),
    };
    let name = sts.metadata.name.as_deref().unwrap_or_default();
    let status = sts.status.clone().unwrap_or_default();
    let current = status.current_revision.unwrap_or_default();
    let update = status.update_revision.unwrap_or_default();
    let rolling = update != current && !update.is_empty() && !current.is_empty();
    let spec = sts.spec.clone().unwrap_or_default();
    let ordered = spec.pod_management_policy.as_deref().unwrap_or("OrderedReady") == "OrderedReady";
    let on_delete = spec.update_strategy.as_ref().and_then(|u| u.type_.as_deref()) == Some("OnDelete");
    let partition = spec.update_strategy.as_ref().and_then(|u| u.rolling_update.as_ref()).and_then(|r| r.partition).unwrap_or(0);
    let by_ordinal: std::collections::BTreeMap<i32, &k8s_openapi::api::core::v1::Pod> =
        pods.iter().filter_map(|p| Some((k8s::sts_ordinal(p.metadata.name.as_deref()?, name)?, p))).collect();
    let node_state = |node: &str| nodes.iter().find(|(n, _)| n == node).map(|(_, r)| r);
    let revision_of = |p: &k8s_openapi::api::core::v1::Pod| {
        p.metadata.labels.as_ref().and_then(|l| l.get("controller-revision-hash")).cloned().unwrap_or_default()
    };

    // A pod's phase, readiness, revision and node, and a finding when it is
    // stuck terminating on a node that cannot finish it.
    let describe = |p: &k8s_openapi::api::core::v1::Pod, pod_name: &str, findings: &mut Vec<String>| -> String {
        let st = p.status.clone().unwrap_or_default();
        let mut line = format!("{}{}", st.phase.as_deref().unwrap_or("Unknown"), if pod_is_ready(p) { ", ready" } else { ", NOT READY" });
        for c in st.init_container_statuses.iter().flatten().chain(st.container_statuses.iter().flatten()) {
            if let Some(w) = c.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                line.push_str(&format!("; {} waiting: {}", c.name, w.reason.as_deref().unwrap_or("?")));
            }
        }
        let hash = revision_of(p);
        line.push_str(&format!(
            "; revision {}{}",
            if hash.is_empty() { "(unlabelled)" } else { &hash },
            if !rolling {
                if hash.is_empty() || hash == update { "" } else { " (NOT THE CURRENT REVISION)" }
            } else if hash == update {
                " (new)"
            } else if hash == current {
                " (old)"
            } else {
                " (an older revision)"
            }
        ));
        let mut bad_node = None;
        match p.spec.as_ref().and_then(|s| s.node_name.as_deref()) {
            None => line.push_str("; not scheduled"),
            Some(n) => {
                line.push_str(&format!("; on {n}"));
                match node_state(n) {
                    Some(Ok(Some(false))) => {
                        line.push_str(" (node NOT READY)");
                        bad_node = Some("NOT READY");
                    }
                    Some(Ok(None)) => {
                        line.push_str(" (NODE NO LONGER EXISTS)");
                        bad_node = Some("GONE");
                    }
                    Some(Err(e)) => line.push_str(&format!(" (node unavailable: {e})")),
                    _ => {}
                }
            }
        }
        if let Some(t) = p.metadata.deletion_timestamp.as_ref() {
            let mins = (now - t.0).num_minutes();
            line.push_str(&format!("; TERMINATING since {} ({})", t.0.to_rfc3339(), if mins < 1 { "under a minute".to_string() } else { format!("{mins} min") }));
            if let Some(why) = bad_node {
                findings.push(format!(
                    "{pod_name} IS STUCK TERMINATING ON A NODE THAT IS {why}: a StatefulSet never runs two pods with one identity, so it does not recreate {pod_name} until the pod object is gone"
                ));
            }
        }
        line
    };

    let mut lines = Vec::new();
    let mut unhealthy = Vec::new();
    let mut findings = Vec::new();
    let wanted = sts_ordinals(sts);
    for i in wanted.clone() {
        let pod_name = format!("{name}-{i}");
        let Some(p) = by_ordinal.get(&i) else {
            lines.push(format!("{pod_name}: MISSING"));
            unhealthy.push(pod_name);
            continue;
        };
        lines.push(format!("{pod_name}: {}", describe(p, &pod_name, &mut findings)));
        let terminating = p.metadata.deletion_timestamp.is_some();
        if pod_is_ready(p) && !terminating {
            continue;
        }
        // Whether a pod that is not ready gets replaced turns on its revision:
        // with OrderedReady the controller waits for every pod to be ready,
        // so it never replaces one that is not, even one whose template has
        // since been corrected.
        let hash = revision_of(p);
        let finished = p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Succeeded");
        if !terminating && !finished && !on_delete && !hash.is_empty() && !update.is_empty() {
            if hash == update {
                if rolling {
                    findings.push(format!(
                        "{pod_name} IS ON THE NEW REVISION AND NOT READY: the rollout waits on it. It may only be starting; if the new template is broken, correct or revert it{}",
                        if ordered {
                            ", then delete this pod if it is still not ready: with OrderedReady the controller does not replace a pod that is not ready"
                        } else {
                            ", and the controller then replaces this pod"
                        }
                    ));
                }
            } else if ordered && i - wanted.start >= partition {
                findings.push(format!(
                    "{pod_name} IS NOT READY ON A SUPERSEDED REVISION, {hash}: with OrderedReady the controller does not replace a pod that is not ready, so it is not moved to {update} — if it does not become ready, delete it and the controller recreates it on {update}"
                ));
            }
        }
        unhealthy.push(pod_name);
    }
    // Pods past the desired ordinals are left from a scale-down; one stuck
    // terminating is why the scale-down has not finished.
    for (i, p) in &by_ordinal {
        if !wanted.contains(i) {
            let pod_name = p.metadata.name.as_deref().unwrap_or_default();
            lines.push(format!(
                "{pod_name}: beyond the desired ordinals{}; {}",
                if p.metadata.deletion_timestamp.is_some() { "" } else { ", waiting to be removed" },
                describe(p, pod_name, &mut findings)
            ));
        }
    }
    if ordered && wanted.len() > 1 {
        if let Some(first) = unhealthy.first() {
            findings.push(format!(
                "ORDEREDREADY: the controller creates, updates or removes no other pod while {first} is not running and ready{}",
                if unhealthy.len() > 1 { format!(" ({} ordinals in all are not)", unhealthy.len()) } else { String::new() }
            ));
        }
    }
    lines.extend(findings);
    if lines.is_empty() {
        return "(scaled to zero: no ordinal is wanted and no pod remains)".to_string();
    }
    lines.join("\n")
}

/// The claim each volumeClaimTemplate makes for each desired ordinal, and how
/// each differs from its template.
fn render_sts_claims(
    sts: &k8s_openapi::api::apps::v1::StatefulSet,
    claims: &Result<Vec<k8s_openapi::api::core::v1::PersistentVolumeClaim>, String>,
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
) -> String {
    let templates = sts.spec.as_ref().and_then(|s| s.volume_claim_templates.clone()).unwrap_or_default();
    if templates.is_empty() {
        return "(no volumeClaimTemplates: its pods keep no volume of their own)".to_string();
    }
    let claims = match claims {
        Ok(c) => c,
        Err(e) => return format!("(claims unavailable: {e})"),
    };
    let name = sts.metadata.name.as_deref().unwrap_or_default();
    let has_pod = |i: i32| pods.iter().flatten().any(|p| k8s::sts_ordinal(p.metadata.name.as_deref().unwrap_or_default(), name) == Some(i));
    let storage = |r: Option<&k8s_openapi::api::core::v1::VolumeResourceRequirements>| {
        r.and_then(|r| r.requests.as_ref()).and_then(|q| q.get("storage")).map(|q| q.0.clone())
    };
    let wanted = sts_ordinals(sts);
    let mut lines = Vec::new();
    for t in &templates {
        let t_name = t.metadata.name.as_deref().unwrap_or_default();
        let t_spec = t.spec.clone().unwrap_or_default();
        let t_size = storage(t_spec.resources.as_ref());
        let t_class = t_spec.storage_class_name.clone();
        lines.push(format!(
            "template {t_name}: requests {}, class {}, access modes {}",
            t_size.as_deref().unwrap_or("(none)"),
            t_class.as_deref().unwrap_or("(the default)"),
            t_spec.access_modes.clone().unwrap_or_default().join(", ")
        ));
        let prefix = format!("{t_name}-{name}");
        for i in wanted.clone() {
            let claim_name = format!("{prefix}-{i}");
            let Some(c) = claims.iter().find(|c| c.metadata.name.as_deref() == Some(claim_name.as_str())) else {
                lines.push(format!("  {claim_name}: {}", if has_pod(i) { "MISSING, though its pod exists" } else { "not created yet (it is made with its pod)" }));
                continue;
            };
            let spec = c.spec.clone().unwrap_or_default();
            let st = c.status.clone().unwrap_or_default();
            let phase = st.phase.clone().unwrap_or_else(|| "Unknown".into());
            let mut line = format!(
                "  {claim_name}: {}, capacity {}",
                if phase == "Bound" { phase.clone() } else { phase.to_uppercase() },
                st.capacity.as_ref().and_then(|c| c.get("storage")).map(|q| q.0.clone()).unwrap_or_else(|| "(none)".into())
            );
            if c.metadata.deletion_timestamp.is_some() {
                line.push_str("; BEING DELETED (held while a pod uses it)");
            }
            if let (Some(want), Some(have)) = (&t_size, storage(spec.resources.as_ref())) {
                if k8s::parse_memory_ki(&have) < k8s::parse_memory_ki(want) {
                    line.push_str(&format!("; REQUESTS {have}, LESS THAN THE TEMPLATE'S {want}: template changes do not resize existing claims"));
                }
            }
            if let (Some(want), Some(have)) = (&t_class, &spec.storage_class_name) {
                if want != have {
                    line.push_str(&format!("; CLASS {have}, NOT THE TEMPLATE'S {want}"));
                }
            }
            lines.push(line);
        }
        let beyond = claims
            .iter()
            .filter_map(|c| k8s::sts_ordinal(c.metadata.name.as_deref().unwrap_or_default(), &prefix))
            .filter(|i| !wanted.contains(i))
            .count();
        if beyond > 0 {
            lines.push(format!("  and {beyond} for ordinals beyond the desired ones, kept from a scale-down and reused if it scales back up"));
        }
    }
    lines.join("\n")
}

/// Names, the first few of them, for a line that must stay short.
fn sts_pod_list(names: &[String]) -> String {
    const SHOWN: usize = 5;
    let mut out = names.iter().take(SHOWN).cloned().collect::<Vec<_>>().join(", ");
    if names.len() > SHOWN {
        out.push_str(&format!(" and {} more", names.len() - SHOWN));
    }
    out
}

/// The governing Service: whether it exists, is headless and selects the pods.
fn render_sts_service(
    sts: &k8s_openapi::api::apps::v1::StatefulSet,
    service: &Option<Result<Option<k8s_openapi::api::core::v1::Service>, String>>,
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
) -> String {
    let spec = sts.spec.clone().unwrap_or_default();
    let svc = match service {
        None => return "(serviceName is empty: its pods get no per-pod DNS names)".to_string(),
        Some(Err(e)) => return format!("(Service unavailable: {e})"),
        Some(Ok(None)) => {
            return format!(
                "GOVERNING SERVICE {} DOES NOT EXIST: the pods run, but get no per-pod DNS names (<pod>.{})",
                spec.service_name, spec.service_name
            )
        }
        Some(Ok(Some(s))) => s,
    };
    let s_spec = svc.spec.clone().unwrap_or_default();
    let ip = s_spec.cluster_ip.clone().unwrap_or_default();
    let mut lines = vec![format!(
        "{}: {}",
        spec.service_name,
        if ip == "None" { "headless".to_string() } else { format!("NOT HEADLESS (clusterIP {ip}): per-pod DNS names exist only for a headless Service") }
    )];
    // Checked against the pods' own labels: a selector may use one the
    // controller adds, such as statefulset.kubernetes.io/pod-name, which the
    // template does not carry.
    match s_spec.selector.as_ref().filter(|s| !s.is_empty()) {
        None => lines.push(
            "no selector: its endpoints are managed by hand, in Endpoints or EndpointSlices this diagnosis does not read, so whether they list the pods is unchecked"
                .to_string(),
        ),
        Some(sel) => {
            let terms = sel.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ");
            lines.push(match pods {
                Err(e) => format!("selector {terms}: not checked against the pods (pods unavailable: {e})"),
                Ok(p) if p.is_empty() => format!("selector {terms}: no pod exists to check it against"),
                Ok(p) => {
                    let missed: Vec<String> = p
                        .iter()
                        .filter(|p| k8s::selector_terms_met(sel, p.metadata.labels.as_ref()) < sel.len())
                        .filter_map(|p| p.metadata.name.clone())
                        .collect();
                    if missed.is_empty() {
                        format!("its selector matches all {} pods", p.len())
                    } else if missed.len() == p.len() {
                        format!("ITS SELECTOR DOES NOT SELECT THE PODS: {terms}")
                    } else {
                        format!("ITS SELECTOR MISSES {}: {terms}", sts_pod_list(&missed))
                    }
                }
            });
        }
    }
    lines.push(format!(
        "publishNotReadyAddresses: {}",
        if s_spec.publish_not_ready_addresses == Some(true) { "true" } else { "false (a pod has no DNS name until it is ready)" }
    ));
    lines.join("\n")
}

/// The PodDisruptionBudgets over the pods, and whether they let a drain through.
fn render_pdbs(pdbs: &Result<Vec<(k8s_openapi::api::policy::v1::PodDisruptionBudget, Option<Vec<String>>)>, String>) -> String {
    let pdbs = match pdbs {
        Ok(p) if p.is_empty() => return "(no PodDisruptionBudget covers its pods)".to_string(),
        Ok(p) => p,
        Err(e) => return format!("(PodDisruptionBudgets unavailable: {e})"),
    };
    let mut lines: Vec<String> = pdbs
        .iter()
        .map(|(b, covered)| {
            let spec = b.spec.clone().unwrap_or_default();
            let st = b.status.clone().unwrap_or_default();
            let limit = match (&spec.min_available, &spec.max_unavailable) {
                (Some(m), _) => format!("minAvailable {}", int_or_string(m)),
                (_, Some(m)) => format!("maxUnavailable {}", int_or_string(m)),
                _ => "no limit".to_string(),
            };
            // No disruption allowed stops the eviction of healthy pods; an
            // unready one may still go, as its unhealthyPodEvictionPolicy says.
            let blocks = if st.disruptions_allowed > 0 {
                String::new()
            } else {
                let unready = match spec.unhealthy_pod_eviction_policy.as_deref() {
                    Some("AlwaysAllow") => "a running pod that is not ready can still be evicted (unhealthyPodEvictionPolicy AlwaysAllow)".to_string(),
                    policy => {
                        let policy = if policy.is_some() { "IfHealthyBudget" } else { "IfHealthyBudget, the default" };
                        if st.current_healthy >= st.desired_healthy {
                            format!("the budget is met, so a running pod that is not ready can still be evicted (unhealthyPodEvictionPolicy {policy})")
                        } else {
                            format!("the budget is not met, so a running pod that is not ready cannot be evicted either (unhealthyPodEvictionPolicy {policy})")
                        }
                    }
                };
                format!(" — NO HEALTHY POD MAY BE EVICTED: a drain waits on any node running one of its ready pods; {unready}")
            };
            format!(
                "{}: {limit}; covers {}; healthy {} of {} expected, {} needed; disruptions allowed {}{blocks}",
                b.metadata.name.as_deref().unwrap_or_default(),
                match covered.as_deref() {
                    None => "the pod template (no pod to check)".to_string(),
                    Some([]) => "no pods".to_string(),
                    Some(c) => sts_pod_list(c),
                },
                st.current_healthy,
                st.expected_pods,
                st.desired_healthy,
                st.disruptions_allowed,
            )
        })
        .collect();
    // The eviction API refuses a pod under two budgets, but budgets over
    // different ordinals do not overlap.
    if pdbs.iter().all(|(_, c)| c.is_none()) {
        if pdbs.len() > 1 {
            lines.push("MORE THAN ONE BUDGET COVERS THE POD TEMPLATE: the eviction API refuses to evict a pod covered by more than one".to_string());
        }
    } else {
        let mut seen = std::collections::BTreeMap::<&str, usize>::new();
        for pod in pdbs.iter().filter_map(|(_, c)| c.as_ref()).flatten() {
            *seen.entry(pod.as_str()).or_default() += 1;
        }
        let shared: Vec<String> = seen.into_iter().filter(|(_, n)| *n > 1).map(|(p, _)| p.to_string()).collect();
        if !shared.is_empty() {
            lines.push(format!(
                "MORE THAN ONE BUDGET COVERS {}: the eviction API refuses to evict a pod covered by more than one",
                sts_pod_list(&shared)
            ));
        }
    }
    lines.join("\n")
}

/// The StatefulSet sections of a workload diagnosis.
fn render_sts_sections(d: &k8s::StatefulSetDiagnostics, now: chrono::DateTime<chrono::Utc>) -> String {
    let claim_events = if d.claim_events.is_empty() {
        String::new()
    } else {
        format!(
            "\n\n## Events (Pending claims)\n{}",
            d.claim_events
                .iter()
                .map(|(c, e)| format!("claim {c}:\n{}", render_nap_events(e, "(no events for it)", false, 10)))
                .collect::<Vec<_>>()
                .join("\n\n")
        )
    };
    format!(
        "## StatefulSet\n{}\n\n## Pods by ordinal\n{}\n\n## Volume claims\n{}{claim_events}\n\n## Governing Service\n{}\n\n## PodDisruptionBudgets\n{}",
        render_sts_spec(&d.sts),
        render_sts_ordinals(&d.sts, &d.pods, &d.nodes, now),
        render_sts_claims(&d.sts, &d.claims, &d.pods),
        render_sts_service(&d.sts, &d.service, &d.pods),
        render_pdbs(&d.pdbs),
    )
}

/// A DaemonSet's node counts, update strategy and latest revision, and
/// whether a rollout is under way.
fn render_ds_spec(ds: &k8s_openapi::api::apps::v1::DaemonSet, latest: &Result<Option<String>, String>) -> String {
    let spec = ds.spec.clone().unwrap_or_default();
    let status = ds.status.clone().unwrap_or_default();
    let desired = status.desired_number_scheduled;
    let updated = status.updated_number_scheduled.unwrap_or(0);
    let mut lines = vec![format!(
        "nodes: desired {desired}, scheduled {}, ready {}, available {}, up to date {updated}, misscheduled {}",
        status.current_number_scheduled,
        status.number_ready,
        status.number_available.unwrap_or(0),
        status.number_misscheduled
    )];
    let strategy = spec.update_strategy.clone().unwrap_or_default();
    let kind = strategy.type_.clone().unwrap_or_else(|| "RollingUpdate".into());
    let rolling = strategy.rolling_update.clone().unwrap_or_default();
    let mut strategy_line = format!("update strategy: {kind}");
    let mut budget = Vec::new();
    if kind == "RollingUpdate" {
        if let Some(m) = &rolling.max_unavailable {
            budget.push(format!("maxUnavailable {}", int_or_string(m)));
        }
        if let Some(m) = &rolling.max_surge {
            budget.push(format!("maxSurge {}", int_or_string(m)));
        }
        if !budget.is_empty() {
            strategy_line.push_str(&format!(", {}", budget.join(", ")));
        }
    }
    lines.push(strategy_line);
    if let Some(s) = spec.min_ready_seconds.filter(|s| *s > 0) {
        lines.push(format!("minReadySeconds: {s}"));
    }
    lines.push(match latest {
        Ok(Some(h)) => format!("latest revision: {h}"),
        Ok(None) => "latest revision: (none found)".to_string(),
        Err(e) => format!("latest revision: (revisions unavailable: {e})"),
    });
    if let (Some(g), Some(o)) = (ds.metadata.generation, status.observed_generation) {
        if g > o {
            lines.push(format!("THE CONTROLLER HAS NOT YET ACTED ON THE LATEST SPEC: generation {g}, observed {o}"));
        }
    }
    if updated < desired {
        lines.push(if kind == "OnDelete" {
            format!("ON DELETE: {updated} of {desired} nodes run the latest template, and a pod moves to it only when deleted")
        } else {
            format!(
                "ROLLOUT IN PROGRESS: {updated} of {desired} nodes run the latest template; it replaces old pods {} at a time",
                if budget.is_empty() { "maxUnavailable".to_string() } else { budget.join(", ") }
            )
        });
    }
    lines.join("\n")
}

/// Which nodes should run a DaemonSet's pod and which do, why the others are
/// left out, and its pods that are not ready, with what is holding them.
fn render_ds_nodes(
    ds: &k8s_openapi::api::apps::v1::DaemonSet,
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
    nodes: &Result<Vec<k8s_openapi::api::core::v1::Node>, String>,
    latest: &Result<Option<String>, String>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    // Lines of each kind, so one large cluster cannot crowd out the rest.
    const SHOWN: usize = 10;
    let pods = match pods {
        Ok(p) => p,
        Err(e) => return format!("(pods unavailable: {e})"),
    };
    let spec = ds.spec.clone().unwrap_or_default();
    let template = spec.template.spec.clone().unwrap_or_default();
    let latest = latest.as_ref().ok().cloned().flatten();
    let rolling_update = spec.update_strategy.as_ref().and_then(|u| u.type_.as_deref()).unwrap_or("RollingUpdate") == "RollingUpdate";
    let node_list = nodes.as_ref().ok();
    let node_by_name: std::collections::BTreeMap<&str, &k8s_openapi::api::core::v1::Node> =
        node_list.into_iter().flatten().filter_map(|n| Some((n.metadata.name.as_deref()?, n))).collect();
    let mut by_node: std::collections::BTreeMap<String, Vec<&k8s_openapi::api::core::v1::Pod>> = std::collections::BTreeMap::new();
    for p in pods {
        by_node.entry(k8s::daemon_pod_node(p).unwrap_or_default()).or_default().push(p);
    }
    let node_note = |n: &str| match node_by_name.get(n) {
        None if node_list.is_some() && !n.is_empty() => " (NODE NO LONGER EXISTS)",
        Some(node) if !k8s::node_is_ready(node) => " (node NOT READY)",
        Some(node) if node.spec.as_ref().and_then(|s| s.unschedulable) == Some(true) => " (node cordoned)",
        _ => "",
    };
    let more = |n: usize| if n > SHOWN { format!(" and {} more", n - SHOWN) } else { String::new() };

    let mut lines = Vec::new();
    let mut findings = Vec::new();
    match nodes {
        Err(e) => lines.push(format!("(nodes unavailable: {e}; which nodes should run its pod was not worked out)")),
        Ok(_) if node_by_name.is_empty() => lines.push("(the cluster lists no nodes)".to_string()),
        Ok(_) => {
            let mut excluded: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
            let mut missing = Vec::new();
            let mut misscheduled = Vec::new();
            let (mut should, mut kept) = (0, 0);
            for (n, node) in &node_by_name {
                let here = by_node.get(*n).map(Vec::as_slice).unwrap_or_default();
                let misfit = k8s::daemon_pod_misfit(&template, node, true);
                should += misfit.is_none() as usize;
                match (misfit, here.is_empty()) {
                    (None, true) => missing.push(format!("{n}{}", node_note(n))),
                    (Some(why), true) => *excluded.entry(why).or_default() += 1,
                    (None, false) => {}
                    (Some(_), false) => match k8s::daemon_pod_misfit(&template, node, false) {
                        Some(why) => misscheduled.extend(here.iter().map(|p| format!("{} on {n}: {why}", p.metadata.name.as_deref().unwrap_or_default()))),
                        None => kept += 1,
                    },
                }
            }
            lines.push(format!(
                "{} node{}: {should} should run its pod, by its nodeSelector, required node affinity and tolerations (with those every DaemonSet pod gets); {} should not",
                node_by_name.len(),
                if node_by_name.len() == 1 { "" } else { "s" },
                node_by_name.len() - should
            ));
            let mut reasons: Vec<(String, usize)> = excluded.into_iter().collect();
            reasons.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            for (why, count) in reasons.iter().take(SHOWN) {
                lines.push(format!("  {count} left out: {why}"));
            }
            if reasons.len() > SHOWN {
                lines.push(format!("  and {} more reasons", reasons.len() - SHOWN));
            }
            if kept > 0 {
                lines.push(format!(
                    "  {kept} more {} a pod {} would not get now, under a NoSchedule taint it does not tolerate: a running pod is kept through one",
                    if kept == 1 { "runs" } else { "run" },
                    if kept == 1 { "it" } else { "they" }
                ));
            }
            if !missing.is_empty() {
                findings.push(format!(
                    "NO POD ON {} NODE{} THAT SHOULD RUN ONE: {}{}; the controller creates one per node, and when it has not, its events say why",
                    missing.len(),
                    if missing.len() == 1 { "" } else { "S" },
                    missing.iter().take(SHOWN).cloned().collect::<Vec<_>>().join(", "),
                    more(missing.len())
                ));
            }
            if !misscheduled.is_empty() {
                findings.push(format!(
                    "MISSCHEDULED, AND DELETED BY THE CONTROLLER: {}{}",
                    misscheduled.iter().take(SHOWN).cloned().collect::<Vec<_>>().join("; "),
                    more(misscheduled.len())
                ));
            }
        }
    }

    // Its pods that are not ready or are terminating, by name.
    let mut troubled: Vec<&k8s_openapi::api::core::v1::Pod> =
        pods.iter().filter(|p| !pod_is_ready(p) || p.metadata.deletion_timestamp.is_some()).collect();
    troubled.sort_by_key(|p| p.metadata.name.clone());
    let (mut new_unready, mut old) = (Vec::new(), 0);
    let (mut no_room, mut port_taken) = (Vec::new(), 0);
    let mut stuck = Vec::new();
    for p in pods {
        let hash = p.metadata.labels.as_ref().and_then(|l| l.get("controller-revision-hash")).cloned().unwrap_or_default();
        if p.metadata.deletion_timestamp.is_none() && !hash.is_empty() {
            match &latest {
                Some(l) if *l == hash => {
                    if !pod_is_ready(p) && p.status.as_ref().and_then(|s| s.phase.as_deref()) != Some("Succeeded") {
                        new_unready.push(p.metadata.name.clone().unwrap_or_default());
                    }
                }
                Some(_) => old += 1,
                None => {}
            }
        }
    }
    if troubled.is_empty() {
        lines.push(if pods.is_empty() { "(it has no pods)".to_string() } else { format!("all {} of its pods are ready", pods.len()) });
    } else {
        lines.push(format!("{} of its {} pods are not ready or are terminating:", troubled.len(), pods.len()));
    }
    for (i, p) in troubled.iter().enumerate() {
        let pod_name = p.metadata.name.as_deref().unwrap_or_default();
        let node = k8s::daemon_pod_node(p).unwrap_or_default();
        let st = p.status.clone().unwrap_or_default();
        let note = node_note(&node);
        let scheduled = p.spec.as_ref().and_then(|s| s.node_name.as_deref()).is_some_and(|n| !n.is_empty());
        let mut line = format!(
            "  {pod_name} {} {}{note}: {}{}",
            if scheduled { "on" } else { "for" },
            if node.is_empty() { "(no node)" } else { &node },
            st.phase.as_deref().unwrap_or("Unknown"),
            if pod_is_ready(p) { ", ready" } else { ", NOT READY" }
        );
        for c in st.init_container_statuses.iter().flatten().chain(st.container_statuses.iter().flatten()) {
            if let Some(w) = c.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                line.push_str(&format!("; {} waiting: {}", c.name, w.reason.as_deref().unwrap_or("?")));
            }
        }
        let hash = p.metadata.labels.as_ref().and_then(|l| l.get("controller-revision-hash")).cloned().unwrap_or_default();
        line.push_str(&format!(
            "; revision {}{}",
            if hash.is_empty() { "(unlabelled)" } else { &hash },
            match &latest {
                Some(l) if *l == hash => " (latest)",
                Some(_) if !hash.is_empty() => " (OLDER)",
                _ => "",
            }
        ));
        if let Some(msg) = st
            .conditions
            .iter()
            .flatten()
            .find(|c| c.type_ == "PodScheduled" && c.status == "False")
            .and_then(|c| c.message.clone())
        {
            if msg.contains("Insufficient") {
                no_room.push(*p);
            }
            port_taken += msg.contains("free ports") as usize;
            let msg: String = msg.chars().take(300).collect();
            line.push_str(&format!("; UNSCHEDULABLE: {msg}"));
        }
        if let Some(t) = p.metadata.deletion_timestamp.as_ref() {
            let mins = (now - t.0).num_minutes();
            line.push_str(&format!("; TERMINATING since {} ({})", t.0.to_rfc3339(), if mins < 1 { "under a minute".to_string() } else { format!("{mins} min") }));
            if !note.is_empty() && note != " (node cordoned)" {
                stuck.push((pod_name.to_string(), if note.contains("NO LONGER") { "GONE" } else { "NOT READY" }));
            }
        }
        // Every one is counted above, but only the head of a long list is
        // shown: the rest usually say the same thing.
        if i < SHOWN * 2 {
            lines.push(line);
        }
    }
    if troubled.len() > SHOWN * 2 {
        lines.push(format!("  and {} more", troubled.len() - SHOWN * 2));
    }
    match stuck.as_slice() {
        [] => {}
        [(pod, why)] => findings.push(format!("{pod} IS STUCK TERMINATING ON A NODE THAT IS {why}: the kubelet there cannot confirm it stopped")),
        many => findings.push(format!(
            "{} PODS ARE STUCK TERMINATING ON NODES THAT ARE NOT READY OR GONE: {}{}; the kubelets there cannot confirm they stopped",
            many.len(),
            many.iter().take(SHOWN).map(|(p, why)| format!("{p} ({why})")).collect::<Vec<_>>().join(", "),
            more(many.len())
        )),
    }
    // Whether a pod can preempt is what admission settled on the pod itself:
    // its priority and preemptionPolicy, which a default class may have set.
    if let Some(first) = no_room.first() {
        let pod_spec = first.spec.clone().unwrap_or_default();
        let priority = pod_spec.priority.unwrap_or(0);
        let class = pod_spec.priority_class_name.map(|c| format!("class {c}")).unwrap_or_else(|| "no priorityClassName".to_string());
        findings.push(format!(
            "{} POD{} CANNOT FIT ON {} NODE: a DaemonSet pod runs only on its own node, so it waits for room there; {}",
            no_room.len(),
            if no_room.len() == 1 { "" } else { "S" },
            if no_room.len() == 1 { "ITS" } else { "THEIR" },
            if pod_spec.preemption_policy.as_deref() == Some("Never") {
                format!("its preemptionPolicy is Never ({class}), so it preempts nothing")
            } else if priority <= 0 {
                format!("at priority {priority} ({class}) it can preempt only pods of lower priority, which few are; a class such as system-node-critical is what lets it make room")
            } else {
                format!("at priority {priority} ({class}) it can preempt pods of lower priority on that node, if evicting them frees enough")
            }
        ));
    }
    if port_taken > 0 {
        findings.push(format!("{port_taken} POD{} BLOCKED BY A HOST PORT ALREADY IN USE ON {} NODE", if port_taken == 1 { " IS" } else { "S ARE" }, if port_taken == 1 { "ITS" } else { "THEIR" }));
    }
    if rolling_update && old > 0 && !new_unready.is_empty() {
        // With no surge, the controller replaces an available old pod only
        // while the nodes without an available pod number fewer than
        // maxUnavailable; surging works differently, so no verdict then.
        let status = ds.status.clone().unwrap_or_default();
        let desired = status.desired_number_scheduled;
        let unavailable = status.number_unavailable.unwrap_or(0);
        let rolling = spec.update_strategy.as_ref().and_then(|u| u.rolling_update.clone()).unwrap_or_default();
        let scaled = |v: &Option<k8s_openapi::apimachinery::pkg::util::intstr::IntOrString>, default: i32| match v {
            Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(i)) => *i,
            Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::String(s)) => {
                s.trim_end_matches('%').parse::<i64>().map(|p| ((p * desired as i64 + 99) / 100) as i32).unwrap_or(default)
            }
            None => default,
        };
        let (max_unavailable, max_surge) = (scaled(&rolling.max_unavailable, 1), scaled(&rolling.max_surge, 0));
        let verdict = if max_surge > 0 {
            format!("it surges up to {max_surge} new pods alongside old ones, and {unavailable} nodes have no available pod")
        } else if unavailable >= max_unavailable {
            format!("{unavailable} nodes have no available pod, which uses up maxUnavailable {max_unavailable}, so no more old pods are replaced until one becomes available")
        } else {
            format!("{unavailable} nodes have no available pod, under maxUnavailable {max_unavailable}, so replacements can continue")
        };
        findings.push(format!(
            "ROLLOUT: {} POD{} OF THE LATEST REVISION {} NOT READY ({}{}), with {old} still on older revisions; {verdict}. They may only be starting; if the new template is broken, correct or revert it, and the controller then replaces them",
            new_unready.len(),
            if new_unready.len() == 1 { "" } else { "S" },
            if new_unready.len() == 1 { "IS" } else { "ARE" },
            new_unready.iter().take(SHOWN).cloned().collect::<Vec<_>>().join(", "),
            more(new_unready.len())
        ));
    }
    lines.extend(findings);
    lines.join("\n")
}

/// The DaemonSet sections of a workload diagnosis.
fn render_ds_sections(d: &k8s::DaemonSetDiagnostics, now: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "## DaemonSet\n{}\n\n## Nodes and pods\n{}",
        render_ds_spec(&d.ds, &d.latest_revision),
        render_ds_nodes(&d.ds, &d.pods, &d.nodes, &d.latest_revision, now),
    )
}

/// A Deployment's replica counts, strategy and conditions, and what its
/// conditions say about its rollout.
fn render_deploy_spec(dep: &k8s_openapi::api::apps::v1::Deployment) -> String {
    let spec = dep.spec.clone().unwrap_or_default();
    let status = dep.status.clone().unwrap_or_default();
    let mut lines = vec![format!(
        "replicas: desired {}, updated {}, ready {}, available {}, unavailable {}",
        spec.replicas.unwrap_or(1),
        status.updated_replicas.unwrap_or(0),
        status.ready_replicas.unwrap_or(0),
        status.available_replicas.unwrap_or(0),
        status.unavailable_replicas.unwrap_or(0)
    )];
    let strategy = spec.strategy.clone().unwrap_or_default();
    let kind = strategy.type_.clone().unwrap_or_else(|| "RollingUpdate".into());
    let mut strategy_line = format!("strategy: {kind}");
    if kind == "RollingUpdate" {
        let rolling = strategy.rolling_update.clone().unwrap_or_default();
        if let Some(m) = &rolling.max_surge {
            strategy_line.push_str(&format!(", maxSurge {}", int_or_string(m)));
        }
        if let Some(m) = &rolling.max_unavailable {
            strategy_line.push_str(&format!(", maxUnavailable {}", int_or_string(m)));
        }
    }
    lines.push(strategy_line);
    if let Some(s) = spec.min_ready_seconds.filter(|s| *s > 0) {
        lines.push(format!("minReadySeconds: {s}"));
    }
    let deadline = spec.progress_deadline_seconds.unwrap_or(600);
    lines.push(format!("progressDeadlineSeconds: {deadline}"));
    if spec.paused == Some(true) {
        lines.push("PAUSED: changes to its template do not roll out until it is resumed (kubectl rollout resume)".to_string());
    }
    if let (Some(g), Some(o)) = (dep.metadata.generation, status.observed_generation) {
        if g > o {
            lines.push(format!("THE CONTROLLER HAS NOT YET ACTED ON THE LATEST SPEC: generation {g}, observed {o}"));
        }
    }
    let conditions = status.conditions.unwrap_or_default();
    for c in &conditions {
        let message: String = c.message.as_deref().unwrap_or_default().chars().take(300).collect();
        lines.push(format!("condition {}={}{}{}", c.type_, c.status, c.reason.as_deref().map(|r| format!(" ({r})")).unwrap_or_default(), if message.is_empty() { String::new() } else { format!(": {message}") }));
    }
    if conditions.iter().any(|c| c.type_ == "Progressing" && c.status == "False" && c.reason.as_deref() == Some("ProgressDeadlineExceeded")) {
        lines.push(format!(
            "ROLLOUT EXCEEDED ITS PROGRESS DEADLINE: it has not progressed for {deadline}s; this marks it failed, and the controller still keeps trying"
        ));
    }
    if let Some(c) = conditions.iter().find(|c| c.type_ == "ReplicaFailure" && c.status == "True") {
        // The reason says which way it failed: FailedCreate or FailedDelete.
        lines.push(format!(
            "REPLICA FAILURE: {}: {}",
            match c.reason.as_deref() {
                Some("FailedCreate") => "pods are not being created".to_string(),
                Some("FailedDelete") => "pods are not being deleted".to_string(),
                r => format!("reason {}", r.unwrap_or("(none)")),
            },
            c.message.as_deref().unwrap_or("(no message)")
        ));
    }
    lines.join("\n")
}

/// A Deployment's ReplicaSets, newest first, with the pods each holds, and
/// where its rollout stands.
fn render_deploy_replicasets(
    dep: &k8s_openapi::api::apps::v1::Deployment,
    replica_sets: &Result<Vec<k8s_openapi::api::apps::v1::ReplicaSet>, String>,
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
) -> String {
    // ReplicaSets shown; the rest, scaled to zero, are rollback history.
    const SHOWN: usize = 6;
    let replica_sets = match replica_sets {
        Ok(r) if r.is_empty() => return "(it has no ReplicaSet: the controller has not created one)".to_string(),
        Ok(r) => r,
        Err(e) => return format!("(ReplicaSets unavailable: {e})"),
    };
    let spec = dep.spec.clone().unwrap_or_default();
    let desired = spec.replicas.unwrap_or(1);
    let recreate = spec.strategy.as_ref().and_then(|s| s.type_.as_deref()) == Some("Recreate");
    // Ready and total pods of a ReplicaSet, from its pods as read.
    let pods_of = |rs: &k8s_openapi::api::apps::v1::ReplicaSet| -> Option<(usize, usize)> {
        let uid = rs.metadata.uid.as_deref()?;
        let mine: Vec<_> = pods
            .as_ref()
            .ok()?
            .iter()
            .filter(|p| p.metadata.owner_references.iter().flatten().any(|o| o.controller == Some(true) && o.uid == uid))
            .collect();
        Some((mine.iter().filter(|p| pod_is_ready(p)).count(), mine.len()))
    };
    // Its replica counts leave out pods that are terminating, so an old
    // ReplicaSet at zero may still own some; it is shown while it does.
    let holds = |rs: &k8s_openapi::api::apps::v1::ReplicaSet| {
        rs.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0) > 0
            || rs.status.as_ref().is_some_and(|s| s.replicas > 0)
            || pods_of(rs).is_some_and(|(_, total)| total > 0)
    };

    let mut lines = Vec::new();
    let mut findings = Vec::new();
    let (mut history, mut unshown) = (0, 0);
    for (i, rs) in replica_sets.iter().enumerate() {
        if i > 0 && !holds(rs) {
            history += 1;
            continue;
        }
        if lines.len() >= SHOWN {
            unshown += 1;
            continue;
        }
        let st = rs.status.clone().unwrap_or_default();
        let images: Vec<String> = rs
            .spec
            .as_ref()
            .and_then(|s| s.template.as_ref())
            .and_then(|t| t.spec.as_ref())
            .map(|s| s.containers.iter().filter_map(|c| c.image.clone()).collect())
            .unwrap_or_default();
        let mut line = format!(
            "{}: revision {}{}; replicas {}, ready {}, available {}",
            rs.metadata.name.as_deref().unwrap_or_default(),
            k8s::rs_revision(rs),
            if i == 0 { " (newest)" } else { "" },
            rs.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0),
            st.ready_replicas.unwrap_or(0),
            st.available_replicas.unwrap_or(0)
        );
        if let Some((ready, total)) = pods_of(rs) {
            line.push_str(&format!("; pods {ready} ready of {total}"));
        }
        if !images.is_empty() {
            line.push_str(&format!("; images {}", images.join(", ")));
        }
        if let Some(c) = st.conditions.iter().flatten().find(|c| c.type_ == "ReplicaFailure" && c.status == "True") {
            let message = c.message.as_deref().unwrap_or("(no message)");
            let reason = c.reason.as_deref().unwrap_or("no reason");
            line.push_str(&format!("; REPLICA FAILURE ({reason}): {message}"));
            // FailedDelete is a scale-down that cannot remove a pod, not this.
            if i == 0 && reason == "FailedCreate" {
                findings.push(format!("THE NEWEST REPLICASET CANNOT CREATE PODS: {message}"));
            }
        }
        lines.push(line);
    }
    if unshown > 0 {
        lines.push(format!("and {unshown} more older ReplicaSet{} still holding pods", if unshown == 1 { "" } else { "s" }));
    }
    if history > 0 {
        lines.push(format!("and {history} older ReplicaSet{} scaled to zero, kept as rollback history", if history == 1 { "" } else { "s" }));
    }
    if let Err(e) = pods {
        lines.push(format!("(pods unavailable: {e})"));
    }

    // Where the rollout stands: older ReplicaSets still holding pods means it
    // has not finished.
    let newest = &replica_sets[0];
    let new_ready = newest.status.as_ref().and_then(|s| s.ready_replicas).unwrap_or(0);
    let new_unready = pods_of(newest).map(|(ready, total)| total - ready).unwrap_or(0);
    let old_pods: i32 = replica_sets[1..].iter().filter_map(|r| r.status.as_ref()).map(|s| s.replicas).sum();
    if old_pods > 0 && recreate {
        findings.push(format!(
            "RECREATE ROLLOUT IN PROGRESS: older ReplicaSets still run {old_pods} pod{}; Recreate stops every old pod before it starts any new one, so the new ReplicaSet waits until they are gone",
            if old_pods == 1 { "" } else { "s" }
        ));
    } else if old_pods > 0 {
        findings.push(format!(
            "ROLLOUT IN PROGRESS: the newest ReplicaSet has {new_ready} of {desired} ready, and older ones still run {old_pods} pod{}; the controller scales them down only as new pods become available{}",
            if old_pods == 1 { "" } else { "s" },
            if new_unready > 0 {
                format!(
                    ". {new_unready} of the new pods {} not ready: they may only be starting; if the new template is broken, a rollback or a corrected template replaces them",
                    if new_unready == 1 { "is" } else { "are" }
                )
            } else {
                String::new()
            }
        ));
    } else if recreate && new_unready > 0 {
        findings.push(format!(
            "RECREATE: no older pod remains, so while {new_unready} of the new pods {} not ready nothing else serves in their place",
            if new_unready == 1 { "is" } else { "are" }
        ));
    }
    lines.extend(findings);
    lines.join("\n")
}

/// The HorizontalPodAutoscalers that target a Deployment, and what they say
/// about scaling it.
fn render_deploy_hpas(hpas: &Result<Vec<k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler>, String>) -> String {
    let hpas = match hpas {
        Ok(h) if h.is_empty() => return "(no HorizontalPodAutoscaler targets it: its replicas are set by hand)".to_string(),
        Ok(h) => h,
        Err(e) => return format!("(HorizontalPodAutoscalers unavailable: {e})"),
    };
    let mut lines: Vec<String> = hpas
        .iter()
        .map(|h| {
            let spec = h.spec.clone().unwrap_or_default();
            let st = h.status.clone().unwrap_or_default();
            let keda = h
                .metadata
                .owner_references
                .iter()
                .flatten()
                .find(|o| o.kind == "ScaledObject")
                .map(|o| format!(" (made by KEDA ScaledObject {})", o.name))
                .unwrap_or_default();
            let mut line = format!(
                "{}{keda}: min {}, max {}, current {}, desired {}",
                h.metadata.name.as_deref().unwrap_or_default(),
                spec.min_replicas.unwrap_or(1),
                spec.max_replicas,
                st.current_replicas.unwrap_or(0),
                st.desired_replicas
            );
            for c in st.conditions.iter().flatten() {
                let notable = match c.type_.as_str() {
                    "AbleToScale" | "ScalingActive" => c.status == "False",
                    "ScalingLimited" => c.status == "True",
                    _ => false,
                };
                if notable {
                    let message: String = c.message.as_deref().unwrap_or_default().chars().take(200).collect();
                    line.push_str(&format!("; {}={} ({}): {message}", c.type_, c.status, c.reason.as_deref().unwrap_or("?")));
                }
            }
            line
        })
        .collect();
    lines.push(if hpas.len() > 1 {
        "MORE THAN ONE HPA TARGETS IT: each overwrites the replica count the other sets".to_string()
    } else {
        "the HPA sets its replicas, so a change to spec.replicas is overwritten".to_string()
    });
    lines.join("\n")
}

/// The Deployment sections of a workload diagnosis.
fn render_deploy_sections(d: &k8s::DeploymentDiagnostics) -> String {
    let events = d
        .new_rs_events
        .as_ref()
        .map(|(rs, e)| format!("\n\n## Events (ReplicaSet {rs})\n{}", render_nap_events(e, "(no events for it)", false, 10)))
        .unwrap_or_default();
    format!(
        "## Deployment\n{}\n\n## ReplicaSets\n{}{events}\n\n## Autoscaling\n{}\n\n## PodDisruptionBudgets\n{}",
        render_deploy_spec(&d.deployment),
        render_deploy_replicasets(&d.deployment, &d.replica_sets, &d.pods),
        render_deploy_hpas(&d.hpas),
        render_pdbs(&d.pdbs),
    )
}

/// A PodDisruptionBudget's own line — its budget, counts and what it lets a
/// drain do — with its selector, conditions and whether its status is
/// current.
fn render_pdb_budget(
    pdb: &k8s_openapi::api::policy::v1::PodDisruptionBudget,
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
) -> String {
    let covered = pods.as_ref().ok().map(|p| p.iter().filter_map(|p| p.metadata.name.clone()).collect::<Vec<_>>());
    let selector = pdb.spec.as_ref().and_then(|s| s.selector.as_ref());
    let mut lines = vec![render_pdbs(&Ok(vec![(pdb.clone(), covered.clone())]))];
    lines.push(match selector {
        None => "selector: (none)".to_string(),
        Some(sel) => {
            let q = k8s::label_selector_query(sel);
            format!("selector: {}", if q.is_empty() { "(empty: every pod in its namespace)".to_string() } else { q })
        }
    });
    let status = pdb.status.clone().unwrap_or_default();
    for c in status.conditions.iter().flatten() {
        let message: String = c.message.chars().take(300).collect();
        lines.push(format!("condition {}={} ({}){}", c.type_, c.status, c.reason, if message.is_empty() { String::new() } else { format!(": {message}") }));
    }
    if let (Some(g), Some(o)) = (pdb.metadata.generation, status.observed_generation) {
        if g > o {
            lines.push(format!("THE CONTROLLER HAS NOT YET ACTED ON THE LATEST SPEC: generation {g}, observed {o}, so the counts above may be stale"));
        }
    }
    match (selector, covered.as_deref()) {
        (None, _) => lines.push("NO SELECTOR: a budget without one selects no pods, so it protects nothing".to_string()),
        (Some(_), Some([])) => lines.push("SELECTS NO PODS: no pod in its namespace has the labels it selects, so it protects nothing".to_string()),
        _ => {}
    }
    lines.join("\n")
}

/// The pods a budget covers, with their readiness and nodes, and whether a
/// drain is waiting on them.
fn render_pdb_pods(
    pdb: &k8s_openapi::api::policy::v1::PodDisruptionBudget,
    pods: &Result<Vec<k8s_openapi::api::core::v1::Pod>, String>,
    nodes: &[(String, Result<Option<k8s_openapi::api::core::v1::Node>, String>)],
) -> String {
    const SHOWN: usize = 15;
    let pods = match pods {
        Ok(p) if p.is_empty() => return "(none)".to_string(),
        Ok(p) => p,
        Err(e) => return format!("(pods unavailable: {e})"),
    };
    let allowed = pdb.status.as_ref().map(|s| s.disruptions_allowed).unwrap_or(0);
    let mut lines = vec![format!("{} pods, {} ready", pods.len(), pods.iter().filter(|p| pod_is_ready(p)).count())];
    let mut cordoned: Vec<String> = Vec::new();
    for (i, p) in pods.iter().enumerate() {
        let node = p.spec.as_ref().and_then(|s| s.node_name.clone()).unwrap_or_default();
        // A node can be both NotReady and cordoned; each is said.
        let note = match nodes.iter().find(|(n, _)| *n == node).map(|(_, r)| r) {
            Some(Ok(None)) => " (NODE NO LONGER EXISTS)".to_string(),
            Some(Ok(Some(n))) => {
                let mut note = String::new();
                if !k8s::node_is_ready(n) {
                    note.push_str(" (node NOT READY)");
                }
                if n.spec.as_ref().and_then(|s| s.unschedulable) == Some(true) {
                    if !cordoned.contains(&node) {
                        cordoned.push(node.clone());
                    }
                    note.push_str(" (node CORDONED)");
                }
                note
            }
            Some(Err(e)) => format!(" (node unavailable: {e})"),
            None => String::new(),
        };
        if i < SHOWN {
            let phase = p.status.as_ref().and_then(|s| s.phase.clone()).unwrap_or_else(|| "Unknown".into());
            lines.push(format!(
                "{}: {}{}; {}{note}",
                p.metadata.name.as_deref().unwrap_or_default(),
                if pod_is_ready(p) { "ready" } else { "NOT READY" },
                if phase == "Running" { String::new() } else { format!(", {phase}") },
                if node.is_empty() { "not scheduled".to_string() } else { format!("on {node}") }
            ));
        }
    }
    if pods.len() > SHOWN {
        lines.push(format!("and {} more", pods.len() - SHOWN));
    }
    if !cordoned.is_empty() {
        let on: Vec<&k8s_openapi::api::core::v1::Pod> =
            pods.iter().filter(|p| p.spec.as_ref().and_then(|s| s.node_name.as_ref()).is_some_and(|n| cordoned.contains(n))).collect();
        let on_cordoned = on.len();
        // Nothing allowed stops a ready pod's eviction; an unready one may
        // still go, as the eviction policy in the budget's line says.
        let ready_on = on.iter().filter(|p| pod_is_ready(p)).count();
        let unready_on = on_cordoned - ready_on;
        lines.push(if allowed == 0 && ready_on > 0 {
            format!(
                "A DRAIN IS WAITING ON THIS BUDGET: {ready_on} ready pod{} on cordoned nodes ({}) cannot be evicted while it allows no disruption{}",
                if ready_on == 1 { "" } else { "s" },
                sts_pod_list(&cordoned),
                if unready_on > 0 {
                    format!("; {unready_on} not ready there may still be, as its unhealthyPodEvictionPolicy decides")
                } else {
                    String::new()
                }
            )
        } else if allowed == 0 {
            format!(
                "{unready_on} of its pods on cordoned nodes ({}) {} not ready: whether a drain can evict {} while it allows no disruption is up to its unhealthyPodEvictionPolicy",
                sts_pod_list(&cordoned),
                if unready_on == 1 { "is" } else { "are" },
                if unready_on == 1 { "it" } else { "them" }
            )
        } else {
            format!(
                "{on_cordoned} of its pods {} on cordoned nodes ({}); it allows {allowed} disruption{} now, so a drain can evict {}",
                if on_cordoned == 1 { "is" } else { "are" },
                sts_pod_list(&cordoned),
                if allowed == 1 { "" } else { "s" },
                if on_cordoned == 1 { "it" } else { "them" }
            )
        });
    }
    lines.join("\n")
}

/// The controllers behind a budget's pods, and whether the budget can ever
/// allow a disruption given the pods they ask for.
fn render_pdb_owners(pdb: &k8s_openapi::api::policy::v1::PodDisruptionBudget, owners: &Result<Vec<k8s::PdbOwner>, String>) -> String {
    let owners = match owners {
        Ok(o) if o.is_empty() => return "(no pods, so no controller)".to_string(),
        Ok(o) => o,
        Err(e) => return format!("(controllers unavailable: {e})"),
    };
    let mut lines: Vec<String> = owners
        .iter()
        .map(|o| {
            if o.kind.is_empty() {
                format!("{} pod{} with no controller: an evicted one is not recreated", o.pods, if o.pods == 1 { "" } else { "s" })
            } else {
                format!(
                    "{} {}: {} of its pods covered; {}",
                    o.kind,
                    o.name,
                    o.pods,
                    match &o.desired {
                        Ok(Some(d)) => format!("asks for {d}"),
                        Ok(None) => "asks for an unknown number".to_string(),
                        Err(e) => format!("its desired count is unavailable: {e}"),
                    }
                )
            }
        })
        .collect();
    // Measured as the disruption controller does: against the pods the
    // controllers ask for. Only when every one of them says.
    let spec = pdb.spec.clone().unwrap_or_default();
    // Pods with no controller count toward an integer minAvailable but ask
    // for no replicas, so with any of them the comparison is not made.
    let managed: Vec<&k8s::PdbOwner> = owners.iter().filter(|o| !o.kind.is_empty()).collect();
    let desired: Option<i32> = if managed.is_empty() || managed.len() < owners.len() {
        None
    } else {
        managed.iter().map(|o| o.desired.clone().ok().flatten()).sum()
    };
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    let never = match (&spec.min_available, &spec.max_unavailable) {
        (Some(IntOrString::String(s)), _) if s.trim() == "100%" => Some(format!("minAvailable {s} keeps every pod")),
        (Some(IntOrString::Int(m)), _) => desired.filter(|d| m >= d).map(|d| format!("minAvailable {m} with {d} pod{} asked for", if d == 1 { "" } else { "s" })),
        (_, Some(IntOrString::Int(0))) => Some("maxUnavailable 0".to_string()),
        (_, Some(IntOrString::String(s))) if s.trim() == "0%" => Some(format!("maxUnavailable {s}")),
        _ => None,
    };
    if let Some(why) = never {
        lines.push(format!("THE BUDGET CAN NEVER ALLOW A DISRUPTION: {why}, so a drain waits until there are more replicas or the budget is relaxed"));
    }
    lines.join("\n")
}

/// The other budgets over any of these pods: the eviction API refuses to
/// evict a pod covered by more than one.
fn render_pdb_others(others: &Result<Vec<(k8s_openapi::api::policy::v1::PodDisruptionBudget, Option<Vec<String>>)>, String>) -> String {
    match others {
        Err(e) => format!("(other budgets unavailable: {e})"),
        Ok(o) if o.is_empty() => "(no other budget in its namespace covers any of its pods)".to_string(),
        Ok(o) => o
            .iter()
            .map(|(b, shared)| {
                format!(
                    "OVERLAPS WITH {} ON {}: the eviction API refuses to evict a pod covered by more than one budget",
                    b.metadata.name.as_deref().unwrap_or_default(),
                    shared.as_deref().map(sts_pod_list).unwrap_or_else(|| "its pods".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Assembles a PodDisruptionBudget diagnosis, redacted.
pub async fn build_pdb_diagnosis_payload(context_name: &str, namespace: &str, name: &str) -> Result<ClaudeDiagnosisPayload, String> {
    let d = k8s::get_pdb_diagnostics(context_name, namespace, name).await?;
    let budget = redact::redact(&render_pdb_budget(&d.pdb, &d.pods));
    let pods = redact::redact(&render_pdb_pods(&d.pdb, &d.pods, &d.nodes));
    let owners = redact::redact(&render_pdb_owners(&d.pdb, &d.owners));
    let others = redact::redact(&render_pdb_others(&d.others));
    let events = redact::redact(&render_nap_events(&d.events, "(no events for this budget)", false, 25));
    let manifest = redact::redact(&d.manifest);
    let redaction_summary = redact::Redacted::merge([&budget, &pods, &owners, &others, &events, &manifest]).summary();

    let prompt = format!(
        "PodDisruptionBudget {namespace}/{name}.\n\n\
         ## Budget\n{}\n\n\
         ## Pods it covers\n{}\n\n\
         ## Their controllers\n{}\n\n\
         ## Other budgets over these pods\n{}\n\n\
         ## Events\n{}\n\n\
         ## Manifest (managed fields omitted)\n```yaml\n{}\n```",
        budget.text, pods.text, owners.text, others.text, events.text, manifest.text,
    );
    Ok(ClaudeDiagnosisPayload { approx_tokens: approx_tokens(&prompt), prompt, redaction_summary, log_note: None })
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
    let (workloads, events, manifest, pods, controller) = tokio::join!(
        k8s::get_workloads(context_name),
        k8s::get_workload_events(context_name, kind, namespace, name),
        k8s::get_workload_manifest(context_name, kind, namespace, name),
        k8s::get_pods(context_name, Some(namespace.to_string())),
        async {
            // A StatefulSet's pods have identities, volumes and an order, so
            // its failures are often about which ordinal is stuck and why, not
            // about what the pods have in common. A DaemonSet's are about
            // nodes: which should run its pod, and what keeps one off. A
            // Deployment's are about its ReplicaSets: whether the newest can
            // create pods, and how far the rollout from the old ones has got.
            match kind {
                "StatefulSet" => Some(match k8s::get_statefulset_diagnostics(context_name, namespace, name).await {
                    Ok(d) => render_sts_sections(&d, chrono::Utc::now()),
                    Err(e) => format!("## StatefulSet\n(StatefulSet details unavailable: {e})"),
                }),
                "DaemonSet" => Some(match k8s::get_daemonset_diagnostics(context_name, namespace, name).await {
                    Ok(d) => render_ds_sections(&d, chrono::Utc::now()),
                    Err(e) => format!("## DaemonSet\n(DaemonSet details unavailable: {e})"),
                }),
                "Deployment" => Some(match k8s::get_deployment_diagnostics(context_name, namespace, name).await {
                    Ok(d) => render_deploy_sections(&d),
                    Err(e) => format!("## Deployment\n(Deployment details unavailable: {e})"),
                }),
                _ => None,
            }
        },
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
    let controller_r = controller.as_ref().map(|s| redact::redact(s));

    let mut parts = vec![&status, &pods_r, &events_r, &pod_events_r, &manifest_r, &logs_r];
    parts.extend(previous_r.as_ref());
    parts.extend(controller_r.as_ref());
    let redaction_summary = redact::Redacted::merge(parts).summary();
    let log_note = combine_log_notes(current_note.clone(), previous_logs.as_ref());

    let log_heading = match (&log_source, &container) {
        (Some(pod), c) if !c.is_empty() => format!(" (pod {pod}, container {c})"),
        _ => String::new(),
    };

    let prompt = format!(
        "{kind} {namespace}/{name}.\n\n\
         ## Status\n{}\n\n\
         ## Pods (worst first)\n{}\n\n{}\
         ## Events ({kind})\n{}\n\n\
         ## Events (worst pod{})\n{}\n\n\
         ## Manifest\n```yaml\n{}\n```\n\n\
         ## Logs{}{}\n```\n{}\n```{}",
        status.text,
        pods_r.text,
        controller_r.as_ref().map(|s| format!("{}\n\n", s.text)).unwrap_or_default(),
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
        "ScaledObject" | "ScaledJob" => DIAGNOSE_KEDA_SYSTEM,
        "Service" => DIAGNOSE_SERVICE_SYSTEM,
        "Ingress" => DIAGNOSE_INGRESS_SYSTEM,
        "PersistentVolumeClaim" => DIAGNOSE_PVC_SYSTEM,
        "PodDisruptionBudget" => DIAGNOSE_PDB_SYSTEM,
        "StatefulSet" => DIAGNOSE_STATEFULSET_SYSTEM,
        "DaemonSet" => DIAGNOSE_DAEMONSET_SYSTEM,
        "Deployment" => DIAGNOSE_DEPLOYMENT_SYSTEM,
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
        assert!(out.ends_with("… and 7 more: 7 Ready with nothing pending"), "{out}");
    }

    #[test]
    fn stuck_claims_past_the_cap_are_counted_as_stuck() {
        let stuck = serde_json::json!([{ "type": "Ready", "status": "False" }]);
        let claims: Vec<_> = (0..DIAGNOSE_NAP_CLAIMS + 2).map(|i| claim(&format!("s-{i}"), stuck.clone(), None, false)).collect();
        let out = render_nap_claims(&Ok(claims), &Ok(vec![]));
        assert!(out.ends_with("… and 2 more: 2 not Ready"), "{out}");
    }

    #[test]
    fn a_target_is_read_through_its_scale_subresource() {
        let scale: k8s_openapi::api::autoscaling::v1::Scale =
            serde_json::from_value(serde_json::json!({ "spec": { "replicas": 4 }, "status": { "replicas": 3, "selector": "app=x" } })).unwrap();
        let crd: kube::api::DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "example.com/v1", "kind": "Pool", "metadata": { "name": "p" }, "spec": { "size": 4 }, "status": { "currentSize": 3 }
        }))
        .unwrap();
        let out = render_hpa_target(&Ok(crd), &Ok(scale), &Ok("app=x".into()));
        assert_eq!(out, "replicas (from its scale subresource): desired 4, current 3\nselector (from its scale subresource): app=x");
        let deployment: kube::api::DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "name": "d" }, "status": { "readyReplicas": 2, "availableReplicas": 2 }
        }))
        .unwrap();
        let out = render_hpa_target(&Ok(deployment), &Err("forbidden".into()), &Err("forbidden".into()));
        assert_eq!(out, "(scale unavailable: forbidden)\nstatus: ready 2, available 2\nselector unavailable: forbidden");
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
        // A container only on pods past the sample is not absent.
        let mut many: Vec<_> = (0..DIAGNOSE_HPA_PODS).map(|i| hpa_pod(&format!("old-{i}"), serde_json::json!([{ "name": "app" }]), serde_json::json!([]), true)).collect();
        many.push(hpa_pod("new", serde_json::json!([{ "name": "app-v2" }]), serde_json::json!([]), true));
        let out = render_hpa_containers(&Ok(many), &Ok(Default::default()), &hpa_request_needs(&[hpa_metric("ContainerResource", "app-v2/cpu", "60%")]));
        assert!(!out.contains("no pod has a container named app-v2"), "{out}");
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

    fn keys(entries: &[(&str, &str, &str, Result<&[&str], &str>)]) -> KeySets {
        entries
            .iter()
            .map(|(k, ns, n, r)| {
                (
                    (k.to_string(), ns.to_string(), n.to_string()),
                    r.map(|ks| ks.iter().map(|s| s.to_string()).collect()).map_err(|e| e.to_string()),
                )
            })
            .collect()
    }

    fn keda_detail_with(triggers: Vec<crate::models::KedaTriggerInfo>) -> crate::models::KedaDetail {
        crate::models::KedaDetail { triggers, ..Default::default() }
    }

    fn trigger(metadata: &[&str], auth_ref: &str) -> crate::models::KedaTriggerInfo {
        crate::models::KedaTriggerInfo {
            trigger_type: "azure-eventhub".into(),
            metadata: metadata.iter().map(|m| m.to_string()).collect(),
            auth_ref: auth_ref.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_from_env_credential_is_traced_to_its_secret_key_or_said_to_be_missing() {
        let containers = vec![serde_json::json!({
            "name": "app",
            "env": [
                { "name": "HUB", "valueFrom": { "secretKeyRef": { "name": "hub", "key": "conn" } } },
                { "name": "WRONG", "valueFrom": { "secretKeyRef": { "name": "hub", "key": "connection" } } },
                { "name": "PLAIN", "value": "Endpoint=sb://secret" },
            ],
            "envFrom": [{ "secretRef": { "name": "bulk" }, "prefix": "APP_" }],
        })];
        let ks = keys(&[
            ("Secret", "ns", "hub", Ok(&["conn", "other"][..])),
            ("Secret", "ns", "bulk", Ok(&["STORAGE"][..])),
        ]);
        let d = keda_detail_with(vec![trigger(
            &["connectionFromEnv=HUB", "storageConnectionFromEnv=APP_STORAGE", "x1FromEnv=WRONG", "x2FromEnv=PLAIN", "x3FromEnv=NOPE", "eventHubName=orders"],
            "",
        )]);
        let out = render_keda_credentials(&d, &serde_json::json!({}), &containers, &[], &ks, "ns", None);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "trigger 0 connectionFromEnv → env HUB: on container app, from Secret hub key conn — present");
        assert_eq!(lines[1], "trigger 0 storageConnectionFromEnv → env APP_STORAGE: on container app, from all of Secret bulk (envFrom), key STORAGE — present");
        assert_eq!(lines[2], "trigger 0 x1FromEnv → env WRONG: on container app, from Secret hub key connection — MISSING; it has: conn, other");
        assert_eq!(lines[3], "trigger 0 x2FromEnv → env PLAIN: on container app, set inline in the manifest");
        assert_eq!(lines[4], "trigger 0 x3FromEnv → env NOPE: NOT DEFINED on container app — KEDA cannot resolve it");
        assert_eq!(lines.len(), 5);
        assert!(!out.contains("Endpoint="), "an inline value must never be copied: {out}");
    }

    #[test]
    fn env_source_container_name_narrows_where_keda_looks() {
        let containers = vec![
            serde_json::json!({ "name": "app", "env": [{ "name": "HUB", "value": "x" }] }),
            serde_json::json!({ "name": "sidecar" }),
        ];
        let d = keda_detail_with(vec![trigger(&["connectionFromEnv=HUB"], "")]);
        let object = serde_json::json!({ "spec": { "scaleTargetRef": { "envSourceContainerName": "sidecar" } } });
        let out = render_keda_credentials(&d, &object, &containers, &[], &KeySets::new(), "ns", None);
        assert_eq!(out, "trigger 0 connectionFromEnv → env HUB: NOT DEFINED on container sidecar — KEDA cannot resolve it");
    }

    #[test]
    fn keda_reads_the_first_container_unless_told_otherwise() {
        let containers = vec![
            serde_json::json!({ "name": "app" }),
            serde_json::json!({ "name": "sidecar", "env": [{ "name": "HUB", "value": "x" }] }),
        ];
        let d = keda_detail_with(vec![trigger(&["connectionFromEnv=HUB"], "")]);
        let out = render_keda_credentials(&d, &serde_json::json!({}), &containers, &[], &KeySets::new(), "ns", None);
        assert_eq!(out, "trigger 0 connectionFromEnv → env HUB: NOT DEFINED on container app — KEDA cannot resolve it");
        let object = serde_json::json!({ "spec": { "envSourceContainerName": "gone" } });
        let out = render_keda_credentials(&d, &object, &containers, &[], &KeySets::new(), "ns", None);
        assert_eq!(out, "trigger 0 connectionFromEnv → env HUB: NOT RESOLVABLE — the target has no container gone");
    }

    #[test]
    fn the_env_from_source_that_wins_is_the_one_reported() {
        let containers = vec![serde_json::json!({
            "name": "app",
            "envFrom": [{ "secretRef": { "name": "a" } }, { "secretRef": { "name": "b" } }, { "secretRef": { "name": "c" } }],
        })];
        let d = keda_detail_with(vec![trigger(&["connectionFromEnv=HUB"], "")]);
        let run = |ks: &KeySets| render_keda_credentials(&d, &serde_json::json!({}), &containers, &[], ks, "ns", None);

        let ks = keys(&[("Secret", "ns", "a", Ok(&["HUB"][..])), ("Secret", "ns", "b", Ok(&["HUB"][..])), ("Secret", "ns", "c", Ok(&[][..]))]);
        assert_eq!(run(&ks), "trigger 0 connectionFromEnv → env HUB: on container app, from all of Secret b (envFrom), key HUB — present");

        let ks = keys(&[("Secret", "ns", "a", Ok(&["HUB"][..])), ("Secret", "ns", "b", Ok(&[][..])), ("Secret", "ns", "c", Err("could not be read: forbidden"))]);
        assert_eq!(
            run(&ks),
            "trigger 0 connectionFromEnv → env HUB: on container app, from all of Secret a (envFrom), key HUB — present, unless Secret c (could not be read: forbidden) (later, so taking precedence) defines it"
        );

        let ks = keys(&[("Secret", "ns", "a", Err("does not exist")), ("Secret", "ns", "b", Ok(&[][..])), ("Secret", "ns", "c", Err("could not be read: forbidden"))]);
        assert_eq!(
            run(&ks),
            "trigger 0 connectionFromEnv → env HUB: not found on container app in what could be read; it may come from Secret c (could not be read: forbidden) (its envFrom names Secret a, which does not exist)"
        );

        let ks = keys(&[("Secret", "ns", "a", Err("does not exist")), ("Secret", "ns", "b", Ok(&[][..])), ("Secret", "ns", "c", Ok(&[][..]))]);
        assert_eq!(
            run(&ks),
            "trigger 0 connectionFromEnv → env HUB: NOT DEFINED on container app — KEDA cannot resolve it (its envFrom names Secret a, which does not exist)"
        );
    }

    #[test]
    fn a_scaled_job_manifest_carries_no_inline_env_value() {
        let object: kube::api::DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "keda.sh/v1alpha1", "kind": "ScaledJob",
            "metadata": { "name": "j", "annotations": { "kubectl.kubernetes.io/last-applied-configuration": "{\"opaque\":\"s3cr3t\"}", "team": "x" } },
            "spec": { "jobTargetRef": { "template": { "spec": {
                "containers": [{ "name": "app", "env": [{ "name": "TOKEN", "value": "s3cr3t" }, { "name": "REF", "valueFrom": { "secretKeyRef": { "name": "s", "key": "k" } } }] }],
                "initContainers": [{ "name": "init", "env": [{ "name": "TOKEN", "value": "s3cr3t" }] }]
            } } } }
        }))
        .unwrap();
        let yaml = k8s::object_manifest(k8s::keda_manifest_for_diagnosis(object)).unwrap().yaml_without_managed_fields;
        assert!(!yaml.contains("s3cr3t"), "{yaml}");
        assert!(!yaml.contains("last-applied"), "{yaml}");
        assert_eq!(yaml.matches("(value omitted)").count(), 2, "{yaml}");
        assert!(yaml.contains("team: x") && yaml.contains("secretKeyRef"), "{yaml}");
    }

    #[test]
    fn a_missing_scale_means_a_missing_target_only_when_the_target_is_missing_too() {
        let not_found = || {
            kube::Error::Api(kube::core::ErrorResponse { status: "Failure".into(), message: "not found".into(), reason: "NotFound".into(), code: 404 })
        };
        let gone: Result<kube::api::DynamicObject, String> = Err("Rollout 'r' does not exist".into());
        assert_eq!(k8s::scale_error("Rollout", "r", &gone, not_found()), "Rollout 'r' does not exist");
        let there: Result<kube::api::DynamicObject, String> = Err("Failed to get Rollout 'r': forbidden".into());
        assert_eq!(k8s::scale_error("Rollout", "r", &there, not_found()), "Failed to read the scale of Rollout 'r': it has no scale subresource");
    }

    #[test]
    fn a_trigger_authentication_is_traced_parameter_by_parameter() {
        let auth: kube::api::DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "keda.sh/v1alpha1", "kind": "ClusterTriggerAuthentication", "metadata": { "name": "hub" },
            "spec": {
                "podIdentity": { "provider": "azure-workload", "identityId": "1111" },
                "secretTargetRef": [{ "parameter": "connection", "name": "hub-conn", "key": "conn" }],
                "azureKeyVault": { "vaultUri": "https://kv.vault.azure.net", "secrets": [{ "parameter": "password", "name": "db-pass" }] }
            }
        }))
        .unwrap();
        let auths = vec![
            ("ClusterTriggerAuthentication/hub".to_string(), Ok(auth)),
            ("TriggerAuthentication/gone".to_string(), Err("TriggerAuthentication 'gone' does not exist".to_string())),
        ];
        let ks = keys(&[("Secret", "kube-system", "hub-conn", Err("does not exist"))]);
        let out = render_keda_credentials(&keda_detail_with(vec![]), &serde_json::json!({}), &[], &auths, &ks, "ns", Some("kube-system"));
        assert_eq!(
            out,
            "ClusterTriggerAuthentication/hub:\n  pod identity: azure-workload, identity 1111\n  connection from Secret hub-conn does not exist\n  Azure Key Vault https://kv.vault.azure.net: password ← db-pass\nTriggerAuthentication/gone: unavailable: TriggerAuthentication 'gone' does not exist"
        );
    }

    #[test]
    fn operator_lines_are_matched_to_their_object_in_every_shape_keda_writes() {
        let handler = "2026-11-01T10:00:00Z\tERROR\tscale_handler\terror getting scale decision\t{\"scaledObject.Namespace\": \"ns\", \"scaledObject.Name\": \"so\", \"scaler\": \"prometheusScaler\", \"error\": \"boom\"}";
        let scaler = "2026-11-01T10:00:01Z\tERROR\tprometheus_scaler\terror executing prometheus query\t{\"type\": \"ScaledObject\", \"namespace\": \"ns\", \"name\": \"so\", \"error\": \"dial tcp: refused\"}";
        let controller = "2026-11-01T10:00:02Z\tERROR\tReconciler error\t{\"controller\": \"scaledobject\", \"ScaledObject\": {\"name\": \"so\", \"namespace\": \"ns\"}, \"namespace\": \"ns\", \"name\": \"so\", \"error\": \"failed to ensure HPA is correctly created for ScaledObject\"}";
        assert!(k8s::keda_log_line_is_about(handler, "ScaledObject", "ns", "so"));
        assert!(k8s::keda_log_line_is_about(scaler, "ScaledObject", "ns", "so"));
        assert!(k8s::keda_log_line_is_about(controller, "ScaledObject", "ns", "so"));
        assert!(!k8s::keda_log_line_is_about(scaler, "ScaledObject", "ns", "other"));
        assert!(!k8s::keda_log_line_is_about(scaler, "ScaledJob", "ns", "so"), "a ScaledJob of the same name is a different object");
        assert!(!k8s::keda_log_line_is_about(controller, "ScaledJob", "ns", "so"), "nor is its controller's line about the ScaledJob");
        let job_controller = "2026-11-01T10:00:03Z\tERROR\tReconciler error\t{\"controller\": \"scaledjob\", \"controllerKind\": \"ScaledJob\", \"ScaledJob\": {\"name\": \"so\", \"namespace\": \"ns\"}, \"namespace\": \"ns\", \"name\": \"so\", \"error\": \"x\"}";
        assert!(k8s::keda_log_line_is_about(job_controller, "ScaledJob", "ns", "so"));
        assert!(!k8s::keda_log_line_is_about(job_controller, "ScaledObject", "ns", "so"));
        assert!(!k8s::keda_log_line_is_about("\tgithub.com/kedacore/keda/v2/pkg/scaling.(*scaleHandler).getScaledObjectState", "ScaledObject", "ns", "so"));

        let lines = Ok(vec![handler.to_string(), scaler.to_string(), scaler.replace("10:00:01", "10:00:31"), controller.to_string()]);
        let out = render_keda_operator_logs(&lines);
        assert_eq!(
            out,
            "ERROR prometheus_scaler: error executing prometheus query (×2, last 2026-11-01T10:00:31Z)\n  dial tcp: refused\n\
             ERROR: Reconciler error (×1, last 2026-11-01T10:00:02Z)\n  failed to ensure HPA is correctly created for ScaledObject\n\
             ERROR scale_handler: error getting scale decision (×1, last 2026-11-01T10:00:00Z)\n  boom"
        );
        assert_eq!(render_keda_operator_logs(&Ok(vec![])), "(the operator logged nothing about this object in its recent log)");
    }

    #[test]
    fn credential_sources_are_collected_from_the_container_and_the_authentication() {
        let containers = vec![serde_json::json!({
            "env": [{ "name": "A", "valueFrom": { "secretKeyRef": { "name": "s1", "key": "a" } } },
                    { "name": "B", "valueFrom": { "configMapKeyRef": { "name": "c1", "key": "b" } } }],
            "envFrom": [{ "secretRef": { "name": "s1" } }, { "configMapRef": { "name": "c2" } }],
        })];
        let auth: kube::api::DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "keda.sh/v1alpha1", "kind": "ClusterTriggerAuthentication", "metadata": { "name": "x" },
            "spec": { "secretTargetRef": [{ "parameter": "p", "name": "s2", "key": "k" }], "configMapTargetRef": [{ "parameter": "q", "name": "c3", "key": "k" }] }
        }))
        .unwrap();
        let refs = k8s::keda_key_set_refs(&containers, &[("ClusterTriggerAuthentication/x".into(), Ok(auth))], "ns", Some("keda"));
        let got: Vec<String> = refs.iter().map(|(k, ns, n)| format!("{k} {ns}/{n}")).collect();
        assert_eq!(got, ["Secret ns/s1", "ConfigMap ns/c1", "ConfigMap ns/c2", "Secret keda/s2", "ConfigMap keda/c3"]);
    }

    fn labelled_pod(name: &str, labels: serde_json::Value, ready: bool, extra: serde_json::Value) -> k8s_openapi::api::core::v1::Pod {
        let mut v = serde_json::json!({
            "metadata": { "name": name, "labels": labels },
            "spec": { "containers": [{ "name": "app" }], "nodeName": "n1" },
            "status": { "phase": "Running", "conditions": [{ "type": "Ready", "status": if ready { "True" } else { "False" } }] }
        });
        json_merge(&mut v, extra);
        serde_json::from_value(v).unwrap()
    }

    fn json_merge(a: &mut serde_json::Value, b: serde_json::Value) {
        match (a, b) {
            (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
                for (k, v) in b {
                    json_merge(a.entry(k).or_insert(serde_json::Value::Null), v);
                }
            }
            (a, b) => *a = b,
        }
    }

    fn selector(terms: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        terms.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn a_selector_that_matches_nothing_shows_what_nearly_does() {
        let sel = selector(&[("app", "api"), ("tier", "web")]);
        let pods = Ok(vec![
            labelled_pod("api-1", serde_json::json!({ "app": "api", "tier": "backend" }), true, serde_json::json!({})),
            labelled_pod("api-2", serde_json::json!({ "app": "api", "tier": "backend" }), true, serde_json::json!({})),
            labelled_pod("api-3", serde_json::json!({ "app": "api" }), true, serde_json::json!({})),
            labelled_pod("other", serde_json::json!({ "app": "db" }), true, serde_json::json!({})),
        ]);
        let out = render_service_pods(&sel, &pods, "ns");
        assert_eq!(
            out,
            "NO POD in namespace ns matches the selector (4 pods in the namespace)\n\
             near misses (pods with some of the selector's labels):\n  \
             2 pod(s), e.g. api-1: tier=backend where the selector wants tier=web\n  \
             1 pod(s), e.g. api-3: no tier label"
        );
        let none = render_service_pods(&selector(&[("component", "etcd")]), &pods, "kube-system");
        assert!(none.ends_with("no pod in the namespace carries any of the selector's labels"), "{none}");
    }

    #[test]
    fn a_workload_scaled_to_zero_is_named_as_the_supplier() {
        let sel = selector(&[("app", "api")]);
        let w = |kind: &str, name: &str, labels: &[(&str, &str)], desired, ready| k8s::ServiceWorkload {
            kind: kind.into(),
            name: name.into(),
            labels: selector(labels),
            desired,
            ready,
        };
        let out = render_service_workloads(
            &sel,
            &[w("Deployment", "api", &[("app", "api")], 0, 0), w("Deployment", "api-v2", &[("app", "api-v2")], 3, 3)],
            &["Failed to list StatefulSets in 'ns': forbidden".to_string()],
        );
        assert_eq!(out, "matching:\n  Deployment/api: 0 desired, 0 ready\n(unavailable: Failed to list StatefulSets in 'ns': forbidden)");
        let sel = selector(&[("app", "api"), ("tier", "web")]);
        let out = render_service_workloads(&sel, &[w("StatefulSet", "api", &[("app", "api")], 2, 2)], &[]);
        assert_eq!(out, "no workload's pod template matches the selector\nnear misses:\n  StatefulSet/api: 2 desired, 2 ready — template has no tier");
    }

    #[test]
    fn matching_pods_list_the_unready_first_with_their_probe() {
        let sel = selector(&[("app", "api")]);
        let probe = serde_json::json!({ "spec": { "containers": [{ "name": "app",
            "readinessProbe": { "httpGet": { "port": "http", "path": "/healthz" }, "periodSeconds": 5 } },
            { "name": "auth", "readinessProbe": { "exec": { "command": ["sh", "-c", "curl -H 'Authorization: s3cr3t'"] } } }] } });
        let crashing = serde_json::json!({ "status": { "containerStatuses": [{ "name": "app", "ready": false, "restartCount": 4, "image": "i", "imageID": "",
            "state": { "waiting": { "reason": "CrashLoopBackOff" } } }] } });
        let pods = Ok(vec![
            labelled_pod("api-ok", serde_json::json!({ "app": "api" }), true, probe.clone()),
            labelled_pod("api-bad", serde_json::json!({ "app": "api" }), false, {
                let mut p = probe.clone();
                json_merge(&mut p, crashing);
                p
            }),
        ]);
        let out = render_service_pods(&sel, &pods, "ns");
        assert_eq!(
            out,
            "2 pods match, 1 ready\n  \
             api-bad: Running, NOT READY, 4 restarts; app waiting: CrashLoopBackOff; on n1\n  \
             api-ok: Running, ready; on n1\n\
             readiness probes:\n  \
             app: httpGet http:http/healthz, every 5s, fails after 3, first after 0s\n  \
             auth: exec (a command), every 10s, fails after 3, first after 0s"
        );
        assert!(!out.contains("s3cr3t"));
    }

    #[test]
    fn a_named_target_port_must_be_declared_on_the_pods() {
        let svc: k8s_openapi::api::core::v1::Service = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "api" },
            "spec": { "selector": { "app": "api" }, "ports": [{ "port": 80, "targetPort": "http" }, { "port": 9090, "targetPort": 9090 }] }
        }))
        .unwrap();
        let declares = serde_json::json!({ "spec": { "containers": [{ "name": "app", "ports": [{ "name": "http", "containerPort": 8080 }] }] } });
        let pods = Ok(vec![
            labelled_pod("api-1", serde_json::json!({ "app": "api" }), true, declares),
            labelled_pod("api-2", serde_json::json!({ "app": "api" }), true, serde_json::json!({})),
        ]);
        assert_eq!(
            render_service_port_check(&svc, &pods),
            "port 80 → http: NAMED PORT NOT DECLARED for TCP on 1 of 2 matching pods (e.g. api-2) — those endpoints get no port\n\
             port 9090 → 9090: no container declares it (harmless if the process listens there anyway; declared: 8080)"
        );
    }

    #[test]
    fn a_pod_stuck_in_init_names_the_init_container() {
        let extra = serde_json::json!({
            "spec": { "initContainers": [{ "name": "migrate" }, { "name": "setup" }, { "name": "proxy", "restartPolicy": "Always" }] },
            "status": {
                "phase": "Pending",
                "initContainerStatuses": [
                    { "name": "setup", "ready": false, "restartCount": 0, "image": "i", "imageID": "", "state": { "terminated": { "exitCode": 0, "reason": "Completed" } } },
                    { "name": "migrate", "ready": false, "restartCount": 2, "image": "i", "imageID": "", "state": { "waiting": { "reason": "ImagePullBackOff" } } },
                    { "name": "proxy", "ready": false, "restartCount": 0, "image": "i", "imageID": "", "state": { "running": {} } }
                ],
                "containerStatuses": [{ "name": "app", "ready": false, "restartCount": 0, "image": "i", "imageID": "", "state": { "waiting": { "reason": "PodInitializing" } } }]
            }
        });
        let p = labelled_pod("api-1", serde_json::json!({ "app": "api" }), false, extra);
        assert_eq!(
            render_service_pod(&p),
            "api-1: Pending, NOT READY, 2 restarts; init migrate waiting: ImagePullBackOff; sidecar proxy running, not ready; app waiting: PodInitializing; on n1"
        );
    }

    #[test]
    fn a_native_sidecar_counts_for_probes_and_ports() {
        let sel = selector(&[("app", "api")]);
        let sidecar = |probe_path: &str| {
            serde_json::json!({ "spec": { "initContainers": [{ "name": "proxy", "restartPolicy": "Always",
                "ports": [{ "name": "mesh", "containerPort": 15001 }, { "name": "dns", "containerPort": 53, "protocol": "UDP" }],
                "readinessProbe": { "httpGet": { "port": 15021, "path": probe_path } } },
                { "name": "migrate", "ports": [{ "name": "once", "containerPort": 9 }] }] } })
        };
        // Mid-rollout: the same container name with two probes, the unready pod's first.
        let pods = Ok(vec![
            labelled_pod("api-old", serde_json::json!({ "app": "api" }), true, sidecar("/ready")),
            labelled_pod("api-new", serde_json::json!({ "app": "api" }), false, sidecar("/healthz/ready")),
        ]);
        let out = render_service_pods(&sel, &pods, "ns");
        let probes = out.split("readiness probes:\n").nth(1).unwrap();
        assert_eq!(
            probes,
            "  app: none (ready as soon as it starts)\n  \
             proxy: httpGet http:15021/healthz/ready, every 10s, fails after 3, first after 0s\n  \
             proxy: httpGet http:15021/ready, every 10s, fails after 3, first after 0s"
        );

        let svc: k8s_openapi::api::core::v1::Service = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "api" },
            "spec": { "selector": { "app": "api" }, "ports": [
                { "port": 15001, "targetPort": "mesh" }, { "port": 53, "targetPort": "dns", "protocol": "TCP" }, { "port": 9, "targetPort": "once" }] }
        }))
        .unwrap();
        assert_eq!(
            render_service_port_check(&svc, &pods),
            "port 15001 → mesh: named port declared on every matching pod, as 15001\n\
             port 53 → dns: NAMED PORT NOT DECLARED for TCP on 2 of 2 matching pods (e.g. api-old) — those endpoints get no port\n\
             port 9 → once: NAMED PORT NOT DECLARED for TCP on 2 of 2 matching pods (e.g. api-old) — those endpoints get no port"
        );
    }

    #[test]
    fn only_aks_settles_that_the_control_plane_runs_no_pods() {
        let aks = render_service_cluster(&Ok(k8s::ControlPlane { role_nodes: 0, aks: true }));
        assert!(aks.starts_with("AKS: yes — the control plane is managed by Azure"), "{aks}");
        assert_eq!(render_service_cluster(&Ok(k8s::ControlPlane { role_nodes: 0, aks: false })), "AKS: no\nnodes labelled control-plane or master: 0");
    }

    fn ingress(v: serde_json::Value) -> k8s_openapi::api::networking::v1::Ingress {
        let mut base = serde_json::json!({ "metadata": { "name": "web", "namespace": "ns" } });
        json_merge(&mut base, v);
        serde_json::from_value(base).unwrap()
    }

    fn ingress_class(name: &str, controller: &str, default: bool) -> k8s_openapi::api::networking::v1::IngressClass {
        let annotations = if default { serde_json::json!({ "ingressclass.kubernetes.io/is-default-class": "true" }) } else { serde_json::json!({}) };
        serde_json::from_value(serde_json::json!({ "metadata": { "name": name, "annotations": annotations }, "spec": { "controller": controller } })).unwrap()
    }

    #[test]
    fn controller_log_lines_are_matched_without_access_logs() {
        let about = vec!["web".to_string(), "api".to_string()];
        let nginx = "W1102 10:00:00.000000       7 controller.go:1214] Service \"ns/api\" does not have any active Endpoint.";
        let traefik = "time=\"2026-11-02T10:00:00Z\" level=error msg=\"Cannot create service\" error=\"service not found\" ingress=web namespace=ns serviceName=api";
        let access = "10.0.0.1 - - [02/Nov/2026:10:00:00 +0000] \"GET /ns/api HTTP/1.1\" 502 150 \"-\" \"curl\" 80 0.001 [ns-api-80] []";
        assert!(k8s::ingress_log_line_is_about(nginx, "ns", &about));
        assert!(k8s::ingress_log_line_is_about(traefik, "ns", &about));
        assert!(!k8s::ingress_log_line_is_about(access, "ns", &about), "access logs carry client addresses");
        assert!(!k8s::ingress_log_line_is_about("W1102 10:00:00.000000 7 x.go:1] Service \"other/api\" has no endpoints", "ns", &about));
        assert!(!k8s::ingress_log_line_is_about("W1102 10:00:00.000000 7 x.go:1] Service \"other-ns/api\" has no endpoints", "ns", &about));
        assert!(!k8s::ingress_log_line_is_about("W1102 10:00:00.000000 7 x.go:1] Service \"ns/api-old\" has no endpoints", "ns", &about));
        assert!(!k8s::ingress_log_line_is_about("level=error msg=\"x\" namespace=ns-2 ingress=web", "ns", &about));

        // Pod by pod: the second replica's older line comes after the first's newer one.
        let lines = Some(Ok((2, vec![
            nginx.replace("10:00:00", "10:00:30"),
            nginx.to_string(),
            traefik.to_string(),
            r#"{"level":"error","time":"2026-11-02T10:01:00Z","msg":"reload failed","error":"bad config"}"#.to_string(),
        ])));
        assert_eq!(
            render_ingress_controller_logs(&lines),
            "ERROR reload failed: bad config (×1, last 2026-11-02T10:01:00Z)\n\
             ERROR Cannot create service: service not found (×1, last 2026-11-02T10:00:00Z)\n\
             WARN Service \"ns/api\" does not have any active Endpoint. (×2, last 1102 10:00:30.000000)"
        );
        assert_eq!(render_ingress_controller_logs(&Some(Ok((0, vec![])))), "(the controller has no pods, so there is no log to read)");
        let escaped = r#"time="2026-11-02T10:00:00Z" level=error msg="Cannot create service" error="service \"ns/api\" not found" namespace=ns"#;
        assert_eq!(
            render_ingress_controller_logs(&Some(Ok((1, vec![escaped.to_string()])))),
            "ERROR Cannot create service: service \"ns/api\" not found (×1, last 2026-11-02T10:00:00Z)"
        );
        let scaled = Ok(vec![k8s::IngressControllerWorkload {
            kind: "Deployment".into(),
            namespace: "ingress-nginx".into(),
            name: "ingress-nginx-controller".into(),
            desired: 0,
            ready: 0,
            matched_by: "its args name this class or controller".into(),
            selector: "app=nginx".into(),
            container: "controller".into(),
        }]);
        assert!(render_ingress_controllers(&scaled).contains("SCALED TO ZERO"));
    }

    #[test]
    fn a_controller_is_found_by_a_class_flag_not_by_any_word() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let m = |a: &[&str], class: Option<&str>| k8s::controller_flags_match(&args(a), class, Some("k8s.io/ingress-nginx"));
        assert!(m(&["/nginx-ingress-controller", "--ingress-class=nginx"], Some("nginx")));
        assert!(m(&["/nginx-ingress-controller", "--controller-class", "k8s.io/ingress-nginx"], Some("nginx")));
        assert!(m(&["--providers.kubernetesingress.ingressclass=nginx"], Some("nginx")));
        assert!(!m(&["nginx", "-g", "daemon off;"], Some("nginx")), "a web server named nginx is not a controller");
        assert!(!m(&["--election-id=nginx"], Some("nginx")));
        assert!(m(&["--watch-ingress-without-class=true"], None));
        assert!(m(&["--watch-ingress-without-class"], None));
        assert!(!m(&["--watch-ingress-without-class=false"], None));

        let sel: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector = serde_json::from_value(serde_json::json!({
            "matchLabels": { "app": "nginx" },
            "matchExpressions": [{ "key": "tier", "operator": "In", "values": ["a", "b"] }, { "key": "canary", "operator": "DoesNotExist" }, { "key": "zone", "operator": "Exists" }]
        }))
        .unwrap();
        assert_eq!(k8s::label_selector_query(&sel), "app=nginx,tier in (a,b),!canary,zone");
    }

    #[test]
    fn the_class_in_effect_is_found_or_said_to_be_missing() {
        let classes = Ok(vec![ingress_class("nginx", "k8s.io/ingress-nginx", false), ingress_class("webapprouting.kubernetes.azure.com", "approuting.kubernetes.azure.com/nginx", true)]);
        let named = |c: &str| ingress(serde_json::json!({ "spec": { "ingressClassName": c } }));
        assert_eq!(render_ingress_class(&named("nginx"), &classes), "named class exists: nginx (controller k8s.io/ingress-nginx)");
        assert!(render_ingress_class(&named("traefik"), &classes).starts_with("NAMED CLASS traefik DOES NOT EXIST"));
        // A default existing now does not make it this Ingress's class.
        assert!(render_ingress_class(&ingress(serde_json::json!({})), &classes).starts_with("NO CLASS: it names none"));
        let legacy = |c: &str| ingress(serde_json::json!({ "metadata": { "annotations": { "kubernetes.io/ingress.class": c } } }));
        assert!(render_ingress_class(&legacy("nginx"), &classes).starts_with("named class exists: nginx"));
        // The annotation needs no IngressClass: not a missing class.
        assert!(render_ingress_class(&legacy("internal"), &classes).starts_with("named internal by the legacy kubernetes.io/ingress.class annotation"));
    }

    #[test]
    fn each_backend_is_checked_for_its_service_port_and_endpoints() {
        let ing = ingress(serde_json::json!({ "spec": { "rules": [{ "host": "a.example.com", "http": { "paths": [
            { "path": "/", "pathType": "Prefix", "backend": { "service": { "name": "api", "port": { "name": "http" } } } },
            { "path": "/v2", "pathType": "Prefix", "backend": { "service": { "name": "api", "port": { "number": 8080 } } } },
            { "path": "/gone", "pathType": "Prefix", "backend": { "service": { "name": "gone", "port": { "number": 80 } } } },
            { "path": "/idle", "pathType": "Prefix", "backend": { "service": { "name": "idle", "port": { "number": 80 } } } }
        ] } }] } }));
        let svc = |name: &str| -> k8s_openapi::api::core::v1::Service {
            serde_json::from_value(serde_json::json!({ "metadata": { "name": name }, "spec": { "ports": [{ "name": "http", "port": 80, "targetPort": 8080 }] } })).unwrap()
        };
        let slice = |port: &str, ready: &[bool]| -> k8s_openapi::api::discovery::v1::EndpointSlice {
            serde_json::from_value(serde_json::json!({
                "metadata": { "name": "s" }, "addressType": "IPv4", "ports": [{ "name": port, "port": 8080 }],
                "endpoints": ready.iter().map(|r| serde_json::json!({ "addresses": ["10.0.0.1"], "conditions": { "ready": r } })).collect::<Vec<_>>()
            }))
            .unwrap()
        };
        let backends = vec![
            k8s::IngressBackend { name: "api".into(), service: Ok(svc("api")), slices: Ok(vec![slice("http", &[true, true])]) },
            k8s::IngressBackend { name: "gone".into(), service: Err("Service 'gone' does not exist".into()), slices: Ok(vec![]) },
            k8s::IngressBackend { name: "idle".into(), service: Ok(svc("idle")), slices: Ok(vec![slice("http", &[false, false, false])]) },
        ];
        assert_eq!(
            render_ingress_backends(&ing, &backends),
            "Service api:8080 (ClusterIP): PORT 8080 IS NOT A PORT OF THE SERVICE (it has 80/http); 2 of 2 endpoints ready\n\
             Service api:http (ClusterIP): port exists, → target port 8080; 2 of 2 endpoints ready\n\
             Service gone:80: (Service 'gone' does not exist)\n\
             Service idle:80 (ClusterIP): port exists, → target port 8080; NO READY ENDPOINT (0 of 3)"
        );

        // Endpoints for its metrics port only: the http port resolves on no pod.
        let multi: k8s_openapi::api::core::v1::Service = serde_json::from_value(serde_json::json!({ "metadata": { "name": "api" },
            "spec": { "ports": [{ "name": "http", "port": 80, "targetPort": "web" }, { "name": "metrics", "port": 9090 }] } }))
        .unwrap();
        let only_api = ingress(serde_json::json!({ "spec": { "defaultBackend": { "service": { "name": "api", "port": { "name": "http" } } } } }));
        let backends = vec![k8s::IngressBackend { name: "api".into(), service: Ok(multi), slices: Ok(vec![slice("metrics", &[true, true])]) }];
        assert_eq!(
            render_ingress_backends(&only_api, &backends),
            "Service api:http (ClusterIP): port exists, → target port web; NO ENDPOINT SERVES THIS PORT (2 endpoints serve its other ports — the target port resolves on none of the pods)"
        );
    }

    #[test]
    fn a_tls_secret_is_checked_for_keys_expiry_and_hosts() {
        let ing = ingress(serde_json::json!({ "spec": {
            "tls": [{ "hosts": ["a.example.com", "b.other.com"], "secretName": "web-tls" }, { "hosts": ["c.example.com"], "secretName": "gone" }],
            "rules": [{ "host": "a.example.com" }, { "host": "plain.example.com" }]
        } }));
        let leaf = crate::x509::CertificateInfo {
            subject: "CN=a.example.com".into(),
            issuer: "CN=R3".into(),
            sans: vec!["*.example.com".into()],
            not_after: Some("2026-10-30T00:00:00Z".into()),
            ..Default::default()
        };
        let tls = vec![
            ("web-tls".to_string(), Ok(k8s::IngressTlsSecret { secret_type: "kubernetes.io/tls".into(), keys: vec!["tls.crt".into()], leaf: Some(leaf) })),
            ("gone".to_string(), Err("Secret 'gone' does not exist".to_string())),
        ];
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-02T00:00:00Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(
            render_ingress_tls(&ing, &tls, now),
            "Secret web-tls (kubernetes.io/tls): MISSING KEY tls.key\n  \
             certificate: subject CN=a.example.com, issuer CN=R3\n  \
             EXPIRED on 2026-10-30T00:00:00Z, 3 days ago\n  \
             DOES NOT COVER b.other.com (it names *.example.com)\n\
             Secret gone: (Secret 'gone' does not exist)"
        );
        let hour_ago = chrono::DateTime::parse_from_rfc3339("2026-10-30T01:00:00Z").unwrap().with_timezone(&chrono::Utc);
        assert!(render_ingress_tls(&ing, &tls, hour_ago).contains("EXPIRED on 2026-10-30T00:00:00Z, less than a day ago"), "{}", render_ingress_tls(&ing, &tls, hour_ago));
        assert!(san_covers("*.example.com", "A.example.com"));
        assert!(!san_covers("*.example.com", "a.b.example.com"));
        assert!(!san_covers("*.example.com", "example.com"));
        assert!(render_ingress_spec(&ing).contains("hosts in the rules but in no TLS entry: plain.example.com"));
        assert!(render_ingress_spec(&ing).contains("address: none published"));
    }

    #[test]
    fn another_ingress_on_the_same_host_and_path_is_a_conflict() {
        let typed = |path: &str, kind: &str| serde_json::json!({ "rules": [{ "host": "a.example.com", "http": { "paths": [{ "path": path, "pathType": kind,
            "backend": { "service": { "name": "api", "port": { "number": 80 } } } }] } }], "ingressClassName": "nginx" });
        let rule = |path: &str| serde_json::json!({ "rules": [{ "host": "a.example.com", "http": { "paths": [{ "path": path, "pathType": "Prefix",
            "backend": { "service": { "name": "api", "port": { "number": 80 } } } }] } }], "ingressClassName": "nginx" });
        let me = ingress(serde_json::json!({ "spec": rule("/") }));
        let twin = ingress(serde_json::json!({ "metadata": { "name": "web-old", "namespace": "other" }, "spec": rule("/") }));
        let sibling = ingress(serde_json::json!({ "metadata": { "name": "web-api" }, "spec": rule("/api") }));
        let exact = ingress(serde_json::json!({ "metadata": { "name": "web-exact" }, "spec": typed("/", "Exact") }));
        assert_eq!(
            render_ingress_same_host(&me, &Ok(vec![twin, sibling, exact])),
            "other/web-old (class nginx): a.example.com/ (Prefix) — SAME HOST, PATH AND PATH TYPE AS THIS ONE: a.example.com/ (Prefix)\n\
             ns/web-api (class nginx): a.example.com/api (Prefix)\n\
             ns/web-exact (class nginx): a.example.com/ (Exact)"
        );
    }

    fn pvc(v: serde_json::Value) -> k8s_openapi::api::core::v1::PersistentVolumeClaim {
        let mut base = serde_json::json!({ "metadata": { "name": "data", "namespace": "ns", "uid": "u1" }, "spec": { "accessModes": ["ReadWriteOnce"] } });
        json_merge(&mut base, v);
        serde_json::from_value(base).unwrap()
    }

    fn storage_class(name: &str, default: bool, extra: serde_json::Value) -> k8s_openapi::api::storage::v1::StorageClass {
        let annotations = if default { serde_json::json!({ "storageclass.kubernetes.io/is-default-class": "true" }) } else { serde_json::json!({}) };
        let mut v = serde_json::json!({ "metadata": { "name": name, "annotations": annotations }, "provisioner": "disk.csi.azure.com" });
        json_merge(&mut v, extra);
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn a_claims_class_is_found_or_its_absence_explained() {
        let classes = Ok(vec![
            storage_class("managed-csi", true, serde_json::json!({ "volumeBindingMode": "WaitForFirstConsumer", "allowVolumeExpansion": true, "parameters": { "skuName": "StandardSSD_LRS" } })),
            storage_class("azurefile", false, serde_json::json!({ "provisioner": "file.csi.azure.com" })),
        ]);
        let named = |c: &str| pvc(serde_json::json!({ "spec": { "storageClassName": c } }));
        assert_eq!(
            render_pvc_storage_class(&named("managed-csi"), &classes),
            "managed-csi: provisioner disk.csi.azure.com\nbinding: WaitForFirstConsumer\nreclaim policy: Delete\nvolume expansion: allowed\nparameters: skuName=StandardSSD_LRS"
        );
        assert!(render_pvc_storage_class(&named("azurefile"), &classes).contains("volume expansion: NOT ALLOWED"));
        assert!(render_pvc_storage_class(&named("premium"), &classes).starts_with("CLASS premium DOES NOT EXIST"));
        assert!(render_pvc_storage_class(&named(""), &classes).starts_with("none, by request: it binds only to a pre-created PersistentVolume"));
        assert!(render_pvc_storage_class(&pvc(serde_json::json!({})), &classes).starts_with("NO CLASS SET: there was no default class when it was created, and none has been applied since; default classes now: managed-csi"));
    }

    #[test]
    fn a_single_node_volume_wanted_on_two_nodes_is_called_out() {
        let mounting = |name: &str, node: &str, ready: bool| {
            labelled_pod(name, serde_json::json!({}), ready, serde_json::json!({ "spec": { "nodeName": node, "volumes": [{ "name": "d", "persistentVolumeClaim": { "claimName": "data" } }] } }))
        };
        let pods = vec![mounting("db-0", "n1", true), mounting("db-1", "n2", false)];
        assert!(k8s::pod_mounts_claim(&pods[0], "data"));
        assert!(!k8s::pod_mounts_claim(&pods[0], "other"));
        let ephemeral = labelled_pod("job-x", serde_json::json!({}), true, serde_json::json!({ "spec": { "volumes": [{ "name": "scratch", "ephemeral": {} }] } }));
        assert!(k8s::pod_mounts_claim(&ephemeral, "job-x-scratch"));
        assert_eq!(
            render_pvc_pods(&pvc(serde_json::json!({})), &Ok(pods)),
            "db-0: Running, ready; on n1\ndb-1: Running, NOT READY; on n2\nA SINGLE-NODE VOLUME (ReadWriteOnce) IS MOUNTED BY PODS ON 2 NODES: n1, n2"
        );

        // A finished Job pod on another node holds nothing.
        let done = labelled_pod("job-1", serde_json::json!({}), false, serde_json::json!({
            "spec": { "nodeName": "n2", "volumes": [{ "name": "d", "persistentVolumeClaim": { "claimName": "data" } }] }, "status": { "phase": "Succeeded" }
        }));
        let rwop = pvc(serde_json::json!({ "spec": { "accessModes": ["ReadWriteOncePod"] } }));
        let out = render_pvc_pods(&rwop, &Ok(vec![mounting("db-0", "n1", true), done]));
        assert!(!out.contains("SINGLE-NODE") && !out.contains("only one can"), "{out}");
    }

    #[test]
    fn the_volume_attachment_and_usage_say_where_it_is_and_how_full() {
        let va: k8s_openapi::api::storage::v1::VolumeAttachment = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "csi-1" },
            "spec": { "attacher": "disk.csi.azure.com", "nodeName": "n2", "source": { "persistentVolumeName": "pv-1" } },
            "status": { "attached": false, "attachError": { "message": "disk is attached to another node" } }
        }))
        .unwrap();
        assert_eq!(render_pvc_attachments(&Ok(vec![va]), true), "on n2: NOT ATTACHED\n  attach error: disk is attached to another node");
        assert_eq!(render_pvc_attachments(&Ok(vec![]), false), "(no volume to attach)");
        assert_eq!(render_pvc_attachments(&Ok(vec![]), true), "(no VolumeAttachment objects for it)");

        let summary = serde_json::json!({ "pods": [{ "volume": [
            { "name": "d", "usedBytes": 9_663_676_416u64, "capacityBytes": 10_737_418_240u64, "inodesUsed": 100, "inodes": 1000, "pvcRef": { "name": "data", "namespace": "ns" } },
            { "name": "other", "usedBytes": 1, "capacityBytes": 2, "pvcRef": { "name": "data", "namespace": "other-ns" } }
        ] }] });
        let u = k8s::pvc_usage_from_summary(&summary, "n1", "ns", "data");
        assert_eq!(render_pvc_usage(&[Ok(u)], true), "on n1: 9.0Gi of 10.0Gi used (90%) — NEARLY FULL; inodes 100 of 1000 (10%)");
        assert!(k8s::pvc_usage_from_summary(&summary, "n1", "ns", "gone").is_none());
        assert_eq!(render_pvc_usage(&[], false), "(no running pod mounts it, so the kubelet reports no usage)");
    }

    fn statefulset(v: serde_json::Value) -> k8s_openapi::api::apps::v1::StatefulSet {
        let mut base = serde_json::json!({
            "metadata": { "name": "db", "namespace": "ns", "generation": 3 },
            "spec": {
                "replicas": 3, "serviceName": "db", "selector": { "matchLabels": { "app": "db" } },
                "template": { "metadata": { "labels": { "app": "db" } }, "spec": { "containers": [{ "name": "db" }] } },
                "volumeClaimTemplates": [{ "metadata": { "name": "data" }, "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "managed-csi",
                    "resources": { "requests": { "storage": "20Gi" } } } }]
            },
            "status": { "replicas": 3, "readyReplicas": 3, "currentReplicas": 3, "updatedReplicas": 3, "observedGeneration": 3,
                "currentRevision": "db-old", "updateRevision": "db-old" }
        });
        json_merge(&mut base, v);
        serde_json::from_value(base).unwrap()
    }

    fn sts_pod(ordinal: i32, revision: &str, ready: bool, extra: serde_json::Value) -> k8s_openapi::api::core::v1::Pod {
        let mut p = labelled_pod(&format!("db-{ordinal}"), serde_json::json!({ "app": "db", "controller-revision-hash": revision }), ready, extra);
        p.metadata.owner_references = Some(vec![serde_json::from_value(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "StatefulSet", "name": "db", "uid": "u", "controller": true
        })).unwrap()]);
        p
    }

    #[test]
    fn ordinals_and_selectors_are_read_as_the_controller_does() {
        assert_eq!(k8s::sts_ordinal("db-12", "db"), Some(12));
        assert_eq!(k8s::sts_ordinal("data-db-0", "data-db"), Some(0));
        assert_eq!(k8s::sts_ordinal("db-backup-0", "db"), None);
        assert_eq!(k8s::sts_ordinal("db-", "db"), None);
        let labels: std::collections::BTreeMap<String, String> = [("app".to_string(), "db".to_string()), ("tier".to_string(), "data".to_string())].into();
        let sel = |v: serde_json::Value| -> k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector { serde_json::from_value(v).unwrap() };
        assert!(k8s::label_selector_matches(&sel(serde_json::json!({})), Some(&labels)));
        assert!(k8s::label_selector_matches(&sel(serde_json::json!({ "matchLabels": { "app": "db" },
            "matchExpressions": [{ "key": "tier", "operator": "In", "values": ["data"] }, { "key": "canary", "operator": "DoesNotExist" }] })), Some(&labels)));
        assert!(!k8s::label_selector_matches(&sel(serde_json::json!({ "matchExpressions": [{ "key": "tier", "operator": "NotIn", "values": ["data"] }] })), Some(&labels)));
        assert!(!k8s::label_selector_matches(&sel(serde_json::json!({ "matchLabels": { "app": "web" } })), Some(&labels)));
    }

    #[test]
    fn a_statefulsets_rollout_says_what_governs_it() {
        let healthy = statefulset(serde_json::json!({}));
        assert_eq!(
            render_sts_spec(&healthy),
            "replicas: desired 3, ready 3, current 3, updated 3, available 0\npod management: OrderedReady\nupdate strategy: RollingUpdate\nrevisions: current db-old, update db-old"
        );
        let partitioned = statefulset(serde_json::json!({
            "metadata": { "generation": 4 },
            "spec": { "updateStrategy": { "type": "RollingUpdate", "rollingUpdate": { "partition": 2 } } },
            "status": { "updatedReplicas": 1, "updateRevision": "db-new" }
        }));
        let out = render_sts_spec(&partitioned);
        assert!(out.contains("update strategy: RollingUpdate, partition 2"), "{out}");
        assert!(out.contains("THE CONTROLLER HAS NOT YET ACTED ON THE LATEST SPEC: generation 4, observed 3"), "{out}");
        assert!(out.contains("ROLLOUT PARTITIONED AT 2: only ordinals 2 and above move to the new revision; 1 of 3 are on it"), "{out}");
        let on_delete = statefulset(serde_json::json!({ "spec": { "updateStrategy": { "type": "OnDelete" } }, "status": { "updatedReplicas": 0, "updateRevision": "db-new" } }));
        assert!(render_sts_spec(&on_delete).contains("ON DELETE: a new revision exists"));
    }

    #[test]
    fn the_ordinal_holding_a_statefulset_back_is_named() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-03T10:30:00Z").unwrap().with_timezone(&chrono::Utc);
        let rolling = statefulset(serde_json::json!({ "status": { "readyReplicas": 1, "updatedReplicas": 1, "updateRevision": "db-new" } }));
        let pods = vec![
            sts_pod(0, "db-old", true, serde_json::json!({})),
            sts_pod(2, "db-new", false, serde_json::json!({ "status": { "containerStatuses": [{ "name": "db", "image": "x", "imageID": "", "ready": false,
                "restartCount": 4, "state": { "waiting": { "reason": "CrashLoopBackOff" } } }] } })),
        ];
        assert_eq!(
            render_sts_ordinals(&rolling, &Ok(pods), &[], now),
            "db-0: Running, ready; revision db-old (old); on n1\n\
             db-1: MISSING\n\
             db-2: Running, NOT READY; db waiting: CrashLoopBackOff; revision db-new (new); on n1\n\
             db-2 IS ON THE NEW REVISION AND NOT READY: the rollout waits on it. It may only be starting; if the new template is broken, correct or revert it, then delete this pod if it is still not ready: with OrderedReady the controller does not replace a pod that is not ready\n\
             ORDEREDREADY: the controller creates, updates or removes no other pod while db-1 is not running and ready (2 ordinals in all are not)"
        );

        let stuck = vec![
            sts_pod(0, "db-old", false, serde_json::json!({ "metadata": { "deletionTimestamp": "2026-11-03T10:00:00Z" }, "spec": { "nodeName": "gone" } })),
            sts_pod(1, "db-old", true, serde_json::json!({})),
            sts_pod(2, "db-old", true, serde_json::json!({})),
            sts_pod(3, "db-old", true, serde_json::json!({ "metadata": { "deletionTimestamp": "2026-11-03T10:29:30Z" } })),
        ];
        let out = render_sts_ordinals(&statefulset(serde_json::json!({})), &Ok(stuck), &[("gone".to_string(), Ok(None))], now);
        assert!(out.starts_with("db-0: Running, NOT READY; revision db-old; on gone (NODE NO LONGER EXISTS); TERMINATING since 2026-11-03T10:00:00+00:00 (30 min)"), "{out}");
        assert!(out.contains("db-0 IS STUCK TERMINATING ON A NODE THAT IS GONE"), "{out}");
        assert!(out.contains("db-3: beyond the desired ordinals; Running, ready; revision db-old; on n1; TERMINATING since"), "{out}");
        assert!(out.contains("ORDEREDREADY: the controller creates, updates or removes no other pod while db-0 is not running and ready\n") || out.ends_with("while db-0 is not running and ready"), "{out}");

        // A pod left on a broken revision once the template is reverted (both
        // revisions name the good one) or corrected (a third revision): with
        // OrderedReady it is never replaced, unless the partition holds it.
        let crashing = || sts_pod(2, "db-bad", false, serde_json::json!({}));
        let healthy = || vec![sts_pod(0, "db-old", true, serde_json::json!({})), sts_pod(1, "db-old", true, serde_json::json!({}))];
        let reverted = statefulset(serde_json::json!({}));
        let out = render_sts_ordinals(&reverted, &Ok([healthy(), vec![crashing()]].concat()), &[], now);
        assert!(out.contains("db-2: Running, NOT READY; revision db-bad (NOT THE CURRENT REVISION)"), "{out}");
        assert!(out.contains("db-2 IS NOT READY ON A SUPERSEDED REVISION, db-bad: with OrderedReady the controller does not replace a pod that is not ready"), "{out}");
        let corrected = statefulset(serde_json::json!({ "status": { "updateRevision": "db-fixed" } }));
        let out = render_sts_ordinals(&corrected, &Ok([healthy(), vec![crashing()]].concat()), &[], now);
        assert!(out.contains("revision db-bad (an older revision)") && out.contains("db-2 IS NOT READY ON A SUPERSEDED REVISION, db-bad") && out.contains("recreates it on db-fixed"), "{out}");
        let held = statefulset(serde_json::json!({ "spec": { "updateStrategy": { "type": "RollingUpdate", "rollingUpdate": { "partition": 3 } } },
            "status": { "updateRevision": "db-fixed" } }));
        assert!(!render_sts_ordinals(&held, &Ok([healthy(), vec![crashing()]].concat()), &[], now).contains("SUPERSEDED"));
        let parallel = statefulset(serde_json::json!({ "spec": { "podManagementPolicy": "Parallel" }, "status": { "updateRevision": "db-fixed" } }));
        let out = render_sts_ordinals(&parallel, &Ok([healthy(), vec![crashing()]].concat()), &[], now);
        assert!(!out.contains("ORDEREDREADY") && !out.contains("SUPERSEDED"), "{out}");
        let new_parallel = statefulset(serde_json::json!({ "spec": { "podManagementPolicy": "Parallel" }, "status": { "updateRevision": "db-bad" } }));
        assert!(render_sts_ordinals(&new_parallel, &Ok([healthy(), vec![crashing()]].concat()), &[], now)
            .contains("db-2 IS ON THE NEW REVISION AND NOT READY: the rollout waits on it. It may only be starting; if the new template is broken, correct or revert it, and the controller then replaces this pod"));

        // A scale-down held up by a pod past the desired ordinals that is stuck
        // on a node that is gone, scaled to zero or not.
        let leftover = || vec![sts_pod(0, "db-old", false, serde_json::json!({ "metadata": { "deletionTimestamp": "2026-11-03T10:00:00Z" }, "spec": { "nodeName": "gone" } }))];
        let out = render_sts_ordinals(&statefulset(serde_json::json!({ "spec": { "replicas": 0 } })), &Ok(leftover()), &[("gone".to_string(), Ok(None))], now);
        assert_eq!(
            out,
            "db-0: beyond the desired ordinals; Running, NOT READY; revision db-old; on gone (NODE NO LONGER EXISTS); TERMINATING since 2026-11-03T10:00:00+00:00 (30 min)\n\
             db-0 IS STUCK TERMINATING ON A NODE THAT IS GONE: a StatefulSet never runs two pods with one identity, so it does not recreate db-0 until the pod object is gone"
        );
        let waiting = render_sts_ordinals(&statefulset(serde_json::json!({ "spec": { "replicas": 0 } })), &Ok(vec![sts_pod(0, "db-old", true, serde_json::json!({}))]), &[], now);
        assert_eq!(waiting, "db-0: beyond the desired ordinals, waiting to be removed; Running, ready; revision db-old; on n1");
        let zero = statefulset(serde_json::json!({ "spec": { "replicas": 0 } }));
        assert_eq!(render_sts_ordinals(&zero, &Ok(vec![]), &[], now), "(scaled to zero: no ordinal is wanted and no pod remains)");
    }

    #[test]
    fn each_ordinals_claim_is_checked_against_its_template() {
        let sts = statefulset(serde_json::json!({}));
        let claim = |name: &str, phase: &str, size: &str, class: &str| -> k8s_openapi::api::core::v1::PersistentVolumeClaim {
            pvc(serde_json::json!({ "metadata": { "name": name }, "spec": { "storageClassName": class, "resources": { "requests": { "storage": size } } },
                "status": { "phase": phase, "capacity": { "storage": size } } }))
        };
        let claims = vec![
            claim("data-db-0", "Bound", "10Gi", "managed-csi"),
            claim("data-db-1", "Pending", "20Gi", "premium"),
            claim("data-db-5", "Bound", "20Gi", "managed-csi"),
        ];
        let pods = Ok(vec![sts_pod(0, "db-old", true, serde_json::json!({})), sts_pod(2, "db-old", false, serde_json::json!({}))]);
        assert_eq!(
            render_sts_claims(&sts, &Ok(claims), &pods),
            "template data: requests 20Gi, class managed-csi, access modes ReadWriteOnce\n  \
             data-db-0: Bound, capacity 10Gi; REQUESTS 10Gi, LESS THAN THE TEMPLATE'S 20Gi: template changes do not resize existing claims\n  \
             data-db-1: PENDING, capacity 20Gi; CLASS premium, NOT THE TEMPLATE'S managed-csi\n  \
             data-db-2: MISSING, though its pod exists\n  \
             and 1 for ordinals beyond the desired ones, kept from a scale-down and reused if it scales back up"
        );
        let none = statefulset(serde_json::json!({ "spec": { "volumeClaimTemplates": null } }));
        assert!(render_sts_claims(&none, &Ok(vec![]), &Ok(vec![])).starts_with("(no volumeClaimTemplates"));
    }

    #[test]
    fn the_governing_service_and_budgets_are_checked() {
        let sts = statefulset(serde_json::json!({}));
        let pods = Ok(vec![sts_pod(0, "db-old", true, serde_json::json!({})), sts_pod(1, "db-old", true, serde_json::json!({}))]);
        assert!(render_sts_service(&sts, &Some(Ok(None)), &pods).starts_with("GOVERNING SERVICE db DOES NOT EXIST"));
        let svc = |v: serde_json::Value| -> k8s_openapi::api::core::v1::Service { serde_json::from_value(serde_json::json!({ "metadata": { "name": "db" }, "spec": v })).unwrap() };
        assert_eq!(
            render_sts_service(&sts, &Some(Ok(Some(svc(serde_json::json!({ "clusterIP": "None", "selector": { "app": "db" }, "publishNotReadyAddresses": true }))))), &pods),
            "db: headless\nits selector matches all 2 pods\npublishNotReadyAddresses: true"
        );
        let out = render_sts_service(&sts, &Some(Ok(Some(svc(serde_json::json!({ "clusterIP": "10.0.0.5", "selector": { "app": "postgres" } }))))), &pods);
        assert!(out.contains("NOT HEADLESS (clusterIP 10.0.0.5)") && out.contains("ITS SELECTOR DOES NOT SELECT THE PODS: app=postgres"), "{out}");
        // A label the controller adds is on the pods, not the template.
        let mut named = pods.clone().unwrap();
        named[0].metadata.labels.as_mut().unwrap().insert("statefulset.kubernetes.io/pod-name".into(), "db-0".into());
        let by_name = svc(serde_json::json!({ "clusterIP": "None", "selector": { "statefulset.kubernetes.io/pod-name": "db-0" } }));
        assert!(render_sts_service(&sts, &Some(Ok(Some(by_name.clone()))), &Ok(named)).contains("ITS SELECTOR MISSES db-1: statefulset.kubernetes.io/pod-name=db-0"));
        assert!(render_sts_service(&sts, &Some(Ok(Some(by_name))), &Err("boom".into())).contains("not checked against the pods (pods unavailable: boom)"));
        let manual = render_sts_service(&sts, &Some(Ok(Some(svc(serde_json::json!({ "clusterIP": "None" }))))), &pods);
        assert!(manual.contains("no selector: its endpoints are managed by hand") && !manual.contains("SELECTOR"), "{manual}");

        let pdb = |name: &str, healthy: i32, allowed: i32, policy: Option<&str>| -> k8s_openapi::api::policy::v1::PodDisruptionBudget {
            serde_json::from_value(serde_json::json!({ "metadata": { "name": name },
                "spec": { "minAvailable": 3, "selector": { "matchLabels": { "app": "db" } }, "unhealthyPodEvictionPolicy": policy },
                "status": { "currentHealthy": healthy, "desiredHealthy": 3, "expectedPods": 3, "disruptionsAllowed": allowed } })).unwrap()
        };
        let all = || Some(vec!["db-0".to_string(), "db-1".to_string(), "db-2".to_string()]);
        assert_eq!(render_pdbs(&Ok(vec![])), "(no PodDisruptionBudget covers its pods)");
        assert_eq!(
            render_pdbs(&Ok(vec![(pdb("db", 3, 0, None), all()), (pdb("db-extra", 3, 1, None), Some(vec!["db-2".to_string()]))])),
            "db: minAvailable 3; covers db-0, db-1, db-2; healthy 3 of 3 expected, 3 needed; disruptions allowed 0 — NO HEALTHY POD MAY BE EVICTED: a drain waits on any node running one of its ready pods; the budget is met, so a running pod that is not ready can still be evicted (unhealthyPodEvictionPolicy IfHealthyBudget, the default)\n\
             db-extra: minAvailable 3; covers db-2; healthy 3 of 3 expected, 3 needed; disruptions allowed 1\n\
             MORE THAN ONE BUDGET COVERS db-2: the eviction API refuses to evict a pod covered by more than one"
        );
        assert!(render_pdbs(&Ok(vec![(pdb("db", 2, 0, Some("IfHealthyBudget")), all())]))
            .ends_with("the budget is not met, so a running pod that is not ready cannot be evicted either (unhealthyPodEvictionPolicy IfHealthyBudget)"));
        assert!(render_pdbs(&Ok(vec![(pdb("db", 2, 0, Some("AlwaysAllow")), all())])).ends_with("a running pod that is not ready can still be evicted (unhealthyPodEvictionPolicy AlwaysAllow)"));
        // Budgets over different ordinals do not overlap.
        let split = render_pdbs(&Ok(vec![(pdb("a", 3, 1, None), Some(vec!["db-0".to_string()])), (pdb("b", 3, 1, None), Some(vec!["db-1".to_string()]))]));
        assert!(!split.contains("MORE THAN ONE"), "{split}");
        assert!(render_pdbs(&Ok(vec![(pdb("a", 3, 1, None), None), (pdb("b", 3, 1, None), None)]))
            .contains("covers the pod template (no pod to check)"));
    }

    fn daemonset(v: serde_json::Value) -> k8s_openapi::api::apps::v1::DaemonSet {
        let mut base = serde_json::json!({
            "metadata": { "name": "agent", "namespace": "ns", "generation": 2 },
            "spec": {
                "selector": { "matchLabels": { "app": "agent" } },
                "template": { "metadata": { "labels": { "app": "agent" } },
                    "spec": { "containers": [{ "name": "agent" }], "nodeSelector": { "kubernetes.io/os": "linux" } } },
                "updateStrategy": { "type": "RollingUpdate", "rollingUpdate": { "maxUnavailable": 1, "maxSurge": 0 } }
            },
            "status": { "desiredNumberScheduled": 3, "currentNumberScheduled": 3, "numberReady": 3, "numberAvailable": 3,
                "updatedNumberScheduled": 3, "numberMisscheduled": 0, "observedGeneration": 2 }
        });
        json_merge(&mut base, v);
        serde_json::from_value(base).unwrap()
    }

    fn ds_node(name: &str, os: &str, ready: bool, taints: serde_json::Value) -> k8s_openapi::api::core::v1::Node {
        serde_json::from_value(serde_json::json!({
            "metadata": { "name": name, "labels": { "kubernetes.io/os": os, "agentpool": "sys", "cores": "8" } },
            "spec": { "taints": taints },
            "status": { "conditions": [{ "type": "Ready", "status": if ready { "True" } else { "False" } }] }
        }))
        .unwrap()
    }

    fn ds_pod(node: &str, revision: &str, ready: bool, extra: serde_json::Value) -> k8s_openapi::api::core::v1::Pod {
        let mut p = labelled_pod(&format!("agent-{node}"), serde_json::json!({ "app": "agent", "controller-revision-hash": revision }), ready, extra);
        if p.spec.as_ref().and_then(|s| s.node_name.as_deref()) == Some("n1") {
            p.spec.as_mut().unwrap().node_name = Some(node.to_string());
        }
        p
    }

    #[test]
    fn which_nodes_should_run_a_daemon_pod_is_read_as_the_controller_does() {
        let toleration = |v: serde_json::Value| -> k8s_openapi::api::core::v1::Toleration { serde_json::from_value(v).unwrap() };
        let taint = |v: serde_json::Value| -> k8s_openapi::api::core::v1::Taint { serde_json::from_value(v).unwrap() };
        let gpu = taint(serde_json::json!({ "key": "sku", "value": "gpu", "effect": "NoSchedule" }));
        assert!(k8s::tolerates(&toleration(serde_json::json!({ "operator": "Exists" })), &gpu));
        assert!(k8s::tolerates(&toleration(serde_json::json!({ "key": "sku", "operator": "Exists", "effect": "NoSchedule" })), &gpu));
        assert!(k8s::tolerates(&toleration(serde_json::json!({ "key": "sku", "value": "gpu" })), &gpu));
        assert!(!k8s::tolerates(&toleration(serde_json::json!({ "key": "sku", "value": "cpu" })), &gpu));
        assert!(!k8s::tolerates(&toleration(serde_json::json!({ "key": "sku", "operator": "Exists", "effect": "NoExecute" })), &gpu));

        let term = |v: serde_json::Value| -> k8s_openapi::api::core::v1::NodeSelectorTerm { serde_json::from_value(v).unwrap() };
        let n = ds_node("n1", "linux", true, serde_json::json!([]));
        assert!(k8s::node_term_matches(&term(serde_json::json!({ "matchExpressions": [{ "key": "cores", "operator": "Gt", "values": ["4"] }] })), &n));
        assert!(!k8s::node_term_matches(&term(serde_json::json!({ "matchExpressions": [{ "key": "cores", "operator": "Lt", "values": ["4"] }] })), &n));
        assert!(k8s::node_term_matches(&term(serde_json::json!({ "matchFields": [{ "key": "metadata.name", "operator": "In", "values": ["n1"] }] })), &n));
        assert!(!k8s::node_term_matches(&term(serde_json::json!({})), &n));

        let spec = |v: serde_json::Value| -> k8s_openapi::api::core::v1::PodSpec {
            let mut base = serde_json::json!({ "containers": [{ "name": "agent" }], "nodeSelector": { "kubernetes.io/os": "linux" } });
            json_merge(&mut base, v);
            serde_json::from_value(base).unwrap()
        };
        let plain = spec(serde_json::json!({}));
        assert_eq!(k8s::daemon_pod_misfit(&plain, &n, true), None);
        assert_eq!(k8s::daemon_pod_misfit(&plain, &ds_node("w1", "windows", true, serde_json::json!([])), true).as_deref(), Some("nodeSelector kubernetes.io/os=linux not matched"));
        let affine = spec(serde_json::json!({ "affinity": { "nodeAffinity": { "requiredDuringSchedulingIgnoredDuringExecution": {
            "nodeSelectorTerms": [{ "matchExpressions": [{ "key": "agentpool", "operator": "In", "values": ["user"] }] }] } } } }));
        assert_eq!(k8s::daemon_pod_misfit(&affine, &n, false).as_deref(), Some("required node affinity not matched"));
        // NoSchedule keeps a new pod off but not a running one; NoExecute both.
        let tainted = ds_node("n2", "linux", true, serde_json::json!([{ "key": "sku", "value": "gpu", "effect": "NoSchedule" }]));
        assert_eq!(k8s::daemon_pod_misfit(&plain, &tainted, true).as_deref(), Some("taint sku=gpu:NoSchedule not tolerated"));
        assert_eq!(k8s::daemon_pod_misfit(&plain, &tainted, false), None);
        let evicting = ds_node("n3", "linux", true, serde_json::json!([{ "key": "dedicated", "effect": "NoExecute" }]));
        assert_eq!(k8s::daemon_pod_misfit(&plain, &evicting, false).as_deref(), Some("taint dedicated:NoExecute not tolerated"));
        // The tolerations the controller adds: a cordoned or NotReady node
        // still gets its pod; one without networking only a hostNetwork pod.
        let down = ds_node("n4", "linux", false, serde_json::json!([
            { "key": "node.kubernetes.io/not-ready", "effect": "NoExecute" }, { "key": "node.kubernetes.io/unschedulable", "effect": "NoSchedule" }]));
        assert_eq!(k8s::daemon_pod_misfit(&plain, &down, true), None);
        let no_net = ds_node("n5", "linux", true, serde_json::json!([{ "key": "node.kubernetes.io/network-unavailable", "effect": "NoSchedule" }]));
        assert!(k8s::daemon_pod_misfit(&plain, &no_net, true).is_some());
        assert_eq!(k8s::daemon_pod_misfit(&spec(serde_json::json!({ "hostNetwork": true })), &no_net, true), None);

        let pending = ds_pod("n7", "h", false, serde_json::json!({ "spec": { "nodeName": null, "affinity": { "nodeAffinity": { "requiredDuringSchedulingIgnoredDuringExecution": {
            "nodeSelectorTerms": [{ "matchFields": [{ "key": "metadata.name", "operator": "In", "values": ["n7"] }] }] } } } } }));
        assert_eq!(k8s::daemon_pod_node(&pending).as_deref(), Some("n7"));
        assert_eq!(k8s::daemon_pod_node(&ds_pod("n1", "h", true, serde_json::json!({}))).as_deref(), Some("n1"));
    }

    #[test]
    fn a_daemonsets_rollout_says_what_governs_it() {
        assert_eq!(
            render_ds_spec(&daemonset(serde_json::json!({})), &Ok(Some("h1".into()))),
            "nodes: desired 3, scheduled 3, ready 3, available 3, up to date 3, misscheduled 0\nupdate strategy: RollingUpdate, maxUnavailable 1, maxSurge 0\nlatest revision: h1"
        );
        let rolling = daemonset(serde_json::json!({ "metadata": { "generation": 3 }, "status": { "updatedNumberScheduled": 1 } }));
        let out = render_ds_spec(&rolling, &Err("boom".into()));
        assert!(out.contains("latest revision: (revisions unavailable: boom)"), "{out}");
        assert!(out.contains("THE CONTROLLER HAS NOT YET ACTED ON THE LATEST SPEC: generation 3, observed 2"), "{out}");
        assert!(out.ends_with("ROLLOUT IN PROGRESS: 1 of 3 nodes run the latest template; it replaces old pods maxUnavailable 1, maxSurge 0 at a time"), "{out}");
        let on_delete = daemonset(serde_json::json!({ "spec": { "updateStrategy": { "type": "OnDelete", "rollingUpdate": null } }, "status": { "updatedNumberScheduled": 2 } }));
        let out = render_ds_spec(&on_delete, &Ok(None));
        assert!(out.contains("update strategy: OnDelete\n") && out.ends_with("ON DELETE: 2 of 3 nodes run the latest template, and a pod moves to it only when deleted"), "{out}");
    }

    #[test]
    fn the_nodes_a_daemonset_misses_are_named() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-03T10:30:00Z").unwrap().with_timezone(&chrono::Utc);
        let ds = daemonset(serde_json::json!({ "status": { "numberUnavailable": 2 } }));
        let nodes = vec![
            ds_node("n1", "linux", true, serde_json::json!([])),
            ds_node("n2", "linux", true, serde_json::json!([{ "key": "sku", "value": "gpu", "effect": "NoSchedule" }])),
            ds_node("n3", "linux", false, serde_json::json!([])),
            ds_node("n4", "windows", true, serde_json::json!([])),
            ds_node("n5", "linux", true, serde_json::json!([{ "key": "sku", "value": "gpu", "effect": "NoSchedule" }])),
            ds_node("n6", "linux", true, serde_json::json!([{ "key": "dedicated", "effect": "NoExecute" }])),
            ds_node("n7", "linux", true, serde_json::json!([])),
        ];
        let pods = vec![
            ds_pod("n1", "h1", true, serde_json::json!({})),
            ds_pod("n5", "h2", true, serde_json::json!({})),
            ds_pod("n6", "h2", true, serde_json::json!({})),
            ds_pod("n7", "h2", false, serde_json::json!({ "spec": { "nodeName": null, "affinity": { "nodeAffinity": { "requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": [{ "matchFields": [{ "key": "metadata.name", "operator": "In", "values": ["n7"] }] }] } } } },
                "status": { "phase": "Pending", "conditions": [{ "type": "PodScheduled", "status": "False",
                    "message": "0/7 nodes are available: 1 Insufficient cpu, 6 node(s) didn't match Pod's node affinity/selector." }] } })),
            ds_pod("gone", "h1", false, serde_json::json!({ "metadata": { "deletionTimestamp": "2026-11-03T10:00:00Z" } })),
        ];
        let out = render_ds_nodes(&ds, &Ok(pods), &Ok(nodes), &Ok(Some("h2".into())), now);
        assert_eq!(
            out,
            "7 nodes: 3 should run its pod, by its nodeSelector, required node affinity and tolerations (with those every DaemonSet pod gets); 4 should not\n  \
             1 left out: nodeSelector kubernetes.io/os=linux not matched\n  \
             1 left out: taint sku=gpu:NoSchedule not tolerated\n  \
             1 more runs a pod it would not get now, under a NoSchedule taint it does not tolerate: a running pod is kept through one\n\
             2 of its 5 pods are not ready or are terminating:\n  \
             agent-gone on gone (NODE NO LONGER EXISTS): Running, NOT READY; revision h1 (OLDER); TERMINATING since 2026-11-03T10:00:00+00:00 (30 min)\n  \
             agent-n7 for n7: Pending, NOT READY; revision h2 (latest); UNSCHEDULABLE: 0/7 nodes are available: 1 Insufficient cpu, 6 node(s) didn't match Pod's node affinity/selector.\n\
             NO POD ON 1 NODE THAT SHOULD RUN ONE: n3 (node NOT READY); the controller creates one per node, and when it has not, its events say why\n\
             MISSCHEDULED, AND DELETED BY THE CONTROLLER: agent-n6 on n6: taint dedicated:NoExecute not tolerated\n\
             agent-gone IS STUCK TERMINATING ON A NODE THAT IS GONE: the kubelet there cannot confirm it stopped\n\
             1 POD CANNOT FIT ON ITS NODE: a DaemonSet pod runs only on its own node, so it waits for room there; at priority 0 (no priorityClassName) it can preempt only pods of lower priority, which few are; a class such as system-node-critical is what lets it make room\n\
             ROLLOUT: 1 POD OF THE LATEST REVISION IS NOT READY (agent-n7), with 1 still on older revisions; 2 nodes have no available pod, which uses up maxUnavailable 1, so no more old pods are replaced until one becomes available. They may only be starting; if the new template is broken, correct or revert it, and the controller then replaces them"
        );

        let healthy = render_ds_nodes(&ds, &Ok(vec![ds_pod("n1", "h2", true, serde_json::json!({}))]), &Ok(vec![ds_node("n1", "linux", true, serde_json::json!([]))]), &Ok(Some("h2".into())), now);
        assert_eq!(healthy, "1 node: 1 should run its pod, by its nodeSelector, required node affinity and tolerations (with those every DaemonSet pod gets); 0 should not\nall 1 of its pods are ready");
        let blind = render_ds_nodes(&ds, &Ok(vec![]), &Err("forbidden".into()), &Ok(None), now);
        assert_eq!(blind, "(nodes unavailable: forbidden; which nodes should run its pod was not worked out)\n(it has no pods)");
        let on_delete = daemonset(serde_json::json!({ "spec": { "updateStrategy": { "type": "OnDelete", "rollingUpdate": null } } }));
        let stalled = vec![ds_pod("n1", "h1", true, serde_json::json!({})), ds_pod("n7", "h2", false, serde_json::json!({}))];
        assert!(!render_ds_nodes(&on_delete, &Ok(stalled.clone()), &Ok(vec![]), &Ok(Some("h2".into())), now).contains("ROLLOUT"));
        // Under the budget the rollout carries on; a percentage is of desired,
        // rounded up; with a surge no verdict is given.
        let budget = |v: serde_json::Value| render_ds_nodes(&daemonset(v), &Ok(stalled.clone()), &Ok(vec![]), &Ok(Some("h2".into())), now);
        let out = budget(serde_json::json!({ "spec": { "updateStrategy": { "rollingUpdate": { "maxUnavailable": "50%" } } }, "status": { "numberUnavailable": 1 } }));
        assert!(out.contains("1 nodes have no available pod, under maxUnavailable 2, so replacements can continue"), "{out}");
        let out = budget(serde_json::json!({ "spec": { "updateStrategy": { "rollingUpdate": { "maxUnavailable": 0, "maxSurge": 1 } } }, "status": { "numberUnavailable": 1 } }));
        assert!(out.contains("it surges up to 1 new pods alongside old ones"), "{out}");

        // Preemption is read from the pod as admitted; stuck pods are named
        // up to the cap and counted beyond it.
        let starved = |spec: serde_json::Value| {
            let mut extra = serde_json::json!({ "spec": { "nodeName": null }, "status": { "phase": "Pending", "conditions": [{ "type": "PodScheduled", "status": "False", "message": "0/1 nodes are available: 1 Insufficient memory." }] } });
            json_merge(&mut extra, serde_json::json!({ "spec": spec }));
            render_ds_nodes(&ds, &Ok(vec![ds_pod("n1", "h2", false, extra)]), &Ok(vec![]), &Ok(Some("h2".into())), now)
        };
        assert!(starved(serde_json::json!({ "priority": 2000001000, "priorityClassName": "system-node-critical" }))
            .contains("at priority 2000001000 (class system-node-critical) it can preempt pods of lower priority on that node"));
        assert!(starved(serde_json::json!({ "priority": 1000, "preemptionPolicy": "Never" })).contains("its preemptionPolicy is Never (no priorityClassName), so it preempts nothing"));
        let outage: Vec<_> = (0..25).map(|i| ds_pod(&format!("x{i:02}"), "h2", false, serde_json::json!({ "metadata": { "deletionTimestamp": "2026-11-03T10:00:00Z" } }))).collect();
        let out = render_ds_nodes(&ds, &Ok(outage), &Ok(vec![ds_node("n1", "linux", true, serde_json::json!([]))]), &Ok(Some("h2".into())), now);
        assert!(out.ends_with("25 PODS ARE STUCK TERMINATING ON NODES THAT ARE NOT READY OR GONE: agent-x00 (GONE), agent-x01 (GONE), agent-x02 (GONE), agent-x03 (GONE), agent-x04 (GONE), agent-x05 (GONE), agent-x06 (GONE), agent-x07 (GONE), agent-x08 (GONE), agent-x09 (GONE) and 15 more; the kubelets there cannot confirm they stopped"), "{out}");
        assert_eq!(out.matches("STUCK").count(), 1);
    }

    fn deployment(v: serde_json::Value) -> k8s_openapi::api::apps::v1::Deployment {
        let mut base = serde_json::json!({
            "metadata": { "name": "web", "namespace": "ns", "generation": 4, "uid": "d-uid" },
            "spec": {
                "replicas": 3, "selector": { "matchLabels": { "app": "web" } },
                "template": { "metadata": { "labels": { "app": "web" } }, "spec": { "containers": [{ "name": "web", "image": "web:2" }] } },
                "strategy": { "type": "RollingUpdate", "rollingUpdate": { "maxSurge": "25%", "maxUnavailable": "25%" } }
            },
            "status": { "replicas": 3, "updatedReplicas": 3, "readyReplicas": 3, "availableReplicas": 3, "observedGeneration": 4,
                "conditions": [{ "type": "Available", "status": "True", "reason": "MinimumReplicasAvailable" },
                    { "type": "Progressing", "status": "True", "reason": "NewReplicaSetAvailable" }] }
        });
        json_merge(&mut base, v);
        serde_json::from_value(base).unwrap()
    }

    fn replica_set(revision: i64, replicas: i32, ready: i32, extra: serde_json::Value) -> k8s_openapi::api::apps::v1::ReplicaSet {
        let mut base = serde_json::json!({
            "metadata": { "name": format!("web-r{revision}"), "uid": format!("rs-{revision}"), "annotations": { "deployment.kubernetes.io/revision": revision.to_string() } },
            "spec": { "replicas": replicas, "selector": { "matchLabels": { "app": "web" } },
                "template": { "spec": { "containers": [{ "name": "web", "image": format!("web:{revision}") }] } } },
            "status": { "replicas": replicas, "readyReplicas": ready, "availableReplicas": ready }
        });
        json_merge(&mut base, extra);
        serde_json::from_value(base).unwrap()
    }

    fn rs_pod(revision: i64, n: usize, ready: bool) -> k8s_openapi::api::core::v1::Pod {
        let mut p = labelled_pod(&format!("web-r{revision}-{n}"), serde_json::json!({ "app": "web" }), ready, serde_json::json!({}));
        p.metadata.owner_references = Some(vec![serde_json::from_value(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": format!("web-r{revision}"), "uid": format!("rs-{revision}"), "controller": true
        })).unwrap()]);
        p
    }

    #[test]
    fn a_deployments_conditions_say_where_its_rollout_stands() {
        assert_eq!(
            render_deploy_spec(&deployment(serde_json::json!({}))),
            "replicas: desired 3, updated 3, ready 3, available 3, unavailable 0\n\
             strategy: RollingUpdate, maxSurge 25%, maxUnavailable 25%\n\
             progressDeadlineSeconds: 600\n\
             condition Available=True (MinimumReplicasAvailable)\n\
             condition Progressing=True (NewReplicaSetAvailable)"
        );
        let failed = deployment(serde_json::json!({
            "metadata": { "generation": 5 },
            "spec": { "paused": true, "progressDeadlineSeconds": 120 },
            "status": { "conditions": [
                { "type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded", "message": "ReplicaSet \"web-r7\" has timed out progressing." },
                { "type": "ReplicaFailure", "status": "True", "reason": "FailedCreate", "message": "pods \"web-r7-x\" is forbidden: exceeded quota: compute" }] }
        }));
        let out = render_deploy_spec(&failed);
        assert!(out.contains("PAUSED: changes to its template do not roll out until it is resumed"), "{out}");
        assert!(out.contains("THE CONTROLLER HAS NOT YET ACTED ON THE LATEST SPEC: generation 5, observed 4"), "{out}");
        assert!(out.contains("ROLLOUT EXCEEDED ITS PROGRESS DEADLINE: it has not progressed for 120s"), "{out}");
        assert!(out.ends_with("REPLICA FAILURE: pods are not being created: pods \"web-r7-x\" is forbidden: exceeded quota: compute"), "{out}");
        let not_deleting = deployment(serde_json::json!({ "status": { "conditions": [
            { "type": "ReplicaFailure", "status": "True", "reason": "FailedDelete", "message": "denied" }] } }));
        assert!(render_deploy_spec(&not_deleting).ends_with("REPLICA FAILURE: pods are not being deleted: denied"));
        let recreate = deployment(serde_json::json!({ "spec": { "strategy": { "type": "Recreate", "rollingUpdate": null } } }));
        assert!(render_deploy_spec(&recreate).contains("strategy: Recreate\n"));
    }

    #[test]
    fn a_deployments_replicasets_show_how_far_it_has_rolled() {
        let dep = deployment(serde_json::json!({}));
        let rss = vec![
            replica_set(7, 2, 0, serde_json::json!({ "status": { "conditions": [{ "type": "ReplicaFailure", "status": "True", "reason": "FailedCreate",
                "message": "admission webhook denied the request" }] } })),
            replica_set(6, 2, 2, serde_json::json!({})),
            replica_set(5, 0, 0, serde_json::json!({})),
            replica_set(4, 0, 0, serde_json::json!({})),
        ];
        let pods = vec![rs_pod(7, 0, false), rs_pod(6, 0, true), rs_pod(6, 1, true)];
        assert_eq!(
            render_deploy_replicasets(&dep, &Ok(rss), &Ok(pods)),
            "web-r7: revision 7 (newest); replicas 2, ready 0, available 0; pods 0 ready of 1; images web:7; REPLICA FAILURE (FailedCreate): admission webhook denied the request\n\
             web-r6: revision 6; replicas 2, ready 2, available 2; pods 2 ready of 2; images web:6\n\
             and 2 older ReplicaSets scaled to zero, kept as rollback history\n\
             THE NEWEST REPLICASET CANNOT CREATE PODS: admission webhook denied the request\n\
             ROLLOUT IN PROGRESS: the newest ReplicaSet has 0 of 3 ready, and older ones still run 2 pods; the controller scales them down only as new pods become available. 1 of the new pods is not ready: they may only be starting; if the new template is broken, a rollback or a corrected template replaces them"
        );
        // Settled: one ReplicaSet holds every pod.
        let settled = render_deploy_replicasets(&dep, &Ok(vec![replica_set(7, 3, 3, serde_json::json!({})), replica_set(6, 0, 0, serde_json::json!({}))]),
            &Ok(vec![rs_pod(7, 0, true), rs_pod(7, 1, true), rs_pod(7, 2, true)]));
        assert_eq!(settled, "web-r7: revision 7 (newest); replicas 3, ready 3, available 3; pods 3 ready of 3; images web:7\nand 1 older ReplicaSet scaled to zero, kept as rollback history");
        let recreate = deployment(serde_json::json!({ "spec": { "strategy": { "type": "Recreate", "rollingUpdate": null } } }));
        assert!(render_deploy_replicasets(&recreate, &Ok(vec![replica_set(7, 3, 0, serde_json::json!({}))]), &Ok(vec![rs_pod(7, 0, false)]))
            .ends_with("RECREATE: no older pod remains, so while 1 of the new pods is not ready nothing else serves in their place"));
        let tearing_down = render_deploy_replicasets(&recreate, &Ok(vec![replica_set(7, 0, 0, serde_json::json!({})), replica_set(6, 0, 0, serde_json::json!({ "status": { "replicas": 2 } }))]), &Ok(vec![]));
        assert!(tearing_down.ends_with("RECREATE ROLLOUT IN PROGRESS: older ReplicaSets still run 2 pods; Recreate stops every old pod before it starts any new one, so the new ReplicaSet waits until they are gone"), "{tearing_down}");

        // A scale-down that cannot delete is not a failure to create; an old
        // ReplicaSet at zero still owning a terminating pod stays shown.
        let deleting = render_deploy_replicasets(&dep, &Ok(vec![replica_set(7, 1, 1, serde_json::json!({ "status": { "conditions": [{ "type": "ReplicaFailure", "status": "True",
            "reason": "FailedDelete", "message": "pods \"web-r7-0\" is forbidden" }] } })), replica_set(6, 0, 0, serde_json::json!({}))]), &Ok(vec![rs_pod(7, 0, true), rs_pod(6, 0, false)]));
        assert!(deleting.contains("REPLICA FAILURE (FailedDelete)") && !deleting.contains("CANNOT CREATE"), "{deleting}");
        assert!(deleting.contains("web-r6: revision 6; replicas 0, ready 0, available 0; pods 0 ready of 1") && !deleting.contains("rollback history"), "{deleting}");
        assert_eq!(render_deploy_replicasets(&dep, &Ok(vec![]), &Ok(vec![])), "(it has no ReplicaSet: the controller has not created one)");
        let blind = render_deploy_replicasets(&dep, &Ok(vec![replica_set(7, 3, 3, serde_json::json!({}))]), &Err("forbidden".into()));
        assert_eq!(blind, "web-r7: revision 7 (newest); replicas 3, ready 3, available 3; images web:7\n(pods unavailable: forbidden)");
    }

    #[test]
    fn the_autoscalers_on_a_deployment_are_named() {
        let hpa = |name: &str, extra: serde_json::Value| -> k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler {
            let mut base = serde_json::json!({ "metadata": { "name": name },
                "spec": { "minReplicas": 2, "maxReplicas": 10, "scaleTargetRef": { "apiVersion": "apps/v1", "kind": "Deployment", "name": "web" } },
                "status": { "currentReplicas": 10, "desiredReplicas": 10 } });
            json_merge(&mut base, extra);
            serde_json::from_value(base).unwrap()
        };
        assert_eq!(render_deploy_hpas(&Ok(vec![])), "(no HorizontalPodAutoscaler targets it: its replicas are set by hand)");
        let limited = hpa("web", serde_json::json!({ "status": { "conditions": [
            { "type": "AbleToScale", "status": "True", "reason": "ReadyForNewScale" },
            { "type": "ScalingLimited", "status": "True", "reason": "TooManyReplicas", "message": "the desired replica count is more than the maximum replica count" }] } }));
        assert_eq!(
            render_deploy_hpas(&Ok(vec![limited])),
            "web: min 2, max 10, current 10, desired 10; ScalingLimited=True (TooManyReplicas): the desired replica count is more than the maximum replica count\n\
             the HPA sets its replicas, so a change to spec.replicas is overwritten"
        );
        let keda = hpa("keda-hpa-web", serde_json::json!({ "metadata": { "ownerReferences": [{ "apiVersion": "keda.sh/v1alpha1", "kind": "ScaledObject", "name": "web", "uid": "u" }] } }));
        let out = render_deploy_hpas(&Ok(vec![hpa("web", serde_json::json!({})), keda]));
        assert!(out.contains("keda-hpa-web (made by KEDA ScaledObject web): min 2") && out.ends_with("MORE THAN ONE HPA TARGETS IT: each overwrites the replica count the other sets"), "{out}");
    }

    fn budget(v: serde_json::Value) -> k8s_openapi::api::policy::v1::PodDisruptionBudget {
        let mut base = serde_json::json!({
            "metadata": { "name": "web", "namespace": "ns", "generation": 2 },
            "spec": { "minAvailable": 1, "selector": { "matchLabels": { "app": "web" } } },
            "status": { "currentHealthy": 1, "desiredHealthy": 1, "expectedPods": 1, "disruptionsAllowed": 0, "observedGeneration": 2,
                "conditions": [{ "type": "DisruptionAllowed", "status": "False", "reason": "InsufficientPods", "message": "", "lastTransitionTime": "2026-11-09T10:00:00Z" }] }
        });
        json_merge(&mut base, v);
        serde_json::from_value(base).unwrap()
    }

    fn owner(kind: &str, name: &str, desired: Option<i32>, pods: usize) -> k8s::PdbOwner {
        k8s::PdbOwner { kind: kind.into(), name: name.into(), desired: Ok(desired), pods }
    }

    #[test]
    fn a_budget_says_whether_a_drain_can_get_past_it() {
        let pods = || Ok(vec![labelled_pod("web-1", serde_json::json!({ "app": "web" }), true, serde_json::json!({}))]);
        assert_eq!(
            render_pdb_budget(&budget(serde_json::json!({})), &pods()),
            "web: minAvailable 1; covers web-1; healthy 1 of 1 expected, 1 needed; disruptions allowed 0 — NO HEALTHY POD MAY BE EVICTED: a drain waits on any node running one of its ready pods; the budget is met, so a running pod that is not ready can still be evicted (unhealthyPodEvictionPolicy IfHealthyBudget, the default)\n\
             selector: app=web\n\
             condition DisruptionAllowed=False (InsufficientPods)"
        );
        let none = render_pdb_budget(&budget(serde_json::json!({ "spec": { "selector": null } })), &Ok(vec![]));
        assert!(none.contains("covers no pods") && none.contains("selector: (none)") && none.ends_with("NO SELECTOR: a budget without one selects no pods, so it protects nothing"), "{none}");
        let misses = render_pdb_budget(&budget(serde_json::json!({ "metadata": { "generation": 3 } })), &Ok(vec![]));
        assert!(misses.contains("THE CONTROLLER HAS NOT YET ACTED ON THE LATEST SPEC: generation 3, observed 2") && misses.ends_with("SELECTS NO PODS: no pod in its namespace has the labels it selects, so it protects nothing"), "{misses}");

        // A drain waiting: a covered pod on a cordoned node, nothing allowed.
        let node = |name: &str, ready: &str, cordoned: bool| -> k8s_openapi::api::core::v1::Node {
            serde_json::from_value(serde_json::json!({ "metadata": { "name": name }, "spec": { "unschedulable": cordoned },
                "status": { "conditions": [{ "type": "Ready", "status": ready }] } })).unwrap()
        };
        let p = |name: &str, on: &str, ready: bool| labelled_pod(name, serde_json::json!({ "app": "web" }), ready, serde_json::json!({ "spec": { "nodeName": on } }));
        let nodes = vec![
            ("n1".to_string(), Ok(Some(node("n1", "True", true)))),
            ("n2".to_string(), Ok(None)),
            ("n3".to_string(), Ok(Some(node("n3", "False", false)))),
            ("n4".to_string(), Ok(Some(node("n4", "False", true)))),
        ];
        assert_eq!(
            render_pdb_pods(&budget(serde_json::json!({})), &Ok(vec![p("web-1", "n1", true), p("web-2", "n2", false), p("web-3", "n3", false), p("web-4", "n4", false)]), &nodes),
            "4 pods, 1 ready\n\
             web-1: ready; on n1 (node CORDONED)\n\
             web-2: NOT READY; on n2 (NODE NO LONGER EXISTS)\n\
             web-3: NOT READY; on n3 (node NOT READY)\n\
             web-4: NOT READY; on n4 (node NOT READY) (node CORDONED)\n\
             A DRAIN IS WAITING ON THIS BUDGET: 1 ready pod on cordoned nodes (n1, n4) cannot be evicted while it allows no disruption; 1 not ready there may still be, as its unhealthyPodEvictionPolicy decides"
        );
        // Only unready pods on the cordoned node: not called blocked.
        let unready_only = render_pdb_pods(&budget(serde_json::json!({})), &Ok(vec![p("web-4", "n4", false)]), &nodes);
        assert!(unready_only.ends_with("1 of its pods on cordoned nodes (n4) is not ready: whether a drain can evict it while it allows no disruption is up to its unhealthyPodEvictionPolicy") && !unready_only.contains("WAITING"), "{unready_only}");
        let loose = budget(serde_json::json!({ "status": { "disruptionsAllowed": 2 } }));
        assert!(render_pdb_pods(&loose, &Ok(vec![p("web-1", "n1", true)]), &nodes).ends_with("1 of its pods is on cordoned nodes (n1); it allows 2 disruptions now, so a drain can evict it"));
        assert_eq!(render_pdb_pods(&loose, &Err("forbidden".into()), &[]), "(pods unavailable: forbidden)");
    }

    #[test]
    fn a_budget_tighter_than_its_replicas_and_overlaps_are_named() {
        let tight = render_pdb_owners(&budget(serde_json::json!({})), &Ok(vec![owner("Deployment", "web", Some(1), 1)]));
        assert_eq!(
            tight,
            "Deployment web: 1 of its pods covered; asks for 1\n\
             THE BUDGET CAN NEVER ALLOW A DISRUPTION: minAvailable 1 with 1 pod asked for, so a drain waits until there are more replicas or the budget is relaxed"
        );
        assert!(!render_pdb_owners(&budget(serde_json::json!({})), &Ok(vec![owner("Deployment", "web", Some(3), 3)])).contains("NEVER"));
        assert!(render_pdb_owners(&budget(serde_json::json!({ "spec": { "minAvailable": null, "maxUnavailable": 0 } })), &Ok(vec![owner("StatefulSet", "db", Some(3), 3)]))
            .contains("THE BUDGET CAN NEVER ALLOW A DISRUPTION: maxUnavailable 0"));
        assert!(render_pdb_owners(&budget(serde_json::json!({ "spec": { "minAvailable": "100%" } })), &Ok(vec![owner("Deployment", "web", Some(5), 5)]))
            .contains("minAvailable 100% keeps every pod"));
        // Unmanaged pods are said, and give no replica count to measure against.
        let bare = render_pdb_owners(&budget(serde_json::json!({})), &Ok(vec![owner("", "", None, 2)]));
        assert_eq!(bare, "2 pods with no controller: an evicted one is not recreated");
        // An unmanaged pod counts toward minAvailable without asking for a
        // replica, so a Deployment of 1 plus one bare pod is not called stuck.
        assert!(!render_pdb_owners(&budget(serde_json::json!({})), &Ok(vec![owner("Deployment", "web", Some(1), 1), owner("", "", None, 1)])).contains("NEVER"));
        assert_eq!(render_pdb_owners(&budget(serde_json::json!({})), &Ok(vec![])), "(no pods, so no controller)");

        assert_eq!(render_pdb_others(&Ok(vec![])), "(no other budget in its namespace covers any of its pods)");
        assert_eq!(
            render_pdb_others(&Ok(vec![(budget(serde_json::json!({ "metadata": { "name": "web-extra" } })), Some(vec!["web-1".to_string()]))])),
            "OVERLAPS WITH web-extra ON web-1: the eviction API refuses to evict a pod covered by more than one budget"
        );
        assert_eq!(render_pdb_others(&Err("not checked: the budget's pods could not be read".into())), "(other budgets unavailable: not checked: the budget's pods could not be read)");
    }

    #[test]
    fn a_volume_bound_elsewhere_or_pinned_to_a_zone_is_said() {
        let pv: k8s_openapi::api::core::v1::PersistentVolume = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "pv-1" },
            "spec": {
                "capacity": { "storage": "10Gi" }, "accessModes": ["ReadWriteOnce"], "persistentVolumeReclaimPolicy": "Retain",
                "claimRef": { "namespace": "ns", "name": "data", "uid": "old-uid" },
                "csi": { "driver": "disk.csi.azure.com", "volumeHandle": "disk-1" },
                "nodeAffinity": { "required": { "nodeSelectorTerms": [{ "matchExpressions": [{ "key": "topology.disk.csi.azure.com/zone", "operator": "In", "values": ["westeurope-1"] }] }] } }
            },
            "status": { "phase": "Released" }
        }))
        .unwrap();
        let csi = Some(Ok(k8s::PvcCsiDriver { name: "disk.csi.azure.com".into(), registered: true, on_nodes: 5, nodes: 6 }));
        let mut unclaimed = pv.clone();
        unclaimed.spec.as_mut().unwrap().claim_ref = None;
        let out = render_pvc_volume(&pvc(serde_json::json!({})), &Some(Ok(unclaimed)), &None);
        assert!(out.contains("no claimRef: the volume is not bound to any claim yet") && !out.contains("CLAIMED BY"), "{out}");
        assert_eq!(
            render_pvc_volume(&pvc(serde_json::json!({})), &Some(Ok(pv)), &csi),
            "pv-1: phase Released, capacity 10Gi, access modes ReadWriteOnce, reclaim policy Retain\n\
             CLAIMED BY AN EARLIER CLAIM OF THE SAME NAME: its claimRef's uid is not this claim's\n\
             CSI driver disk.csi.azure.com, volume handle disk-1\n\
             attaches only to nodes with: topology.disk.csi.azure.com/zone In (westeurope-1)\n\
             CSI driver disk.csi.azure.com: registered; on 5 of 6 nodes"
        );
    }

    #[test]
    fn a_claims_status_shows_a_resize_in_progress() {
        let c = pvc(serde_json::json!({
            "metadata": { "annotations": { "volume.kubernetes.io/selected-node": "n1" } },
            "spec": { "storageClassName": "managed-csi", "volumeName": "pv-1", "resources": { "requests": { "storage": "20Gi" } } },
            "status": { "phase": "Bound", "capacity": { "storage": "10Gi" }, "allocatedResources": { "storage": "20Gi" },
                        "allocatedResourceStatuses": { "storage": "NodeResizePending" },
                        "conditions": [{ "type": "FileSystemResizePending", "status": "True", "message": "Waiting for user to (re-)start a pod" }] }
        }));
        assert_eq!(
            render_pvc_status(&c),
            "phase: Bound\nrequested: 20Gi; capacity: 10Gi\naccess modes: ReadWriteOnce\nvolume mode: Filesystem\nstorage class: managed-csi\nvolume: pv-1\n\
             selected node (WaitForFirstConsumer): n1\nresize of storage: NodeResizePending\nallocated (resize target): 20Gi\n\
             condition FileSystemResizePending=True: Waiting for user to (re-)start a pod"
        );
    }

    #[test]
    fn endpoints_and_spec_say_what_is_behind_the_service() {
        let slice: k8s_openapi::api::discovery::v1::EndpointSlice = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "api-x" }, "addressType": "IPv4",
            "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }],
            "endpoints": [
                { "addresses": ["10.0.0.1"], "conditions": { "ready": true }, "targetRef": { "kind": "Pod", "name": "api-1" }, "nodeName": "n1" },
                { "addresses": ["10.0.0.2"], "conditions": { "ready": false }, "targetRef": { "kind": "Pod", "name": "api-2" } },
                { "addresses": ["10.0.0.3"], "conditions": { "ready": false, "terminating": true } }
            ]
        }))
        .unwrap();
        assert_eq!(
            render_service_endpoints(&Ok(vec![slice]), true),
            "1 of 3 ready, 1 terminating; resolved ports: http 8080/TCP\n  \
             10.0.0.1 ready (Pod api-1) on n1\n  10.0.0.2 NOT READY (Pod api-2)\n  10.0.0.3 terminating"
        );
        assert_eq!(render_service_endpoints(&Ok(vec![]), true), "(no endpoints: nothing is behind it)");

        let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "web" },
            "spec": { "type": "LoadBalancer", "clusterIP": "10.3.0.9", "selector": { "app": "web" },
                      "ports": [{ "name": "https", "port": 443, "targetPort": 8443, "nodePort": 31443, "protocol": "TCP" }], "externalTrafficPolicy": "Local" },
            "status": { "loadBalancer": {} }
        }))
        .unwrap();
        assert_eq!(
            render_service_spec(&lb),
            "type: LoadBalancer\ncluster IP: 10.3.0.9\nselector: app=web\nports:\n  https 443 → target port 8443/TCP, node port 31443\n\
             external traffic policy: Local\nload balancer address: PENDING — none assigned yet"
        );
        let ext: k8s_openapi::api::core::v1::Service =
            serde_json::from_value(serde_json::json!({ "metadata": { "name": "x" }, "spec": { "type": "ExternalName", "externalName": "db.example.com" } })).unwrap();
        assert_eq!(render_service_spec(&ext), "type: ExternalName\nexternal name: db.example.com (a DNS CNAME; it has no selector, endpoints or ports of its own by design)");
    }

    #[test]
    fn a_missing_target_is_said_once_as_a_fact() {
        let e = "Deployment 'api' does not exist".to_string();
        let out = render_hpa_target(&Err(e.clone()), &Err(e), &Err("x".into()));
        assert_eq!(out, "(Deployment 'api' does not exist)");
        assert_eq!(read_failure("generated HPA", "HorizontalPodAutoscaler 'keda-hpa-x' does not exist"), "(HorizontalPodAutoscaler 'keda-hpa-x' does not exist)");
        assert_eq!(read_failure("generated HPA", "forbidden"), "(generated HPA unavailable: forbidden)");
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

    /// Builds a diagnosis for every Service with no ready endpoint, and for a
    /// sample of healthy ones, and checks that each empty one is explained: no
    /// pod matches, or the ones that do are not ready. Prints counts only.
    ///
    ///   SERVICE_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml service_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set SERVICE_DIAG_TEST_CONTEXT to run"]
    async fn service_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("SERVICE_DIAG_TEST_CONTEXT") else { return };
        let services = crate::resources::get_services(&ctx).await.expect("services");
        let empty: Vec<_> = services.iter().filter(|s| s.endpoints_ready == Some(0)).collect();
        let healthy: Vec<_> = services.iter().filter(|s| s.endpoints_ready.is_some_and(|n| n > 0)).take(20).collect();
        let (mut built, mut unavailable, mut largest) = (0, 0, 0);
        let (mut no_pod, mut near_miss, mut not_ready, mut scaled_to_zero, mut unexplained) = (0, 0, 0, 0, 0);
        let (mut healthy_ready, mut managed_plane) = (0, 0);
        for s in &empty {
            let payload = build_service_diagnosis_payload(&ctx, &s.namespace, &s.name).await.expect("payload");
            built += 1;
            unavailable += payload.prompt.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            let p = &payload.prompt;
            no_pod += p.contains("NO POD in namespace") as usize;
            near_miss += p.contains("near misses (pods") as usize;
            not_ready += p.contains(", NOT READY") as usize;
            scaled_to_zero += p.contains(": 0 desired,") as usize;
            managed_plane += p.contains("AKS: yes") as usize;
            unexplained += !(p.contains("NO POD in namespace") || p.contains(", NOT READY")) as usize;
        }
        for s in &healthy {
            let payload = build_service_diagnosis_payload(&ctx, &s.namespace, &s.name).await.expect("payload");
            built += 1;
            unavailable += payload.prompt.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            healthy_ready += payload.prompt.contains(" ready\n") as usize;
        }
        println!(
            "services={} empty={} built={built} unavailable_sections={unavailable} largest_tokens={largest} no_pod={no_pod} near_miss={near_miss} not_ready={not_ready} scaled_to_zero={scaled_to_zero} unexplained={unexplained} managed_plane={managed_plane} healthy_with_ready_pod={healthy_ready}/{}",
            services.len(),
            empty.len(),
            healthy.len()
        );
        assert!(built > 0, "no Service to diagnose");
        assert_eq!(unavailable, 0);
        assert_eq!(unexplained, 0);
    }

    /// Builds a diagnosis for every Ingress on a cluster without an address,
    /// and for a sample of the rest, and checks each section was read, and
    /// that one with no address is explained by its class or its controller.
    /// Prints counts only.
    ///
    ///   INGRESS_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml ingress_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set INGRESS_DIAG_TEST_CONTEXT to run"]
    async fn ingress_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("INGRESS_DIAG_TEST_CONTEXT") else { return };
        let all = crate::resources::get_ingresses(&ctx).await.expect("ingresses");
        // Every one without an address, and a sample of the rest: each reads
        // an hour of every controller pod's log.
        let mut ingresses: Vec<_> = all.iter().filter(|i| i.address.is_empty()).collect();
        ingresses.extend(all.iter().filter(|i| !i.address.is_empty()).take(15));
        let (mut built, mut unavailable, mut largest) = (0, 0, 0);
        let (mut no_address, mut no_address_explained, mut controller_found, mut log_lines) = (0, 0, 0, 0);
        let (mut bad_backend, mut tls_checked, mut tls_problem, mut cert_manager, mut scaled_to_zero) = (0, 0, 0, 0, 0);
        for i in ingresses.iter().copied() {
            let payload = build_ingress_diagnosis_payload(&ctx, &i.namespace, &i.name).await.expect("payload");
            let p = &payload.prompt;
            built += 1;
            unavailable += p.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            controller_found += p.contains("(matched by its args") as usize;
            log_lines += (!p.contains("logged nothing about this Ingress") && !p.contains("no log to read")) as usize;
            scaled_to_zero += p.contains("SCALED TO ZERO") as usize;
            bad_backend += (p.contains("NO READY ENDPOINT")
                || p.contains("NO ENDPOINTS")
                || p.contains("NO ENDPOINT SERVES")
                || p.contains("IS NOT A PORT")
                || p.contains("does not exist)")) as usize;
            tls_checked += p.contains("  certificate: subject") as usize;
            tls_problem += (p.contains("EXPIRED on") || p.contains("DOES NOT COVER") || p.contains("MISSING KEY")) as usize;
            cert_manager += p.contains("Certificate ") as usize;
            if i.address.is_empty() {
                no_address += 1;
                no_address_explained += (p.contains("DOES NOT EXIST")
                    || p.contains("NO CLASS:")
                    || p.contains("by the legacy kubernetes.io/ingress.class annotation")
                    || p.contains("NOT ALL READY")
                    || p.contains("SCALED TO ZERO")
                    || p.contains("(no Deployment or DaemonSet names")) as usize;
            }
        }
        println!(
            "ingresses={} sampled={} built={built} unavailable_sections={unavailable} largest_tokens={largest} no_address={no_address}/{no_address_explained} controller_found={controller_found} with_log_lines={log_lines} bad_backend={bad_backend} tls_checked={tls_checked} tls_problem={tls_problem} cert_manager={cert_manager} controller_scaled_to_zero={scaled_to_zero}",
            all.len(),
            ingresses.len()
        );
        assert!(built > 0, "no Ingress to diagnose");
        assert_eq!(unavailable, 0);
    }

    /// Builds a diagnosis for every claim that is not Bound and for a sample of
    /// the rest, and checks each section was read and each unbound one is
    /// explained. Prints counts only.
    ///
    ///   PVC_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml pvc_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set PVC_DIAG_TEST_CONTEXT to run"]
    async fn pvc_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("PVC_DIAG_TEST_CONTEXT") else { return };
        let all = crate::resources::get_pvcs(&ctx).await.expect("pvcs");
        let mut claims: Vec<_> = all.iter().filter(|c| c.status != "Bound").collect();
        claims.extend(all.iter().filter(|c| c.status == "Bound").take(20));
        let (mut built, mut unavailable, mut largest, mut unbound, mut unbound_explained) = (0, 0, 0, 0, 0);
        let (mut with_usage, mut nearly_full, mut attach_errors, mut multi_node, mut with_pods, mut csi_registered) = (0, 0, 0, 0, 0, 0);
        for c in claims.iter().copied() {
            let payload = build_pvc_diagnosis_payload(&ctx, &c.namespace, &c.name).await.expect("payload");
            let p = &payload.prompt;
            built += 1;
            unavailable += p.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            with_usage += p.contains(" used (") as usize;
            nearly_full += (p.contains("NEARLY FULL") || p.contains("INODES NEARLY EXHAUSTED")) as usize;
            attach_errors += p.contains("attach error") as usize;
            multi_node += p.contains("A SINGLE-NODE VOLUME") as usize;
            with_pods += !p.contains("(no pod mounts it)") as usize;
            csi_registered += p.contains(": registered; on ") as usize;
            if c.status != "Bound" {
                unbound += 1;
                unbound_explained += (p.contains("NO CLASS SET")
                    || p.contains("DOES NOT EXIST")
                    || p.contains("binding: WaitForFirstConsumer")
                    || p.contains("none, by request")
                    || p.contains("ProvisioningFailed")
                    || p.contains("phase Released")
                    || p.contains("CLAIMED BY")) as usize;
            }
        }
        println!(
            "pvcs={} sampled={} built={built} unavailable_sections={unavailable} largest_tokens={largest} unbound={unbound}/{unbound_explained} with_pods={with_pods} with_usage={with_usage} nearly_full={nearly_full} attach_errors={attach_errors} multi_node={multi_node} csi_registered={csi_registered}",
            all.len(),
            claims.len()
        );
        assert!(built > 0, "no claim to diagnose");
        assert_eq!(unavailable, 0);
        assert_eq!(unbound_explained, unbound);
    }

    /// Builds a diagnosis for every ScaledObject and ScaledJob on a cluster and
    /// checks each section was read, every FromEnv credential was resolved one
    /// way or the other, and a not-Ready object's operator log was found.
    /// Prints counts only — no names, log lines or values.
    ///
    ///   KEDA_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml keda_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster with KEDA; set KEDA_DIAG_TEST_CONTEXT to run"]
    async fn keda_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("KEDA_DIAG_TEST_CONTEXT") else { return };
        let objects = k8s::get_keda_scaled_objects(&ctx).await.expect("keda").scaled_objects;
        let (mut built, mut unavailable, mut largest) = (0, 0, 0);
        let (mut present, mut missing, mut undefined, mut unresolved) = (0, 0, 0, 0);
        let (mut not_ready, mut not_ready_with_log) = (0, 0);
        for o in &objects {
            let payload = build_keda_diagnosis_payload(&ctx, &o.namespace, &o.kind, &o.name).await.expect("payload");
            built += 1;
            unavailable += payload.prompt.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            let creds = payload.prompt.split("## Credentials\n").nth(1).and_then(|s| s.split("\n\n## ").next()).unwrap_or_default();
            for line in creds.lines().filter(|l| l.starts_with("trigger ")) {
                if line.contains("— present") {
                    present += 1
                } else if line.contains("MISSING") {
                    missing += 1
                } else if line.contains("NOT DEFINED") {
                    undefined += 1
                } else {
                    unresolved += 1
                }
            }
            if !o.ready {
                not_ready += 1;
                not_ready_with_log += !payload.prompt.contains("(the operator logged nothing about this object") as usize;
            }
        }
        println!(
            "objects={} built={built} unavailable_sections={unavailable} largest_tokens={largest} from_env: present={present} missing_key={missing} not_defined={undefined} other={unresolved} not_ready={not_ready} not_ready_with_operator_log={not_ready_with_log}",
            objects.len()
        );
        assert!(built > 0, "no KEDA object to diagnose");
        assert_eq!(unavailable, 0);
    }

    /// Builds a diagnosis for every unhealthy StatefulSet and a sample of the
    /// rest, and checks the StatefulSet sections were read and each unhealthy
    /// one is explained by an ordinal, claim or rollout line. Prints counts only.
    ///
    ///   STATEFULSET_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml statefulset_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set STATEFULSET_DIAG_TEST_CONTEXT to run"]
    async fn statefulset_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("STATEFULSET_DIAG_TEST_CONTEXT") else { return };
        let all: Vec<_> = k8s::get_workloads(&ctx).await.expect("workloads").into_iter().filter(|w| w.kind == "StatefulSet").collect();
        let mut sample: Vec<_> = all.iter().filter(|w| !w.healthy).collect();
        sample.extend(all.iter().filter(|w| w.healthy).take(15));
        let (mut built, mut unavailable, mut largest, mut unhealthy, mut explained) = (0, 0, 0, 0, 0);
        let (mut with_claims, mut pending_claims, mut small_claims, mut rolling, mut ordered_block, mut stuck) = (0, 0, 0, 0, 0, 0);
        let (mut headless, mut no_service, mut not_headless, mut selector_miss, mut with_pdb, mut pdb_blocks, mut multi_pdb) = (0, 0, 0, 0, 0, 0, 0);
        for w in sample.iter().copied() {
            let payload = build_workload_diagnosis_payload(&ctx, &w.kind, &w.namespace, &w.name).await.expect("payload");
            let p = &payload.prompt;
            let sts = p.split("## StatefulSet\n").nth(1).and_then(|s| s.split("\n\n## Events (StatefulSet)").next()).expect("StatefulSet sections");
            built += 1;
            unavailable += sts.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            with_claims += !sts.contains("(no volumeClaimTemplates") as usize;
            pending_claims += sts.contains(": PENDING, capacity") as usize;
            small_claims += sts.contains("LESS THAN THE TEMPLATE'S") as usize;
            rolling += (sts.contains("ROLLOUT IN PROGRESS") || sts.contains("ROLLOUT PARTITIONED") || sts.contains("ON DELETE:")) as usize;
            ordered_block += sts.contains("ORDEREDREADY:") as usize;
            stuck += sts.contains("IS STUCK TERMINATING") as usize;
            headless += sts.contains(": headless\n") as usize;
            no_service += (sts.contains("GOVERNING SERVICE") || sts.contains("(serviceName is empty")) as usize;
            not_headless += sts.contains("NOT HEADLESS") as usize;
            selector_miss += (sts.contains("ITS SELECTOR DOES NOT SELECT") || sts.contains("ITS SELECTOR MISSES")) as usize;
            with_pdb += !sts.contains("(no PodDisruptionBudget covers") as usize;
            pdb_blocks += sts.contains("NO HEALTHY POD MAY BE EVICTED") as usize;
            multi_pdb += sts.contains("MORE THAN ONE BUDGET") as usize;
            if !w.healthy {
                unhealthy += 1;
                explained += (sts.contains("NOT READY")
                    || sts.contains("MISSING")
                    || sts.contains("TERMINATING")
                    || sts.contains("PENDING")
                    || sts.contains("ROLLOUT")
                    || sts.contains("ON DELETE")
                    || sts.contains("NOT YET ACTED")
                    || sts.contains("beyond the desired")
                    || sts.contains("scaled to zero")) as usize;
            }
        }
        println!(
            "statefulsets={} sampled={} built={built} unavailable_sections={unavailable} largest_tokens={largest} unhealthy={unhealthy}/{explained} with_claims={with_claims} pending_claims={pending_claims} small_claims={small_claims} rolling={rolling} ordered_block={ordered_block} stuck_terminating={stuck} headless={headless} no_service={no_service} not_headless={not_headless} selector_miss={selector_miss} with_pdb={with_pdb} pdb_blocks={pdb_blocks} multi_pdb={multi_pdb}",
            all.len(),
            sample.len()
        );
        assert!(built > 0, "no StatefulSet to diagnose");
        assert_eq!(unavailable, 0);
        assert_eq!(explained, unhealthy);
    }

    /// Builds DaemonSet diagnoses on a live cluster: every unhealthy one and
    /// up to 15 healthy ones. Prints counts only.
    ///
    ///   DAEMONSET_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml daemonset_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set DAEMONSET_DIAG_TEST_CONTEXT to run"]
    async fn daemonset_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("DAEMONSET_DIAG_TEST_CONTEXT") else { return };
        let all: Vec<_> = k8s::get_workloads(&ctx).await.expect("workloads").into_iter().filter(|w| w.kind == "DaemonSet").collect();
        let mut sample: Vec<_> = all.iter().filter(|w| !w.healthy).collect();
        sample.extend(all.iter().filter(|w| w.healthy).take(15));
        let (mut built, mut unavailable, mut largest, mut unhealthy, mut explained) = (0, 0, 0, 0, 0);
        let (mut left_out, mut kept, mut missing, mut misscheduled, mut no_room, mut port, mut rolling, mut stuck, mut all_ready) = (0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut no_pods, mut eligibility_agrees, mut eligibility_differs) = (0, 0, 0);
        for w in sample.iter().copied() {
            let payload = build_workload_diagnosis_payload(&ctx, &w.kind, &w.namespace, &w.name).await.expect("payload");
            let p = &payload.prompt;
            let ds = p.split("## DaemonSet\n").nth(1).and_then(|s| s.split("\n\n## Events (DaemonSet)").next()).expect("DaemonSet sections");
            built += 1;
            unavailable += ds.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            left_out += ds.contains(" left out: ") as usize;
            kept += ds.contains("NoSchedule taint it does not tolerate") as usize;
            missing += ds.contains("NO POD ON") as usize;
            misscheduled += ds.contains("MISSCHEDULED") as usize;
            no_room += ds.contains("CANNOT FIT ON") as usize;
            port += ds.contains("HOST PORT ALREADY IN USE") as usize;
            rolling += (ds.contains("ROLLOUT IN PROGRESS") || ds.contains("ON DELETE:")) as usize;
            stuck += ds.contains("IS STUCK TERMINATING") as usize;
            all_ready += ds.contains("of its pods are ready") as usize;
            no_pods += ds.contains("(it has no pods)") as usize;
            // The controller's desiredNumberScheduled counts the nodes its pod
            // should run on, so the eligibility worked out here must agree.
            let number = |prefix: &str, end: char| {
                ds.split(prefix).nth(1).and_then(|r| r.split(end).next()).and_then(|n| n.trim().parse::<usize>().ok())
            };
            let should = ds.lines().find(|l| l.contains(" should run its pod")).and_then(|l| l.split(": ").nth(1)?.split(' ').next()?.parse::<usize>().ok());
            match (number("nodes: desired ", ','), should) {
                (Some(d), Some(s)) if d == s => eligibility_agrees += 1,
                _ => eligibility_differs += 1,
            }
            if !w.healthy {
                unhealthy += 1;
                explained += (ds.contains("NOT READY")
                    || ds.contains("NO POD ON")
                    || ds.contains("MISSCHEDULED")
                    || ds.contains("ROLLOUT")
                    || ds.contains("ON DELETE")
                    || ds.contains("NOT YET ACTED")
                    || ds.contains("TERMINATING")
                    || ds.contains("UNSCHEDULABLE")) as usize;
            }
        }
        println!(
            "daemonsets={} sampled={} built={built} unavailable_sections={unavailable} largest_tokens={largest} unhealthy={unhealthy}/{explained} left_out={left_out} kept={kept} missing={missing} misscheduled={misscheduled} no_room={no_room} host_port={port} rolling={rolling} stuck_terminating={stuck} all_ready={all_ready} no_pods={no_pods} eligibility_agrees={eligibility_agrees} eligibility_differs={eligibility_differs}",
            all.len(),
            sample.len()
        );
        assert!(built > 0, "no DaemonSet to diagnose");
        assert_eq!(unavailable, 0);
        assert_eq!(explained, unhealthy);
        assert_eq!(eligibility_differs, 0);
    }

    /// Builds Deployment diagnoses on a live cluster: every unhealthy one and
    /// up to 15 healthy ones. Prints counts only.
    ///
    ///   DEPLOYMENT_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml deployment_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set DEPLOYMENT_DIAG_TEST_CONTEXT to run"]
    async fn deployment_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("DEPLOYMENT_DIAG_TEST_CONTEXT") else { return };
        let all: Vec<_> = k8s::get_workloads(&ctx).await.expect("workloads").into_iter().filter(|w| w.kind == "Deployment").collect();
        let mut sample: Vec<_> = all.iter().filter(|w| !w.healthy).collect();
        sample.extend(all.iter().filter(|w| w.healthy).take(15));
        let (mut built, mut unavailable, mut largest, mut unhealthy, mut explained) = (0, 0, 0, 0, 0);
        let (mut no_rs, mut history, mut rolling, mut replica_failure, mut deadline, mut paused, mut largest_section) = (0, 0, 0, 0, 0, 0, 0);
        let (mut with_hpa, mut multi_hpa, mut keda, mut with_pdb, mut pdb_blocks, mut pods_mismatch) = (0, 0, 0, 0, 0, 0);
        for w in sample.iter().copied() {
            let payload = build_workload_diagnosis_payload(&ctx, &w.kind, &w.namespace, &w.name).await.expect("payload");
            let p = &payload.prompt;
            let dep = p.split("## Deployment\n").nth(1).and_then(|s| s.split("\n\n## Events (Deployment)").next()).expect("Deployment sections");
            built += 1;
            unavailable += dep.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            largest_section = largest_section.max(dep.len() / 4);
            no_rs += dep.contains("(it has no ReplicaSet") as usize;
            history += dep.contains("kept as rollback history") as usize;
            rolling += dep.contains("ROLLOUT IN PROGRESS") as usize;
            replica_failure += (dep.contains("REPLICA FAILURE") || dep.contains("CANNOT CREATE PODS")) as usize;
            deadline += dep.contains("PROGRESS DEADLINE") as usize;
            paused += dep.contains("PAUSED:") as usize;
            with_hpa += !dep.contains("(no HorizontalPodAutoscaler targets it") as usize;
            multi_hpa += dep.contains("MORE THAN ONE HPA") as usize;
            keda += dep.contains("(made by KEDA ScaledObject") as usize;
            with_pdb += !dep.contains("(no PodDisruptionBudget covers") as usize;
            pdb_blocks += dep.contains("NO HEALTHY POD MAY BE EVICTED") as usize;
            // The pods counted under its ReplicaSets should be the pods the
            // generic table lists for it: both are its pods, read two ways.
            let counted: usize = dep
                .lines()
                .filter_map(|l| l.split("; pods ").nth(1)?.split(';').next()?.split(" ready of ").nth(1)?.trim().parse::<usize>().ok())
                .sum();
            let table = p.split("## Pods (worst first)\n").nth(1).and_then(|s| s.split("\n\n").next()).unwrap_or_default();
            let listed = if table.starts_with('(') { 0 } else { table.lines().filter(|l| !l.starts_with("(…")).count() };
            pods_mismatch += (listed < 20 && counted != listed) as usize;
            if !w.healthy {
                unhealthy += 1;
                let short = dep.lines().any(|l| {
                    l.split("; pods ").nth(1).and_then(|r| r.split(';').next()).and_then(|r| r.split_once(" ready of ")).is_some_and(|(a, b)| a.trim() != b.trim())
                });
                explained += (short
                    || dep.contains("REPLICA FAILURE")
                    || dep.contains("ROLLOUT")
                    || dep.contains("PAUSED")
                    || dep.contains("NOT YET ACTED")
                    || dep.contains("condition Available=False")
                    || dep.contains("(it has no ReplicaSet")) as usize;
            }
        }
        println!(
            "deployments={} sampled={} built={built} unavailable_sections={unavailable} largest_tokens={largest} largest_section_tokens={largest_section} unhealthy={unhealthy}/{explained} no_rs={no_rs} history={history} rolling={rolling} replica_failure={replica_failure} deadline={deadline} paused={paused} with_hpa={with_hpa} multi_hpa={multi_hpa} keda={keda} with_pdb={with_pdb} pdb_blocks={pdb_blocks} pods_mismatch={pods_mismatch}",
            all.len(),
            sample.len()
        );
        assert!(built > 0, "no Deployment to diagnose");
        assert_eq!(unavailable, 0);
        assert_eq!(explained, unhealthy);
        assert_eq!(pods_mismatch, 0);
    }

    /// Builds a diagnosis for every PodDisruptionBudget on a live cluster.
    /// Prints counts only.
    ///
    ///   PDB_DIAG_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml pdb_diagnosis_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set PDB_DIAG_TEST_CONTEXT to run"]
    async fn pdb_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("PDB_DIAG_TEST_CONTEXT") else { return };
        let all = crate::resources::get_pdbs(&ctx).await.expect("pdbs");
        let (mut built, mut unavailable, mut largest, mut blocks, mut listed_blocking) = (0, 0, 0, 0, 0);
        let (mut no_pods, mut never, mut overlap, mut drain_waiting, mut unmanaged, mut count_mismatch) = (0, 0, 0, 0, 0, 0);
        for b in &all {
            let payload = build_pdb_diagnosis_payload(&ctx, &b.namespace, &b.name).await.expect("payload");
            let p = &payload.prompt;
            built += 1;
            unavailable += p.matches("unavailable: ").count();
            largest = largest.max(payload.approx_tokens);
            blocks += p.contains("NO HEALTHY POD MAY BE EVICTED") as usize;
            listed_blocking += (b.disruptions_allowed == 0) as usize;
            no_pods += (p.contains("SELECTS NO PODS") || p.contains("NO SELECTOR:")) as usize;
            never += p.contains("CAN NEVER ALLOW A DISRUPTION") as usize;
            overlap += p.contains("OVERLAPS WITH") as usize;
            drain_waiting += p.contains("A DRAIN IS WAITING") as usize;
            unmanaged += p.contains("with no controller") as usize;
            // The pods it covers, read here, against the controller's own count.
            let read = p
                .split("## Pods it covers\n")
                .nth(1)
                .and_then(|s| s.split(" pods, ").next())
                .and_then(|n| n.trim().parse::<i32>().ok())
                .unwrap_or(0);
            count_mismatch += (read != b.expected_pods) as usize;
        }
        println!(
            "pdbs={} built={built} unavailable_sections={unavailable} largest_tokens={largest} blocks={blocks} listed_blocking={listed_blocking} no_pods={no_pods} never={never} overlap={overlap} drain_waiting={drain_waiting} unmanaged={unmanaged} count_mismatch={count_mismatch}",
            all.len()
        );
        assert!(built > 0, "no PodDisruptionBudget to diagnose");
        assert_eq!(unavailable, 0);
        assert_eq!(blocks, listed_blocking);
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
