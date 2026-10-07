//! Serializable data types shared between the Rust backend and the TypeScript frontend.
//! Keep these in sync with `src/types.ts` on the frontend.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Clone, Debug)]
pub struct ClusterEntry {
    pub context_name: String,
    pub cluster_name: String,
    pub server: String,
    pub namespace: Option<String>,
    /// Best-effort guess at whether this looks like an AKS context (cluster server
    /// hostname contains "azmk8s.io", or context name matches common az-cli naming).
    pub is_aks: bool,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ClusterOverview {
    pub context_name: String,
    pub reachable: bool,
    pub error: Option<String>,
    pub kubernetes_version: Option<String>,
    pub node_count: usize,
    pub nodes_ready: usize,
    pub namespace_count: usize,
    pub pod_count: usize,
    pub pods_running: usize,
    pub pods_not_ready: usize,
    pub warning_event_count: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct NodeInfo {
    pub name: String,
    pub ready: bool,
    pub roles: Vec<String>,
    pub kubelet_version: String,
    pub os_image: String,
    pub instance_type: Option<String>,
    /// `karpenter.sh/nodepool` label — absent on a node NAP didn't provision.
    pub node_pool: Option<String>,
    pub zone: Option<String>,
    pub cpu_capacity: String,
    pub cpu_allocatable: String,
    pub memory_capacity: String,
    pub memory_allocatable: String,
    pub memory_allocatable_ki: Option<i64>,
    pub cpu_usage_millicores: Option<i64>,
    pub memory_usage_ki: Option<i64>,
    pub conditions: Vec<String>,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
    pub unschedulable: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct PodInfo {
    pub name: String,
    pub namespace: String,
    pub node: Option<String>,
    pub phase: String,
    pub ready: String,
    pub restarts: i32,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
    /// The workload kind that owns this pod (e.g. "Deployment", "StatefulSet",
    /// "DaemonSet", "Job"), resolved through its ReplicaSet if it has one.
    pub owner_kind: Option<String>,
    pub owner_name: Option<String>,
    pub cpu_usage_millicores: Option<i64>,
    pub memory_usage_ki: Option<i64>,
    pub status_reason: Option<String>,
    /// The container that is failing, so a diagnosis targets it rather than
    /// the pod's first container. `None` for a pod-level failure
    /// such as `Evicted`, which belongs to no container.
    pub failure_container: Option<String>,
    /// The failing container's reason and message.
    ///
    /// Separate from `status_reason`, which is `pod.status.reason` and is only
    /// set for pod-level failures like `Evicted` — unset on every pod of a
    /// real fleet. What an operator actually needs is in the container's
    /// waiting or terminated state: "ImagePullBackOff: Back-off pulling image
    /// …: ErrImagePull: …".
    pub failure_message: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct PodManifest {
    pub containers: Vec<String>,
    pub yaml_full: String,
    pub yaml_without_managed_fields: String,
    /// What the panel's Overview shows, read from the same fetch as the YAML.
    pub detail: PodDetail,
}

/// The facts a pod's YAML buries: where it runs, what each container is
/// doing and why it last stopped, and what it mounts. Mirrors `PodDetail` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct PodDetail {
    pub phase: String,
    /// `status.reason` / `status.message`: set for a pod-level failure such as Evicted.
    pub reason: String,
    pub message: String,
    pub node: String,
    pub pod_ip: String,
    pub host_ip: String,
    pub qos_class: String,
    pub service_account: String,
    pub priority_class: String,
    pub restart_policy: String,
    pub start_time: Option<String>,
    /// The controller that owns it as the API records it — usually a
    /// ReplicaSet; the row's `owner_*` already resolves that to its Deployment.
    pub controller_kind: String,
    pub controller_name: String,
    pub init_containers: Vec<ContainerDetail>,
    pub containers: Vec<ContainerDetail>,
    pub conditions: Vec<PodConditionInfo>,
    /// Every ConfigMap, Secret and PersistentVolumeClaim it reads, deduplicated,
    /// with how — so the panel can link to each.
    pub references: Vec<PodReference>,
}

/// One container (or init container) of a pod: its spec and its status merged.
#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct ContainerDetail {
    pub name: String,
    pub image: String,
    pub ready: bool,
    pub restart_count: i32,
    /// `running`, `waiting`, `terminated`, or empty before the kubelet reports.
    pub state: String,
    /// Waiting: `CrashLoopBackOff`, `ImagePullBackOff`… Terminated: `Completed`, `OOMKilled`, `Error`.
    pub state_reason: String,
    pub state_message: String,
    /// When it started running, or when it finished.
    pub state_since: Option<String>,
    pub exit_code: Option<i32>,
    /// Why the previous run ended — the line that explains a restart loop.
    pub last_reason: String,
    pub last_exit_code: Option<i32>,
    pub last_finished: Option<String>,
    pub last_message: String,
    pub cpu_request: String,
    pub cpu_limit: String,
    pub memory_request: String,
    pub memory_limit: String,
    /// `8080/TCP`, or `http 8080/TCP` when named.
    pub ports: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct PodConditionInfo {
    pub condition_type: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    pub last_transition: Option<String>,
}

/// An object a pod reads. `kind` is `ConfigMap`, `Secret` or `PersistentVolumeClaim`.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct PodReference {
    pub kind: String,
    pub name: String,
    /// How it is used, deduplicated: `volume`, `env`, `envFrom`, `imagePull`.
    pub via: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct NodeManifest {
    pub yaml_full: String,
    pub yaml_without_managed_fields: String,
    /// What the panel's Overview shows, read from the same fetch as the YAML.
    pub detail: NodeDetail,
}

/// The facts a node's YAML buries: why it is not Ready, what is pressuring
/// it, what keeps pods off it, and what it has to give. Mirrors `NodeDetail` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct NodeDetail {
    /// The facts below come from the node itself, not the Nodes tab's row, so
    /// the Overview is right even when opened before that tab has loaded.
    pub unschedulable: bool,
    pub roles: Vec<String>,
    pub instance_type: String,
    pub zone: String,
    /// `karpenter.sh/nodepool`: a NAP pool. Empty for any other node.
    pub nap_pool: String,
    /// `agentpool`: the AKS node pool, for a node NAP did not provision.
    pub agent_pool: String,
    pub kubelet_version: String,
    pub os_image: String,
    pub created_at: Option<String>,
    pub conditions: Vec<PodConditionInfo>,
    /// `key=value:Effect`, or `key:Effect` without a value.
    pub taints: Vec<String>,
    /// `key=value`, sorted.
    pub labels: Vec<String>,
    pub kernel_version: String,
    pub container_runtime: String,
    pub architecture: String,
    pub operating_system: String,
    pub internal_ip: String,
    pub external_ip: String,
    pub pod_cidrs: Vec<String>,
    /// The cloud's own ID for it — on AKS, the VMSS instance.
    pub provider_id: String,
    /// Every resource the node reports, as the API spells the quantity:
    /// cpu, memory, pods, ephemeral-storage, and any extended ones (GPUs).
    pub capacity: std::collections::BTreeMap<String, String>,
    pub allocatable: std::collections::BTreeMap<String, String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct WorkloadManifest {
    pub yaml_full: String,
    pub yaml_without_managed_fields: String,
    /// From the workload's own pod template — same for every pod it owns,
    /// so there's no need to ask any particular pod instance for this.
    pub containers: Vec<String>,
    /// What the panel's Overview shows, read from the same fetch as the YAML.
    pub detail: WorkloadDetail,
}

/// The facts a workload's YAML buries: how it rolls out, what it selects,
/// whether the controller has caught up, and what its pods are built from.
/// Mirrors `WorkloadDetail` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct WorkloadDetail {
    /// `RollingUpdate (max surge 25%, max unavailable 25%)`, `Recreate`, `OnDelete`…
    pub strategy: String,
    /// `key=value` for matchLabels, `key In (a, b)` for each expression.
    pub selector: Vec<String>,
    /// The pod template's labels, `key=value` — what a Service selects on.
    pub template_labels: Vec<String>,
    /// Deployment: the `deployment.kubernetes.io/revision` annotation.
    /// StatefulSet: `currentRevision`, and `updateRevision` when a rollout is underway.
    pub revision: String,
    pub update_revision: String,
    pub generation: i64,
    pub observed_generation: i64,
    /// Deployment `spec.paused`: rollouts are held until it is resumed.
    pub paused: bool,
    /// StatefulSet: the headless Service that gives its pods stable names.
    pub service_name: String,
    pub pod_management_policy: String,
    /// StatefulSet volumeClaimTemplates: one PVC per pod is created from each.
    pub volume_claim_templates: Vec<String>,
    /// DaemonSet / pod template `nodeSelector`, `key=value`.
    pub node_selector: Vec<String>,
    /// DaemonSet: pods running where they should not.
    pub misscheduled: i32,
    pub conditions: Vec<PodConditionInfo>,
    /// The pod template's containers, spec only — there is no status for a template.
    pub init_containers: Vec<ContainerDetail>,
    pub containers: Vec<ContainerDetail>,
    pub references: Vec<PodReference>,
}

#[derive(Serialize, Clone, Debug)]
pub struct WorkloadInfo {
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub desired: i32,
    pub ready: i32,
    pub updated: i32,
    pub available: i32,
    pub healthy: bool,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
    /// What version is running: the `app.kubernetes.io/version` label where
    /// set, otherwise the first container's image tag.
    pub version: String,
    /// Whether `version` came from the label (true) or was derived from an
    /// image tag (false) — the label can drift from the image actually
    /// deployed, so the UI says which it is.
    pub version_from_label: bool,
    /// Main containers' images (init containers excluded).
    pub images: Vec<String>,
    /// `helm.sh/chart` label, e.g. "apisix-2.14.0", when Helm installed it.
    pub chart: Option<String>,
    /// The most informative failing condition, shown as the status tooltip.
    ///
    /// Controllers mostly report `MinimumReplicasUnavailable: Deployment does
    /// not have minimum availability`, which restates the ready count and
    /// explains nothing — so `ProgressDeadlineExceeded` and `ReplicaFailure`
    /// are preferred when present, being the two that name a cause.
    pub failure_message: Option<String>,
}

/// One entry of a workload's rollout history — a ReplicaSet for a Deployment,
/// or a ControllerRevision for a StatefulSet/DaemonSet.
#[derive(Serialize, Clone, Debug)]
pub struct WorkloadRevisionInfo {
    pub revision: i64,
    /// The ReplicaSet / ControllerRevision name.
    pub name: String,
    /// Desired replicas for this revision. `None` for a ControllerRevision,
    /// which is a stored pod template rather than a running replica set.
    pub replicas: Option<i32>,
    pub ready_replicas: Option<i32>,
    /// The images this revision runs — effectively the version it pinned.
    pub images: Vec<String>,
    /// This revision's pod template as YAML, normalised for diffing (hash
    /// labels stripped). Carried in the list rather than fetched per
    /// comparison: the underlying objects are already transferred by the same
    /// call, so this costs no extra round trip and makes comparing instant.
    pub template_yaml: String,
    /// The newest revision, i.e. the one the workload is currently on.
    pub current: bool,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct EventInfo {
    pub namespace: String,
    pub involved_object: String,
    pub reason: String,
    pub message: String,
    pub event_type: String,
    pub count: i32,
    pub last_seen: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ResourceUsageSummary {
    pub metrics_available: bool,
    pub cpu_used_millicores: i64,
    pub cpu_allocatable_millicores: i64,
    pub memory_used_ki: i64,
    pub memory_allocatable_ki: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MetricsBackendKind {
    Prometheus,
    VictoriaMetrics,
}

/// A Prometheus-API-compatible time-series backend (Prometheus or
/// VictoriaMetrics) discovered by scanning Service objects cluster-wide.
/// Queried through the API server's service-proxy subresource, so no direct
/// network route to the in-cluster Service is required — the same path
/// `fetch_node_metrics` already uses for `metrics.k8s.io`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MetricsBackendInfo {
    pub kind: MetricsBackendKind,
    pub namespace: String,
    pub service_name: String,
    pub port: i32,
    /// Path prefix inserted before `/api/v1/query_range`. Empty for
    /// Prometheus and single-node VictoriaMetrics; VictoriaMetrics cluster
    /// mode's `vmselect` component nests the Prometheus-compatible API under
    /// `/select/0/prometheus`.
    pub api_path_prefix: String,
}

/// Outcome of probing a candidate backend, so the user gets a verdict before
/// committing to an override rather than discovering it's wrong via an empty
/// graph.
#[derive(Serialize, Clone, Debug)]
pub struct MetricsBackendTestResult {
    pub ok: bool,
    pub message: String,
    /// Series count for the cAdvisor metric the graphs depend on. A reachable
    /// endpoint reporting zero here answers PromQL but has no container
    /// metrics — which would render empty graphs, so it's worth surfacing
    /// separately from an outright connection failure.
    pub container_series: Option<i64>,
}

#[derive(Serialize, Clone, Debug)]
pub struct MetricSample {
    pub timestamp: i64,
    pub value: f64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct MetricsOverTimeResult {
    pub backend: Option<MetricsBackendInfo>,
    pub error: Option<String>,
    pub cpu_cores: Vec<MetricSample>,
    pub memory_bytes: Vec<MetricSample>,
    pub ephemeral_storage_bytes: Vec<MetricSample>,
    /// GPU series, empty unless DCGM exporter is running *and* this node, pod
    /// or workload actually touches a GPU. Empty is the answer for most of
    /// them, and is what tells the UI not to draw the charts — no separate
    /// "has a GPU" lookup needed.
    pub gpu_util_percent: Vec<MetricSample>,
    pub gpu_memory_bytes: Vec<MetricSample>,
    pub gpu_tensor_percent: Vec<MetricSample>,
}

/// One ArgoCD `Application` (`applications.argoproj.io`), flattened out of its
/// dynamic (non-`k8s_openapi`-typed) CRD shape into the handful of fields the
/// GitOps tab shows.
#[derive(Serialize, Clone, Debug)]
pub struct GitOpsAppInfo {
    pub namespace: String,
    pub name: String,
    pub destination_namespace: String,
    pub sync_status: String,
    pub health_status: String,
    pub repo_url: String,
    pub path: String,
    pub target_revision: String,
    pub revision: String,
    /// `status.operationState.finishedAt`, falling back to `.startedAt` for a
    /// sync still in progress. Deliberately not `status.reconciledAt`: that
    /// timestamp advances on every diff/comparison pass ArgoCD runs (every
    /// few minutes, regardless of whether anything was actually synced), so
    /// it would read as "a few minutes ago" for nearly every app and make
    /// this column useless for spotting one that's gone stale.
    pub last_synced_at: Option<String>,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
}

/// `installed: false` means no `applications.argoproj.io` CRD was found in
/// this cluster (ArgoCD isn't deployed there) — reported this way, rather
/// than as an error, so it renders as an explanatory message the same way an
/// absent metrics backend does on the Metrics tab.
#[derive(Serialize, Clone, Debug, Default)]
pub struct GitOpsResult {
    pub installed: bool,
    pub error: Option<String>,
    pub apps: Vec<GitOpsAppInfo>,
}

/// One resource an ArgoCD `Application` manages that is **not** Synced, with
/// both sides of its diff already normalised for line-diffing.
///
/// A word on what this diff is, because it is not what ArgoCD's own diff is.
/// ArgoCD compares the manifests rendered from Git against the live cluster,
/// and computes that in its repo-server — the result is cached in Redis and is
/// *not* stored on the `Application` resource. `status.resources[]` names each
/// drifted resource and nothing more. So an app holding only a kubeconfig
/// cannot reproduce it.
///
/// What a kubeconfig *can* see is the `last-applied-configuration` annotation
/// each resource carries: what was most recently applied to it. Diffing that
/// against the live object shows **drift** — a change made to the cluster
/// after the last apply. That is a genuinely useful and different question,
/// and it is the one this struct answers. It is deliberately not dressed up as
/// ArgoCD's answer; the UI says which it is.
#[derive(Serialize, Clone, Debug)]
pub struct GitOpsResourceDiff {
    /// Empty for core resources — `status.resources[]` omits the `group` key
    /// entirely rather than setting it null, so "" here means core/v1.
    pub group: String,
    pub version: String,
    pub kind: String,
    /// Empty for cluster-scoped resources.
    pub namespace: String,
    pub name: String,
    /// Carried through from `status.resources[].status` so the UI can label a
    /// row with what ArgoCD actually said, rather than assuming "OutOfSync".
    pub sync_status: String,
    /// The `last-applied-configuration` annotation, normalised. Empty when
    /// `desired_available` is false.
    pub desired_yaml: String,
    /// The live object, normalised, with server-assigned defaults suppressed.
    pub live_yaml: String,
    /// The same live object with nothing suppressed. Both variants ship in one
    /// payload for the same reason `ObjectManifest` carries two: the toggle
    /// then costs no round trip, and — more importantly — cannot end up
    /// showing a *different* live object than the one already on screen.
    pub live_yaml_full: String,
    /// How many lines `live_yaml` hides relative to `live_yaml_full`, so the
    /// UI can say so instead of quietly showing less.
    ///
    /// Counted as the line-count delta between the two rendered strings, not
    /// as a count of suppression rules that fired: one rule can remove a
    /// list-valued field worth several lines (`clusterIPs`, `ipFamilies`).
    pub suppressed_lines: usize,
    /// False when the resource carries no `last-applied-configuration` — which
    /// is the normal state for anything applied server-side (`kubectl apply
    /// --server-side`, or ArgoCD configured for SSA), where the equivalent
    /// information lives in `managedFields` in a form that cannot be
    /// reconstituted into a manifest. Not an error: there is simply nothing to
    /// compare against, and saying so beats rendering an empty diff that reads
    /// as "no drift".
    pub desired_available: bool,
    /// Set when this one resource could not be read at all — RBAC on its kind,
    /// or it has since been deleted. Per-resource rather than failing the
    /// whole panel, because an app can manage many resources and a token
    /// commonly lacks `get` on a few of their kinds.
    pub error: Option<String>,
}

impl GitOpsResourceDiff {
    /// Whether this resource actually drifted.
    ///
    /// One definition, because the two readers disagreeing would mean a
    /// bounded scan stopping on a different count than the one it reports.
    /// Note what it excludes: `desired_available == false` is *not* drift —
    /// there was nothing to compare, and an empty desired side would
    /// otherwise make every server-side-applied resource look rewritten.
    pub fn has_drift(&self) -> bool {
        self.desired_available && self.desired_yaml != self.live_yaml
    }
}

/// Azure Node Auto Provisioning (NAP) is AKS's managed Karpenter, so the
/// resources are Karpenter's own CRDs rather than anything Azure-specific.
/// `installed: false` distinguishes "this cluster has no NAP" from "NAP is on
/// but has no node pools", which look identical from an empty list.
#[derive(Serialize, Clone, Debug)]
pub struct NapResult {
    pub installed: bool,
    pub error: Option<String>,
    pub node_pools: Vec<NapNodePoolInfo>,
}

/// One object rendered to YAML twice, so a detail panel's "show managed
/// fields" toggle can switch between them without a second round trip.
///
/// Shared by every CRD-backed detail panel — ArgoCD Applications, Karpenter
/// NodePools, KEDA ScaledObjects — which all reach the same DynamicObject and
/// render it the same way. The two aliases below keep the per-domain names
/// their panels already use.
#[derive(Serialize, Clone, Debug)]
pub struct ObjectManifest {
    pub yaml_full: String,
    pub yaml_without_managed_fields: String,
}

/// An External Secrets Operator `ExternalSecret`. Mirrors `ExternalSecretInfo`
/// in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ExternalSecretInfo {
    pub namespace: String,
    pub name: String,
    /// `SecretStore` or `ClusterSecretStore` — which one decides where the
    /// store lives, so it is shown alongside the name.
    pub store_kind: String,
    pub store_name: String,
    /// The Secret it writes. `spec.target.name`, which defaults to the
    /// ExternalSecret's own name.
    pub target_name: String,
    /// `spec.target.template.type`, or `Opaque` — what ESO creates by default.
    pub target_type: String,
    /// `spec.refreshInterval` as written, e.g. `1h`. Empty means ESO's default.
    pub refresh_interval: String,
    /// Entries in `spec.data` — one Secret key each.
    pub data_count: usize,
    /// Entries in `spec.dataFrom` — each can yield any number of keys.
    pub data_from_count: usize,
    /// The `Ready` condition is `True`.
    pub ready: bool,
    /// Why not, from the `Ready` condition: `SecretSyncedError`, say. Empty
    /// when there is no condition yet — a brand new object ESO has not reached.
    pub reason: String,
    /// The condition's message: the provider's own error when a sync fails.
    pub message: String,
    /// `status.refreshTime` — when ESO last synced it.
    pub last_refresh: Option<String>,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
}

/// `installed: false` means no served version of the CRD answered — ESO is not
/// on this cluster.
#[derive(Serialize, Clone, Debug)]
pub struct ExternalSecretsResult {
    pub installed: bool,
    pub error: Option<String>,
    pub external_secrets: Vec<ExternalSecretInfo>,
}

/// One `spec.data` entry: which remote key feeds which Secret key.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ExternalSecretMapping {
    pub secret_key: String,
    pub remote_key: String,
    pub property: String,
    pub version: String,
}

/// What the ExternalSecret panel loads.
#[derive(Serialize, Clone, Debug)]
pub struct ExternalSecretDetail {
    pub mappings: Vec<ExternalSecretMapping>,
    /// `spec.dataFrom`, one readable line per entry.
    pub data_from: Vec<String>,
    pub manifest: ObjectManifest,
}

/// One key of a Secret: its name and decoded size, never its value.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct SecretKeyInfo {
    pub name: String,
    /// Decoded length, not the base64 length the API sends — what a reader
    /// means by "how big is this value".
    pub bytes: usize,
}

/// One Secret as the Secrets tab lists it. Mirrors `SecretInfo` in types.ts.
#[derive(Serialize, Clone, Debug)]
pub struct SecretInfo {
    pub namespace: String,
    pub name: String,
    /// `type` in the API, e.g. `Opaque` or `kubernetes.io/tls`.
    pub secret_type: String,
    /// `None` for a Helm release Secret, which is listed metadata-only and so
    /// has no key list to report — see `secrets.rs` for why. Not an empty
    /// list: an empty list would claim the Secret has no keys, which is false.
    pub keys: Option<Vec<SecretKeyInfo>>,
    pub immutable: bool,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
}

/// What the Secret detail panel loads: the key list and the redacted YAML.
#[derive(Serialize, Clone, Debug)]
pub struct SecretDetail {
    pub keys: Vec<SecretKeyInfo>,
    pub manifest: ObjectManifest,
}

/// One revealed value. Exactly one of `text` and `base64` is set.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct SecretValue {
    pub bytes: usize,
    /// The value, when it is valid UTF-8 — passwords, tokens, PEM files.
    pub text: Option<String>,
    /// Otherwise the raw bytes as base64 (a keystore, say), so a binary value
    /// can still be copied without being mangled into text.
    pub base64: Option<String>,
}

pub type NapNodePoolManifest = ObjectManifest;

/// One Karpenter `NodePool` — the provisioning policy — plus its own live
/// rollup of what it has actually provisioned (`status.resources`), which is
/// both the node count and the "used" side of the usage/limit columns below.
#[derive(Serialize, Clone, Debug)]
pub struct NapNodePoolInfo {
    pub name: String,
    /// `spec.template.spec.nodeClassRef.name` — the AKSNodeClass supplying the
    /// image/VM configuration for nodes this pool creates.
    pub node_class: String,
    pub ready: bool,
    /// Why the pool isn't ready, when it isn't; empty otherwise.
    pub status_reason: String,
    /// `status.resources.nodes` — the pool's own count of what it has
    /// provisioned.
    pub nodes: i64,
    /// Provisioned capacity vs the cap, both normalised to millicores/KiB so
    /// the UI can format them the way the Nodes tab does.
    ///
    /// "Used" is `status.resources`, the aggregate capacity of the nodes this
    /// pool owns — which is precisely what Karpenter's limits bound, and what
    /// it stops provisioning against. It is not live utilisation.
    pub cpu_used_millicores: i64,
    /// `None` when the pool sets no limit, which Karpenter treats as
    /// unbounded — distinct from a limit of zero.
    pub cpu_limit_millicores: Option<i64>,
    pub memory_used_ki: i64,
    pub memory_limit_ki: Option<i64>,
    pub weight: i64,
    /// Capacity types the pool may provision ("spot", "on-demand"), from the
    /// `karpenter.sh/capacity-type` requirement.
    pub capacity_types: String,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
}

/// One `HorizontalPodAutoscaler`.
///
/// Unlike the KEDA and Karpenter tabs beside it, this needs no `installed`
/// flag: `autoscaling/v2` is part of Kubernetes itself rather than an addon,
/// so an empty list means "nothing is autoscaled here", never "the API is
/// missing". That is also why it is read through `k8s-openapi`'s generated
/// type instead of a `DynamicObject` — the metric shapes below are nested
/// enough that hand-walking the JSON would be the error-prone way to do it.
#[derive(Serialize, Clone, Debug)]
pub struct HpaInfo {
    pub namespace: String,
    pub name: String,
    /// `spec.scaleTargetRef` — nearly always a Deployment.
    pub target_kind: String,
    pub target_name: String,
    pub min_replicas: i64,
    pub max_replicas: i64,
    pub current_replicas: i64,
    /// What the HPA has decided it wants. Differs from `current_replicas`
    /// while a scale is in flight, and is the more interesting of the two when
    /// they disagree.
    pub desired_replicas: i64,
    /// Current against target, per metric, in the manifest's declaration
    /// order: `cpu: 1%/70%, memory: 42%/80%`. The same summary
    /// `kubectl get hpa` prints, and the reason this tab is worth having next
    /// to the Workloads one.
    pub targets: String,
    /// `AbleToScale` — false when the HPA cannot act at all (a missing target,
    /// or a failed scale subresource call).
    pub able_to_scale: bool,
    /// `ScalingActive` — false when the metrics themselves are unavailable,
    /// which is the classic HPA failure and looks identical to "idle" in the
    /// replica counts alone.
    pub scaling_active: bool,
    /// `ScalingLimited` — the HPA wants to move further but is held at `min`
    /// or `max`. Not a fault, but it is the thing to know before wondering why
    /// load is not being absorbed.
    pub scaling_limited: bool,
    /// The reason and message off whichever condition is unhealthy, since that
    /// is where the actual diagnosis lives (`FailedGetResourceMetric` and
    /// friends). Empty when everything is fine.
    pub condition_reason: String,
    pub last_scale_at: Option<String>,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
}

/// KEDA autoscalers. Same `installed` reasoning as `NapResult`.
#[derive(Serialize, Clone, Debug)]
pub struct KedaResult {
    pub installed: bool,
    pub error: Option<String>,
    pub scaled_objects: Vec<KedaScaledObjectInfo>,
}

/// A KEDA `ScaledObject` or `ScaledJob`. Both are listed together with `kind`
/// telling them apart: they answer the same operational question ("what is
/// event-scaling here, and is it working"), and separating them into two
/// tables would split that view for no benefit.
#[derive(Serialize, Clone, Debug)]
pub struct KedaScaledObjectInfo {
    pub namespace: String,
    pub name: String,
    pub kind: String,
    /// What's being scaled. For a ScaledJob this is the Job template rather
    /// than an existing workload, so `target_kind` is "Job".
    pub target_kind: String,
    pub target_name: String,
    pub min_replicas: i64,
    pub max_replicas: i64,
    /// Trigger types in declaration order, comma-joined (e.g. "azure-servicebus, cron").
    pub triggers: String,
    pub ready: bool,
    /// KEDA reports Active separately from Ready: Ready means the autoscaler
    /// is wired up, Active means a trigger is currently firing.
    pub active: bool,
    pub paused: bool,
    pub age_days: i64,
    pub age_seconds: i64,
    /// When the object was created, RFC 3339 in UTC: what the age above is
    /// counted from, for the frontend's exact-time tooltip. `None` when the
    /// API server sent no `creationTimestamp`.
    pub created_at: Option<String>,
}

pub type GitOpsAppManifest = ObjectManifest;

/// What a drain asked the API server to do, and what it declined.
///
/// Split three ways rather than reported as a count, because the interesting
/// cases are the ones that didn't move: a PodDisruptionBudget refusing an
/// eviction is the answer you actually came for.
#[derive(Serialize, Clone, Debug)]
pub struct DrainReport {
    pub node: String,
    pub cordoned: bool,
    pub evicting: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<String>,
}

/// One Helm release at its latest revision, decoded out of the
/// `helm.sh/release.v1` Secret that Helm uses as its storage backend.
/// Mirrors a row of `helm list --all-namespaces`.
#[derive(Serialize, Clone, Debug)]
pub struct HelmReleaseInfo {
    pub namespace: String,
    pub name: String,
    pub revision: i64,
    pub status: String,
    pub chart_name: String,
    pub chart_version: String,
    pub app_version: String,
    /// Helm's own summary of what the last operation did ("Install complete",
    /// or an upgrade's failure reason).
    pub description: String,
    pub last_deployed: Option<String>,
    pub first_deployed: Option<String>,
    /// How many revisions Helm still has stored for this release.
    pub revision_count: i64,
    /// How many of those are in `failed` state.
    ///
    /// Read off the `status` label the listing already walks, so it costs no
    /// extra request. Worth carrying because the current revision alone hides
    /// it completely: a release that failed to upgrade fifteen times and then
    /// succeeded reads as plain `deployed`.
    pub failed_revisions: i64,
    /// Age since `last_deployed`, matching the other tabs' Age columns.
    pub age_days: i64,
    pub age_seconds: i64,
}


/// Everything a pod diagnosis will send, assembled and redacted but not yet
/// sent — returned to the frontend so the exact payload can be inspected
/// first. Sending log data is the highest-exposure thing this app does, so it
/// is shown rather than implied.
#[derive(Serialize, Clone, Debug)]
pub struct ClaudeDiagnosisPayload {
    /// The verbatim user message that will be sent.
    pub prompt: String,
    /// What redaction removed, e.g. "Redacted: 3× email address, 1× JWT".
    pub redaction_summary: String,
    /// Set when logs were trimmed, e.g. "showing the last 200 of 400 lines".
    pub log_note: Option<String>,
    /// Rough size estimate (~4 chars/token) for conveying scale. Not a
    /// count_tokens call — that would send the payload before approval.
    pub approx_tokens: u32,
}

/// One stored revision of a Helm release.
///
/// `description` is the field worth having: on a failure Helm records the
/// actual error there — the RBAC denial, the timeout, the immutable field —
/// and it exists nowhere else once the revision is superseded.
#[derive(Serialize, Clone, Debug)]
pub struct HelmRevisionInfo {
    pub revision: i64,
    pub status: String,
    /// Empty when this revision's payload was not read. The listing knows
    /// every revision's status from its label, but the description costs a
    /// decode, so only the ones worth reading are fetched.
    pub description: String,
    pub deployed_at: Option<String>,
}

/// `helm get values` / `helm get manifest` / `helm get notes` for one release,
/// fetched on demand rather than as part of the list.
#[derive(Serialize, Clone, Debug)]
pub struct HelmReleaseDetail {
    /// User-supplied values (Helm's `config`), rendered as YAML. Empty when
    /// the release was installed with no overrides.
    pub values_yaml: String,
    /// The chart's own default values, for comparison against the above.
    pub default_values_yaml: String,
    pub manifest: String,
    pub notes: String,
}

/// A Namespace. Mirrors `NamespaceInfo` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct NamespaceInfo {
    pub name: String,
    /// `Active`, or `Terminating` while its contents are being deleted — a
    /// namespace stuck there is the usual reason to come looking.
    pub status: String,
    /// `key=value`, sorted, for display and filtering.
    pub labels: Vec<String>,
    pub age_days: i64,
    pub age_seconds: i64,
    pub created_at: Option<String>,
}

/// A Service. Mirrors `ServiceInfo` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ServiceInfo {
    pub namespace: String,
    pub name: String,
    /// `ClusterIP`, `NodePort`, `LoadBalancer` or `ExternalName`.
    pub service_type: String,
    /// `None` for a headless Service, as kubectl prints it.
    pub cluster_ip: String,
    /// What reaches it from outside: a LoadBalancer's assigned IPs or
    /// hostnames, `spec.externalIPs`, or an ExternalName's target. Empty when
    /// there is none — including a LoadBalancer still waiting for one.
    pub external: Vec<String>,
    /// kubectl's `PORT(S)` shape: `80/TCP`, or `80:30080/TCP` with a node port.
    pub ports: Vec<String>,
    /// `key=value`, sorted. Empty for a selector-less Service.
    pub selector: Vec<String>,
    /// A LoadBalancer with no address yet: provisioning, or stuck.
    pub pending_load_balancer: bool,
    /// Ready endpoints behind it, from its EndpointSlices. `None` when there is
    /// nothing to count against — no selector, or an ExternalName — or when
    /// EndpointSlices could not be listed.
    pub endpoints_ready: Option<i64>,
    pub endpoints_total: Option<i64>,
    pub age_days: i64,
    pub age_seconds: i64,
    pub created_at: Option<String>,
}

/// One `host` + `path` → backend line of an Ingress.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct IngressRuleInfo {
    /// `*` for a rule with no host.
    pub host: String,
    pub path: String,
    /// `service:port`, or `Kind/name` for a resource backend.
    pub backend: String,
}

/// An Ingress (networking.k8s.io/v1). Mirrors `IngressInfo` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct IngressInfo {
    pub namespace: String,
    pub name: String,
    /// `spec.ingressClassName`, falling back to the older
    /// `kubernetes.io/ingress.class` annotation. Empty: the cluster default.
    pub class: String,
    /// Every host its rules name, deduplicated; `*` for a host-less rule.
    pub hosts: Vec<String>,
    /// What the controller published in `status.loadBalancer`: IPs or
    /// hostnames. Empty until a controller has picked it up.
    pub address: Vec<String>,
    pub tls: bool,
    pub rules: Vec<IngressRuleInfo>,
    pub default_backend: Option<String>,
    pub age_days: i64,
    pub age_seconds: i64,
    pub created_at: Option<String>,
}

/// A PersistentVolumeClaim. Mirrors `PvcInfo` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct PvcInfo {
    pub namespace: String,
    pub name: String,
    /// `Bound`, `Pending` or `Lost`.
    pub status: String,
    /// The PersistentVolume it is bound to. Empty until bound.
    pub volume: String,
    /// What the bound volume provides (`status.capacity.storage`). Empty until bound.
    pub capacity: String,
    /// What was asked for (`spec.resources.requests.storage`).
    pub requested: String,
    /// kubectl's abbreviations: RWO, ROX, RWX, RWOP.
    pub access_modes: Vec<String>,
    pub storage_class: String,
    pub volume_mode: String,
    pub age_days: i64,
    pub age_seconds: i64,
    pub created_at: Option<String>,
}

/// A PersistentVolume. Mirrors `PvInfo` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct PvInfo {
    pub name: String,
    pub capacity: String,
    pub access_modes: Vec<String>,
    /// `Retain`, `Delete` or `Recycle`.
    pub reclaim_policy: String,
    /// `Available`, `Bound`, `Released`, `Failed` or `Pending`.
    pub status: String,
    /// The claim it is bound to, as `namespace/name`. Empty when unclaimed.
    pub claim_namespace: String,
    pub claim_name: String,
    pub storage_class: String,
    /// What backs it: the CSI driver (`disk.csi.azure.com`), or the in-tree
    /// volume type for an older volume (`azureDisk`, `nfs`, `hostPath`, …).
    pub source: String,
    /// `status.reason`, set when a volume has Failed.
    pub reason: String,
    pub age_days: i64,
    pub age_seconds: i64,
    pub created_at: Option<String>,
}

/// One key of a ConfigMap, without its value. Mirrors `ConfigMapKeyInfo` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ConfigMapKeyInfo {
    pub name: String,
    /// Length in bytes: the text for `data`, the decoded bytes for `binaryData`.
    pub bytes: usize,
    /// From `binaryData`, which has no text to show.
    pub binary: bool,
}

/// A ConfigMap, listed with its keys and their sizes but not their values:
/// a cluster's ConfigMaps can run to megabytes (dashboards, CA bundles, whole
/// config files), which the table does not need. Mirrors `ConfigMapInfo` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ConfigMapInfo {
    pub namespace: String,
    pub name: String,
    pub keys: Vec<ConfigMapKeyInfo>,
    pub total_bytes: usize,
    pub immutable: bool,
    pub age_days: i64,
    pub age_seconds: i64,
    pub created_at: Option<String>,
}

/// One key of a ConfigMap with its value, for the panel's Data view.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ConfigMapEntry {
    pub key: String,
    /// The text. Empty for a `binaryData` key, which is not shown.
    pub value: String,
    pub binary: bool,
    pub bytes: usize,
}

/// An HPA's YAML and what its panel's Overview shows, from one fetch.
#[derive(Serialize, Clone, Debug)]
pub struct HpaManifest {
    pub yaml_full: String,
    pub yaml_without_managed_fields: String,
    pub detail: HpaDetail,
}

/// One declared metric beside its current reading. Mirrors `HpaMetricRow` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct HpaMetricRow {
    /// `Resource`, `ContainerResource`, `Pods`, `Object` or `External`.
    pub kind: String,
    /// `cpu`, `sidecar/memory`, `queue_length`.
    pub name: String,
    /// `70%`, or a quantity.
    pub target: String,
    /// The same form, or `<unknown>` when the HPA has no reading.
    pub current: String,
}

/// What an HPA's YAML buries. Mirrors `HpaDetail` in types.ts.
#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct HpaDetail {
    /// The replica bounds and counts, target and last scale, from the same
    /// object as the metrics and conditions below. Not from the table's row,
    /// which refreshes on its own clock: mixing the two could pair one
    /// revision's replica count with another's ScalingLimited message.
    pub target_kind: String,
    pub target_name: String,
    pub min_replicas: i64,
    pub max_replicas: i64,
    pub current_replicas: i64,
    pub desired_replicas: i64,
    pub last_scale_at: Option<String>,
    pub metrics: Vec<HpaMetricRow>,
    /// How it scales up and down, one line per rule — or Kubernetes' defaults,
    /// said as such, when `behavior` is not set.
    pub scale_up: Vec<String>,
    pub scale_down: Vec<String>,
    pub behavior_is_default: bool,
    pub conditions: Vec<PodConditionInfo>,
    /// The object that owns it, when one does — a KEDA ScaledObject creates and
    /// owns the HPA that does its scaling.
    pub owner_kind: String,
    pub owner_name: String,
}
