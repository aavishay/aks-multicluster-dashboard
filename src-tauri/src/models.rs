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
    /// The workload kind that owns this pod (e.g. "Deployment", "StatefulSet",
    /// "DaemonSet", "Job"), resolved through its ReplicaSet if it has one.
    pub owner_kind: Option<String>,
    pub owner_name: Option<String>,
    pub cpu_usage_millicores: Option<i64>,
    pub memory_usage_ki: Option<i64>,
    pub status_reason: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct PodManifest {
    pub containers: Vec<String>,
    pub yaml_full: String,
    pub yaml_without_managed_fields: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct NodeManifest {
    pub yaml_full: String,
    pub yaml_without_managed_fields: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct WorkloadManifest {
    pub yaml_full: String,
    pub yaml_without_managed_fields: String,
    /// From the workload's own pod template — same for every pod it owns,
    /// so there's no need to ask any particular pod instance for this.
    pub containers: Vec<String>,
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
}

pub type GitOpsAppManifest = ObjectManifest;

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
    /// Age since `last_deployed`, matching the other tabs' Age columns.
    pub age_days: i64,
    pub age_seconds: i64,
}

/// `helm get values` / `helm get manifest` / `helm get notes` for one release,
/// fetched on demand rather than as part of the list.
/// Whether Claude features are usable, and via which credential source.
#[derive(Serialize, Clone, Debug)]
pub struct ClaudeAuthState {
    pub signed_in: bool,
    /// Human-readable credential source ("API key (Keychain)", "environment variable").
    pub source: Option<String>,
    /// Extra context for the panel — e.g. which key is in use, by its last four.
    pub detail: Option<String>,
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
