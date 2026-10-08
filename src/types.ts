// Mirrors src-tauri/src/models.rs — keep both sides in sync.

export interface ClusterEntry {
  context_name: string;
  cluster_name: string;
  server: string;
  namespace: string | null;
  is_aks: boolean;
}

export interface ClusterOverview {
  context_name: string;
  reachable: boolean;
  error: string | null;
  kubernetes_version: string | null;
  node_count: number;
  nodes_ready: number;
  namespace_count: number;
  pod_count: number;
  pods_running: number;
  pods_not_ready: number;
  warning_event_count: number;
}

export interface NodeInfo {
  name: string;
  ready: boolean;
  roles: string[];
  kubelet_version: string;
  os_image: string;
  instance_type: string | null;
  /** `karpenter.sh/nodepool` label — null on a node NAP didn't provision. */
  node_pool: string | null;
  zone: string | null;
  cpu_capacity: string;
  cpu_allocatable: string;
  memory_capacity: string;
  memory_allocatable: string;
  memory_allocatable_ki: number | null;
  cpu_usage_millicores: number | null;
  memory_usage_ki: number | null;
  conditions: string[];
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
  unschedulable: boolean;
}

export interface PodInfo {
  name: string;
  namespace: string;
  node: string | null;
  phase: string;
  ready: string;
  restarts: number;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
  owner_kind: string | null;
  owner_name: string | null;
  cpu_usage_millicores: number | null;
  memory_usage_ki: number | null;
  status_reason: string | null;
  /** The container that is failing, so a Diagnose targets it. Null for a pod-level failure such as Evicted. */
  failure_container: string | null;
  /** The failing container's reason and message, or null when nothing is wrong. */
  failure_message: string | null;
}

export interface PodManifest {
  containers: string[];
  yaml_full: string;
  yaml_without_managed_fields: string;
  /** What the panel's Overview shows, from the same fetch. */
  detail: PodDetail;
}

/** Mirrors `PodDetail` in models.rs. */
export interface PodDetail {
  phase: string;
  /** Set for a pod-level failure such as Evicted or UnexpectedAdmissionError. */
  reason: string;
  message: string;
  node: string;
  pod_ip: string;
  host_ip: string;
  qos_class: string;
  service_account: string;
  priority_class: string;
  restart_policy: string;
  start_time: string | null;
  /** As the API records it — usually a ReplicaSet. */
  controller_kind: string;
  controller_name: string;
  init_containers: ContainerDetail[];
  containers: ContainerDetail[];
  conditions: PodConditionInfo[];
  references: PodReference[];
}

/** Mirrors `ContainerDetail` in models.rs. */
export interface ContainerDetail {
  name: string;
  image: string;
  ready: boolean;
  restart_count: number;
  /** `running`, `waiting`, `terminated`, or empty. */
  state: string;
  state_reason: string;
  state_message: string;
  state_since: string | null;
  exit_code: number | null;
  last_reason: string;
  last_exit_code: number | null;
  last_finished: string | null;
  last_message: string;
  cpu_request: string;
  cpu_limit: string;
  memory_request: string;
  memory_limit: string;
  ports: string[];
}

export interface PodConditionInfo {
  condition_type: string;
  status: string;
  reason: string;
  message: string;
  last_transition: string | null;
}

export interface PodReference {
  kind: "ConfigMap" | "Secret" | "PersistentVolumeClaim";
  name: string;
  via: string[];
}

export interface NodeManifest {
  yaml_full: string;
  yaml_without_managed_fields: string;
  /** What the panel's Overview shows, from the same fetch. */
  detail: NodeDetail;
}

/** Mirrors `NodeDetail` in models.rs. */
export interface NodeDetail {
  /** From the node itself, so right even before the Nodes tab has loaded. */
  unschedulable: boolean;
  roles: string[];
  instance_type: string;
  zone: string;
  /** `karpenter.sh/nodepool` — a NAP pool; empty otherwise. */
  nap_pool: string;
  /** `agentpool` — the AKS node pool. */
  agent_pool: string;
  kubelet_version: string;
  os_image: string;
  created_at: string | null;
  conditions: PodConditionInfo[];
  /** `key=value:Effect`, or `key:Effect`. */
  taints: string[];
  labels: string[];
  kernel_version: string;
  container_runtime: string;
  architecture: string;
  operating_system: string;
  internal_ip: string;
  external_ip: string;
  pod_cidrs: string[];
  provider_id: string;
  /** cpu, memory, pods, ephemeral-storage and any extended resources, as quantities. */
  capacity: Record<string, string>;
  allocatable: Record<string, string>;
}

export interface WorkloadManifest {
  yaml_full: string;
  yaml_without_managed_fields: string;
  containers: string[];
  /** What the panel's Overview shows, from the same fetch. */
  detail: WorkloadDetail;
}

/** Mirrors `WorkloadDetail` in models.rs. */
export interface WorkloadDetail {
  strategy: string;
  selector: string[];
  /** The pod template's labels, `key=value` — what a Service selects on. */
  template_labels: string[];
  revision: string;
  /** Set only while a StatefulSet rollout is underway. */
  update_revision: string;
  generation: number;
  observed_generation: number;
  paused: boolean;
  service_name: string;
  pod_management_policy: string;
  volume_claim_templates: string[];
  node_selector: string[];
  misscheduled: number;
  conditions: PodConditionInfo[];
  /** Spec only — a template has no status. */
  init_containers: ContainerDetail[];
  containers: ContainerDetail[];
  references: PodReference[];
}

export interface WorkloadInfo {
  kind: string;
  name: string;
  namespace: string;
  desired: number;
  ready: number;
  updated: number;
  available: number;
  healthy: boolean;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
  version: string;
  version_from_label: boolean;
  images: string[];
  chart: string | null;
  /** The most informative failing condition, or null when the workload is healthy. */
  failure_message: string | null;
}

export interface WorkloadRevisionInfo {
  revision: number;
  name: string;
  replicas: number | null;
  ready_replicas: number | null;
  images: string[];
  template_yaml: string;
  current: boolean;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
}

export interface EventInfo {
  namespace: string;
  involved_object: string;
  reason: string;
  message: string;
  event_type: string;
  count: number;
  last_seen: string | null;
}

export interface ResourceUsageSummary {
  metrics_available: boolean;
  cpu_used_millicores: number;
  cpu_allocatable_millicores: number;
  memory_used_ki: number;
  memory_allocatable_ki: number;
}

export type MetricsBackendKind = "Prometheus" | "VictoriaMetrics";

export interface MetricsBackendInfo {
  kind: MetricsBackendKind;
  namespace: string;
  service_name: string;
  port: number;
  api_path_prefix: string;
}

export interface MetricsBackendTestResult {
  ok: boolean;
  message: string;
  container_series: number | null;
}

export interface MetricSample {
  timestamp: number;
  value: number;
}

export interface MetricsOverTimeResult {
  backend: MetricsBackendInfo | null;
  error: string | null;
  cpu_cores: MetricSample[];
  memory_bytes: MetricSample[];
  ephemeral_storage_bytes: MetricSample[];
  /** Empty unless DCGM exporter is running and this scope actually touches a GPU — which is what tells the UI whether to draw the GPU charts at all. */
  gpu_util_percent: MetricSample[];
  gpu_memory_bytes: MetricSample[];
  gpu_tensor_percent: MetricSample[];
}

export interface GitOpsAppInfo {
  namespace: string;
  name: string;
  destination_namespace: string;
  sync_status: string;
  health_status: string;
  repo_url: string;
  path: string;
  target_revision: string;
  revision: string;
  /** When the last sync operation completed (or started, if one is still running). Not ArgoCD's `reconciledAt` — that advances on every diff pass regardless of whether a sync happened, so it can't tell a fresh app from a stale one. */
  last_synced_at: string | null;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
}

export interface GitOpsResult {
  installed: boolean;
  error: string | null;
  apps: GitOpsAppInfo[];
}

/**
 * One object rendered to YAML twice, so a detail panel's "show managed
 * fields" toggle switches between them without a second round trip. Shared by
 * every CRD-backed panel — ArgoCD Applications, Karpenter NodePools, KEDA
 * ScaledObjects — with the aliases keeping the names their panels already use.
 */
export interface ObjectManifest {
  yaml_full: string;
  yaml_without_managed_fields: string;
}

/**
 * One HorizontalPodAutoscaler. Mirrors `HpaInfo` in models.rs.
 *
 * No `installed` wrapper, unlike KedaResult/NapResult beside it:
 * `autoscaling/v2` is part of Kubernetes rather than an addon, so an empty
 * list always means "nothing is autoscaled here".
 */
export interface HpaInfo {
  namespace: string;
  name: string;
  target_kind: string;
  target_name: string;
  min_replicas: number;
  max_replicas: number;
  current_replicas: number;
  desired_replicas: number;
  /** `cpu: 1%/70%, memory: 42%/80%` — current against target, per metric. */
  targets: string;
  able_to_scale: boolean;
  /** False when the metrics are unavailable — the classic HPA failure. */
  scaling_active: boolean;
  /** Held at min or max. Normal at min, so not on its own a fault. */
  scaling_limited: boolean;
  /** Reason and message off whichever condition is unhealthy; empty when fine. */
  condition_reason: string;
  last_scale_at: string | null;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
}

export interface GitOpsAppManifest extends ObjectManifest {
  /** What the panel's Overview shows, read from the same fetch as the YAML. */
  detail: GitOpsDetail;
}

/** One source of an Application (several for a multi-source app). */
export interface GitOpsSourceInfo {
  repo_url: string;
  path: string;
  chart: string;
  target_revision: string;
  /** The revision it is synced to (a commit ID shortened). */
  revision: string;
}

/** One resource the Application manages, from `status.resources`. */
export interface GitOpsManagedResource {
  group: string;
  kind: string;
  namespace: string;
  name: string;
  /** `Synced` or `OutOfSync`. */
  status: string;
  /** Empty for a kind Argo CD assigns no health to, or when it keeps health in its app tree. */
  health: string;
  health_message: string;
  requires_pruning: boolean;
}

/** A resource the last sync failed to apply, or a hook that failed, with Argo CD's reason. */
export interface GitOpsSyncFailure {
  /** `PreSync`, `Sync`, `PostSync`… for a hook; empty for a resource. */
  hook_type: string;
  kind: string;
  namespace: string;
  name: string;
  message: string;
}

export interface GitOpsHistoryEntry {
  /** One per source, in the sources' order; commit IDs shortened. */
  revisions: string[];
  deployed_at: string | null;
}

/** An Argo CD condition. They have no status: one exists only while it holds. */
export interface GitOpsCondition {
  condition_type: string;
  message: string;
  last_transition: string | null;
}

/** What an Application's YAML buries. Mirrors `GitOpsDetail` in models.rs. */
export interface GitOpsDetail {
  project: string;
  sources: GitOpsSourceInfo[];
  destination_server: string;
  destination_name: string;
  destination_namespace: string;
  /** Deploys to the cluster Argo CD runs in — the one this panel is open on. */
  destination_in_cluster: boolean;
  sync_status: string;
  health_status: string;
  health_message: string;
  automated: boolean;
  prune: boolean;
  self_heal: boolean;
  sync_options: string[];
  retry_limit: number | null;
  /** The last sync operation: `Succeeded`, `Failed`, `Error`, `Running`… */
  operation_phase: string;
  operation_message: string;
  operation_started: string | null;
  operation_finished: string | null;
  operation_retries: number | null;
  sync_failures: GitOpsSyncFailure[];
  resources: GitOpsManagedResource[];
  /** Argo CD keeps each resource's health in its app tree, so `resources[].health` is empty. */
  resource_health_in_tree: boolean;
  conditions: GitOpsCondition[];
  images: string[];
  /** Newest first. */
  history: GitOpsHistoryEntry[];
}

/**
 * One resource an ArgoCD Application manages that is **not** Synced, with both
 * sides of its diff already normalised for line-diffing. Mirrors
 * `GitOpsResourceDiff` in models.rs.
 *
 * This is a *drift* diff — the manifest last applied to the resource versus
 * its live state — and deliberately not ArgoCD's own diff, which compares
 * against Git and is computed in ArgoCD's repo-server rather than stored on
 * the Application. See the Rust struct for the full reasoning.
 */
export interface GitOpsResourceDiff {
  /** Empty for core resources: `status.resources[]` omits the key entirely. */
  group: string;
  version: string;
  kind: string;
  /** Empty for cluster-scoped resources. */
  namespace: string;
  name: string;
  sync_status: string;
  /** Empty when `desired_available` is false. */
  desired_yaml: string;
  /** Live, with known server-assigned defaults suppressed. */
  live_yaml: string;
  /** Live, with nothing suppressed — the other side of the defaults toggle. */
  live_yaml_full: string;
  suppressed_lines: number;
  /** False for a server-side-applied resource, which has no annotation to compare against. */
  desired_available: boolean;
  /** Set when this one resource could not be read (RBAC, or since deleted). */
  error: string | null;
}

/** What a drain asked the API server to do, and what it declined. */
export interface DrainReport {
  node: string;
  cordoned: boolean;
  evicting: string[];
  skipped: string[];
  failed: string[];
}

export interface HelmReleaseInfo {
  namespace: string;
  name: string;
  revision: number;
  status: string;
  chart_name: string;
  chart_version: string;
  app_version: string;
  description: string;
  last_deployed: string | null;
  first_deployed: string | null;
  revision_count: number;
  failed_revisions: number;
  age_days: number;
  age_seconds: number;
}

/** An External Secrets Operator `ExternalSecret`. Mirrors `ExternalSecretInfo` in models.rs. */
export interface ExternalSecretInfo {
  namespace: string;
  name: string;
  store_kind: string;
  store_name: string;
  /** The Secret it writes — `spec.target.name`, defaulting to its own name. */
  target_name: string;
  target_type: string;
  /** As written, e.g. "1h". Empty means ESO's default. */
  refresh_interval: string;
  data_count: number;
  data_from_count: number;
  ready: boolean;
  /** From the Ready condition. Empty when there is no condition yet. */
  reason: string;
  message: string;
  last_refresh: string | null;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
}

/** `installed: false` means no served version of the CRD answered — ESO is not on this cluster. */
export interface ExternalSecretsResult {
  installed: boolean;
  error: string | null;
  external_secrets: ExternalSecretInfo[];
}

export interface ExternalSecretMapping {
  secret_key: string;
  remote_key: string;
  property: string;
  version: string;
}

export interface ExternalSecretDetail {
  mappings: ExternalSecretMapping[];
  /** `spec.dataFrom`, one readable line per entry. */
  data_from: string[];
  manifest: ObjectManifest;
}

/** One key of a Secret — its name and decoded size, never its value. Mirrors `SecretKeyInfo` in models.rs. */
export interface SecretKeyInfo {
  name: string;
  bytes: number;
}

/** One Secret as the Secrets tab lists it. Mirrors `SecretInfo` in models.rs. */
export interface SecretInfo {
  namespace: string;
  name: string;
  secret_type: string;
  /** Null for a Helm release Secret, which is listed metadata-only: unknown, not empty. */
  keys: SecretKeyInfo[] | null;
  immutable: boolean;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
}

/** What the Secret panel loads: the key list and the redacted YAML. */
export interface SecretDetail {
  keys: SecretKeyInfo[];
  manifest: ObjectManifest;
  /** What the panel's Overview shows — about the Secret, never its values. */
  overview: SecretOverview;
}

/** One certificate's public fields. Mirrors `CertificateInfo` in x509.rs. */
export interface CertificateInfo {
  subject: string;
  issuer: string;
  sans: string[];
  not_before: string | null;
  not_after: string | null;
  is_ca: boolean;
}

/** The certificates in one key, in the bundle's order. */
export interface SecretCertificates {
  key: string;
  certificates: CertificateInfo[];
  /** The end-entity certificate, found before the cap; null for a bundle of CAs. */
  leaf: CertificateInfo | null;
  /** How many the key holds — more than shown for a CA bundle. */
  total: number;
}

/** What a Secret is for and who writes it. Mirrors `SecretOverview` in models.rs. */
export interface SecretOverview {
  /** From the fetched Secret itself. */
  secret_type: string;
  immutable: boolean;
  created_at: string | null;
  owners: { kind: string; name: string }[];
  managed_by: string;
  helm_release: string;
  helm_namespace: string;
  cert_manager_certificate: string;
  cert_manager_issuer: string;
  cert_manager_issuer_kind: string;
  service_account: string;
  certificates: SecretCertificates[];
  /** Registry hosts only. */
  registries: string[];
}

/** One revealed value. Exactly one of `text` and `base64` is set. */
export interface SecretValue {
  bytes: number;
  text: string | null;
  base64: string | null;
}

export interface HelmReleaseDetail {
  values_yaml: string;
  default_values_yaml: string;
  manifest: string;
  notes: string;
  /** What the panel's Overview shows, read from the same payload. */
  overview: HelmOverview;
}

/** A subchart, with whether Helm enabled it for this release. */
export interface HelmDependency {
  name: string;
  alias: string;
  version: string;
  repository: string;
  /** The values path that switches it, e.g. `redis.enabled`. */
  condition: string;
  enabled: boolean;
}

/** One object the release rendered. */
export interface HelmResource {
  api_version: string;
  kind: string;
  /** Empty when the chart leaves it to the release namespace, or for a cluster-scoped kind. */
  namespace: string;
  name: string;
  /** From API discovery for its group/version/kind; null when discovery could not say. */
  namespaced: boolean | null;
}

export interface HelmHook {
  name: string;
  kind: string;
  events: string[];
  /** `Succeeded`, `Failed`, `Running`; empty if it has not run. */
  phase: string;
  completed_at: string | null;
}

/** One stored revision, from its Secret's labels. */
export interface HelmHistoryEntry {
  revision: number;
  status: string;
  modified_at: string | null;
}

/** What a release's payload buries. Mirrors `HelmOverview` in models.rs. */
export interface HelmOverview {
  status: string;
  description: string;
  first_deployed: string | null;
  last_deployed: string | null;
  chart_name: string;
  chart_version: string;
  app_version: string;
  chart_description: string;
  home: string;
  sources: string[];
  kube_version: string;
  deprecated: boolean;
  dependencies: HelmDependency[];
  /** Top-level keys of the user-supplied values. */
  overridden_keys: string[];
  resources: HelmResource[];
  hooks: HelmHook[];
  /** Newest first. */
  history: HelmHistoryEntry[];
  history_error: string | null;
}

export type AiProvider = "claude" | "gemini" | "ollama";

/** Which model answers, and whether it can be reached. */
export interface AiAuthState {
  provider: AiProvider;
  label: string;
  model: string;
  base_url: string;
  /** False for Ollama, which is local and takes no credential. */
  needs_api_key: boolean;
  signed_in: boolean;
  source: string | null;
  detail: string | null;
}


export interface ClaudeDiagnosisPayload {
  prompt: string;
  redaction_summary: string;
  log_note: string | null;
  approx_tokens: number;
}

export type TabId =
  | "overview"
  | "nodes"
  | "namespaces"
  | "workloads"
  | "pods"
  | "services"
  | "ingresses"
  | "pvcs"
  | "pvs"
  | "resources"
  | "metrics"
  | "events"
  | "nap"
  | "hpa"
  | "keda"
  | "gitops"
  | "helm"
  | "configmaps"
  | "secrets"
  | "serviceaccounts"
  | "externalsecrets"
  | "secretstores"
  | "pdbs"
  | "cost";

/** Azure Node Auto Provisioning (managed Karpenter). `installed: false` means the CRDs aren't registered, i.e. NAP is off for this cluster. */
export interface NapResult {
  installed: boolean;
  error: string | null;
  node_pools: NapNodePoolInfo[];
}

export interface NapNodePoolManifest extends ObjectManifest {
  /** What the panel's Overview shows, read from the same fetch as the YAML. */
  detail: NapDetail;
}

/** One scheduling requirement nodes from the pool must meet. */
export interface NapRequirement {
  key: string;
  operator: string;
  values: string[];
  /** At least this many distinct values must remain possible. */
  min_values: number | null;
}

/** How many nodes Karpenter may disrupt at once, for which reasons, and when. */
export interface NapBudget {
  /** A count or a percentage; `"0"` blocks disruption. */
  nodes: string;
  /** Empty for every reason. */
  reasons: string[];
  /** Cron schedule the budget is active from, for `duration`; empty for always. */
  schedule: string;
  duration: string;
}

/** What the pool has provisioned of one resource, against its limit. */
export interface NapResourceUse {
  name: string;
  unit: "millicores" | "ki" | "count";
  used: number;
  /** `null` when the pool sets no limit, which Karpenter treats as unbounded. */
  limit: number | null;
}

/** What a NodePool's YAML buries. Mirrors `NapDetail` in models.rs. */
export interface NapDetail {
  node_class_kind: string;
  node_class_name: string;
  /** Higher is tried first; `null` is the lowest. */
  weight: number | null;
  requirements: NapRequirement[];
  /** `key=value:Effect`. */
  taints: string[];
  startup_taints: string[];
  /** `key=value`. */
  labels: string[];
  /** A duration or `Never`; Karpenter's default applied. */
  expire_after: string;
  /** Empty for no limit. */
  termination_grace_period: string;
  /** `WhenEmptyOrUnderutilized` or `WhenEmpty` (v1beta1: `WhenUnderutilized`). */
  consolidation_policy: string;
  /** A duration or `Never`; empty for a v1beta1 pool that sets none — no delay. */
  consolidate_after: string;
  /** The pool's budgets, or Karpenter's default of 10% when it sets none. */
  budgets: NapBudget[];
  budgets_default: boolean;
  resources: NapResourceUse[];
  conditions: PodConditionInfo[];
}

export interface NapNodePoolInfo {
  name: string;
  node_class: string;
  ready: boolean;
  status_reason: string;
  /** From the pool's own `status.resources.nodes` — how many nodes it has actually provisioned. */
  nodes: number;
  cpu_used_millicores: number;
  /** `null` means Karpenter enforces no cap at all — distinct from a cap of zero. */
  cpu_limit_millicores: number | null;
  memory_used_ki: number;
  memory_limit_ki: number | null;
  weight: number;
  capacity_types: string;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
}

/** KEDA autoscalers. Same `installed` semantics as `NapResult`. */
export interface KedaResult {
  installed: boolean;
  error: string | null;
  scaled_objects: KedaScaledObjectInfo[];
}

export interface KedaScaledObjectInfo {
  namespace: string;
  name: string;
  kind: string;
  target_kind: string;
  target_name: string;
  min_replicas: number;
  max_replicas: number;
  triggers: string;
  ready: boolean;
  /** Distinct from `ready`: Ready means wired up, Active means a trigger is currently firing. */
  active: boolean;
  paused: boolean;
  age_days: number;
  age_seconds: number;
  /** When it was created, RFC 3339 UTC — what the age is counted from. */
  created_at: string | null;
}

/** A Namespace. Mirrors `NamespaceInfo` in models.rs. */
export interface NamespaceInfo {
  name: string;
  /** `Active`, or `Terminating` while its contents are deleted. */
  status: string;
  /** `key=value`, sorted. */
  labels: string[];
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

/** A Service. Mirrors `ServiceInfo` in models.rs. */
export interface ServiceInfo {
  namespace: string;
  name: string;
  service_type: string;
  /** `None` for a headless Service. */
  cluster_ip: string;
  /** LoadBalancer addresses, externalIPs, or an ExternalName's target. */
  external: string[];
  /** kubectl's shape: `80/TCP`, `80:30080/TCP`. */
  ports: string[];
  selector: string[];
  /** A LoadBalancer with no address yet. */
  pending_load_balancer: boolean;
  /** Ready endpoints behind it; null when there is nothing to count or slices could not be listed. */
  endpoints_ready: number | null;
  endpoints_total: number | null;
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

export interface IngressRuleInfo {
  /** `*` for a host-less rule. */
  host: string;
  path: string;
  /** `service:port`, or `Kind/name` for a resource backend. */
  backend: string;
}

/** An Ingress. Mirrors `IngressInfo` in models.rs. */
export interface IngressInfo {
  namespace: string;
  name: string;
  class: string;
  hosts: string[];
  /** What the controller published; empty until one has picked it up. */
  address: string[];
  tls: boolean;
  rules: IngressRuleInfo[];
  default_backend: string | null;
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

/** A PersistentVolumeClaim. Mirrors `PvcInfo` in models.rs. */
export interface PvcInfo {
  namespace: string;
  name: string;
  /** `Bound`, `Pending` or `Lost`. */
  status: string;
  volume: string;
  /** Provided by the bound volume; empty until bound. */
  capacity: string;
  requested: string;
  /** RWO, ROX, RWX, RWOP. */
  access_modes: string[];
  storage_class: string;
  volume_mode: string;
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

/** A PersistentVolume. Mirrors `PvInfo` in models.rs. */
export interface PvInfo {
  name: string;
  capacity: string;
  access_modes: string[];
  reclaim_policy: string;
  /** `Available`, `Bound`, `Released`, `Failed` or `Pending`. */
  status: string;
  claim_namespace: string;
  claim_name: string;
  storage_class: string;
  /** CSI driver, or the in-tree volume type. */
  source: string;
  reason: string;
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

/** The kinds behind the shared resource detail panel. */
export type ResourceKind =
  | "Namespace"
  | "Service"
  | "Ingress"
  | "PersistentVolumeClaim"
  | "PersistentVolume"
  | "ConfigMap"
  | "ServiceAccount"
  | "PodDisruptionBudget"
  | "SecretStore"
  | "ClusterSecretStore";

/** A ServiceAccount. Mirrors `ServiceAccountInfo` in models.rs. */
export interface ServiceAccountInfo {
  namespace: string;
  name: string;
  /** `azure.workload.identity/client-id`: the identity its pods sign in to Azure as. */
  workload_identity_client_id: string;
  workload_identity_tenant_id: string;
  /** Seconds. */
  workload_identity_token_expiration: string;
  image_pull_secrets: string[];
  secrets: string[];
  /** Null when unset, which Kubernetes treats as true. */
  automount_token: boolean | null;
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

/** A PodDisruptionBudget. Mirrors `PdbInfo` in models.rs. */
export interface PdbInfo {
  namespace: string;
  name: string;
  min_available: string | null;
  max_unavailable: string | null;
  selector: string[];
  current_healthy: number;
  desired_healthy: number;
  expected_pods: number;
  /** 0 blocks every voluntary eviction. */
  disruptions_allowed: number;
  unhealthy_pod_eviction_policy: string;
  reason: string;
  message: string;
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

/** An ESO SecretStore or ClusterSecretStore. Mirrors `SecretStoreInfo` in models.rs. */
export interface SecretStoreInfo {
  kind: "SecretStore" | "ClusterSecretStore";
  /** Empty for a ClusterSecretStore. */
  namespace: string;
  name: string;
  /** `azurekv`, `aws`, `vault`… */
  provider: string;
  /** A vault URL, server or region. */
  target: string;
  auth: string;
  identity: string;
  ready: boolean;
  reason: string;
  message: string;
  capabilities: string;
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

/** Same `installed` semantics as `ExternalSecretsResult`. */
export interface SecretStoresResult {
  installed: boolean;
  /** One of the two kinds failed to list; the other's stores are still here. */
  error: string | null;
  stores: SecretStoreInfo[];
}

/** One key of a ConfigMap, without its value. Mirrors `ConfigMapKeyInfo` in models.rs. */
export interface ConfigMapKeyInfo {
  name: string;
  bytes: number;
  /** From `binaryData`: no text to show. */
  binary: boolean;
}

/** A ConfigMap with its keys and sizes, not its values. Mirrors `ConfigMapInfo` in models.rs. */
export interface ConfigMapInfo {
  namespace: string;
  name: string;
  keys: ConfigMapKeyInfo[];
  total_bytes: number;
  immutable: boolean;
  age_days: number;
  age_seconds: number;
  created_at: string | null;
}

/** One key with its value, for the panel's Data view. Mirrors `ConfigMapEntry` in models.rs. */
export interface ConfigMapEntry {
  key: string;
  /** Empty for a binary key. */
  value: string;
  binary: boolean;
  bytes: number;
}

/** An HPA's YAML and what its panel's Overview shows. Mirrors `HpaManifest` in models.rs. */
export interface HpaManifest {
  yaml_full: string;
  yaml_without_managed_fields: string;
  detail: HpaDetail;
}

/** One declared metric beside its reading. Mirrors `HpaMetricRow` in models.rs. */
export interface HpaMetricRow {
  /** `Resource`, `ContainerResource`, `Pods`, `Object` or `External`. */
  kind: string;
  name: string;
  target: string;
  /** Same form as `target`, or `<unknown>` with no reading. */
  current: string;
}

/** Mirrors `HpaDetail` in models.rs. */
export interface HpaDetail {
  /** From the same object as the metrics and conditions — never the table's separately-refreshed row. */
  target_kind: string;
  target_name: string;
  min_replicas: number;
  max_replicas: number;
  current_replicas: number;
  desired_replicas: number;
  last_scale_at: string | null;
  metrics: HpaMetricRow[];
  scale_up: string[];
  scale_down: string[];
  behavior_is_default: boolean;
  conditions: PodConditionInfo[];
  /** A KEDA ScaledObject, when KEDA created this HPA. */
  owner_kind: string;
  owner_name: string;
}

/** A KEDA object's YAML and what its panel's Overview shows. Mirrors `KedaManifest` in models.rs. */
export interface KedaManifest {
  yaml_full: string;
  yaml_without_managed_fields: string;
  detail: KedaDetail;
}

/** Mirrors `KedaTriggerInfo` in models.rs. */
export interface KedaTriggerInfo {
  trigger_type: string;
  name: string;
  /** `key=value`, sorted. */
  metadata: string[];
  /** `TriggerAuthentication/name` or `ClusterTriggerAuthentication/name`. */
  auth_ref: string;
  metric_type: string;
  /** `Happy` or `Failing`; empty when KEDA has not reported on it. */
  health: string;
  failures: number | null;
}

/** Mirrors `KedaDetail` in models.rs. */
export interface KedaDetail {
  target_kind: string;
  target_name: string;
  /** Both kinds; KEDA's default 0 applied when unset. */
  min_replicas: number;
  max_replicas: number;
  idle_replicas: number | null;
  polling_interval: number;
  /** Null for a ScaledJob. */
  cooldown_period: number | null;
  fallback: string;
  paused: boolean;
  paused_replicas: string | null;
  hpa_name: string;
  last_active: string | null;
  scaling_strategy: string;
  triggers: KedaTriggerInfo[];
  conditions: PodConditionInfo[];
}
