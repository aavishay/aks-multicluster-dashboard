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
  owner_kind: string | null;
  owner_name: string | null;
  cpu_usage_millicores: number | null;
  memory_usage_ki: number | null;
  status_reason: string | null;
}

export interface PodManifest {
  containers: string[];
  yaml_full: string;
  yaml_without_managed_fields: string;
}

export interface NodeManifest {
  yaml_full: string;
  yaml_without_managed_fields: string;
}

export interface WorkloadManifest {
  yaml_full: string;
  yaml_without_managed_fields: string;
  containers: string[];
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
  version: string;
  version_from_label: boolean;
  images: string[];
  chart: string | null;
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
  age_days: number;
  age_seconds: number;
}

export interface GitOpsResult {
  installed: boolean;
  error: string | null;
  apps: GitOpsAppInfo[];
}

export interface GitOpsAppManifest {
  yaml_full: string;
  yaml_without_managed_fields: string;
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
  age_days: number;
  age_seconds: number;
}

export interface HelmReleaseDetail {
  values_yaml: string;
  default_values_yaml: string;
  manifest: string;
  notes: string;
}

export interface ClaudeAuthState {
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

export type TabId = "overview" | "nodes" | "workloads" | "pods" | "resources" | "metrics" | "events" | "nap" | "keda" | "gitops" | "helm" | "cost";

/** Azure Node Auto Provisioning (managed Karpenter). `installed: false` means the CRDs aren't registered, i.e. NAP is off for this cluster. */
export interface NapResult {
  installed: boolean;
  error: string | null;
  node_pools: NapNodePoolInfo[];
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
}
