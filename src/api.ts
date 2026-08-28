import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  ClaudeAuthState,
  ClaudeDiagnosisPayload,
  ClusterEntry,
  ClusterOverview,
  EventInfo,
  GitOpsAppManifest,
  GitOpsResult,
  HelmReleaseDetail,
  HelmReleaseInfo,
  MetricsBackendInfo,
  MetricsBackendTestResult,
  MetricsOverTimeResult,
  NodeInfo,
  NodeManifest,
  PodInfo,
  PodManifest,
  ResourceUsageSummary,
  WorkloadInfo,
  WorkloadManifest,
  WorkloadRevisionInfo,
} from "./types";

export const api = {
  listClusters: () => invoke<ClusterEntry[]>("list_clusters"),
  kubeconfigPath: () => invoke<string | null>("kubeconfig_path"),
  getOverview: (contextName: string) => invoke<ClusterOverview>("get_cluster_overview", { contextName }),
  getNodes: (contextName: string) => invoke<NodeInfo[]>("get_nodes", { contextName }),
  getNodeManifest: (contextName: string, nodeName: string) =>
    invoke<NodeManifest>("get_node_manifest", { contextName, nodeName }),
  getNodeEvents: (contextName: string, nodeName: string) =>
    invoke<EventInfo[]>("get_node_events", { contextName, nodeName }),
  getPods: (contextName: string, namespace?: string) => invoke<PodInfo[]>("get_pods", { contextName, namespace }),
  /**
   * Same data as `getPods`, but paged server-side. `onPage` fires per page as
   * it arrives, for progressive display.
   *
   * The RESOLVED VALUE is the authoritative complete list — never total up the
   * `onPage` pages instead. Tauri delivers a channel payload over 8KB (which
   * every pod page is) by evaluating JS that makes a second async round trip
   * to fetch the body before invoking the callback, while a command's return
   * value resolves its promise directly. This promise therefore resolves
   * before the final page's callback runs, so page-summing silently loses the
   * last page.
   */
  streamPods: (contextName: string, namespace: string | undefined, onPage: (page: PodInfo[]) => void) => {
    const channel = new Channel<PodInfo[]>();
    channel.onmessage = onPage;
    return invoke<PodInfo[]>("stream_pods", { contextName, namespace, onPage: channel });
  },
  getWorkloads: (contextName: string) => invoke<WorkloadInfo[]>("get_workloads", { contextName }),
  getWorkloadManifest: (contextName: string, kind: string, namespace: string, name: string) =>
    invoke<WorkloadManifest>("get_workload_manifest", { contextName, kind, namespace, name }),
  getWorkloadEvents: (contextName: string, kind: string, namespace: string, name: string) =>
    invoke<EventInfo[]>("get_workload_events", { contextName, kind, namespace, name }),
  getWorkloadRevisions: (contextName: string, kind: string, namespace: string, name: string) =>
    invoke<WorkloadRevisionInfo[]>("get_workload_revisions", { contextName, kind, namespace, name }),
  getEvents: (contextName: string, warningsOnly: boolean) =>
    invoke<EventInfo[]>("get_events", { contextName, warningsOnly }),
  getResourceUsage: (contextName: string) => invoke<ResourceUsageSummary>("get_resource_usage", { contextName }),
  getMetricsOverTime: (contextName: string, rangeMinutes: number, overrideBackend?: MetricsBackendInfo | null) =>
    invoke<MetricsOverTimeResult>("get_metrics_over_time", { contextName, rangeMinutes, overrideBackend }),
  getPodManifest: (contextName: string, namespace: string, podName: string) =>
    invoke<PodManifest>("get_pod_manifest", { contextName, namespace, podName }),
  getPodLogs: (contextName: string, namespace: string, podName: string, container: string, tail: boolean, lines: number) =>
    invoke<string>("get_pod_logs", { contextName, namespace, podName, container, tail, lines }),
  /** Starts a live-follow log stream; `onLine` fires once per line until `stopPodLogStream` cancels it. */
  startPodLogStream: (
    contextName: string,
    namespace: string,
    podName: string,
    container: string,
    onLine: (line: string) => void,
  ) => {
    const channel = new Channel<string>();
    channel.onmessage = onLine;
    return invoke<number>("start_pod_log_stream", { contextName, namespace, podName, container, onLine: channel });
  },
  stopPodLogStream: (streamId: number) => invoke<void>("stop_pod_log_stream", { streamId }),
  getPodMetricsOverTime: (
    contextName: string,
    namespace: string,
    podName: string,
    rangeMinutes: number,
    overrideBackend?: MetricsBackendInfo | null,
  ) => invoke<MetricsOverTimeResult>("get_pod_metrics_over_time", { contextName, namespace, podName, rangeMinutes, overrideBackend }),
  /** Merged, chronologically-interleaved Head/Tail across every pod passed in, each line prefixed with its source pod. */
  getWorkloadLogs: (
    contextName: string,
    namespace: string,
    podNames: string[],
    container: string,
    tail: boolean,
    lines: number,
  ) => invoke<string>("get_workload_logs", { contextName, namespace, podNames, container, tail, lines }),
  /** Same idea as `startPodLogStream`, but one stream per pod feeding the same `onLine` callback, each line prefixed with its source pod. */
  startWorkloadLogStream: (
    contextName: string,
    namespace: string,
    podNames: string[],
    container: string,
    onLine: (line: string) => void,
  ) => {
    const channel = new Channel<string>();
    channel.onmessage = onLine;
    return invoke<number>("start_workload_log_stream", { contextName, namespace, podNames, container, onLine: channel });
  },
  getNodeMetricsOverTime: (
    contextName: string,
    nodeName: string,
    rangeMinutes: number,
    overrideBackend?: MetricsBackendInfo | null,
  ) => invoke<MetricsOverTimeResult>("get_node_metrics_over_time", { contextName, nodeName, rangeMinutes, overrideBackend }),
  getWorkloadMetricsOverTime: (
    contextName: string,
    kind: string,
    namespace: string,
    name: string,
    rangeMinutes: number,
    overrideBackend?: MetricsBackendInfo | null,
  ) => invoke<MetricsOverTimeResult>("get_workload_metrics_over_time", { contextName, kind, namespace, name, rangeMinutes, overrideBackend }),
  getHelmReleases: (contextName: string) => invoke<HelmReleaseInfo[]>("get_helm_releases", { contextName }),
  getHelmReleaseDetail: (contextName: string, namespace: string, name: string, revision: number) =>
    invoke<HelmReleaseDetail>("get_helm_release_detail", { contextName, namespace, name, revision }),
  listMetricsBackends: (contextName: string) =>
    invoke<MetricsBackendInfo[]>("list_metrics_backends", { contextName }),
  testMetricsBackend: (contextName: string, backend: MetricsBackendInfo) =>
    invoke<MetricsBackendTestResult>("test_metrics_backend", { contextName, backend }),
  claudeAuthStatus: () => invoke<ClaudeAuthState>("claude_auth_status"),
  /** Stores a pasted key in the OS keychain; the key is never persisted frontend-side. */
  claudeSetApiKey: (apiKey: string) => invoke<ClaudeAuthState>("claude_set_api_key", { apiKey }),
  claudeClearApiKey: () => invoke<ClaudeAuthState>("claude_clear_api_key"),
  /** Assembles the redacted diagnosis payload without sending it, for preview. */
  claudeBuildDiagnosis: (contextName: string, namespace: string, podName: string, container: string) =>
    invoke<ClaudeDiagnosisPayload>("claude_build_diagnosis", { contextName, namespace, podName, container }),
  /** Sends an already-previewed diagnosis payload; `onToken` fires per text delta. */
  claudeDiagnose: (prompt: string, onToken: (chunk: string) => void) => {
    const channel = new Channel<string>();
    channel.onmessage = onToken;
    return invoke<void>("claude_diagnose", { prompt, onToken: channel });
  },
  /** Streams an explanation of one error string; `onToken` fires per text delta. */
  claudeExplainError: (errorText: string, onToken: (chunk: string) => void) => {
    const channel = new Channel<string>();
    channel.onmessage = onToken;
    return invoke<void>("claude_explain_error", { errorText, onToken: channel });
  },
  getGitOpsApps: (contextName: string) => invoke<GitOpsResult>("get_gitops_apps", { contextName }),
  getGitOpsManifest: (contextName: string, namespace: string, name: string) =>
    invoke<GitOpsAppManifest>("get_gitops_manifest", { contextName, namespace, name }),
  getGitOpsEvents: (contextName: string, namespace: string, name: string) =>
    invoke<EventInfo[]>("get_gitops_events", { contextName, namespace, name }),
};
