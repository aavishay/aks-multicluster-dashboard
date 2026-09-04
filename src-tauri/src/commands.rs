use crate::models::*;
use crate::{ai, claude, helm, k8s, kubeconfig, metrics_backend, mutate, retry};
use std::future::Future;
use std::time::Duration;

/// Ceiling on any single cluster operation, enforced here rather than relying
/// on transport timeouts alone.
///
/// The failure mode this exists for: a private-link AKS cluster reached from
/// outside its VNet completes the TCP handshake (the private endpoint's NIC
/// answers) but never returns a response. Without a deadline the tab sits on
/// "Loading…" indefinitely with no error to explain why, and each stalled
/// request pins its connection — and descriptors — until the read timeout
/// elapses. Cancelling the future here drops the connection and frees them.
///
/// Set to `kubeconfig::SLOW_CLUSTER_TIMEOUT` — the same constant
/// `READ_TIMEOUT`/`WRITE_TIMEOUT` use — rather than an independent literal.
/// This used to be its own 60s value, tighter than what the transport layer
/// itself was already configured to allow, so this deadline (not the HTTP
/// client) was the thing declaring a live cluster "unreachable". Sharing the
/// constant makes that drift impossible instead of relying on a comment to
/// keep two numbers in sync by hand.
///
/// Measured directly against a real private-link cluster under degraded
/// (but not dead) network conditions: DNS/connect/TLS together took under
/// 20s, but transferring the node list alone (a few MB — ordinary for ~130
/// nodes, not bloated) took over 90s and was still incomplete, implying well
/// under 50 KB/s effective throughput on that path at the time. A cluster in
/// that state is genuinely reachable and will finish given enough time; 60s
/// was failing it before it could.
const OPERATION_TIMEOUT: Duration = kubeconfig::SLOW_CLUSTER_TIMEOUT;

async fn with_deadline<T>(
    context_name: &str,
    operation: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    match tokio::time::timeout(OPERATION_TIMEOUT, operation).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "Timed out after {}s talking to '{context_name}'. If this is a private cluster, \
             check that you're connected to the VPN and that this machine is allowed to reach \
             the cluster's private endpoint.",
            OPERATION_TIMEOUT.as_secs()
        )),
    }
}

/// Wraps `with_deadline`, re-running `operation` a couple of times if it
/// fails with what looks like a transient network error (see
/// `retry::retry_transient` for the classification and backoff). Safe to
/// layer over every *read* in this file — and only those; the write commands
/// use `with_deadline` directly. Each read is a GET/LIST
/// (or, for the log-follow streams, has its own independent per-line error
/// handling), so re-issuing a request after a blip can't cause any
/// duplicated side effect.
async fn with_retry<T, F, Fut>(context_name: &str, mut operation: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    retry::retry_transient(|| with_deadline(context_name, operation())).await
}

// ---------------------------------------------------------------------------
// Write mode, and the operations it gates
//
// The switch is mirrored in the backend rather than kept in the frontend
// alone: see `mutate::require_write`.
//
// These take `with_deadline` but not `with_retry`, and the two halves have
// different reasons. No retry: re-issuing a read costs a round trip, but
// re-issuing a write risks doing it twice. Still a deadline: a private-link
// cluster that accepts the connection and never answers would otherwise leave
// the confirmation dialog on "Working…" with nothing to cancel it.
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_write_enabled() -> bool {
    mutate::write_enabled()
}

#[tauri::command]
pub fn set_write_enabled(enabled: bool) -> bool {
    mutate::set_write_enabled(enabled);
    mutate::write_enabled()
}

#[tauri::command]
pub async fn delete_pod(context_name: String, namespace: String, name: String) -> Result<String, String> {
    with_deadline(&context_name, mutate::delete_pod(&context_name, &namespace, &name)).await
}

#[tauri::command]
pub async fn restart_workload(
    context_name: String,
    kind: String,
    namespace: String,
    name: String,
) -> Result<String, String> {
    with_deadline(&context_name, mutate::restart_workload(&context_name, &kind, &namespace, &name)).await
}

#[tauri::command]
pub async fn scale_workload(
    context_name: String,
    kind: String,
    namespace: String,
    name: String,
    replicas: i32,
) -> Result<String, String> {
    with_deadline(&context_name, mutate::scale_workload(&context_name, &kind, &namespace, &name, replicas)).await
}

#[tauri::command]
pub async fn set_node_schedulable(context_name: String, name: String, schedulable: bool) -> Result<String, String> {
    with_deadline(&context_name, mutate::set_node_schedulable(&context_name, &name, schedulable)).await
}

#[tauri::command]
pub async fn drain_node(context_name: String, name: String) -> Result<DrainReport, String> {
    with_deadline(&context_name, mutate::drain_node(&context_name, &name)).await
}

#[tauri::command]
pub fn list_clusters() -> Result<Vec<ClusterEntry>, String> {
    kubeconfig::list_contexts()
}

#[tauri::command]
pub async fn get_cluster_overview(context_name: String) -> Result<ClusterOverview, String> {
    // The overview backs the sidebar's per-cluster health dot, so failures are
    // reported in-band as `reachable: false` rather than as a command error —
    // including a timeout, which is the shape an unreachable private cluster
    // takes. That way such a cluster settles on "unreachable" with a reason
    // instead of being stuck on "checking…".
    match with_retry(&context_name, || k8s::get_overview(&context_name)).await {
        Ok(overview) => Ok(overview),
        Err(error) => Ok(ClusterOverview {
            context_name,
            reachable: false,
            error: Some(error),
            ..Default::default()
        }),
    }
}

#[tauri::command]
pub async fn get_nodes(context_name: String) -> Result<Vec<NodeInfo>, String> {
    with_retry(&context_name, || k8s::get_nodes(&context_name)).await
}

#[tauri::command]
pub async fn get_node_manifest(context_name: String, node_name: String) -> Result<NodeManifest, String> {
    with_retry(&context_name, || k8s::get_node_manifest(&context_name, &node_name)).await
}

#[tauri::command]
pub async fn get_node_events(context_name: String, node_name: String) -> Result<Vec<EventInfo>, String> {
    with_retry(&context_name, || k8s::get_node_events(&context_name, &node_name)).await
}

#[tauri::command]
pub async fn get_pods(context_name: String, namespace: Option<String>) -> Result<Vec<PodInfo>, String> {
    with_retry(&context_name, || k8s::get_pods(&context_name, namespace.clone())).await
}

#[tauri::command]
pub async fn stream_pods(
    context_name: String,
    namespace: Option<String>,
    on_page: tauri::ipc::Channel<Vec<PodInfo>>,
) -> Result<Vec<PodInfo>, String> {
    // Not wrapped in with_retry, same reasoning as the log streams below: a
    // retry that re-runs the whole operation from scratch would re-send
    // pages the frontend already appended, double-counting pods rather than
    // recovering cleanly.
    with_deadline(&context_name, k8s::stream_pods(&context_name, namespace, on_page)).await
}

#[tauri::command]
pub async fn get_workloads(context_name: String) -> Result<Vec<WorkloadInfo>, String> {
    with_retry(&context_name, || k8s::get_workloads(&context_name)).await
}

#[tauri::command]
pub async fn get_workload_manifest(
    context_name: String,
    kind: String,
    namespace: String,
    name: String,
) -> Result<WorkloadManifest, String> {
    with_retry(&context_name, || {
        k8s::get_workload_manifest(&context_name, &kind, &namespace, &name)
    })
    .await
}

#[tauri::command]
pub async fn get_workload_events(
    context_name: String,
    kind: String,
    namespace: String,
    name: String,
) -> Result<Vec<EventInfo>, String> {
    with_retry(&context_name, || {
        k8s::get_workload_events(&context_name, &kind, &namespace, &name)
    })
    .await
}

#[tauri::command]
pub async fn get_workload_revisions(
    context_name: String,
    kind: String,
    namespace: String,
    name: String,
) -> Result<Vec<WorkloadRevisionInfo>, String> {
    with_retry(&context_name, || {
        k8s::get_workload_revisions(&context_name, &kind, &namespace, &name)
    })
    .await
}

#[tauri::command]
pub async fn get_events(context_name: String, warnings_only: bool) -> Result<Vec<EventInfo>, String> {
    with_retry(&context_name, || k8s::get_events(&context_name, warnings_only)).await
}

#[tauri::command]
pub async fn get_resource_usage(context_name: String) -> Result<ResourceUsageSummary, String> {
    with_retry(&context_name, || k8s::get_resource_usage(&context_name)).await
}

#[tauri::command]
pub async fn get_metrics_over_time(
    context_name: String,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    with_retry(&context_name, || {
        metrics_backend::get_metrics_over_time(&context_name, range_minutes, override_backend.clone())
    })
    .await
}

#[tauri::command]
pub async fn get_pod_manifest(
    context_name: String,
    namespace: String,
    pod_name: String,
) -> Result<PodManifest, String> {
    with_retry(&context_name, || {
        k8s::get_pod_manifest(&context_name, &namespace, &pod_name)
    })
    .await
}

#[tauri::command]
pub async fn get_pod_logs(
    context_name: String,
    namespace: String,
    pod_name: String,
    container: String,
    tail: bool,
    lines: i64,
) -> Result<String, String> {
    with_retry(&context_name, || {
        k8s::get_pod_logs(&context_name, &namespace, &pod_name, &container, tail, lines)
    })
    .await
}

#[tauri::command]
pub async fn start_pod_log_stream(
    context_name: String,
    namespace: String,
    pod_name: String,
    container: String,
    on_line: tauri::ipc::Channel<String>,
) -> Result<u64, String> {
    with_deadline(
        &context_name,
        k8s::start_pod_log_stream(&context_name, &namespace, &pod_name, &container, on_line),
    )
    .await
}

#[tauri::command]
pub fn stop_pod_log_stream(stream_id: u64) {
    k8s::stop_pod_log_stream(stream_id);
}

#[tauri::command]
pub async fn get_workload_logs(
    context_name: String,
    namespace: String,
    pod_names: Vec<String>,
    container: String,
    tail: bool,
    lines: i64,
) -> Result<String, String> {
    with_retry(&context_name, || {
        k8s::get_workload_logs(&context_name, &namespace, &pod_names, &container, tail, lines)
    })
    .await
}

#[tauri::command]
pub async fn start_workload_log_stream(
    context_name: String,
    namespace: String,
    pod_names: Vec<String>,
    container: String,
    on_line: tauri::ipc::Channel<String>,
) -> Result<u64, String> {
    with_deadline(
        &context_name,
        k8s::start_workload_log_stream(&context_name, &namespace, &pod_names, &container, on_line),
    )
    .await
}

#[tauri::command]
pub async fn get_pod_metrics_over_time(
    context_name: String,
    namespace: String,
    pod_name: String,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    with_retry(&context_name, || {
        metrics_backend::get_pod_metrics_over_time(&context_name, &namespace, &pod_name, range_minutes, override_backend.clone())
    })
    .await
}

#[tauri::command]
pub async fn get_node_metrics_over_time(
    context_name: String,
    node_name: String,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    with_retry(&context_name, || {
        metrics_backend::get_node_metrics_over_time(&context_name, &node_name, range_minutes, override_backend.clone())
    })
    .await
}

#[tauri::command]
pub async fn get_workload_metrics_over_time(
    context_name: String,
    kind: String,
    namespace: String,
    name: String,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    with_retry(&context_name, || {
        metrics_backend::get_workload_metrics_over_time(&context_name, &kind, &namespace, &name, range_minutes, override_backend.clone())
    })
    .await
}

#[tauri::command]
pub async fn get_helm_releases(context_name: String) -> Result<Vec<HelmReleaseInfo>, String> {
    with_retry(&context_name, || helm::get_helm_releases(&context_name)).await
}

#[tauri::command]
pub async fn get_helm_release_detail(
    context_name: String,
    namespace: String,
    name: String,
    revision: i64,
) -> Result<HelmReleaseDetail, String> {
    with_retry(&context_name, || {
        helm::get_helm_release_detail(&context_name, &namespace, &name, revision)
    })
    .await
}

#[tauri::command]
pub async fn get_nap_node_pools(context_name: String) -> Result<NapResult, String> {
    with_retry(&context_name, || k8s::get_nap_node_pools(&context_name)).await
}

#[tauri::command]
pub async fn get_keda_scaled_objects(context_name: String) -> Result<KedaResult, String> {
    with_retry(&context_name, || k8s::get_keda_scaled_objects(&context_name)).await
}

#[tauri::command]
pub async fn get_keda_manifest(
    context_name: String,
    namespace: String,
    kind: String,
    name: String,
) -> Result<ObjectManifest, String> {
    with_retry(&context_name, || k8s::get_keda_manifest(&context_name, &namespace, &kind, &name)).await
}

#[tauri::command]
pub async fn get_keda_events(
    context_name: String,
    namespace: String,
    kind: String,
    name: String,
) -> Result<Vec<EventInfo>, String> {
    with_retry(&context_name, || k8s::get_keda_events(&context_name, &namespace, &kind, &name)).await
}

#[tauri::command]
pub async fn get_nap_node_pool_manifest(context_name: String, name: String) -> Result<NapNodePoolManifest, String> {
    with_retry(&context_name, || k8s::get_nap_node_pool_manifest(&context_name, &name)).await
}

#[tauri::command]
pub async fn get_nap_node_pool_events(context_name: String, name: String) -> Result<Vec<EventInfo>, String> {
    with_retry(&context_name, || k8s::get_nap_node_pool_events(&context_name, &name)).await
}

#[tauri::command]
pub async fn get_nap_node_pool_metrics_over_time(
    context_name: String,
    name: String,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    with_retry(&context_name, || {
        metrics_backend::get_nap_node_pool_metrics_over_time(&context_name, &name, range_minutes, override_backend.clone())
    })
    .await
}

#[tauri::command]
pub async fn get_gitops_apps(context_name: String) -> Result<GitOpsResult, String> {
    with_retry(&context_name, || k8s::get_gitops_apps(&context_name)).await
}

#[tauri::command]
pub async fn get_gitops_manifest(context_name: String, namespace: String, name: String) -> Result<GitOpsAppManifest, String> {
    with_retry(&context_name, || k8s::get_gitops_manifest(&context_name, &namespace, &name)).await
}

#[tauri::command]
pub async fn get_gitops_events(context_name: String, namespace: String, name: String) -> Result<Vec<EventInfo>, String> {
    with_retry(&context_name, || k8s::get_gitops_events(&context_name, &namespace, &name)).await
}

#[tauri::command]
pub async fn list_metrics_backends(context_name: String) -> Result<Vec<MetricsBackendInfo>, String> {
    with_retry(&context_name, || metrics_backend::list_metrics_backends(&context_name)).await
}

#[tauri::command]
pub async fn test_metrics_backend(
    context_name: String,
    backend: MetricsBackendInfo,
) -> Result<MetricsBackendTestResult, String> {
    // Not wrapped in `with_retry`: this is a deliberate probe whose whole
    // purpose is to report a failure verbatim, so retrying would just delay
    // the answer the user asked for.
    with_deadline(&context_name, metrics_backend::test_metrics_backend(&context_name, backend)).await
}

#[tauri::command]
pub fn ai_auth_status() -> ai::AiAuthState {
    // Infallible by design: "no key configured" is a state the UI renders,
    // not an error it has to handle.
    ai::auth_status()
}

/// Selects the provider and its model / base URL, and reports the resulting
/// state — which is what the panel renders, so it can never show a provider
/// the backend isn't actually pointed at.
#[tauri::command]
pub fn ai_set_settings(provider: String, model: String, base_url: String) -> Result<ai::AiAuthState, String> {
    ai::set_settings(&provider, &model, &base_url)?;
    Ok(ai::auth_status())
}

#[tauri::command]
pub fn ai_set_api_key(provider: String, api_key: String) -> Result<ai::AiAuthState, String> {
    ai::set_api_key(&provider, &api_key)?;
    Ok(ai::auth_status())
}

#[tauri::command]
pub fn ai_clear_api_key(provider: String) -> Result<ai::AiAuthState, String> {
    ai::clear_api_key(&provider)?;
    Ok(ai::auth_status())
}

/// Assembles and returns the diagnosis payload *without* sending it, so the UI
/// can show exactly what would leave the machine before anything does.
#[tauri::command]
pub async fn ai_build_diagnosis(
    context_name: String,
    namespace: String,
    pod_name: String,
    container: String,
) -> Result<ClaudeDiagnosisPayload, String> {
    with_retry(&context_name, || {
        claude::build_diagnosis_payload(&context_name, &namespace, &pod_name, &container)
    })
    .await
}

#[tauri::command]
pub async fn ai_diagnose(prompt: String, on_token: tauri::ipc::Channel<String>) -> Result<(), String> {
    claude::diagnose(&prompt, on_token).await
}

#[tauri::command]
pub async fn ai_explain_error(error_text: String, on_token: tauri::ipc::Channel<String>) -> Result<(), String> {
    // Not wrapped in `with_retry`/`with_deadline`: those are keyed to a cluster
    // context, and a streaming call already surfaces progress incrementally, so
    // a stall is visible rather than silent.
    claude::explain_error(&error_text, on_token).await
}

#[tauri::command]
pub fn kubeconfig_path() -> Option<String> {
    kubeconfig::kubeconfig_path().map(|p| p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn with_retry_recovers_from_a_transient_failure() {
        let attempts = std::cell::Cell::new(0);
        let result = with_retry("test-ctx", || {
            attempts.set(attempts.get() + 1);
            let this_attempt = attempts.get();
            async move {
                if this_attempt < 2 {
                    Err("connection reset by peer (os error 54)".to_string())
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(attempts.get(), 2, "should have recovered on the second attempt");
    }

    #[tokio::test]
    async fn with_retry_does_not_retry_a_non_transient_error() {
        let attempts = std::cell::Cell::new(0);
        let result = with_retry("test-ctx", || {
            attempts.set(attempts.get() + 1);
            async move { Err::<(), _>("pods \"x\" not found".to_string()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.get(), 1, "a non-transient error should not be retried at all");
    }
}
