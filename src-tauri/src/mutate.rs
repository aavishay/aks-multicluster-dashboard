//! Cluster-changing operations, and the switch that gates them.
//!
//! Everything else this app does is a read. These are the exceptions, kept in
//! one module so the whole surface that can alter a cluster is a single file
//! you can hold in your head — and so the guard below has exactly one place to
//! live.

use crate::kubeconfig::client_for_context;
use crate::models::DrainReport;
use chrono::Utc;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::api::{Api, DeleteParams, EvictParams, Patch, PatchParams};
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};

/// Whether cluster-changing operations are permitted.
///
/// Off at every launch, and deliberately not persisted. A mode that lets this
/// app alter a production cluster should be something you switch on for the
/// task in front of you, not something a session three days ago left armed.
static WRITE_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_write_enabled(enabled: bool) {
    WRITE_ENABLED.store(enabled, Ordering::SeqCst);
}

pub fn write_enabled() -> bool {
    WRITE_ENABLED.load(Ordering::SeqCst)
}

/// The gate every operation in this module passes through first.
///
/// Enforced here rather than only by disabling buttons: hiding a control stops
/// the accidental click, but this is what makes "read-only" mean the process
/// will not change a cluster regardless of what calls in — a stale frontend, a
/// queued request from before the switch flipped, a future caller that forgets.
fn require_write() -> Result<(), String> {
    if write_enabled() {
        Ok(())
    } else {
        Err("Read-only mode — turn on write mode to make changes.".to_string())
    }
}

/// Kinds that own a pod template, and can therefore be restarted in place.
fn is_restartable(kind: &str) -> bool {
    matches!(kind, "Deployment" | "StatefulSet" | "DaemonSet")
}

pub async fn delete_pod(context_name: &str, namespace: &str, name: &str) -> Result<String, String> {
    require_write()?;
    let client = client_for_context(context_name).await?;
    let api: Api<Pod> = Api::namespaced(client, namespace);
    api.delete(name, &DeleteParams::default())
        .await
        .map_err(|e| format!("Failed to delete pod '{name}': {e}"))?;
    // Deletion is a request, not an outcome: the pod enters Terminating and
    // leaves when its grace period expires, so don't claim it is gone.
    Ok(format!("Deleting pod {namespace}/{name}"))
}

/// A rollout restart, by the same mechanism `kubectl rollout restart` uses:
/// stamping the pod template with a timestamp annotation, which changes the
/// template hash and makes the controller replace pods through its normal
/// rollout strategy. There is no restart verb in the API.
pub async fn restart_workload(context_name: &str, kind: &str, namespace: &str, name: &str) -> Result<String, String> {
    require_write()?;
    if !is_restartable(kind) {
        return Err(format!("{kind} has no pod template to restart."));
    }
    let client = client_for_context(context_name).await?;
    let patch = serde_json::json!({
        "spec": { "template": { "metadata": { "annotations": {
            "kubectl.kubernetes.io/restartedAt": Utc::now().to_rfc3339()
        }}}}
    });
    let merge = Patch::Merge(&patch);

    match kind {
        "Deployment" => {
            let api: Api<Deployment> = Api::namespaced(client, namespace);
            api.patch(name, &PatchParams::default(), &merge).await.map(|_| ()).map_err(|e| e.to_string())
        }
        "StatefulSet" => {
            let api: Api<StatefulSet> = Api::namespaced(client, namespace);
            api.patch(name, &PatchParams::default(), &merge).await.map(|_| ()).map_err(|e| e.to_string())
        }
        _ => {
            let api: Api<DaemonSet> = Api::namespaced(client, namespace);
            api.patch(name, &PatchParams::default(), &merge).await.map(|_| ()).map_err(|e| e.to_string())
        }
    }
    .map_err(|e| format!("Failed to restart {kind} '{name}': {e}"))?;
    Ok(format!("Restarting {kind} {namespace}/{name}"))
}

/// Kinds with a `/scale` subresource. A DaemonSet runs one pod per eligible
/// node, so its replica count isn't ours to set.
fn is_scalable(kind: &str) -> bool {
    matches!(kind, "Deployment" | "StatefulSet")
}

pub async fn scale_workload(
    context_name: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    replicas: i32,
) -> Result<String, String> {
    require_write()?;
    if !is_scalable(kind) {
        return Err(format!("{kind} cannot be scaled — its replica count is decided by the nodes it runs on."));
    }
    if replicas < 0 {
        return Err("Replica count cannot be negative.".to_string());
    }
    let client = client_for_context(context_name).await?;
    let patch = Patch::Merge(serde_json::json!({ "spec": { "replicas": replicas } }));
    let pp = PatchParams::default();

    match kind {
        "Deployment" => {
            let api: Api<Deployment> = Api::namespaced(client, namespace);
            api.patch_scale(name, &pp, &patch).await.map(|_| ()).map_err(|e| e.to_string())
        }
        _ => {
            let api: Api<StatefulSet> = Api::namespaced(client, namespace);
            api.patch_scale(name, &pp, &patch).await.map(|_| ()).map_err(|e| e.to_string())
        }
    }
    .map_err(|e| format!("Failed to scale {kind} '{name}': {e}"))?;
    Ok(format!("Scaled {kind} {namespace}/{name} to {replicas}"))
}

/// Cordon (`schedulable = false`) or uncordon. Cordoning only stops *new* pods
/// landing on the node; what is already running stays put until a drain.
pub async fn set_node_schedulable(context_name: &str, name: &str, schedulable: bool) -> Result<String, String> {
    require_write()?;
    let client = client_for_context(context_name).await?;
    cordon(&client, name, !schedulable).await?;
    Ok(if schedulable {
        format!("Uncordoned node {name}")
    } else {
        format!("Cordoned node {name} — running pods are untouched")
    })
}

async fn cordon(client: &Client, name: &str, unschedulable: bool) -> Result<(), String> {
    let api: Api<Node> = Api::all(client.clone());
    let patch = Patch::Merge(serde_json::json!({ "spec": { "unschedulable": unschedulable } }));
    api.patch(name, &PatchParams::default(), &patch)
        .await
        .map_err(|e| format!("Failed to {} node '{name}': {e}", if unschedulable { "cordon" } else { "uncordon" }))?;
    Ok(())
}

/// Why a pod on a draining node was left alone.
fn drain_skip_reason(pod: &Pod) -> Option<&'static str> {
    let meta = &pod.metadata;

    if meta.annotations.as_ref().is_some_and(|a| a.contains_key("kubernetes.io/config.mirror")) {
        return Some("mirror pod — managed by the kubelet, not the API server");
    }

    let owners = meta.owner_references.as_deref().unwrap_or_default();
    if owners.iter().any(|o| o.kind == "DaemonSet") {
        return Some("DaemonSet pod — would be recreated on this node immediately");
    }
    // kubectl refuses these without --force, and for good reason: nothing owns
    // them, so evicting one destroys it for good rather than moving it.
    if owners.is_empty() {
        return Some("not managed by a controller — evicting it would not recreate it elsewhere");
    }

    let phase = pod.status.as_ref().and_then(|s| s.phase.as_deref());
    if matches!(phase, Some("Succeeded") | Some("Failed")) {
        return Some("already terminated");
    }
    None
}

/// Cordon a node, then ask the API server to evict everything eligible on it.
///
/// Deliberately narrower than `kubectl drain` in one respect: it issues the
/// evictions and reports what the API server said, rather than blocking until
/// every pod has actually gone. A drain can take many minutes — long enough
/// that a UI waiting on it looks hung — and the eviction call is where the
/// interesting answer lives anyway, since that is what a PodDisruptionBudget
/// refuses. Watch the Pods tab to see them leave.
pub async fn drain_node(context_name: &str, name: &str) -> Result<DrainReport, String> {
    require_write()?;
    let client = client_for_context(context_name).await?;

    cordon(&client, name, true).await?;

    let api: Api<Pod> = Api::all(client.clone());
    let pods = api
        .list(&kube::api::ListParams::default().fields(&format!("spec.nodeName={name}")))
        .await
        .map_err(|e| format!("Failed to list pods on node '{name}': {e}"))?;

    let mut evicting = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();

    for pod in pods.items {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let ns = pod.metadata.namespace.clone().unwrap_or_default();
        let label = format!("{ns}/{pod_name}");

        if let Some(reason) = drain_skip_reason(&pod) {
            skipped.push(format!("{label} — {reason}"));
            continue;
        }

        let ns_api: Api<Pod> = Api::namespaced(client.clone(), &ns);
        match ns_api.evict(&pod_name, &EvictParams::default()).await {
            Ok(_) => evicting.push(label),
            // A PodDisruptionBudget refusing an eviction arrives as 429, and is
            // the single most useful thing a drain can tell you — surface the
            // server's own wording rather than flattening it to "failed".
            Err(e) => failed.push(format!("{label} — {e}")),
        }
    }

    Ok(DrainReport { node: name.to_string(), cordoned: true, evicting, skipped, failed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

    fn pod_with(owner: Option<&str>, phase: Option<&str>, mirror: bool) -> Pod {
        let mut pod = Pod::default();
        pod.metadata.name = Some("p".into());
        if let Some(kind) = owner {
            pod.metadata.owner_references = Some(vec![OwnerReference {
                kind: kind.to_string(),
                name: "owner".into(),
                ..Default::default()
            }]);
        }
        if mirror {
            pod.metadata.annotations =
                Some([("kubernetes.io/config.mirror".to_string(), "x".to_string())].into_iter().collect());
        }
        if let Some(p) = phase {
            pod.status = Some(k8s_openapi::api::core::v1::PodStatus { phase: Some(p.into()), ..Default::default() });
        }
        pod
    }

    /// The skip rules are the whole safety story of a drain: evicting the wrong
    /// pod either destroys it outright or churns it for nothing.
    #[test]
    fn drain_skips_exactly_the_pods_kubectl_would() {
        assert!(drain_skip_reason(&pod_with(Some("ReplicaSet"), Some("Running"), false)).is_none());

        assert!(drain_skip_reason(&pod_with(Some("DaemonSet"), Some("Running"), false))
            .is_some_and(|r| r.contains("DaemonSet")));
        assert!(drain_skip_reason(&pod_with(None, Some("Running"), false))
            .is_some_and(|r| r.contains("not managed")));
        assert!(drain_skip_reason(&pod_with(Some("ReplicaSet"), Some("Running"), true))
            .is_some_and(|r| r.contains("mirror")));
        assert!(drain_skip_reason(&pod_with(Some("ReplicaSet"), Some("Succeeded"), false))
            .is_some_and(|r| r.contains("terminated")));
        assert!(drain_skip_reason(&pod_with(Some("ReplicaSet"), Some("Failed"), false)).is_some());
    }

    #[test]
    fn only_pod_templated_kinds_restart_and_only_scalable_kinds_scale() {
        for kind in ["Deployment", "StatefulSet", "DaemonSet"] {
            assert!(is_restartable(kind), "{kind} owns a pod template");
        }
        assert!(!is_restartable("Job"));

        assert!(is_scalable("Deployment"));
        assert!(is_scalable("StatefulSet"));
        // One pod per eligible node — the replica count isn't ours to set.
        assert!(!is_scalable("DaemonSet"));
    }

    /// The gate is the feature. If this ever defaults open, every other
    /// safeguard in the app is decoration.
    #[test]
    fn writes_are_refused_until_the_switch_is_on() {
        set_write_enabled(false);
        assert!(!write_enabled());
        assert!(require_write().is_err());

        set_write_enabled(true);
        assert!(require_write().is_ok());

        set_write_enabled(false);
        assert!(require_write().is_err(), "must latch back off");
    }
}
