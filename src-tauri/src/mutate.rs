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
use kube::api::{Api, DeleteParams, DynamicObject, EvictParams, GroupVersionKind, Patch, PatchParams, PostParams};
use kube::discovery::{ApiCapabilities, Scope};
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

// ---------------------------------------------------------------------------
// Editing a resource
// ---------------------------------------------------------------------------

/// Fields the server owns. Sending them back is either ignored or rejected,
/// and `creationTimestamp: null` — what serde emits for an absent one — is a
/// real rejection rather than a no-op.
///
/// `resourceVersion` is deliberately *not* here: keeping it is what makes this
/// an optimistic-concurrency check. If the object changed between the panel
/// reading it and the reader saving, the server answers 409 rather than
/// quietly discarding whatever the other writer did.
fn strip_server_owned(obj: &mut DynamicObject) {
    obj.metadata.managed_fields = None;
    obj.metadata.uid = None;
    obj.metadata.creation_timestamp = None;
    obj.metadata.generation = None;
    obj.metadata.deletion_timestamp = None;
    if let Some(map) = obj.data.as_object_mut() {
        // A subresource: a replace ignores it, and a CRD without a status
        // subresource would take it verbatim, which is not what an editor
        // means by "save my spec".
        map.remove("status");
    }
}

/// Saves an edited manifest.
///
/// A replace (`PUT`) rather than a server-side apply, which is the choice
/// worth explaining. Apply carries field ownership: this app would become a
/// new field manager, and every field Helm or ArgoCD already owns would come
/// back as a conflict — on the very objects most worth editing. Replace has no
/// ownership semantics. It saves exactly what was typed, which is what an
/// editor means, and leaves the question of whether GitOps will revert it
/// where it belongs: with the reader, who can see the tracking annotations
/// right there in the YAML.
///
/// The identity arguments are the panel's, not the manifest's. Editing the
/// `name` or `kind` in the text would otherwise retarget the write at a
/// different object entirely — creating one, or overwriting an unrelated one —
/// from a dialog that said it was editing this one.
pub async fn apply_manifest(
    context_name: &str,
    expect_kind: &str,
    expect_namespace: &str,
    expect_name: &str,
    yaml: &str,
) -> Result<String, String> {
    require_write()?;

    let mut obj: DynamicObject =
        serde_yaml::from_str(yaml).map_err(|e| format!("That isn't valid YAML: {e}"))?;

    let types = obj
        .types
        .clone()
        .ok_or_else(|| "The manifest needs both apiVersion and kind.".to_string())?;
    let gvk = GroupVersionKind::try_from(&types).map_err(|e| format!("Unrecognised apiVersion/kind: {e}"))?;

    let name = obj.metadata.name.clone().unwrap_or_default();
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    if gvk.kind != expect_kind || name != expect_name || namespace != expect_namespace {
        return Err(format!(
            "This editor is open on {expect_kind} {}, but the manifest describes {} {}.              Change those back, or open the other object to edit it.",
            describe(expect_namespace, expect_name),
            gvk.kind,
            describe(&namespace, &name)
        ));
    }

    let client = client_for_context(context_name).await?;
    // Asked rather than guessed: the plural is not derivable from the kind for
    // every resource, and this has to work for CRDs the app has never seen.
    let (ar, caps): (_, ApiCapabilities) = kube::discovery::oneshot::pinned_kind(&client, &gvk)
        .await
        .map_err(|e| format!("The cluster doesn't recognise {}: {e}", gvk.kind))?;

    strip_server_owned(&mut obj);

    let api: Api<DynamicObject> = match caps.scope {
        Scope::Namespaced => Api::namespaced_with(client, expect_namespace, &ar),
        Scope::Cluster => Api::all_with(client, &ar),
    };

    api.replace(expect_name, &PostParams::default(), &obj).await.map_err(|e| describe_apply_error(&gvk.kind, e))?;

    Ok(format!("Saved {} {}", gvk.kind, describe(expect_namespace, expect_name)))
}

fn describe(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}/{name}")
    }
}

/// The API server's own words, with the two cases worth naming spelled out —
/// both arrive as a status code that says nothing on its own.
fn describe_apply_error(kind: &str, e: kube::Error) -> String {
    if let kube::Error::Api(resp) = &e {
        return match resp.code {
            409 => format!(
                "This {kind} changed in the cluster while you were editing it.                  Close and reopen the panel to pick up the current version, then redo your change. ({})",
                resp.message
            ),
            422 => format!("The cluster rejected this {kind}: {}", resp.message),
            403 => format!("Not allowed to update this {kind}: {}", resp.message),
            _ => format!("Failed to save the {kind}: {}", resp.message),
        };
    }
    format!("Failed to save the {kind}: {e}")
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

    /// The identity check is what keeps an edit an edit. Without it, changing
    /// `name` in the text turns "save this Deployment" into "write a different
    /// one", from a dialog that said otherwise.
    #[tokio::test]
    async fn an_edit_cannot_retarget_another_object() {
        set_write_enabled(true);
        let yaml = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: other\n  namespace: dev\n";
        let err = apply_manifest("ctx", "Deployment", "dev", "mine", yaml).await.unwrap_err();
        assert!(err.contains("dev/mine") && err.contains("dev/other"), "{err}");

        // Same for the kind, and for the namespace.
        let yaml = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: mine\n  namespace: dev\n";
        assert!(apply_manifest("ctx", "Deployment", "dev", "mine", yaml).await.is_err());
        let yaml = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: mine\n  namespace: prod\n";
        assert!(apply_manifest("ctx", "Deployment", "dev", "mine", yaml).await.is_err());

        set_write_enabled(false);
    }

    /// Every check above must sit behind the guard, or the editor becomes a way
    /// around read-only mode.
    #[tokio::test]
    async fn editing_is_refused_while_read_only() {
        set_write_enabled(false);
        let yaml = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: mine\n  namespace: dev\n";
        let err = apply_manifest("ctx", "Deployment", "dev", "mine", yaml).await.unwrap_err();
        assert!(err.contains("Read-only"), "{err}");
    }

    #[test]
    fn strip_removes_what_the_server_owns_and_keeps_the_concurrency_token() {
        let mut obj: DynamicObject = serde_yaml::from_str(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  uid: abc\n  generation: 4\n  resourceVersion: '77'\nstatus:\n  phase: Bound\ndata:\n  k: v\n",
        )
        .unwrap();
        strip_server_owned(&mut obj);

        assert!(obj.metadata.uid.is_none());
        assert!(obj.metadata.generation.is_none());
        assert!(obj.data.get("status").is_none(), "status is a subresource, not ours to send");
        assert!(obj.data.get("data").is_some(), "the actual content must survive");
        // The whole point: this is what turns a save into an optimistic check.
        assert_eq!(obj.metadata.resource_version.as_deref(), Some("77"));
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
