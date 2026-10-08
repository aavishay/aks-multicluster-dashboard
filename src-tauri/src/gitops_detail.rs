//! The GitOps panel's Overview: whether an Argo CD Application is synced and
//! healthy and if not why, what it deploys from where to where, how it syncs,
//! what the last sync did, and which of its resources need attention — read
//! from the same Application object the YAML view renders.

use crate::k8s::json_str;
use crate::models::{GitOpsCondition, GitOpsDetail, GitOpsHistoryEntry, GitOpsManagedResource, GitOpsSourceInfo, GitOpsSyncFailure};
use kube::api::DynamicObject;
use serde_json::Value;

/// The argocd-server address for its own cluster, and the name Argo CD gives it.
const IN_CLUSTER_SERVER: &str = "https://kubernetes.default.svc";
const IN_CLUSTER_NAME: &str = "in-cluster";

/// How many past deployments to show: the recent ones are what explains a change.
const HISTORY_SHOWN: usize = 5;

fn opt_str(v: Option<&Value>, key: &str) -> Option<String> {
    v.and_then(|v| v.get(key)).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// A commit ID shortened the way Git shows it; anything else — a chart
/// version such as `18.10.12`, a tag — kept whole, since cutting it would name
/// a different release.
fn short(rev: &str) -> String {
    let commit = matches!(rev.len(), 40 | 64) && rev.bytes().all(|b| b.is_ascii_hexdigit());
    if commit { rev[..7].to_string() } else { rev.to_string() }
}

fn array<'a>(v: Option<&'a Value>, key: &str) -> &'a [Value] {
    v.and_then(|v| v.get(key)).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default()
}

pub(crate) fn gitops_detail(obj: &DynamicObject) -> GitOpsDetail {
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");
    let sync = status.and_then(|s| s.get("sync"));

    // One source, or several for a multi-source app; `sync.revisions` is
    // index-aligned with `spec.sources`, as the row mapper notes.
    let single = spec.and_then(|s| s.get("source"));
    let multi = array(spec, "sources");
    let revisions = array(sync, "revisions");
    let sources: Vec<GitOpsSourceInfo> = if multi.is_empty() {
        single
            .map(|s| GitOpsSourceInfo {
                repo_url: json_str(Some(s), "repoURL").to_string(),
                path: json_str(Some(s), "path").to_string(),
                chart: json_str(Some(s), "chart").to_string(),
                target_revision: json_str(Some(s), "targetRevision").to_string(),
                revision: short(json_str(sync, "revision")),
            })
            .into_iter()
            .collect()
    } else {
        multi
            .iter()
            .enumerate()
            .map(|(i, s)| GitOpsSourceInfo {
                repo_url: json_str(Some(s), "repoURL").to_string(),
                path: json_str(Some(s), "path").to_string(),
                chart: json_str(Some(s), "chart").to_string(),
                target_revision: json_str(Some(s), "targetRevision").to_string(),
                revision: short(revisions.get(i).and_then(Value::as_str).unwrap_or_default()),
            })
            .collect()
    };

    let destination = spec.and_then(|s| s.get("destination"));
    let server = json_str(destination, "server").to_string();
    let dest_name = json_str(destination, "name").to_string();
    let policy = spec.and_then(|s| s.get("syncPolicy"));
    let automated = policy.and_then(|p| p.get("automated"));
    let operation = status.and_then(|s| s.get("operationState"));
    let health = status.and_then(|s| s.get("health"));

    GitOpsDetail {
        project: json_str(spec, "project").to_string(),
        destination_in_cluster: server == IN_CLUSTER_SERVER || dest_name == IN_CLUSTER_NAME,
        destination_server: server,
        destination_name: dest_name,
        destination_namespace: json_str(destination, "namespace").to_string(),
        sources,
        sync_status: match json_str(sync, "status") {
            "" => "Unknown".to_string(),
            s => s.to_string(),
        },
        health_status: match json_str(health, "status") {
            "" => "Unknown".to_string(),
            s => s.to_string(),
        },
        health_message: json_str(health, "message").to_string(),
        automated: automated.is_some_and(|a| !a.is_null()),
        prune: automated.and_then(|a| a.get("prune")).and_then(Value::as_bool).unwrap_or(false),
        self_heal: automated.and_then(|a| a.get("selfHeal")).and_then(Value::as_bool).unwrap_or(false),
        sync_options: array(policy, "syncOptions").iter().filter_map(Value::as_str).map(str::to_string).collect(),
        retry_limit: policy.and_then(|p| p.get("retry")).and_then(|r| r.get("limit")).and_then(Value::as_i64),
        operation_phase: json_str(operation, "phase").to_string(),
        operation_message: json_str(operation, "message").to_string(),
        operation_started: opt_str(operation, "startedAt"),
        operation_finished: opt_str(operation, "finishedAt"),
        operation_retries: operation.and_then(|o| o.get("retryCount")).and_then(Value::as_i64),
        sync_failures: array(operation.and_then(|o| o.get("syncResult")), "resources")
            .iter()
            // A hook's result has no status; its outcome is in `hookPhase`.
            .filter(|r| {
                let s = json_str(Some(r), "status");
                (!s.is_empty() && s != "Synced" && s != "Pruned") || matches!(json_str(Some(r), "hookPhase"), "Failed" | "Error")
            })
            .map(|r| GitOpsSyncFailure {
                hook_type: json_str(Some(r), "hookType").to_string(),
                kind: json_str(Some(r), "kind").to_string(),
                namespace: json_str(Some(r), "namespace").to_string(),
                name: json_str(Some(r), "name").to_string(),
                message: json_str(Some(r), "message").to_string(),
            })
            .collect(),
        resources: array(status, "resources")
            .iter()
            .map(|r| GitOpsManagedResource {
                group: json_str(Some(r), "group").to_string(),
                kind: json_str(Some(r), "kind").to_string(),
                namespace: json_str(Some(r), "namespace").to_string(),
                name: json_str(Some(r), "name").to_string(),
                status: json_str(Some(r), "status").to_string(),
                health: json_str(r.get("health"), "status").to_string(),
                health_message: json_str(r.get("health"), "message").to_string(),
                requires_pruning: r.get("requiresPruning").and_then(Value::as_bool).unwrap_or(false),
            })
            .collect(),
        resource_health_in_tree: json_str(status, "resourceHealthSource") == "appTree",
        conditions: array(status, "conditions")
            .iter()
            .map(|c| GitOpsCondition {
                condition_type: json_str(Some(c), "type").to_string(),
                message: json_str(Some(c), "message").to_string(),
                last_transition: opt_str(Some(c), "lastTransitionTime"),
            })
            .collect(),
        images: array(status.and_then(|s| s.get("summary")), "images").iter().filter_map(Value::as_str).map(str::to_string).collect(),
        // Argo CD appends, so the newest is last.
        history: array(status, "history")
            .iter()
            .rev()
            .take(HISTORY_SHOWN)
            // One revision, or one per source for a multi-source app.
            .map(|h| GitOpsHistoryEntry {
                revisions: match json_str(Some(h), "revision") {
                    "" => array(Some(h), "revisions").iter().filter_map(Value::as_str).map(short).collect(),
                    r => vec![short(r)],
                },
                deployed_at: opt_str(Some(h), "deployedAt"),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use serde_json::json;

    fn app(data: Value) -> DynamicObject {
        DynamicObject { types: None, metadata: ObjectMeta::default(), data }
    }

    #[test]
    fn a_degraded_app_with_a_failed_sync() {
        let d = gitops_detail(&app(json!({
            "spec": {
                "project": "platform",
                "source": { "repoURL": "https://git/x", "path": "apps/api", "targetRevision": "main" },
                "destination": { "server": "https://kubernetes.default.svc", "namespace": "prod-weu" },
                "syncPolicy": { "automated": { "prune": true, "selfHeal": true }, "syncOptions": ["CreateNamespace=true"], "retry": { "limit": 5 } }
            },
            "status": {
                "sync": { "status": "OutOfSync", "revision": "abcdef1234567890abcdef1234567890abcdef12" },
                "health": { "status": "Degraded", "message": "Deployment has timed out progressing" },
                "operationState": {
                    "phase": "Failed", "message": "one or more objects failed to apply", "startedAt": "2026-10-07T08:00:00Z", "finishedAt": "2026-10-07T08:01:00Z", "retryCount": 2,
                    "syncResult": { "resources": [
                        { "kind": "Deployment", "namespace": "prod-weu", "name": "api", "status": "SyncFailed", "message": "admission webhook denied the request" },
                        { "kind": "Service", "namespace": "prod-weu", "name": "api", "status": "Synced" },
                        { "kind": "Job", "namespace": "prod-weu", "name": "migrate", "hookType": "PreSync", "hookPhase": "Failed", "message": "Job has reached the specified backoff limit" },
                        { "kind": "Job", "namespace": "prod-weu", "name": "smoke", "hookType": "PostSync", "hookPhase": "Succeeded" }
                    ] }
                },
                "resources": [
                    { "group": "apps", "kind": "Deployment", "namespace": "prod-weu", "name": "api", "status": "OutOfSync", "health": { "status": "Degraded", "message": "timed out" } },
                    { "kind": "Service", "namespace": "prod-weu", "name": "api", "status": "Synced", "health": { "status": "Healthy" } }
                ],
                "conditions": [{ "type": "SyncError", "message": "Failed sync attempt", "lastTransitionTime": "2026-10-07T08:01:00Z" }],
                "summary": { "images": ["acr.io/api:1.4.2"] },
                "history": [
                    { "revision": "1111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "deployedAt": "2026-10-01T00:00:00Z" },
                    { "revision": "2222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "deployedAt": "2026-10-05T00:00:00Z" }
                ]
            }
        })));
        assert!(d.destination_in_cluster);
        assert_eq!((d.sync_status.as_str(), d.health_status.as_str()), ("OutOfSync", "Degraded"));
        assert_eq!(d.sources[0].revision, "abcdef1");
        assert!(d.automated && d.prune && d.self_heal);
        assert_eq!((d.retry_limit, d.operation_retries), (Some(5), Some(2)));
        assert_eq!(d.sync_failures.len(), 2);
        assert_eq!((d.sync_failures[1].hook_type.as_str(), d.sync_failures[1].name.as_str()), ("PreSync", "migrate"));
        assert_eq!(d.sync_failures[0].message, "admission webhook denied the request");
        assert_eq!(d.resources[0].health, "Degraded");
        assert!(!d.resource_health_in_tree);
        assert_eq!(d.conditions[0].condition_type, "SyncError");
        assert_eq!(d.history.iter().map(|h| h.revisions.join(",")).collect::<Vec<_>>(), vec!["2222222", "1111111"]);
    }

    #[test]
    fn a_multi_source_app_to_another_cluster() {
        let d = gitops_detail(&app(json!({
            "spec": {
                "sources": [
                    { "repoURL": "https://charts", "chart": "redis", "targetRevision": "18.10.12" },
                    { "repoURL": "https://git/values", "path": "redis", "targetRevision": "HEAD" }
                ],
                "destination": { "name": "prod-eus", "namespace": "cache" }
            },
            "status": {
                "sync": { "status": "Synced", "revisions": ["18.10.12", "9f8e7d6ccccccccccccccccccccccccccccccccc"] },
                "resourceHealthSource": "appTree",
                "history": [{ "revisions": ["18.10.12", "9f8e7d6ccccccccccccccccccccccccccccccccc"], "deployedAt": "2026-10-05T00:00:00Z" }]
            }
        })));
        assert!(!d.destination_in_cluster);
        assert!(!d.automated);
        assert_eq!(d.sources.len(), 2);
        assert_eq!((d.sources[0].chart.as_str(), d.sources[0].revision.as_str()), ("redis", "18.10.12"));
        assert_eq!(d.sources[1].revision, "9f8e7d6");
        assert_eq!(d.health_status, "Unknown");
        assert!(d.resource_health_in_tree);
        assert_eq!(d.history[0].revisions, vec!["18.10.12", "9f8e7d6"]);
    }

    /// Fetches every Application's manifest through the real command path.
    /// Prints counts only — no names, repos or messages.
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set GITOPS_DETAIL_TEST_CONTEXT to run"]
    async fn gitops_detail_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("GITOPS_DETAIL_TEST_CONTEXT") else { return };
        let list = crate::k8s::get_gitops_apps(&ctx).await.expect("apps");
        let (mut in_cluster, mut multi, mut automated, mut resources, mut problem_resources, mut failed_ops, mut sync_failures, mut conditions, mut in_tree) =
            (0, 0, 0, 0, 0, 0, 0, 0, 0);
        for a in &list.apps {
            let d = crate::k8s::get_gitops_manifest(&ctx, &a.namespace, &a.name).await.expect("manifest + detail").detail;
            in_cluster += usize::from(d.destination_in_cluster);
            multi += usize::from(d.sources.len() > 1);
            automated += usize::from(d.automated);
            resources += d.resources.len();
            problem_resources += d.resources.iter().filter(|r| r.status == "OutOfSync" || (!r.health.is_empty() && r.health != "Healthy")).count();
            failed_ops += usize::from(matches!(d.operation_phase.as_str(), "Failed" | "Error"));
            sync_failures += d.sync_failures.len();
            conditions += d.conditions.len();
            in_tree += usize::from(d.resource_health_in_tree);
            assert_eq!(d.sync_status, a.sync_status);
            assert_eq!(d.health_status, a.health_status);
        }
        println!(
            "installed={} apps={} in_cluster={in_cluster} multi_source={multi} automated={automated} resources={resources} needing_attention={problem_resources} failed_ops={failed_ops} sync_failures={sync_failures} conditions={conditions} health_in_tree={in_tree}",
            list.installed,
            list.apps.len()
        );
    }
}
