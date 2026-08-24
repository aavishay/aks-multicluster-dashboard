//! Data-fetching functions against a single cluster context. Each function
//! opens Kubernetes API calls concurrently where sensible and maps results
//! onto the plain-data structs in `models.rs`.

use crate::kubeconfig::{client_for_context, SLOW_CLUSTER_TIMEOUT};
use crate::models::*;
use chrono::Utc;
use futures::{AsyncBufReadExt, TryStreamExt};
use k8s_openapi::api::apps::v1::{ControllerRevision, DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::{Event, Namespace, Node, Pod};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams, LogParams, ResourceExt};
use kube::Client;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tauri::ipc::Channel;
use tokio::task::AbortHandle;

/// `metrics.k8s.io` requests are "best-effort" by design (absence of
/// metrics-server is handled as "no data", not an error) — but that only
/// holds if a broken/absent metrics-server actually errors quickly. Some
/// clusters instead leave the aggregated-API request hanging with no
/// response at all, which without a request-level timeout would ride the
/// client's full (multi-minute) read timeout, making the whole nodes/pods
/// list look permanently stuck on "Loading…" instead of just missing usage
/// numbers.
///
/// This used to be a flat 5s, which was measured directly against this
/// fleet to be far too tight: a full-cluster pod-metrics request took
/// 12-40s across repeated attempts on multiple clusters, metrics-server
/// healthy and responding the whole time. That made usage data disappear
/// on most loads, not just occasional slow ones. Defined as a fraction of
/// `SLOW_CLUSTER_TIMEOUT` rather than its own picked number so it stays
/// comfortably below the pods/nodes list's own deadline — a metrics
/// endpoint that's genuinely hanging should still fail faster than the
/// list itself would time out — without the two constants needing to be
/// hand-kept in agreement.
const METRICS_REQUEST_TIMEOUT: Duration = Duration::from_secs(SLOW_CLUSTER_TIMEOUT.as_secs() / 2);

/// The `metrics.k8s.io` aggregated API (backed by metrics-server) isn't part
/// of `k8s-openapi`'s typed models, and pulling in a separate crate for it
/// drags in its own pinned `k8s-openapi` version which tends to conflict with
/// ours. It's a small, stable JSON shape, so we just hit it as a raw request
/// and parse the bits we need. Absence of metrics-server (common on smaller
/// or freshly-provisioned AKS clusters) is expected and handled as "no data"
/// rather than an error.
async fn fetch_node_metrics(client: &Client) -> HashMap<String, (i64, i64)> {
    let req = match http::Request::builder()
        .uri("/apis/metrics.k8s.io/v1beta1/nodes")
        .body(Vec::new())
    {
        Ok(r) => r,
        Err(_) => return HashMap::new(),
    };
    let value: serde_json::Value = match tokio::time::timeout(METRICS_REQUEST_TIMEOUT, client.request(req)).await {
        Ok(Ok(v)) => v,
        _ => return HashMap::new(),
    };
    let mut out = HashMap::new();
    if let Some(items) = value.get("items").and_then(|v| v.as_array()) {
        for item in items {
            let name = item
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string();
            let cpu = item
                .get("usage")
                .and_then(|u| u.get("cpu"))
                .and_then(|c| c.as_str())
                .map(parse_cpu_millicores)
                .unwrap_or(0);
            let mem = item
                .get("usage")
                .and_then(|u| u.get("memory"))
                .and_then(|c| c.as_str())
                .map(parse_memory_ki)
                .unwrap_or(0);
            out.insert(name, (cpu, mem));
        }
    }
    out
}

async fn fetch_pod_metrics(client: &Client, namespace: &Option<String>) -> HashMap<(String, String), (i64, i64)> {
    let uri = match namespace {
        Some(ns) => format!("/apis/metrics.k8s.io/v1beta1/namespaces/{ns}/pods"),
        None => "/apis/metrics.k8s.io/v1beta1/pods".to_string(),
    };
    let req = match http::Request::builder().uri(uri).body(Vec::new()) {
        Ok(r) => r,
        Err(_) => return HashMap::new(),
    };
    let value: serde_json::Value = match tokio::time::timeout(METRICS_REQUEST_TIMEOUT, client.request(req)).await {
        Ok(Ok(v)) => v,
        _ => return HashMap::new(),
    };
    let mut out = HashMap::new();
    if let Some(items) = value.get("items").and_then(|v| v.as_array()) {
        for item in items {
            let name = item
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string();
            let ns = item
                .get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string();
            let mut cpu_total = 0i64;
            let mut mem_total = 0i64;
            if let Some(containers) = item.get("containers").and_then(|v| v.as_array()) {
                for c in containers {
                    cpu_total += c
                        .get("usage")
                        .and_then(|u| u.get("cpu"))
                        .and_then(|v| v.as_str())
                        .map(parse_cpu_millicores)
                        .unwrap_or(0);
                    mem_total += c
                        .get("usage")
                        .and_then(|u| u.get("memory"))
                        .and_then(|v| v.as_str())
                        .map(parse_memory_ki)
                        .unwrap_or(0);
                }
            }
            out.insert((ns, name), (cpu_total, mem_total));
        }
    }
    out
}

fn age_days(ts: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>) -> i64 {
    match ts {
        Some(t) => (Utc::now() - t.0).num_days().max(0),
        None => 0,
    }
}

fn age_seconds(ts: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>) -> i64 {
    match ts {
        Some(t) => (Utc::now() - t.0).num_seconds().max(0),
        None => 0,
    }
}

/// The object's managing controller (kind, name), if it has one — e.g. a Pod's
/// managing controller is usually the ReplicaSet that created it, not the
/// Deployment that created the ReplicaSet.
fn controller_owner(refs: &Option<Vec<OwnerReference>>) -> Option<(&str, &str)> {
    refs.as_ref()?
        .iter()
        .find(|o| o.controller == Some(true))
        .map(|o| (o.kind.as_str(), o.name.as_str()))
}

/// Parse a Kubernetes quantity string (e.g. "500m", "4", "8Gi", "16384Ki")
/// into millicores (for cpu-ish quantities) or Ki (for memory-ish
/// quantities). Callers pick the right parser for the field they're reading.
///
/// The unit a CPU quantity arrives in depends on which field it came from,
/// and the two differ: a Node's `capacity`/`allocatable` are whole cores or
/// millicores ("4", "3860m"), but `metrics.k8s.io` reports *usage* in
/// nanocores ("3405814n"), occasionally microcores ("512u") for a nearly-idle
/// container. Handling only "m" and bare numbers meant every nanocore reading
/// failed to parse and fell back to zero — so the Pods/Nodes tabs showed
/// "0m" CPU for everything while memory (whose "Ki"/"Mi" suffixes were
/// covered) looked correct.
fn parse_cpu_millicores(q: &str) -> i64 {
    // Ordered longest-suffix-first isn't needed here — these are all distinct
    // single characters — but the shape mirrors `parse_memory_ki` below.
    let units: [(&str, f64); 3] = [
        ("n", 1.0 / 1_000_000.0), // nanocores  -> millicores
        ("u", 1.0 / 1_000.0),     // microcores -> millicores
        ("m", 1.0),               // millicores
    ];
    for (suffix, factor_millicores) in units {
        if let Some(stripped) = q.strip_suffix(suffix) {
            return (stripped.parse::<f64>().unwrap_or(0.0) * factor_millicores).round() as i64;
        }
    }
    // Bare number: whole cores -> millicores
    (q.parse::<f64>().unwrap_or(0.0) * 1000.0).round() as i64
}

fn parse_memory_ki(q: &str) -> i64 {
    let units: [(&str, f64); 8] = [
        ("Ki", 1.0),
        ("Mi", 1024.0),
        ("Gi", 1024.0 * 1024.0),
        ("Ti", 1024.0 * 1024.0 * 1024.0),
        ("K", 1.0 / 1.024),
        ("M", 1000.0 / 1.024),
        ("G", 1_000_000.0 / 1.024),
        ("T", 1_000_000_000.0 / 1.024),
    ];
    for (suffix, factor_ki) in units {
        if let Some(stripped) = q.strip_suffix(suffix) {
            return (stripped.parse::<f64>().unwrap_or(0.0) * factor_ki) as i64;
        }
    }
    // Bare number: bytes -> Ki
    (q.parse::<f64>().unwrap_or(0.0) / 1024.0) as i64
}

pub async fn get_overview(context_name: &str) -> Result<ClusterOverview, String> {
    let client = match client_for_context(context_name).await {
        Ok(c) => c,
        Err(e) => {
            return Ok(ClusterOverview {
                context_name: context_name.to_string(),
                reachable: false,
                error: Some(e),
                ..Default::default()
            })
        }
    };

    let nodes_api: Api<Node> = Api::all(client.clone());
    let pods_api: Api<Pod> = Api::all(client.clone());
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let events_api: Api<Event> = Api::all(client.clone());

    // These five reads are independent of each other, so they're issued
    // concurrently rather than one after another — over a loaded VPN/private-
    // link path each round trip alone can take several seconds to tens of
    // seconds, and five back-to-back easily exceed the per-command deadline
    // even though the cluster is still responding, just slowly.
    let lp = ListParams::default();
    let (version, nodes_result, namespaces_result, pods_result, events_result) = tokio::join!(
        client.apiserver_version(),
        nodes_api.list(&lp),
        ns_api.list(&lp),
        pods_api.list(&lp),
        events_api.list(&lp),
    );

    let nodes = match nodes_result {
        Ok(l) => l.items,
        Err(e) => {
            return Ok(ClusterOverview {
                context_name: context_name.to_string(),
                reachable: false,
                error: Some(format!("Cluster unreachable or unauthorized: {e}")),
                ..Default::default()
            })
        }
    };
    let nodes_ready = nodes.iter().filter(|n| node_is_ready(n)).count();

    let namespaces = namespaces_result.map(|l| l.items.len()).unwrap_or(0);

    let pods = pods_result.map(|l| l.items).unwrap_or_default();
    let pods_running = pods
        .iter()
        .filter(|p| p.status.as_ref().and_then(|s| s.phase.clone()).as_deref() == Some("Running"))
        .count();
    let pods_not_ready = pods.len().saturating_sub(pods_running);

    let warning_event_count = events_result
        .map(|l| l.items.iter().filter(|e| e.type_.as_deref() == Some("Warning")).count())
        .unwrap_or(0);

    Ok(ClusterOverview {
        context_name: context_name.to_string(),
        reachable: true,
        error: None,
        kubernetes_version: version.ok().map(|v| format!("{}.{}", v.major, v.minor)),
        node_count: nodes.len(),
        nodes_ready,
        namespace_count: namespaces,
        pod_count: pods.len(),
        pods_running,
        pods_not_ready,
        warning_event_count,
    })
}

fn node_is_ready(n: &Node) -> bool {
    n.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|conds| {
            conds
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        })
        .unwrap_or(false)
}

pub async fn get_nodes(context_name: &str) -> Result<Vec<NodeInfo>, String> {
    let client = client_for_context(context_name).await?;
    let nodes_api: Api<Node> = Api::all(client.clone());

    // Metrics are best-effort (metrics-server may not be installed) and
    // independent of the node list, so it's fetched concurrently rather than
    // after — see `get_overview` for why that matters over a slow link.
    let lp = ListParams::default();
    let (nodes_result, metrics) = tokio::join!(nodes_api.list(&lp), fetch_node_metrics(&client));
    let nodes = nodes_result.map_err(|e| format!("Failed to list nodes: {e}"))?.items;

    let result = nodes
        .into_iter()
        .map(|n| {
            let name = n.name_any();
            let status = n.status.clone().unwrap_or_default();
            let alloc = status.allocatable.clone().unwrap_or_default();
            let cap = status.capacity.clone().unwrap_or_default();
            let node_info = status.node_info.clone();
            let labels = n.labels();
            let roles: Vec<String> = labels
                .keys()
                .filter_map(|k| k.strip_prefix("node-role.kubernetes.io/"))
                .map(|s| s.to_string())
                .collect();
            let roles = if roles.is_empty() { vec!["worker".to_string()] } else { roles };
            let zone = labels
                .get("topology.kubernetes.io/zone")
                .or_else(|| labels.get("failure-domain.beta.kubernetes.io/zone"))
                .cloned();
            let instance_type = labels.get("node.kubernetes.io/instance-type").cloned();
            let conditions: Vec<String> = status
                .conditions
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter(|c| c.status == "True")
                .map(|c| c.type_)
                .collect();
            let (cpu_usage, mem_usage) = metrics.get(&name).cloned().unwrap_or((0, 0));
            let has_metrics = metrics.contains_key(&name);

            NodeInfo {
                name: name.clone(),
                ready: node_is_ready(&n),
                roles,
                kubelet_version: node_info.as_ref().map(|i| i.kubelet_version.clone()).unwrap_or_default(),
                os_image: node_info.as_ref().map(|i| i.os_image.clone()).unwrap_or_default(),
                instance_type,
                zone,
                cpu_capacity: cap.get("cpu").map(|q| q.0.clone()).unwrap_or_default(),
                cpu_allocatable: alloc.get("cpu").map(|q| q.0.clone()).unwrap_or_default(),
                memory_capacity: cap.get("memory").map(|q| q.0.clone()).unwrap_or_default(),
                memory_allocatable: alloc.get("memory").map(|q| q.0.clone()).unwrap_or_default(),
                cpu_usage_millicores: if has_metrics { Some(cpu_usage) } else { None },
                memory_usage_ki: if has_metrics { Some(mem_usage) } else { None },
                conditions,
                age_days: age_days(n.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(n.metadata.creation_timestamp.clone()),
                unschedulable: n.spec.as_ref().and_then(|s| s.unschedulable).unwrap_or(false),
            }
        })
        .collect();

    Ok(result)
}

pub async fn get_node_manifest(context_name: &str, node_name: &str) -> Result<NodeManifest, String> {
    let client = client_for_context(context_name).await?;
    let nodes_api: Api<Node> = Api::all(client);
    let node = nodes_api
        .get(node_name)
        .await
        .map_err(|e| format!("Failed to get node '{node_name}': {e}"))?;

    let yaml_full = k8s_object_to_yaml(&node, "v1", "Node")?;

    let mut stripped = node.clone();
    stripped.metadata.managed_fields = None;
    let yaml_without_managed_fields = k8s_object_to_yaml(&stripped, "v1", "Node")?;

    Ok(NodeManifest {
        yaml_full,
        yaml_without_managed_fields,
    })
}

pub async fn get_pods(context_name: &str, namespace: Option<String>) -> Result<Vec<PodInfo>, String> {
    let client = client_for_context(context_name).await?;
    let pods_api: Api<Pod> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    // A Pod's own owner is normally the ReplicaSet that created it, not the
    // Deployment that created the ReplicaSet — resolve that one extra hop so
    // pods can be traced back to the workload shown in the Workloads tab.
    let replicasets_api: Api<ReplicaSet> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    // The pod list, its metrics, and the ReplicaSets needed for ownership are
    // all independent reads, issued concurrently — see `get_overview` for why
    // that matters once each round trip alone takes several seconds.
    let lp = ListParams::default();
    let (pods_result, metrics, rs_list_result) = tokio::join!(
        pods_api.list(&lp),
        fetch_pod_metrics(&client, &namespace),
        replicasets_api.list(&lp),
    );
    let pods = pods_result.map_err(|e| format!("Failed to list pods: {e}"))?.items;

    let rs_owner: HashMap<(String, String), (String, String)> = rs_list_result
        .map(|list| {
            list.items
                .into_iter()
                .filter_map(|rs| {
                    let (kind, owner_name) = controller_owner(&rs.metadata.owner_references)?;
                    let key = (rs.namespace().unwrap_or_default(), rs.name_any());
                    Some((key, (kind.to_string(), owner_name.to_string())))
                })
                .collect()
        })
        .unwrap_or_default();

    let result = pods
        .into_iter()
        .map(|p| {
            let name = p.name_any();
            let ns = p.namespace().unwrap_or_default();
            let status = p.status.clone().unwrap_or_default();
            let container_statuses = status.container_statuses.clone().unwrap_or_default();
            let total = container_statuses.len();
            let ready_count = container_statuses.iter().filter(|c| c.ready).count();
            let restarts = container_statuses.iter().map(|c| c.restart_count).sum();
            let key = (ns.clone(), name.clone());
            let (cpu, mem) = metrics.get(&key).cloned().unwrap_or((0, 0));
            let has_metrics = metrics.contains_key(&key);

            let (owner_kind, owner_name) = match controller_owner(&p.metadata.owner_references) {
                Some(("ReplicaSet", rs_name)) => rs_owner
                    .get(&(ns.clone(), rs_name.to_string()))
                    .cloned()
                    .map_or((Some("ReplicaSet".to_string()), Some(rs_name.to_string())), |(k, n)| {
                        (Some(k), Some(n))
                    }),
                Some((kind, owner_name)) => (Some(kind.to_string()), Some(owner_name.to_string())),
                None => (None, None),
            };

            PodInfo {
                name,
                namespace: ns,
                node: p.spec.as_ref().and_then(|s| s.node_name.clone()),
                phase: status.phase.clone().unwrap_or_else(|| "Unknown".to_string()),
                ready: format!("{ready_count}/{total}"),
                restarts,
                age_days: age_days(p.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(p.metadata.creation_timestamp.clone()),
                owner_kind,
                owner_name,
                cpu_usage_millicores: if has_metrics { Some(cpu) } else { None },
                memory_usage_ki: if has_metrics { Some(mem) } else { None },
                status_reason: status.reason.clone(),
            }
        })
        .collect();

    Ok(result)
}

/// Renders a pod as YAML the way `kubectl get pod -o yaml` would present it —
/// `k8s_openapi` structs don't carry `apiVersion`/`kind` as serialized fields
/// (they're compile-time constants on the `Resource` trait instead), so those
/// two are stitched in by hand. Field order ends up alphabetical rather than
/// kubectl's canonical order, since `serde_json`'s default map doesn't
/// preserve insertion order — a readable, if less familiar, tradeoff for not
/// pulling in an ordered-map dependency just for display.
/// Shared by every "view YAML" entry point (Pod, Node, ...): `k8s_openapi`
/// structs don't carry `apiVersion`/`kind` as serialized fields (they're
/// compile-time constants on the `Resource` trait instead), so those two are
/// stitched in by hand. Field order ends up alphabetical rather than
/// kubectl's canonical order, since `serde_json`'s default map doesn't
/// preserve insertion order — a readable, if less familiar, tradeoff for not
/// pulling in an ordered-map dependency just for display.
fn k8s_object_to_yaml<T: serde::Serialize>(obj: &T, api_version: &str, kind: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(obj).map_err(|e| format!("Failed to serialize object: {e}"))?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert("apiVersion".to_string(), serde_json::Value::String(api_version.to_string()));
        map.insert("kind".to_string(), serde_json::Value::String(kind.to_string()));
    }
    serde_yaml::to_string(&value).map_err(|e| format!("Failed to render YAML: {e}"))
}

/// Fetches a namespaced object by type and renders both YAML variants —
/// shared across workload kinds (Deployment/StatefulSet/DaemonSet) rather
/// than repeating the get-clone-strip-render sequence per kind. `meta_mut()`
/// comes from `kube::Resource` itself, implemented generically for every
/// k8s_openapi type, so this doesn't need a kind-specific field access.
/// Deployment/StatefulSet/DaemonSet all carry a `spec.template: PodTemplateSpec`
/// at the same field name but aren't related by any shared k8s_openapi trait —
/// this local one lets `fetch_workload_yaml` read the pod template's container
/// names generically instead of duplicating the same three-armed match twice.
trait HasPodTemplateContainers {
    fn container_names(&self) -> Vec<String>;
}

fn container_names_from(spec: Option<&k8s_openapi::api::core::v1::PodSpec>) -> Vec<String> {
    spec.map(|s| s.containers.iter().map(|c| c.name.clone()).collect()).unwrap_or_default()
}

impl HasPodTemplateContainers for Deployment {
    fn container_names(&self) -> Vec<String> {
        self.spec.as_ref().map_or_else(Vec::new, |s| container_names_from(s.template.spec.as_ref()))
    }
}

impl HasPodTemplateContainers for StatefulSet {
    fn container_names(&self) -> Vec<String> {
        self.spec.as_ref().map_or_else(Vec::new, |s| container_names_from(s.template.spec.as_ref()))
    }
}

impl HasPodTemplateContainers for DaemonSet {
    fn container_names(&self) -> Vec<String> {
        self.spec.as_ref().map_or_else(Vec::new, |s| container_names_from(s.template.spec.as_ref()))
    }
}

async fn fetch_workload_yaml<K>(
    client: Client,
    namespace: &str,
    name: &str,
    api_version: &str,
    kind: &str,
) -> Result<(String, String, Vec<String>), String>
where
    K: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope, DynamicType = ()>
        + HasPodTemplateContainers
        + Clone
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
{
    let api: Api<K> = Api::namespaced(client, namespace);
    let obj = api.get(name).await.map_err(|e| format!("Failed to get {kind} '{name}': {e}"))?;
    let containers = obj.container_names();
    let yaml_full = k8s_object_to_yaml(&obj, api_version, kind)?;

    let mut stripped = obj.clone();
    stripped.meta_mut().managed_fields = None;
    let yaml_without_managed_fields = k8s_object_to_yaml(&stripped, api_version, kind)?;

    Ok((yaml_full, yaml_without_managed_fields, containers))
}

pub async fn get_workload_manifest(
    context_name: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<WorkloadManifest, String> {
    let client = client_for_context(context_name).await?;
    let (yaml_full, yaml_without_managed_fields, containers) = match kind {
        "Deployment" => fetch_workload_yaml::<Deployment>(client, namespace, name, "apps/v1", "Deployment").await?,
        "StatefulSet" => fetch_workload_yaml::<StatefulSet>(client, namespace, name, "apps/v1", "StatefulSet").await?,
        "DaemonSet" => fetch_workload_yaml::<DaemonSet>(client, namespace, name, "apps/v1", "DaemonSet").await?,
        other => return Err(format!("Unsupported workload kind '{other}'")),
    };
    Ok(WorkloadManifest {
        yaml_full,
        yaml_without_managed_fields,
        containers,
    })
}

pub async fn get_pod_manifest(context_name: &str, namespace: &str, pod_name: &str) -> Result<PodManifest, String> {
    let client = client_for_context(context_name).await?;
    let pods_api: Api<Pod> = Api::namespaced(client, namespace);
    let pod = pods_api
        .get(pod_name)
        .await
        .map_err(|e| format!("Failed to get pod '{pod_name}': {e}"))?;

    let containers = pod
        .spec
        .as_ref()
        .map(|s| s.containers.iter().map(|c| c.name.clone()).collect())
        .unwrap_or_default();

    let yaml_full = k8s_object_to_yaml(&pod, "v1", "Pod")?;

    let mut stripped = pod.clone();
    stripped.metadata.managed_fields = None;
    let yaml_without_managed_fields = k8s_object_to_yaml(&stripped, "v1", "Pod")?;

    Ok(PodManifest {
        containers,
        yaml_full,
        yaml_without_managed_fields,
    })
}

/// One-shot log fetch, for the Head/Tail views. `tail` selects the last
/// `lines` lines via the API's own `tailLines` param (cheap, server-side);
/// "head" has no server-side equivalent — the log API can only bound *bytes*
/// from the start (`limitBytes`), not lines — so this over-fetches a capped
/// byte window and truncates to `lines` client-side.
pub async fn get_pod_logs(
    context_name: &str,
    namespace: &str,
    pod_name: &str,
    container: &str,
    tail: bool,
    lines: i64,
) -> Result<String, String> {
    let client = client_for_context(context_name).await?;
    let pods_api: Api<Pod> = Api::namespaced(client, namespace);
    let lines = lines.clamp(1, 5000);

    if tail {
        let lp = LogParams {
            container: Some(container.to_string()),
            tail_lines: Some(lines),
            ..Default::default()
        };
        pods_api
            .logs(pod_name, &lp)
            .await
            .map_err(|e| format!("Failed to fetch logs: {e}"))
    } else {
        let lp = LogParams {
            container: Some(container.to_string()),
            limit_bytes: Some(1_000_000),
            ..Default::default()
        };
        let full = pods_api
            .logs(pod_name, &lp)
            .await
            .map_err(|e| format!("Failed to fetch logs: {e}"))?;
        Ok(full.lines().take(lines as usize).collect::<Vec<_>>().join("\n"))
    }
}

/// Live-follow log streams, keyed by an id handed back to the frontend so a
/// later `stop_pod_log_stream` call can cancel the right one. A Tauri command
/// runs to completion and can't be "awaited partially" by the frontend, so
/// `start_pod_log_stream`/`start_workload_log_stream` spawn the actual
/// streaming as background tasks and return immediately — cancellation is
/// therefore explicit (abort the task) rather than implied by the command
/// returning. One id maps to *several* handles for a workload's merged
/// stream (one background task per pod) so a single `stop_pod_log_stream`
/// call tears down all of them together.
static NEXT_LOG_STREAM_ID: AtomicU64 = AtomicU64::new(1);
static LOG_STREAMS: OnceLock<Mutex<HashMap<u64, Vec<AbortHandle>>>> = OnceLock::new();

fn log_streams() -> &'static Mutex<HashMap<u64, Vec<AbortHandle>>> {
    LOG_STREAMS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Runs one pod's follow loop, sending each line (already formatted by the
/// caller) through `on_line` until the receiver goes away or the stream ends.
async fn stream_pod_lines<F>(pods_api: Api<Pod>, pod_name: String, container: String, on_line: Channel<String>, format_line: F)
where
    F: Fn(&str) -> String,
{
    let lp = LogParams {
        container: Some(container),
        follow: true,
        tail_lines: Some(100),
        ..Default::default()
    };
    let stream = match pods_api.log_stream(&pod_name, &lp).await {
        Ok(s) => s,
        Err(e) => {
            let _ = on_line.send(format_line(&format!("[error] failed to start log stream: {e}")));
            return;
        }
    };
    let mut lines = stream.lines();
    loop {
        match lines.try_next().await {
            Ok(Some(line)) => {
                if on_line.send(format_line(&line)).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = on_line.send(format_line(&format!("[error] {e}")));
                break;
            }
        }
    }
}

pub async fn start_pod_log_stream(
    context_name: &str,
    namespace: &str,
    pod_name: &str,
    container: &str,
    on_line: Channel<String>,
) -> Result<u64, String> {
    let client = client_for_context(context_name).await?;
    let pods_api: Api<Pod> = Api::namespaced(client, namespace);
    let pod_name = pod_name.to_string();
    let container = container.to_string();

    let id = NEXT_LOG_STREAM_ID.fetch_add(1, Ordering::SeqCst);
    let join_handle = tokio::spawn(async move {
        stream_pod_lines(pods_api, pod_name, container, on_line, |line| line.to_string()).await;
    });

    log_streams().lock().unwrap().insert(id, vec![join_handle.abort_handle()]);
    Ok(id)
}

/// Same idea as `start_pod_log_stream`, but one background task per pod, all
/// feeding the same channel — each line prefixed with its source pod so the
/// merged view (like `stern`/`kubetail`, not plain `kubectl logs`, which only
/// ever picks one pod) stays attributable. Interleaving is by arrival order
/// rather than a strict timestamp merge, which is what every such tool does
/// for a *live* tail — the lines are arriving in real time already.
pub async fn start_workload_log_stream(
    context_name: &str,
    namespace: &str,
    pod_names: &[String],
    container: &str,
    on_line: Channel<String>,
) -> Result<u64, String> {
    let client = client_for_context(context_name).await?;
    let id = NEXT_LOG_STREAM_ID.fetch_add(1, Ordering::SeqCst);

    let mut handles = Vec::with_capacity(pod_names.len());
    for pod_name in pod_names {
        let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
        let pod_name = pod_name.clone();
        let container = container.to_string();
        let on_line = on_line.clone();
        let prefix = pod_name.clone();
        let join_handle = tokio::spawn(async move {
            stream_pod_lines(pods_api, pod_name, container, on_line, move |line| format!("[{prefix}] {line}")).await;
        });
        handles.push(join_handle.abort_handle());
    }

    log_streams().lock().unwrap().insert(id, handles);
    Ok(id)
}

pub fn stop_pod_log_stream(stream_id: u64) {
    if let Some(handles) = log_streams().lock().unwrap().remove(&stream_id) {
        for handle in handles {
            handle.abort();
        }
    }
}

/// Kubelet prefixes each line with an RFC3339Nano timestamp when `timestamps:
/// true` is requested — split it off so multi-pod fetches can be merged in
/// chronological order rather than one pod's whole chunk followed by the
/// next's. Falls back to treating the whole line as content (empty
/// timestamp, sorts first) if a line doesn't look like it has one.
fn split_log_timestamp(line: &str) -> (&str, &str) {
    match line.split_once(' ') {
        Some((ts, rest)) if ts.contains('T') && ts.ends_with('Z') => (ts, rest),
        _ => ("", line),
    }
}

/// One-shot Head/Tail fetch across every pod, merged chronologically and
/// prefixed by pod name — unlike plain `kubectl logs deployment/x` (which
/// only shows one arbitrarily-chosen pod), this matches what `stern`/
/// `kubetail` show. A pod whose fetch fails gets a single inline error line
/// instead of failing the whole request, so one bad pod doesn't blank the
/// rest.
pub async fn get_workload_logs(
    context_name: &str,
    namespace: &str,
    pod_names: &[String],
    container: &str,
    tail: bool,
    lines: i64,
) -> Result<String, String> {
    let client = client_for_context(context_name).await?;
    let pods_api: Api<Pod> = Api::namespaced(client, namespace);
    let lines = lines.clamp(1, 5000);

    let fetches = pod_names.iter().map(|pod_name| {
        let pods_api = pods_api.clone();
        let container = container.to_string();
        let pod_name = pod_name.clone();
        async move {
            let lp = if tail {
                LogParams {
                    container: Some(container),
                    tail_lines: Some(lines),
                    timestamps: true,
                    ..Default::default()
                }
            } else {
                LogParams {
                    container: Some(container),
                    limit_bytes: Some(1_000_000),
                    timestamps: true,
                    ..Default::default()
                }
            };
            let result = pods_api.logs(&pod_name, &lp).await.map_err(|e| e.to_string());
            (pod_name, result)
        }
    });

    let mut merged: Vec<(String, String, String)> = Vec::new(); // (timestamp, pod, content)
    let mut errors: Vec<String> = Vec::new();
    for (pod_name, result) in futures::future::join_all(fetches).await {
        match result {
            Ok(text) => {
                for line in text.lines() {
                    let (ts, content) = split_log_timestamp(line);
                    merged.push((ts.to_string(), pod_name.clone(), content.to_string()));
                }
            }
            Err(e) => errors.push(format!("[{pod_name}] [error fetching logs: {e}]")),
        }
    }

    merged.sort_by(|a, b| a.0.cmp(&b.0));
    if tail {
        let start = merged.len().saturating_sub(lines as usize);
        merged.drain(..start);
    } else {
        merged.truncate(lines as usize);
    }

    let mut out: Vec<String> = merged.into_iter().map(|(_, pod, content)| format!("[{pod}] {content}")).collect();
    out.extend(errors);
    Ok(out.join("\n"))
}

/// The version-ish part of a container image reference.
///
/// Two shapes make this more than a `split(':')`: a registry can carry a port
/// (`registry:5000/img:tag` — that first colon isn't a tag separator), and an
/// image can be digest-pinned (`img@sha256:…`) with no tag at all. A tagless
/// image means `:latest` to Kubernetes, so that's what's reported.
fn image_version(image: &str) -> String {
    if let Some((_, digest)) = image.split_once('@') {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        return format!("@{}", hex.chars().take(12).collect::<String>());
    }
    // Only the final path segment can hold a tag; any earlier colon is a port.
    let last_segment = image.rsplit('/').next().unwrap_or(image);
    match last_segment.split_once(':') {
        Some((_, tag)) if !tag.is_empty() => tag.to_string(),
        _ => "latest".to_string(),
    }
}

/// Version/provenance fields shared by all three workload kinds: the
/// `app.kubernetes.io/version` label is the canonical answer where set (it's
/// what Helm charts and the Kubernetes recommended-labels convention write),
/// but roughly a quarter of real workloads don't carry it — those fall back to
/// the first container's image tag, which is the version actually running.
/// The label can also drift from reality if someone patches an image without
/// updating it, so the UI reports which source it used.
struct WorkloadVersionFields {
    version: String,
    version_from_label: bool,
    images: Vec<String>,
    chart: Option<String>,
}

fn workload_version_fields(
    labels: &std::collections::BTreeMap<String, String>,
    pod_spec: Option<&k8s_openapi::api::core::v1::PodSpec>,
) -> WorkloadVersionFields {
    // Init containers are deliberately excluded: they're setup helpers, and
    // their tags would muddy "what version is this workload".
    let images: Vec<String> = pod_spec
        .map(|s| s.containers.iter().filter_map(|c| c.image.clone()).collect())
        .unwrap_or_default();

    let label_version = labels.get("app.kubernetes.io/version").filter(|v| !v.is_empty());
    let (version, version_from_label) = match label_version {
        Some(v) => (v.clone(), true),
        None => (images.first().map(|i| image_version(i)).unwrap_or_default(), false),
    };

    WorkloadVersionFields {
        version,
        version_from_label,
        images,
        chart: labels.get("helm.sh/chart").filter(|v| !v.is_empty()).cloned(),
    }
}

pub async fn get_workloads(context_name: &str) -> Result<Vec<WorkloadInfo>, String> {
    let client = client_for_context(context_name).await?;

    let deployments: Api<Deployment> = Api::all(client.clone());
    let statefulsets: Api<StatefulSet> = Api::all(client.clone());
    let daemonsets: Api<DaemonSet> = Api::all(client.clone());

    // Three independent lists, issued concurrently — see `get_overview` for
    // why that matters once each round trip alone takes several seconds.
    let lp = ListParams::default();
    let (deployments_result, statefulsets_result, daemonsets_result) = tokio::join!(
        deployments.list(&lp),
        statefulsets.list(&lp),
        daemonsets.list(&lp),
    );

    let mut out = Vec::new();

    if let Ok(list) = deployments_result {
        for d in list.items {
            let spec = d.spec.clone().unwrap_or_default();
            let status = d.status.clone().unwrap_or_default();
            let desired = spec.replicas.unwrap_or(0);
            let ready = status.ready_replicas.unwrap_or(0);
            let v = workload_version_fields(d.labels(), spec.template.spec.as_ref());
            out.push(WorkloadInfo {
                kind: "Deployment".to_string(),
                name: d.name_any(),
                namespace: d.namespace().unwrap_or_default(),
                desired,
                ready,
                updated: status.updated_replicas.unwrap_or(0),
                available: status.available_replicas.unwrap_or(0),
                healthy: desired == ready,
                age_days: age_days(d.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(d.metadata.creation_timestamp.clone()),
                version: v.version,
                version_from_label: v.version_from_label,
                images: v.images,
                chart: v.chart,
            });
        }
    }

    if let Ok(list) = statefulsets_result {
        for s in list.items {
            let spec = s.spec.clone().unwrap_or_default();
            let status = s.status.clone().unwrap_or_default();
            let desired = spec.replicas.unwrap_or(0);
            let ready = status.ready_replicas.unwrap_or(0);
            let v = workload_version_fields(s.labels(), spec.template.spec.as_ref());
            out.push(WorkloadInfo {
                kind: "StatefulSet".to_string(),
                name: s.name_any(),
                namespace: s.namespace().unwrap_or_default(),
                desired,
                ready,
                updated: status.updated_replicas.unwrap_or(0),
                available: status.available_replicas.unwrap_or(0),
                healthy: desired == ready,
                age_days: age_days(s.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(s.metadata.creation_timestamp.clone()),
                version: v.version,
                version_from_label: v.version_from_label,
                images: v.images,
                chart: v.chart,
            });
        }
    }

    if let Ok(list) = daemonsets_result {
        for d in list.items {
            let status = d.status.clone().unwrap_or_default();
            let desired = status.desired_number_scheduled;
            let ready = status.number_ready;
            let v = workload_version_fields(d.labels(), d.spec.as_ref().and_then(|sp| sp.template.spec.as_ref()));
            out.push(WorkloadInfo {
                kind: "DaemonSet".to_string(),
                name: d.name_any(),
                namespace: d.namespace().unwrap_or_default(),
                desired,
                ready,
                updated: status.updated_number_scheduled.unwrap_or(0),
                available: status.number_available.unwrap_or(0),
                healthy: desired == ready,
                age_days: age_days(d.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(d.metadata.creation_timestamp.clone()),
                version: v.version,
                version_from_label: v.version_from_label,
                images: v.images,
                chart: v.chart,
            });
        }
    }

    out.sort_by(|a, b| a.healthy.cmp(&b.healthy).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

/// Labels that change on every revision *by construction* — they're hashes of
/// the template itself — so they carry no information when two revisions are
/// compared, and would add a guaranteed difference to every single diff.
/// Verified against a real rollout: stripping `pod-template-hash` took a
/// rev-110→111 diff from two changes down to the one that mattered (the image
/// tag).
const REVISION_HASH_LABELS: &[&str] = &["pod-template-hash", "controller-revision-hash"];

/// A revision's pod template as YAML, normalised for diffing.
///
/// Both revision sources are funnelled through `serde_json::Value` rather than
/// their own types so this normalisation is written once: a ReplicaSet has a
/// typed `PodTemplateSpec`, while a ControllerRevision only has opaque
/// serialized JSON.
fn revision_template_yaml(template: &serde_json::Value) -> String {
    let mut normalised = template.clone();
    if let Some(labels) = normalised.pointer_mut("/metadata/labels").and_then(|l| l.as_object_mut()) {
        for label in REVISION_HASH_LABELS {
            labels.remove(*label);
        }
    }
    // A serialized pod template always carries an explicit null
    // creationTimestamp (the field isn't `Option`-skipped); it's never
    // meaningful and would otherwise sit in every rendered template.
    if let Some(meta) = normalised.pointer_mut("/metadata").and_then(|m| m.as_object_mut()) {
        if meta.get("creationTimestamp").is_some_and(|v| v.is_null()) {
            meta.remove("creationTimestamp");
        }
    }
    serde_yaml::to_string(&normalised).unwrap_or_default()
}

/// Images out of a ControllerRevision's embedded pod template. A
/// ControllerRevision stores its state as opaque serialized JSON (`data`, a
/// `RawExtension`) rather than a typed pod spec, so this reads the container
/// images out of that JSON by path instead of deserializing the whole thing.
fn controller_revision_images(cr: &ControllerRevision) -> Vec<String> {
    cr.data
        .as_ref()
        .and_then(|d| d.0.pointer("/spec/template/spec/containers"))
        .and_then(|c| c.as_array())
        .map(|containers| {
            containers
                .iter()
                .filter_map(|c| c.get("image").and_then(|i| i.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// A workload's rollout history.
///
/// The two mechanisms Kubernetes uses here are different objects, not one
/// abstraction: a Deployment's history is the ReplicaSets it owns, each
/// tagged with a `deployment.kubernetes.io/revision` annotation, while a
/// StatefulSet's or DaemonSet's is a set of ControllerRevisions carrying a
/// first-class `revision` field. Both are reported through the same shape.
///
/// `replicas` is only meaningful for a Deployment: a ReplicaSet is a running
/// object that can be scaled (the current revision holds the replicas, older
/// ones sit at zero — which is what makes a rollback possible), whereas a
/// ControllerRevision is an immutable stored template with no replica count
/// of its own.
pub async fn get_workload_revisions(
    context_name: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<Vec<WorkloadRevisionInfo>, String> {
    let client = client_for_context(context_name).await?;
    let lp = ListParams::default();

    let mut revisions: Vec<WorkloadRevisionInfo> = match kind {
        "Deployment" => {
            let api: Api<ReplicaSet> = Api::namespaced(client, namespace);
            api.list(&lp)
                .await
                .map_err(|e| format!("Failed to list ReplicaSets: {e}"))?
                .items
                .into_iter()
                // Ownership, not a name prefix: a name prefix would also pull
                // in a same-prefixed sibling Deployment's ReplicaSets.
                .filter(|rs| controller_owner(&rs.metadata.owner_references) == Some(("Deployment", name)))
                .map(|rs| {
                    let spec = rs.spec.clone().unwrap_or_default();
                    let status = rs.status.clone().unwrap_or_default();
                    WorkloadRevisionInfo {
                        revision: rs
                            .annotations()
                            .get("deployment.kubernetes.io/revision")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0),
                        name: rs.name_any(),
                        replicas: Some(spec.replicas.unwrap_or(0)),
                        ready_replicas: Some(status.ready_replicas.unwrap_or(0)),
                        images: spec
                            .template
                            .as_ref()
                            .and_then(|t| t.spec.as_ref())
                            .map(|s| s.containers.iter().filter_map(|c| c.image.clone()).collect())
                            .unwrap_or_default(),
                        template_yaml: spec
                            .template
                            .as_ref()
                            .and_then(|t| serde_json::to_value(t).ok())
                            .map(|v| revision_template_yaml(&v))
                            .unwrap_or_default(),
                        current: false,
                        age_days: age_days(rs.metadata.creation_timestamp.clone()),
                        age_seconds: age_seconds(rs.metadata.creation_timestamp.clone()),
                    }
                })
                .collect()
        }
        "StatefulSet" | "DaemonSet" => {
            let api: Api<ControllerRevision> = Api::namespaced(client, namespace);
            api.list(&lp)
                .await
                .map_err(|e| format!("Failed to list ControllerRevisions: {e}"))?
                .items
                .into_iter()
                .filter(|cr| controller_owner(&cr.metadata.owner_references) == Some((kind, name)))
                .map(|cr| WorkloadRevisionInfo {
                    revision: cr.revision,
                    name: cr.name_any(),
                    replicas: None,
                    ready_replicas: None,
                    images: controller_revision_images(&cr),
                    template_yaml: cr
                        .data
                        .as_ref()
                        .and_then(|d| d.0.pointer("/spec/template"))
                        .map(revision_template_yaml)
                        .unwrap_or_default(),
                    current: false,
                    age_days: age_days(cr.metadata.creation_timestamp.clone()),
                    age_seconds: age_seconds(cr.metadata.creation_timestamp.clone()),
                })
                .collect()
        }
        other => return Err(format!("Unsupported workload kind '{other}'")),
    };

    // Newest first, the order a rollout history is read in.
    revisions.sort_by(|a, b| b.revision.cmp(&a.revision));
    if let Some(first) = revisions.first_mut() {
        first.current = true;
    }
    Ok(revisions)
}

fn event_to_info(e: Event) -> EventInfo {
    EventInfo {
        namespace: e.metadata.namespace.clone().unwrap_or_default(),
        involved_object: format!(
            "{}/{}",
            e.involved_object.kind.clone().unwrap_or_default(),
            e.involved_object.name.clone().unwrap_or_default()
        ),
        reason: e.reason.clone().unwrap_or_default(),
        message: e.message.clone().unwrap_or_default(),
        event_type: e.type_.clone().unwrap_or_default(),
        count: e.count.unwrap_or(0),
        last_seen: e.last_timestamp.clone().map(|t| t.0.to_rfc3339()),
    }
}

/// Every `get_*_events` variant below needs the same cluster-wide list,
/// newest-first — factored out so each only has to say what it filters for.
async fn list_events_sorted(client: &Client) -> Result<Vec<Event>, String> {
    let events_api: Api<Event> = Api::all(client.clone());
    let mut items = events_api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list events: {e}"))?
        .items;

    items.sort_by(|a, b| {
        let a_time = a.last_timestamp.clone().map(|t| t.0);
        let b_time = b.last_timestamp.clone().map(|t| t.0);
        b_time.cmp(&a_time)
    });
    Ok(items)
}

pub async fn get_events(context_name: &str, warnings_only: bool) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;

    Ok(items
        .into_iter()
        .filter(|e| !warnings_only || e.type_.as_deref() == Some("Warning"))
        .take(300)
        .map(event_to_info)
        .collect())
}

/// Unlike `get_events`, filters by involved-object *before* the top-300 cap
/// a cluster-wide fetch needs — otherwise a node's own (typically infrequent)
/// events could get crowded out of that cap by churn elsewhere in a busy
/// cluster and simply not show up here.
pub async fn get_node_events(context_name: &str, node_name: &str) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;

    Ok(items
        .into_iter()
        .filter(|e| e.involved_object.kind.as_deref() == Some("Node") && e.involved_object.name.as_deref() == Some(node_name))
        .map(event_to_info)
        .collect())
}

/// Same reasoning as `get_node_events` (filter before the cap, not after).
/// Namespace is included in the match since a Deployment/StatefulSet/DaemonSet
/// name is only unique within its namespace, not cluster-wide.
pub async fn get_workload_events(
    context_name: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;

    Ok(items
        .into_iter()
        .filter(|e| {
            e.involved_object.kind.as_deref() == Some(kind)
                && e.involved_object.name.as_deref() == Some(name)
                && e.metadata.namespace.as_deref() == Some(namespace)
        })
        .map(event_to_info)
        .collect())
}

/// Same reasoning as `get_node_events` — filter by involved object *before*
/// the cluster-wide cap, so a quiet pod's events aren't crowded out by churn
/// elsewhere.
pub async fn get_pod_events(context_name: &str, namespace: &str, pod_name: &str) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;

    Ok(items
        .into_iter()
        .filter(|e| {
            e.involved_object.kind.as_deref() == Some("Pod")
                && e.involved_object.name.as_deref() == Some(pod_name)
                && e.metadata.namespace.as_deref() == Some(namespace)
        })
        .map(event_to_info)
        .collect())
}

pub async fn get_resource_usage(context_name: &str) -> Result<ResourceUsageSummary, String> {
    let client = client_for_context(context_name).await?;
    let nodes_api: Api<Node> = Api::all(client.clone());

    // Node metrics don't depend on the node list itself, only on the client
    // — fetched concurrently rather than after, same reasoning as `get_overview`.
    let lp = ListParams::default();
    let (nodes_result, node_metrics) = tokio::join!(nodes_api.list(&lp), fetch_node_metrics(&client));
    let nodes = nodes_result.map_err(|e| format!("Failed to list nodes: {e}"))?.items;

    let cpu_allocatable_millicores: i64 = nodes
        .iter()
        .filter_map(|n| n.status.as_ref()?.allocatable.as_ref()?.get("cpu"))
        .map(|q| parse_cpu_millicores(&q.0))
        .sum();
    let memory_allocatable_ki: i64 = nodes
        .iter()
        .filter_map(|n| n.status.as_ref()?.allocatable.as_ref()?.get("memory"))
        .map(|q| parse_memory_ki(&q.0))
        .sum();
    if node_metrics.is_empty() {
        return Ok(ResourceUsageSummary {
            metrics_available: false,
            cpu_used_millicores: 0,
            cpu_allocatable_millicores,
            memory_used_ki: 0,
            memory_allocatable_ki,
        });
    }
    let cpu_used: i64 = node_metrics.values().map(|(cpu, _)| cpu).sum();
    let mem_used: i64 = node_metrics.values().map(|(_, mem)| mem).sum();
    Ok(ResourceUsageSummary {
        metrics_available: true,
        cpu_used_millicores: cpu_used,
        cpu_allocatable_millicores,
        memory_used_ki: mem_used,
        memory_allocatable_ki,
    })
}

/// ArgoCD's `Application` CRD isn't part of `k8s_openapi` (it's third-party,
/// not core/aggregated Kubernetes API), so it's queried as a `DynamicObject`
/// against its GVK rather than through a generated type — the same approach
/// `fetch_node_metrics` uses for the `metrics.k8s.io` aggregated API, just
/// via `kube`'s dynamic-object support instead of a raw HTTP request, since
/// this one *is* a normal list/get-able Kubernetes resource once its GVK is
/// known.
fn argocd_application_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk("argoproj.io", "v1alpha1", "Application");
    ApiResource::from_gvk_with_plural(&gvk, "applications")
}

fn json_str<'a>(value: Option<&'a serde_json::Value>, key: &str) -> &'a str {
    value.and_then(|v| v.get(key)).and_then(|v| v.as_str()).unwrap_or_default()
}

/// Flattens a raw `Application` object's `spec`/`status` JSON into the fields
/// the GitOps tab shows. Multi-source apps (`spec.sources`, plural) are rare
/// next to the single-source `spec.source` shape, so only the first entry is
/// surfaced here rather than modelling the full list.
fn dynamic_object_to_gitops_app(obj: DynamicObject) -> GitOpsAppInfo {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();

    let spec = obj.data.get("spec");
    let status = obj.data.get("status");
    let source = spec
        .and_then(|s| s.get("source"))
        .or_else(|| spec.and_then(|s| s.get("sources")).and_then(|s| s.as_array()).and_then(|a| a.first()));

    let path = json_str(source, "path");
    let path = if !path.is_empty() {
        path.to_string()
    } else {
        match json_str(source, "chart") {
            "" => String::new(),
            chart => format!("chart: {chart}"),
        }
    };

    let sync = status.and_then(|s| s.get("sync"));
    let revision = json_str(sync, "revision");
    let sync_status = match json_str(sync, "status") {
        "" => "Unknown".to_string(),
        s => s.to_string(),
    };
    let health_status = match json_str(status.and_then(|s| s.get("health")), "status") {
        "" => "Unknown".to_string(),
        s => s.to_string(),
    };

    GitOpsAppInfo {
        namespace,
        destination_namespace: json_str(spec.and_then(|s| s.get("destination")), "namespace").to_string(),
        sync_status,
        health_status,
        repo_url: json_str(source, "repoURL").to_string(),
        path,
        target_revision: json_str(source, "targetRevision").to_string(),
        revision: revision.get(..revision.len().min(7)).unwrap_or_default().to_string(),
        age_days: age_days(obj.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(obj.metadata.creation_timestamp.clone()),
        name,
    }
}

pub async fn get_gitops_apps(context_name: &str) -> Result<GitOpsResult, String> {
    let client = client_for_context(context_name).await?;
    let ar = argocd_application_resource();
    let api: Api<DynamicObject> = Api::all_with(client, &ar);

    let list = match api.list(&ListParams::default()).await {
        Ok(l) => l,
        Err(kube::Error::Api(resp)) if resp.code == 404 => {
            return Ok(GitOpsResult { installed: false, error: None, apps: Vec::new() })
        }
        Err(e) => return Err(format!("Failed to list ArgoCD applications: {e}")),
    };

    Ok(GitOpsResult {
        installed: true,
        error: None,
        apps: list.items.into_iter().map(dynamic_object_to_gitops_app).collect(),
    })
}

pub async fn get_gitops_manifest(context_name: &str, namespace: &str, name: &str) -> Result<GitOpsAppManifest, String> {
    let client = client_for_context(context_name).await?;
    let ar = argocd_application_resource();
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &ar);
    let obj = api.get(name).await.map_err(|e| format!("Failed to get Application '{name}': {e}"))?;

    let yaml_full = serde_yaml::to_string(&obj).map_err(|e| format!("Failed to render YAML: {e}"))?;

    let mut stripped = obj;
    stripped.metadata.managed_fields = None;
    let yaml_without_managed_fields = serde_yaml::to_string(&stripped).map_err(|e| format!("Failed to render YAML: {e}"))?;

    Ok(GitOpsAppManifest { yaml_full, yaml_without_managed_fields })
}

/// Same reasoning as `get_workload_events` (filter before the cap).
pub async fn get_gitops_events(context_name: &str, namespace: &str, name: &str) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;

    Ok(items
        .into_iter()
        .filter(|e| {
            e.involved_object.kind.as_deref() == Some("Application")
                && e.involved_object.name.as_deref() == Some(name)
                && e.metadata.namespace.as_deref() == Some(namespace)
        })
        .map(event_to_info)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_log_timestamp_separates_kubelet_prefixed_lines() {
        assert_eq!(
            split_log_timestamp("2024-01-15T12:34:56.789012345Z hello world"),
            ("2024-01-15T12:34:56.789012345Z", "hello world")
        );
    }

    #[test]
    fn split_log_timestamp_falls_back_when_no_timestamp_present() {
        assert_eq!(split_log_timestamp("just a log line"), ("", "just a log line"));
        assert_eq!(split_log_timestamp("{\"level\":\"info\"}"), ("", "{\"level\":\"info\"}"));
    }

    #[test]
    fn split_log_timestamp_handles_a_line_with_no_spaces() {
        assert_eq!(split_log_timestamp("nospaceshere"), ("", "nospaceshere"));
    }

    /// The units `metrics.k8s.io` actually reports usage in — nanocores for
    /// almost everything, microcores for a nearly-idle container. Parsing
    /// these as zero is what made every pod's CPU read "0m".
    #[test]
    fn parse_cpu_millicores_handles_metrics_server_usage_units() {
        assert_eq!(parse_cpu_millicores("3405814n"), 3);
        assert_eq!(parse_cpu_millicores("265286814n"), 265);
        assert_eq!(parse_cpu_millicores("1000000n"), 1);
        assert_eq!(parse_cpu_millicores("512u"), 1); // 0.512m, rounded
        assert_eq!(parse_cpu_millicores("2500u"), 3); // 2.5m, rounded
    }

    /// The units a Node's `capacity`/`allocatable` use — these already worked
    /// and must keep working, since the same parser reads both fields.
    #[test]
    fn parse_cpu_millicores_handles_node_capacity_units() {
        assert_eq!(parse_cpu_millicores("4"), 4000);
        assert_eq!(parse_cpu_millicores("3860m"), 3860);
        assert_eq!(parse_cpu_millicores("0"), 0);
        assert_eq!(parse_cpu_millicores("0.5"), 500);
    }

    #[test]
    fn parse_cpu_millicores_falls_back_to_zero_on_garbage() {
        assert_eq!(parse_cpu_millicores(""), 0);
        assert_eq!(parse_cpu_millicores("notanumber"), 0);
    }

    /// Sub-millicore usage rounds rather than truncating, so a genuinely busy
    /// but low-usage container doesn't report a flat 0m.
    #[test]
    fn parse_cpu_millicores_rounds_sub_millicore_usage() {
        assert_eq!(parse_cpu_millicores("600000n"), 1); // 0.6m
        assert_eq!(parse_cpu_millicores("400000n"), 0); // 0.4m -> genuinely ~0
    }

    /// Real image references seen on the cluster, plus the two shapes a naive
    /// `split(':')` gets wrong: a registry port and a digest pin.
    #[test]
    fn image_version_extracts_the_tag() {
        assert_eq!(image_version("myregistry.azurecr.io/inx-service:ffbe3449"), "ffbe3449");
        assert_eq!(image_version("docker.io/bitnamilegacy/etcd:3.6.4-debian-12-r3"), "3.6.4-debian-12-r3");
        assert_eq!(image_version("nginx:v1.2.3"), "v1.2.3");
    }

    #[test]
    fn image_version_treats_a_tagless_image_as_latest() {
        // Kubernetes itself resolves a tagless reference to `:latest`.
        assert_eq!(image_version("nginx"), "latest");
        assert_eq!(image_version("docker.io/library/nginx"), "latest");
        assert_eq!(image_version("nginx:"), "latest");
    }

    #[test]
    fn image_version_does_not_mistake_a_registry_port_for_a_tag() {
        assert_eq!(image_version("registry.internal:5000/team/app:2.1.0"), "2.1.0");
        // Port present but no tag — still `latest`, not "5000".
        assert_eq!(image_version("registry.internal:5000/team/app"), "latest");
    }

    #[test]
    fn image_version_shortens_a_digest_pin() {
        assert_eq!(
            image_version("ghcr.io/org/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            "@0123456789ab"
        );
        // A digest pin can also carry a tag; the digest is the precise answer.
        assert!(image_version("app:1.0@sha256:abcdef0123456789").starts_with('@'));
    }

    fn labels_of(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn pod_spec_with(images: &[&str]) -> k8s_openapi::api::core::v1::PodSpec {
        k8s_openapi::api::core::v1::PodSpec {
            containers: images
                .iter()
                .enumerate()
                .map(|(i, img)| k8s_openapi::api::core::v1::Container {
                    name: format!("c{i}"),
                    image: Some(img.to_string()),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn workload_version_prefers_the_canonical_label() {
        let spec = pod_spec_with(&["repo/app:from-image"]);
        let v = workload_version_fields(&labels_of(&[("app.kubernetes.io/version", "1.4.2")]), Some(&spec));
        assert_eq!(v.version, "1.4.2");
        assert!(v.version_from_label);
        assert_eq!(v.images, vec!["repo/app:from-image"]);
    }

    #[test]
    fn workload_version_falls_back_to_the_image_tag() {
        let spec = pod_spec_with(&["acr.io/inx-service:ffbe3449", "sidecar:9.9"]);
        let v = workload_version_fields(&labels_of(&[]), Some(&spec));
        assert_eq!(v.version, "ffbe3449", "uses the first container's tag");
        assert!(!v.version_from_label);
        assert_eq!(v.images.len(), 2, "but still reports every container's image");
    }

    #[test]
    fn workload_version_ignores_an_empty_label_and_survives_no_containers() {
        let spec = pod_spec_with(&["repo/app:2.0"]);
        let v = workload_version_fields(&labels_of(&[("app.kubernetes.io/version", "")]), Some(&spec));
        assert_eq!(v.version, "2.0", "an empty label is not a version");

        let none = workload_version_fields(&labels_of(&[]), None);
        assert_eq!(none.version, "");
        assert!(none.images.is_empty());
        assert_eq!(none.chart, None);
    }

    #[test]
    fn workload_version_reports_the_helm_chart_label() {
        let v = workload_version_fields(&labels_of(&[("helm.sh/chart", "apisix-2.14.0")]), None);
        assert_eq!(v.chart.as_deref(), Some("apisix-2.14.0"));
    }

    #[test]
    fn revision_template_yaml_strips_the_hash_labels_that_change_every_revision() {
        let template = serde_json::json!({
            "metadata": {
                "creationTimestamp": null,
                "labels": { "app": "inx-service", "pod-template-hash": "8675f58c44", "controller-revision-hash": "abc123" }
            },
            "spec": { "containers": [{ "name": "app", "image": "repo/app:1.0" }] }
        });
        let yaml = revision_template_yaml(&template);
        assert!(!yaml.contains("pod-template-hash"), "hash label must be stripped:\n{yaml}");
        assert!(!yaml.contains("controller-revision-hash"), "hash label must be stripped:\n{yaml}");
        assert!(!yaml.contains("creationTimestamp"), "null timestamp must be dropped:\n{yaml}");
        // Everything that actually describes the workload survives.
        assert!(yaml.contains("app: inx-service"));
        assert!(yaml.contains("repo/app:1.0"));
    }

    /// The whole point of the normalisation: two revisions that differ only by
    /// their template hash must render identically, so a diff of them is empty.
    #[test]
    fn revision_template_yaml_makes_hash_only_changes_diff_free() {
        let with_hash = |hash: &str| {
            serde_json::json!({
                "metadata": { "labels": { "app": "x", "pod-template-hash": hash } },
                "spec": { "containers": [{ "name": "app", "image": "repo/app:1.0" }] }
            })
        };
        assert_eq!(
            revision_template_yaml(&with_hash("aaaa")),
            revision_template_yaml(&with_hash("bbbb"))
        );
    }

    #[test]
    fn revision_template_yaml_keeps_a_real_creation_timestamp_and_survives_odd_shapes() {
        // Only a *null* timestamp is noise; a real one is data.
        let real = serde_json::json!({ "metadata": { "creationTimestamp": "2026-04-29T00:00:00Z" } });
        assert!(revision_template_yaml(&real).contains("creationTimestamp"));

        // No metadata, no labels, or an outright non-object must not panic.
        assert!(!revision_template_yaml(&serde_json::json!({ "spec": {} })).is_empty());
        assert!(!revision_template_yaml(&serde_json::json!({ "metadata": {} })).is_empty());
        assert!(!revision_template_yaml(&serde_json::Value::Null).is_empty());
    }

    #[test]
    fn controller_revision_images_reads_the_embedded_template() {
        let cr = ControllerRevision {
            revision: 3,
            data: Some(k8s_openapi::apimachinery::pkg::runtime::RawExtension(serde_json::json!({
                "spec": { "template": { "spec": { "containers": [
                    { "name": "etcd", "image": "docker.io/bitnamilegacy/etcd:latest" }
                ] } } }
            }))),
            metadata: Default::default(),
        };
        assert_eq!(controller_revision_images(&cr), vec!["docker.io/bitnamilegacy/etcd:latest"]);

        // A revision with no usable data must not panic.
        let empty = ControllerRevision { revision: 1, data: None, metadata: Default::default() };
        assert!(controller_revision_images(&empty).is_empty());
    }

    #[test]
    fn parse_memory_ki_handles_the_units_metrics_and_nodes_report() {
        assert_eq!(parse_memory_ki("122736Ki"), 122_736);
        assert_eq!(parse_memory_ki("16374836Ki"), 16_374_836);
        assert_eq!(parse_memory_ki("470Mi"), 481_280);
        assert_eq!(parse_memory_ki("8Gi"), 8 * 1024 * 1024);
    }
}
