//! Data-fetching functions against a single cluster context. Each function
//! opens Kubernetes API calls concurrently where sensible and maps results
//! onto the plain-data structs in `models.rs`.

use crate::kubeconfig::{client_for_context, SLOW_CLUSTER_TIMEOUT};
use crate::models::*;
use crate::retry::retry_transient;
use chrono::Utc;
use futures::{AsyncBufReadExt, TryStreamExt};
use k8s_openapi::api::apps::v1::{ControllerRevision, DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::autoscaling::v2::{
    CrossVersionObjectReference, HorizontalPodAutoscaler, HorizontalPodAutoscalerCondition, MetricSpec, MetricStatus,
    MetricTarget, MetricValueStatus,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::api::core::v1::{Event, Namespace, Node, Pod};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams, LogParams, ObjectList, ResourceExt};
use kube::discovery::Scope;
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

pub(crate) fn age_days(ts: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>) -> i64 {
    match ts {
        Some(t) => (Utc::now() - t.0).num_days().max(0),
        None => 0,
    }
}

pub(crate) fn age_seconds(ts: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>) -> i64 {
    match ts {
        Some(t) => (Utc::now() - t.0).num_seconds().max(0),
        None => 0,
    }
}

/// The timestamp `age_days`/`age_seconds` count from, as RFC 3339 in UTC to the
/// second. Sent alongside the age rather than worked out from it: the age is
/// measured when the list is built, so subtracting it from the frontend's clock
/// later would be off by however long ago that was.
pub(crate) fn created_at(ts: &Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>) -> Option<String> {
    ts.as_ref().map(|t| t.0.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
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

/// Whether this object's controller is the given one: by UID too, so that
/// what a deleted object of the same name left behind is not counted as its.
fn controlled_by(refs: &Option<Vec<OwnerReference>>, kind: &str, name: &str, uid: Option<&str>) -> bool {
    refs.iter()
        .flatten()
        .find(|o| o.controller == Some(true))
        .is_some_and(|o| o.kind == kind && o.name == name && uid.is_none_or(|u| o.uid == u))
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
pub(crate) fn parse_cpu_millicores(q: &str) -> i64 {
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

pub(crate) fn parse_memory_ki(q: &str) -> i64 {
    // Kubernetes' own canonical Quantity serialization uses lowercase "k" for
    // decimal kilo (1000ies never being uppercase, per resource.Quantity's
    // suffix table); "K" is kept alongside it only for leniency, since it's
    // not actually a suffix the API server itself ever emits in
    // `status.allocatable`/`status.capacity`/`metrics.k8s.io` — every real
    // value seen here is API-server-generated, never hand-authored.
    let units: [(&str, f64); 9] = [
        ("Ki", 1.0),
        ("Mi", 1024.0),
        ("Gi", 1024.0 * 1024.0),
        ("Ti", 1024.0 * 1024.0 * 1024.0),
        ("k", 1.0 / 1.024),
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

/// Splits a total pod count and a not-Running count into the
/// `(running, not_ready)` pair the overview reports.
///
/// Pulled out of `get_overview` so the clamp has somewhere to be tested. The
/// two inputs are separate concurrent round trips to a live cluster, so they
/// can legitimately disagree — pods come and go between them — and a
/// not-Running count above the total would otherwise underflow `running` into
/// a nonsense figure.
fn split_pod_counts(total: usize, not_running: usize) -> (usize, usize) {
    let not_ready = not_running.min(total);
    (total - not_ready, not_ready)
}

/// Page size for the rare fallback path in `count_matching` — big enough that
/// counting a large collection takes few round trips, since each one costs a
/// full VPN round trip.
const COUNT_PAGE_SIZE: u32 = 500;

/// Number of objects matching `lp`, counted without downloading the objects.
///
/// The overview reduces whole collections to single integers, but was fetching
/// them in full to do it. Measured against this app's own dev cluster that is
/// 22 MB of Pods (1,181 objects) and 6 MB of Events (5,235 objects) — ~30 MB
/// per cluster, on every auto-refresh tick, over a VPN, to produce four
/// numbers. Against a private-link cluster that alone can saturate the tunnel
/// and starve every other request sharing it, `kubectl` included.
///
/// Two things make the count cheap:
///
/// * `limit=1` makes the apiserver report `metadata.remainingItemCount`, so an
///   *unfiltered* count is one small round trip. This is only filled in for an
///   unfiltered list — with a field selector the server returns a continue
///   token and no remainder, because selectors are applied after the etcd
///   range read and it genuinely cannot know the count without scanning. So a
///   field-selected count has to walk pages; callers should select for the
///   *small* side of a split and subtract (see `get_overview`).
/// * The request asks for `PartialObjectMetadata`, so even the pages that do
///   get walked carry only object metadata rather than full specs and statuses
///   — for a Pod, the difference between a name and a whole podspec.
///
/// A missing `remainingItemCount` is handled rather than assumed: with no
/// continue token the response wasn't truncated and `items` is already
/// everything. Only a truncated response without a reported remainder walks
/// pages, and that never holds more than one page at a time.
async fn count_matching<K>(api: &Api<K>, lp: &ListParams) -> Result<usize, kube::Error>
where
    K: Clone + std::fmt::Debug + serde::de::DeserializeOwned + kube::Resource,
    K::DynamicType: Default,
{
    let first = api.list_metadata(&lp.clone().limit(1)).await?;
    if let Some(remaining) = first.metadata.remaining_item_count {
        return Ok(first.items.len() + remaining.max(0) as usize);
    }
    let Some(mut token) = first.metadata.continue_.clone().filter(|t| !t.is_empty()) else {
        return Ok(first.items.len());
    };

    let mut total = first.items.len();
    loop {
        let page = api
            .list_metadata(&lp.clone().limit(COUNT_PAGE_SIZE).continue_token(&token))
            .await?;
        total += page.items.len();
        match page.metadata.continue_.clone().filter(|t| !t.is_empty()) {
            Some(next) => token = next,
            None => return Ok(total),
        }
    }
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

    // Only the Node list is fetched in full: readiness comes from
    // `status.conditions`, which no field selector can filter on. Everything
    // else this overview needs is a count, so it's counted server-side by
    // `count_matching` rather than downloaded — see that helper for the sizes
    // involved, which are the difference between a few hundred bytes and tens
    // of megabytes per cluster per refresh tick.
    //
    // These reads are independent of each other, so they're issued
    // concurrently rather than one after another — over a loaded VPN/private-
    // link path each round trip alone can take several seconds to tens of
    // seconds, and issuing them back-to-back easily exceeds the per-command
    // deadline even though the cluster is still responding, just slowly.
    let all = ListParams::default();
    // Selected as the complement — not-Running rather than Running — because a
    // field-selected count has to walk pages (see `count_matching`), so it
    // should walk the short side. On this app's own dev cluster that is 35
    // pods against 1,146 Running, and a cluster where the ratio inverts has
    // worse problems than a slow overview.
    let not_running_pods = ListParams::default().fields("status.phase!=Running");
    let warning_events = ListParams::default().fields("type=Warning");
    let (version, nodes_result, namespaces_result, pods_result, not_running_result, events_result) = tokio::join!(
        client.apiserver_version(),
        nodes_api.list(&all),
        count_matching(&ns_api, &all),
        count_matching(&pods_api, &all),
        count_matching(&pods_api, &not_running_pods),
        count_matching(&events_api, &warning_events),
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

    // Best-effort, exactly as the full-list version treated these: a count
    // that fails shows as zero rather than failing the whole overview, which
    // still has a usable node picture to show.
    let namespaces = namespaces_result.unwrap_or(0);

    let pod_count = pods_result.unwrap_or(0);
    let (pods_running, pods_not_ready) = split_pod_counts(pod_count, not_running_result.unwrap_or(0));

    let warning_event_count = events_result.unwrap_or(0);

    Ok(ClusterOverview {
        context_name: context_name.to_string(),
        reachable: true,
        error: None,
        kubernetes_version: version.ok().map(|v| format!("{}.{}", v.major, v.minor)),
        node_count: nodes.len(),
        nodes_ready,
        namespace_count: namespaces,
        pod_count,
        pods_running,
        pods_not_ready,
        warning_event_count,
    })
}

pub(crate) fn node_is_ready(n: &Node) -> bool {
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

/// What a node's labels say it is. One reading shared by the Nodes table and
/// the Node panel's Overview, so the two cannot describe a node differently.
pub(crate) struct NodeIdentity {
    pub roles: Vec<String>,
    pub zone: Option<String>,
    pub instance_type: Option<String>,
    /// `karpenter.sh/nodepool`: set only on a node NAP provisioned.
    pub node_pool: Option<String>,
}

pub(crate) fn node_identity(n: &Node) -> NodeIdentity {
    let labels = n.labels();
    let roles: Vec<String> = labels
        .keys()
        .filter_map(|k| k.strip_prefix("node-role.kubernetes.io/"))
        .map(|s| s.to_string())
        .collect();
    NodeIdentity {
        roles: if roles.is_empty() { vec!["worker".to_string()] } else { roles },
        zone: labels
            .get("topology.kubernetes.io/zone")
            .or_else(|| labels.get("failure-domain.beta.kubernetes.io/zone"))
            .cloned(),
        instance_type: labels.get("node.kubernetes.io/instance-type").cloned(),
        node_pool: labels.get("karpenter.sh/nodepool").cloned(),
    }
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
            let NodeIdentity { roles, zone, instance_type, node_pool } = node_identity(&n);
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
                node_pool,
                zone,
                cpu_capacity: cap.get("cpu").map(|q| q.0.clone()).unwrap_or_default(),
                cpu_allocatable: alloc.get("cpu").map(|q| q.0.clone()).unwrap_or_default(),
                memory_capacity: cap.get("memory").map(|q| q.0.clone()).unwrap_or_default(),
                memory_allocatable: alloc.get("memory").map(|q| q.0.clone()).unwrap_or_default(),
                memory_allocatable_ki: alloc.get("memory").map(|q| parse_memory_ki(&q.0)),
                cpu_usage_millicores: if has_metrics { Some(cpu_usage) } else { None },
                memory_usage_ki: if has_metrics { Some(mem_usage) } else { None },
                conditions,
                age_days: age_days(n.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(n.metadata.creation_timestamp.clone()),
                created_at: created_at(&n.metadata.creation_timestamp),
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
        detail: crate::node_detail::node_detail(&node),
    })
}

/// Owner resolution and usage-metrics lookup shared by `get_pods` (one
/// unpaginated call) and `stream_pods` (the same mapping, applied per page).
fn build_pod_info(p: Pod, metrics: &HashMap<(String, String), (i64, i64)>, rs_owner: &HashMap<(String, String), (String, String)>) -> PodInfo {
    let name = p.name_any();
    let ns = p.namespace().unwrap_or_default();
    let status = p.status.clone().unwrap_or_default();
    let container_statuses = status.container_statuses.clone().unwrap_or_default();
    let total = container_statuses.len();
    let ready_count = container_statuses.iter().filter(|c| c.ready).count();
    let restarts = container_statuses.iter().map(|c| c.restart_count).sum();
    let key = (ns.clone(), name.clone());
    let (cpu, mem, has_metrics) = match metrics.get(&key) {
        Some(&(cpu, mem)) => (cpu, mem, true),
        None => (0, 0, false),
    };

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
        created_at: created_at(&p.metadata.creation_timestamp),
        owner_kind,
        owner_name,
        cpu_usage_millicores: if has_metrics { Some(cpu) } else { None },
        memory_usage_ki: if has_metrics { Some(mem) } else { None },
        status_reason: status.reason.clone(),
        failure_container: pod_failure(&status).and_then(|(c, _)| c),
        failure_message: pod_failure(&status).map(|(_, m)| m),
    }
}

/// Waiting reasons that mean "still starting", not "broken".
///
/// A pod is briefly in both on every normal rollout and neither carries a
/// message. Reporting `ContainerCreating` as a failure would flag every pod
/// on every rollout for a container that is simply being created.
const TRANSIENT_WAITING_REASONS: [&str; 2] = ["ContainerCreating", "PodInitializing"];

/// The failing container and the message describing it, or `None` for a pod
/// with nothing wrong.
///
/// The container is returned so a diagnosis targets the one that is actually
/// broken rather than whichever the pod lists first — on a pod with a healthy
/// sidecar those differ, and the sidecar's logs explain nothing.
///
/// Reads the container states rather than `pod.status.reason`: that field is
/// only set for pod-level failures such as `Evicted`, and was unset on all
/// 1091 pods of the cluster this was checked against, while the useful text
/// sits in a container's waiting or terminated state.
///
/// Ready containers are skipped so a healthy sidecar cannot mask the one that
/// is actually broken. `last_state` is the fallback for a container between
/// restarts, where the current state is bare but the previous termination
/// still carries the exit code. Init containers come last: a pod stuck
/// initializing has one as its cause, but a main container's failure is both
/// more common and more specific.
fn pod_failure(status: &k8s_openapi::api::core::v1::PodStatus) -> Option<(Option<String>, String)> {
    // Pod-level first, and only when `phase` is Failed.
    //
    // An evicted pod keeps its container statuses — typically terminated with
    // `ContainerStatusUnknown` and exit 137 — so scanning containers first
    // claimed one of them and returned it as the failing container. That is
    // wrong twice over: "ContainerStatusUnknown (exit 137)" is less use than
    // "Evicted: The node was low on resource: memory", and naming a container
    // makes the row ask for logs from a container the node has already
    // reclaimed.
    //
    // Gated on `phase == "Failed"` so a succeeded pod whose `reason` is
    // `Completed` does not read as a failure, and on `reason` being set so a
    // Job pod that failed through its container — which carries no pod-level
    // reason — still reaches the container scan below.
    if status.phase.as_deref() == Some("Failed") {
        if let Some(r) = status.reason.as_deref().filter(|r| !r.is_empty()) {
            return Some(match status.message.as_deref().filter(|m| !m.is_empty()) {
                Some(m) => (None, format!("{r}: {m}")),
                None => (None, r.to_string()),
            });
        }
    }

    let main = status.container_statuses.iter().flatten();
    let init = status.init_container_statuses.iter().flatten();

    for cs in main.chain(init).filter(|cs| !cs.ready) {
        let from_state = cs.state.as_ref().and_then(container_state_message);
        let from_last = cs.last_state.as_ref().and_then(container_state_message);
        if let Some(msg) = from_state.or(from_last) {
            return Some((Some(cs.name.clone()), format!("{}: {msg}", cs.name)));
        }
    }

    None
}

/// A container state as "Reason: message", or `None` when it is not a failure.
///
/// A clean exit is not a failure even though the container is not ready: a
/// finished CronJob pod sits at `Completed (exit 0)` indefinitely, and on one
/// real cluster those were half the not-ready pods. Flagging a job that
/// worked as failed is worse than flagging nothing.
fn container_state_message(state: &k8s_openapi::api::core::v1::ContainerState) -> Option<String> {
    if let Some(w) = &state.waiting {
        let reason = w.reason.clone().unwrap_or_default();
        if reason.is_empty() || TRANSIENT_WAITING_REASONS.contains(&reason.as_str()) {
            return None;
        }
        return Some(match &w.message {
            Some(m) if !m.is_empty() => format!("{reason}: {m}"),
            _ => reason,
        });
    }
    if let Some(t) = &state.terminated {
        let reason = t.reason.clone().unwrap_or_default();
        if reason.is_empty() || t.exit_code == 0 {
            return None;
        }
        let head = format!("{reason} (exit {})", t.exit_code);
        return Some(match &t.message {
            Some(m) if !m.is_empty() => format!("{head}: {m}"),
            _ => head,
        });
    }
    None
}

/// The most informative failing condition on a workload, or `None`.
///
/// Takes the fields rather than a condition type: Deployment, StatefulSet and
/// DaemonSet each have their own condition struct with identical field names,
/// and normalising at the call site is shorter than three near-identical
/// functions.
///
/// `ProgressDeadlineExceeded` and `ReplicaFailure` are preferred because they
/// name a cause. Everything else is usually `MinimumReplicasUnavailable:
/// Deployment does not have minimum availability`, which restates the ready
/// count the row already shows — on a real fleet that was the only condition
/// on four of six unready Deployments. It is still returned when nothing
/// better exists, since it is what the controller reports, but it sorts last.
fn pick_failure_condition<'a>(conds: impl Iterator<Item = (&'a str, &'a str, &'a str, &'a str)>) -> Option<String> {
    let mut fallback = None;
    for (type_, cond_status, reason, message) in conds {
        // A failing condition is either False on a "things are fine" type, or
        // True on a "something is wrong" type — ReplicaFailure is the latter.
        let failing = cond_status == "False" || (type_ == "ReplicaFailure" && cond_status == "True");
        if !failing || reason.is_empty() {
            continue;
        }
        let text = if message.is_empty() { reason.to_string() } else { format!("{reason}: {message}") };
        // `ReplicaFailure` is matched on the type, not the reason: Kubernetes
        // puts the cause in the reason — `FailedCreate`, `FailedDelete` — so
        // comparing the reason against "ReplicaFailure" never matched, and the
        // condition that names the real problem lost to whichever boilerplate
        // happened to come first.
        if reason == "ProgressDeadlineExceeded" || type_ == "ReplicaFailure" {
            return Some(text);
        }
        fallback.get_or_insert(text);
    }
    fallback
}

/// Resolves each ReplicaSet's own controller owner, for tracing a pod back to
/// the Deployment shown in the Workloads tab (a pod's *direct* owner is
/// normally the ReplicaSet, not the Deployment that created it). Not paged:
/// in practice a namespace/cluster has far fewer ReplicaSets than Pods, and
/// every page of pods needs the same complete map to resolve ownership
/// correctly regardless of which page a given owning ReplicaSet happens to
/// be listed on.
async fn fetch_replicaset_owners(replicasets_api: &Api<ReplicaSet>) -> HashMap<(String, String), (String, String)> {
    replicasets_api
        .list(&ListParams::default())
        .await
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
        .unwrap_or_default()
}

pub async fn get_pods(context_name: &str, namespace: Option<String>) -> Result<Vec<PodInfo>, String> {
    let client = client_for_context(context_name).await?;
    let pods_api: Api<Pod> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let replicasets_api: Api<ReplicaSet> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    // The pod list, its metrics, and the ReplicaSets needed for ownership are
    // all independent reads, issued concurrently — see `get_overview` for why
    // that matters once each round trip alone takes several seconds.
    let lp = ListParams::default();
    let (pods_result, metrics, rs_owner) = tokio::join!(
        pods_api.list(&lp),
        fetch_pod_metrics(&client, &namespace),
        fetch_replicaset_owners(&replicasets_api),
    );
    let pods = pods_result.map_err(|e| format!("Failed to list pods: {e}"))?.items;

    Ok(pods.into_iter().map(|p| build_pod_info(p, &metrics, &rs_owner)).collect())
}

/// Matches `kubectl`'s own default `--chunk-size`: large enough that a
/// many-thousand-pod cluster still only takes a handful of round trips, small
/// enough that the first page — and so the first visible rows in the Pods
/// table — lands in a fraction of the time a single unpaginated list() of the
/// whole cluster would take.
const POD_PAGE_SIZE: u32 = 500;

/// Retries a single page fetch — not the whole multi-page operation — on a
/// transient network blip (see `retry::retry_transient` for the
/// classification and backoff). Scoped to just the failing page so a blip
/// on, say, page 3 doesn't force re-fetching (and re-sending, duplicating)
/// pages 1-2 that already arrived cleanly: that duplication risk is exactly
/// why `stream_pods`'s own command wrapper deliberately uses `with_deadline`
/// instead of retrying the operation as a whole. Measured directly against
/// this fleet: a full-cluster pods list can fail outright with a
/// transport-level error mid-transfer (proven live: "error reading a body
/// from connection" after 111s on one cluster, immediately after a
/// successful call to a different one), so a multi-page fetch that never
/// retries any single page is only as reliable as its least reliable
/// individual request.
async fn list_pods_page(pods_api: &Api<Pod>, lp: &ListParams) -> Result<ObjectList<Pod>, String> {
    retry_transient(|| async { pods_api.list(lp).await.map_err(|e| format!("Failed to list pods: {e}")) }).await
}

/// Same data as `get_pods`, but paged through `limit`/`continue_token`
/// instead of one unbounded `list()`, sending each page to `on_page` as it
/// arrives rather than waiting for the whole cluster's pods to accumulate
/// before the caller sees anything. Built for large clusters (some in this
/// fleet run well past a thousand pods) where that single-shot wait was the
/// entire time-to-first-row.
///
/// Returns the complete list as well as streaming it, and that return value —
/// not the sum of the channel messages — is what a caller must treat as
/// authoritative. The two travel over different IPC paths with different
/// latencies: a `Channel` payload over 8KB (which every pod page is, by a
/// wide margin) is delivered by evaluating JS that performs a *second*
/// async round trip to fetch the body before invoking the callback, whereas
/// a command's return value resolves its promise directly. The awaited
/// promise therefore resolves *before* the last page's callback runs, so a
/// caller that totals up the channel messages at await-time reliably loses
/// the final page — which showed up as a Pods table stuck at exactly 1000
/// of 1065. Streaming stays useful for progressive display; the return
/// value is what's correct.
pub async fn stream_pods(context_name: &str, namespace: Option<String>, on_page: Channel<Vec<PodInfo>>) -> Result<Vec<PodInfo>, String> {
    let client = client_for_context(context_name).await?;
    let pods_api: Api<Pod> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let replicasets_api: Api<ReplicaSet> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    let first_page_lp = ListParams::default().limit(POD_PAGE_SIZE);
    let (first_page_result, metrics, rs_owner) = tokio::join!(
        list_pods_page(&pods_api, &first_page_lp),
        fetch_pod_metrics(&client, &namespace),
        fetch_replicaset_owners(&replicasets_api),
    );

    let mut all = Vec::new();
    let mut page = first_page_result?;
    loop {
        let mapped: Vec<PodInfo> = page.items.drain(..).map(|p| build_pod_info(p, &metrics, &rs_owner)).collect();
        all.extend_from_slice(&mapped);
        // Sending is best-effort: if the frontend has already torn down the
        // channel (e.g. the user switched clusters mid-fetch), there's no one
        // left to deliver a page to, but the fetch itself is cheap enough to
        // let finish rather than plumbing a cancellation path for it.
        let _ = on_page.send(mapped);

        let Some(token) = page.metadata.continue_.clone() else {
            break;
        };
        let next_lp = ListParams::default().limit(POD_PAGE_SIZE).continue_token(&token);
        page = list_pods_page(&pods_api, &next_lp).await?;
    }

    Ok(all)
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
) -> Result<(String, String, Vec<String>, K), String>
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

    Ok((yaml_full, yaml_without_managed_fields, containers, obj))
}

pub async fn get_workload_manifest(
    context_name: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<WorkloadManifest, String> {
    let client = client_for_context(context_name).await?;
    // The typed object comes back too, for the Overview's detail: each kind
    // keeps its strategy and revision in its own fields.
    let (yaml_full, yaml_without_managed_fields, containers, detail) = match kind {
        "Deployment" => {
            let (f, s, c, o) = fetch_workload_yaml::<Deployment>(client, namespace, name, "apps/v1", "Deployment").await?;
            (f, s, c, crate::workload_detail::deployment_detail(&o))
        }
        "StatefulSet" => {
            let (f, s, c, o) = fetch_workload_yaml::<StatefulSet>(client, namespace, name, "apps/v1", "StatefulSet").await?;
            (f, s, c, crate::workload_detail::statefulset_detail(&o))
        }
        "DaemonSet" => {
            let (f, s, c, o) = fetch_workload_yaml::<DaemonSet>(client, namespace, name, "apps/v1", "DaemonSet").await?;
            (f, s, c, crate::workload_detail::daemonset_detail(&o))
        }
        other => return Err(format!("Unsupported workload kind '{other}'")),
    };
    Ok(WorkloadManifest {
        yaml_full,
        yaml_without_managed_fields,
        containers,
        detail,
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
        detail: crate::pod_detail::pod_detail(&pod),
    })
}

/// One-shot log fetch, for the Head/Tail views. `tail` selects the last
/// `lines` lines via the API's own `tailLines` param (cheap, server-side);
/// "head" has no server-side equivalent — the log API can only bound *bytes*
/// from the start (`limitBytes`), not lines — so this over-fetches a capped
/// byte window and truncates to `lines` client-side.
/// The kubelet's reply when a container has no earlier instance to read: it
/// has never restarted, or the earlier one was already garbage-collected.
pub(crate) fn is_no_previous_instance(message: &str) -> bool {
    message.contains("previous terminated container") && message.contains("not found")
}

/// The last `lines` lines of a container's *previous* instance — the one that
/// last exited. For a crash loop this is where the crash itself is written;
/// the current instance has often only just started. `Ok(None)` when there is
/// no previous instance, which is a fact rather than a failure.
pub async fn get_previous_pod_logs(context_name: &str, namespace: &str, pod_name: &str, container: &str, lines: i64) -> Result<Option<String>, String> {
    let client = client_for_context(context_name).await?;
    let pods_api: Api<Pod> = Api::namespaced(client, namespace);
    let lp = LogParams {
        container: Some(container.to_string()),
        previous: true,
        tail_lines: Some(lines.clamp(1, 5000)),
        ..Default::default()
    };
    match pods_api.logs(pod_name, &lp).await {
        Ok(text) => Ok(Some(text)),
        Err(kube::Error::Api(resp)) if resp.code == 400 && is_no_previous_instance(&resp.message) => Ok(None),
        Err(e) => Err(format!("Failed to fetch previous logs: {e}")),
    }
}

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

/// Whether a workload has at least as many ready replicas as it wants.
///
/// `>=`, not `==`: a rolling update with `maxSurge` runs more ready replicas
/// than desired for the length of the rollout, and a scale-down does the same
/// while the old pods drain. Measured on a live fleet, `wms-service` sat at 5
/// ready against 3 desired with maxSurge 2 — `Available=True`,
/// `Progressing=True`, serving normally, and reported red.
///
/// One function rather than the comparison written out at each reader, so the
/// three cannot diverge and a test can exercise what actually runs. The three
/// readers below are its only callers.
fn workload_healthy(ready: i32, desired: i32) -> bool {
    ready >= desired
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
                healthy: workload_healthy(ready, desired),
                age_days: age_days(d.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(d.metadata.creation_timestamp.clone()),
                created_at: created_at(&d.metadata.creation_timestamp),
                version: v.version,
                version_from_label: v.version_from_label,
                images: v.images,
                chart: v.chart,
                failure_message: pick_failure_condition(status.conditions.iter().flatten().map(|c| {
                    (
                        c.type_.as_str(),
                        c.status.as_str(),
                        c.reason.as_deref().unwrap_or(""),
                        c.message.as_deref().unwrap_or(""),
                    )
                })),
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
                healthy: workload_healthy(ready, desired),
                age_days: age_days(s.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(s.metadata.creation_timestamp.clone()),
                created_at: created_at(&s.metadata.creation_timestamp),
                version: v.version,
                version_from_label: v.version_from_label,
                images: v.images,
                chart: v.chart,
                failure_message: pick_failure_condition(status.conditions.iter().flatten().map(|c| {
                    (
                        c.type_.as_str(),
                        c.status.as_str(),
                        c.reason.as_deref().unwrap_or(""),
                        c.message.as_deref().unwrap_or(""),
                    )
                })),
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
                healthy: workload_healthy(ready, desired),
                age_days: age_days(d.metadata.creation_timestamp.clone()),
                age_seconds: age_seconds(d.metadata.creation_timestamp.clone()),
                created_at: created_at(&d.metadata.creation_timestamp),
                version: v.version,
                version_from_label: v.version_from_label,
                images: v.images,
                chart: v.chart,
                failure_message: pick_failure_condition(status.conditions.iter().flatten().map(|c| {
                    (
                        c.type_.as_str(),
                        c.status.as_str(),
                        c.reason.as_deref().unwrap_or(""),
                        c.message.as_deref().unwrap_or(""),
                    )
                })),
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
                        created_at: created_at(&rs.metadata.creation_timestamp),
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
                    created_at: created_at(&cr.metadata.creation_timestamp),
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

/// How many times an event has fired.
///
/// Three sources, because it depends on which API wrote the event. The legacy
/// core/v1 path sets `count`. `events.k8s.io/v1` puts a repeat count in
/// `series.count` and leaves `count` unset entirely for a single occurrence —
/// so an absent count means *once*, not never.
///
/// Defaulting it to 0, as this did, rendered `FailedScheduling` as `x0`: an
/// event the API only emits because it happened, displayed as having not
/// happened. On one real cluster that covered 122 of 683 pod events.
fn event_count(e: &Event) -> i32 {
    e.series
        .as_ref()
        .and_then(|s| s.count)
        .or(e.count)
        .unwrap_or(1)
}

/// When an event was last observed, or `None` only if it genuinely carries no
/// time at all.
///
/// Four sources, most authoritative first, for the same reason as the count:
/// `events.k8s.io/v1` sets `event_time` (and `series.last_observed_time` once
/// it repeats) while leaving both `Time` fields empty, and core/v1 sets
/// `first_timestamp`/`last_timestamp`. Reading `last_timestamp` alone left
/// every `Scheduled`, `FailedScheduling` and `Preempted` event with a blank
/// timestamp — and, because `list_events_sorted` orders on this, sorted them
/// below every timestamped event regardless of age, where the cluster-wide
/// `take(300)` then cut them first.
fn event_last_seen(e: &Event) -> Option<chrono::DateTime<Utc>> {
    e.series
        .as_ref()
        .and_then(|s| s.last_observed_time.as_ref())
        .map(|t| t.0)
        .or_else(|| e.last_timestamp.as_ref().map(|t| t.0))
        .or_else(|| e.event_time.as_ref().map(|t| t.0))
        .or_else(|| e.first_timestamp.as_ref().map(|t| t.0))
}

/// Who reported an event: `events.k8s.io`'s reporting controller and
/// instance where set, else core/v1's source component and host.
fn event_source(e: &Event) -> String {
    let join = |component: Option<&String>, host: Option<&String>| match (component.filter(|c| !c.is_empty()), host.filter(|h| !h.is_empty())) {
        (Some(c), Some(h)) => format!("{c} on {h}"),
        (Some(c), None) => c.clone(),
        (None, Some(h)) => h.clone(),
        (None, None) => String::new(),
    };
    match join(e.reporting_component.as_ref(), e.reporting_instance.as_ref()) {
        s if !s.is_empty() => s,
        _ => join(e.source.as_ref().and_then(|s| s.component.as_ref()), e.source.as_ref().and_then(|s| s.host.as_ref())),
    }
}

pub(crate) fn event_to_info(e: Event) -> EventInfo {
    let o = &e.involved_object;
    EventInfo {
        namespace: e.metadata.namespace.clone().unwrap_or_default(),
        involved_object: format!("{}/{}", o.kind.clone().unwrap_or_default(), o.name.clone().unwrap_or_default()),
        object_api_version: o.api_version.clone().unwrap_or_default(),
        object_kind: o.kind.clone().unwrap_or_default(),
        object_namespace: o.namespace.clone().unwrap_or_default(),
        object_name: o.name.clone().unwrap_or_default(),
        object_uid: o.uid.clone().unwrap_or_default(),
        name: e.metadata.name.clone().unwrap_or_default(),
        first_seen: e.first_timestamp.as_ref().map(|t| t.0).or_else(|| e.event_time.as_ref().map(|t| t.0)).map(|t| t.to_rfc3339()),
        source: event_source(&e),
        field_path: o.field_path.clone().unwrap_or_default(),
        action: e.action.clone().unwrap_or_default(),
        related: e
            .related
            .as_ref()
            .map(|r| format!("{}/{}", r.kind.clone().unwrap_or_default(), r.name.clone().unwrap_or_default()))
            .unwrap_or_default(),
        reason: e.reason.clone().unwrap_or_default(),
        message: e.message.clone().unwrap_or_default(),
        event_type: e.type_.clone().unwrap_or_default(),
        count: event_count(&e),
        last_seen: event_last_seen(&e).map(|t| t.to_rfc3339()),
    }
}

/// Every `get_*_events` variant below needs the same cluster-wide list,
/// newest-first — factored out so each only has to say what it filters for.
pub(crate) async fn list_events_sorted(client: &Client) -> Result<Vec<Event>, String> {
    let events_api: Api<Event> = Api::all(client.clone());
    let mut items = events_api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list events: {e}"))?
        .items;

    // Sorted on the same effective timestamp the rows display, not on
    // `last_timestamp` alone. `None` sorts below `Some` in Rust, so keying on
    // a field that a fifth of real events never set sank exactly those events
    // to the bottom — a `FailedScheduling` from a minute ago ordered below a
    // `Killing` from two hours ago, and `get_events`' `take(300)` then dropped
    // them off the cluster-wide tab entirely.
    items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
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

/// Every event about one object, of any kind, newest first.
///
/// Matched on the object's UID when it is known, as well as kind and name:
/// a deleted and recreated object of the same name is a different object,
/// and its predecessor's events can still be retained.
///
/// Filtered by the API server on `involvedObject` field selectors rather than
/// by listing the whole cluster's events and matching here: on a busy
/// private-link cluster that full list takes a quarter of a minute, and an
/// event panel asks for this as soon as it opens. A namespaced object's events
/// live in its namespace, so that list is namespaced too; a cluster-scoped
/// object's events are recorded wherever the reporting component put them.
pub async fn get_object_events(context_name: &str, kind: &str, namespace: &str, name: &str, uid: &str) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let mut fields = format!("involvedObject.kind={kind},involvedObject.name={name}");
    if !uid.is_empty() {
        fields.push_str(&format!(",involvedObject.uid={uid}"));
    }
    let api: Api<Event> = if namespace.is_empty() {
        Api::all(client)
    } else {
        fields.push_str(&format!(",involvedObject.namespace={namespace}"));
        Api::namespaced(client, namespace)
    };
    let mut items = api
        .list(&ListParams::default().fields(&fields))
        .await
        .map_err(|e| format!("Failed to list events for {kind}/{name}: {e}"))?
        .items;
    items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
    Ok(items.into_iter().map(event_to_info).collect())
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

/// One pod as a node diagnosis needs it.
///
/// Deliberately not `PodInfo`: that carries owner resolution and a metrics
/// join, both of which cost extra requests to answer a question this does not
/// ask. What matters here is how many pods the node is holding and which of
/// them are not running.
pub struct NodePodSummary {
    pub namespace: String,
    pub name: String,
    pub phase: String,
    pub ready: String,
    pub restarts: i32,
    pub healthy: bool,
}

/// Everything a node diagnosis needs, fetched in one round.
///
/// The two lists keep their errors rather than collapsing to empty. A node
/// whose pods could not be listed is a different statement from a node with no
/// pods, and the payload has to be able to say which — a 403 or a timeout
/// rendered as "no pods on this node" would have the model reason from a fact
/// that is not true.
pub struct NodeDiagnostics {
    pub node: Node,
    /// Unhealthy first, then by restart count — the same worst-first
    /// convention the workload payload uses.
    pub pods: Result<Vec<NodePodSummary>, String>,
    pub events: Result<Vec<EventInfo>, String>,
}

pub async fn get_node_diagnostics(context_name: &str, node_name: &str) -> Result<NodeDiagnostics, String> {
    let client = client_for_context(context_name).await?;
    let nodes_api: Api<Node> = Api::all(client.clone());
    let pods_api: Api<Pod> = Api::all(client.clone());

    // Asked of the apiserver rather than filtered here: a fleet node holds a
    // few dozen pods out of a thousand-odd on the cluster, and listing them
    // all to discard 98% of them is the kind of thing that makes a detail
    // panel slow on exactly the cluster where it matters.
    let pod_params = ListParams::default().fields(&format!("spec.nodeName={node_name}"));

    let (node, pods, events) = tokio::join!(
        nodes_api.get(node_name),
        pods_api.list(&pod_params),
        get_node_events(context_name, node_name),
    );

    let node = node.map_err(|e| format!("Failed to get node '{node_name}': {e}"))?;

    let pods = pods
        .map_err(|e| format!("Failed to list pods on '{node_name}': {e}"))
        .map(|list| {
            let mut summaries: Vec<NodePodSummary> = list
                .items
                .into_iter()
                .map(|p| {
                    let status = p.status.clone().unwrap_or_default();
                    let statuses = status.container_statuses.clone().unwrap_or_default();
                    let ready_count = statuses.iter().filter(|c| c.ready).count();
                    let phase = status.phase.clone().unwrap_or_default();
                    NodePodSummary {
                        namespace: p.namespace().unwrap_or_default(),
                        name: p.name_any(),
                        ready: format!("{ready_count}/{}", statuses.len()),
                        restarts: statuses.iter().map(|c| c.restart_count).sum(),
                        // Succeeded is a finished Job's pod, not a problem.
                        healthy: (phase == "Running" && ready_count == statuses.len() && !statuses.is_empty())
                            || phase == "Succeeded",
                        phase,
                    }
                })
                .collect();
            summaries.sort_by(|a, b| a.healthy.cmp(&b.healthy).then_with(|| b.restarts.cmp(&a.restarts)));
            summaries
        });

    Ok(NodeDiagnostics { node, pods, events })
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

pub(crate) fn json_str<'a>(value: Option<&'a serde_json::Value>, key: &str) -> &'a str {
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
    // A multi-source app records one revision per source in
    // `status.sync.revisions` (plural) and leaves the singular
    // `status.sync.revision` null — so reading only the singular field left
    // the Revision column empty for every such app, which on a fleet where
    // multi-source is the norm meant nearly all of them.
    //
    // Index 0 to match the source whose repo and path this same row already
    // shows: `source` above resolves to `spec.sources[0]`, and `revisions` is
    // index-aligned with `sources`, so the SHA shown belongs to the repo shown.
    let revision = match json_str(sync, "revision") {
        "" => sync
            .and_then(|s| s.get("revisions"))
            .and_then(|r| r.as_array())
            .and_then(|r| r.first())
            .and_then(|r| r.as_str())
            .unwrap_or_default(),
        single => single,
    };
    let sync_status = match json_str(sync, "status") {
        "" => "Unknown".to_string(),
        s => s.to_string(),
    };
    let health_status = match json_str(status.and_then(|s| s.get("health")), "status") {
        "" => "Unknown".to_string(),
        s => s.to_string(),
    };

    let operation_state = status.and_then(|s| s.get("operationState"));
    // A sync currently in flight has startedAt but no finishedAt yet, so
    // fall back to that rather than showing nothing while one is running.
    let last_synced_at = json_str_opt(operation_state, "finishedAt")
        .or_else(|| json_str_opt(operation_state, "startedAt"))
        .map(str::to_string);

    GitOpsAppInfo {
        namespace,
        destination_namespace: json_str(spec.and_then(|s| s.get("destination")), "namespace").to_string(),
        sync_status,
        health_status,
        repo_url: json_str(source, "repoURL").to_string(),
        path,
        target_revision: json_str(source, "targetRevision").to_string(),
        revision: revision.get(..revision.len().min(7)).unwrap_or_default().to_string(),
        last_synced_at,
        age_days: age_days(obj.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(obj.metadata.creation_timestamp.clone()),
        created_at: created_at(&obj.metadata.creation_timestamp),
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

/// Reads a `status.conditions[]` entry by type, the shape both Karpenter and
/// KEDA use. Returns (status == "True", reason).
fn json_condition(status: Option<&serde_json::Value>, want: &str) -> (bool, String) {
    let found = status
        .and_then(|s| s.get("conditions"))
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.iter().find(|c| json_str(Some(c), "type") == want));
    match found {
        Some(c) => (json_str(Some(c), "status") == "True", json_str(Some(c), "reason").to_string()),
        None => (false, String::new()),
    }
}

fn json_i64(value: Option<&serde_json::Value>, key: &str) -> i64 {
    value.and_then(|v| v.get(key)).and_then(|v| v.as_i64()).unwrap_or_default()
}

/// Karpenter promoted these CRDs from `v1beta1` to `v1` in Karpenter 1.0, and
/// AKS clusters are on both depending on when NAP was enabled — so each list
/// is attempted newest-first rather than pinning one version and reporting a
/// perfectly healthy older cluster as "not installed".
const KARPENTER_VERSIONS: &[&str] = &["v1", "v1beta1"];

fn karpenter_resource(version: &str, kind: &str, plural: &str) -> ApiResource {
    ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk("karpenter.sh", version, kind), plural)
}

/// Lists a Karpenter resource across its known API versions. `Ok(None)` means
/// every version answered 404 — the CRD isn't registered, i.e. NAP is off.
async fn list_karpenter(
    client: &Client,
    kind: &str,
    plural: &str,
) -> Result<Option<Vec<DynamicObject>>, String> {
    list_karpenter_with(client, kind, plural, &ListParams::default()).await
}

/// `list_karpenter`, narrowed by the caller's selectors.
async fn list_karpenter_with(
    client: &Client,
    kind: &str,
    plural: &str,
    params: &ListParams,
) -> Result<Option<Vec<DynamicObject>>, String> {
    for version in KARPENTER_VERSIONS {
        let ar = karpenter_resource(version, kind, plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match api.list(params).await {
            Ok(list) => return Ok(Some(list.items)),
            Err(kube::Error::Api(resp)) if resp.code == 404 => continue,
            Err(e) => return Err(format!("Failed to list Karpenter {plural}: {e}")),
        }
    }
    Ok(None)
}

/// `json_str`, but `None` rather than `""` for a missing/empty field —
/// for a caller that needs to tell "absent" apart from "empty" (an `Option`
/// output, or `unwrap_or` with a non-empty-string default).
///
/// Doubles as the fix for a real gotcha with Kubernetes `resource.Quantity`
/// fields specifically (`spec.limits.cpu`, `status.resources.memory`, and
/// even integer-looking counts like `status.resources.nodes`/`.pods`): every
/// one of them is ALWAYS a JSON *string* on the wire, never a JSON number.
/// `json_i64`'s `.as_i64()` looks like the obvious tool for
/// `status.resources.nodes` but silently returns 0 for every pool against
/// it, since `as_i64` only matches an actual JSON number.
fn json_str_opt<'a>(value: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    let s = json_str(value, key);
    (!s.is_empty()).then_some(s)
}

fn dynamic_object_to_nap_node_pool(obj: DynamicObject) -> NapNodePoolInfo {
    let spec = obj.data.get("spec");
    let template_spec = spec.and_then(|s| s.get("template")).and_then(|t| t.get("spec"));
    let limits = spec.and_then(|s| s.get("limits"));
    let status = obj.data.get("status");
    // Karpenter's own rollup of what this pool has actually provisioned —
    // reconciled by the controller itself, so it's both the node count and
    // the "used" side of the usage/limit columns without a second API call.
    let resources = status.and_then(|s| s.get("resources"));

    // Capacity type lives in the requirement list rather than a dedicated
    // field, since Karpenter models it as just another node selector term.
    let capacity_types = template_spec
        .and_then(|t| t.get("requirements"))
        .and_then(|r| r.as_array())
        .map(|reqs| {
            reqs.iter()
                .filter(|r| json_str(Some(r), "key") == "karpenter.sh/capacity-type")
                .filter_map(|r| r.get("values").and_then(|v| v.as_array()))
                .flatten()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();

    let (ready, reason) = json_condition(status, "Ready");

    NapNodePoolInfo {
        name: obj.metadata.name.clone().unwrap_or_default(),
        node_class: json_str(template_spec.and_then(|t| t.get("nodeClassRef")), "name").to_string(),
        ready,
        status_reason: if ready { String::new() } else { reason },
        // Absent (a brand new pool with nothing provisioned yet) reads the
        // same as explicit "0", so this stays a plain parse-or-zero rather
        // than an Option.
        nodes: json_str_opt(resources, "nodes").and_then(|s| s.parse().ok()).unwrap_or(0),
        cpu_used_millicores: json_str_opt(resources, "cpu").map(parse_cpu_millicores).unwrap_or(0),
        // Absent here means Karpenter enforces no cap at all, which reads
        // very differently from a cap of zero — kept as `None` rather than
        // collapsing both to 0.
        cpu_limit_millicores: json_str_opt(limits, "cpu").map(parse_cpu_millicores),
        memory_used_ki: json_str_opt(resources, "memory").map(parse_memory_ki).unwrap_or(0),
        memory_limit_ki: json_str_opt(limits, "memory").map(parse_memory_ki),
        weight: json_i64(spec, "weight"),
        capacity_types,
        age_days: age_days(obj.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(obj.metadata.creation_timestamp.clone()),
        created_at: created_at(&obj.metadata.creation_timestamp),
    }
}

pub async fn get_nap_node_pools(context_name: &str) -> Result<NapResult, String> {
    let client = client_for_context(context_name).await?;

    let Some(pools) = list_karpenter(&client, "NodePool", "nodepools").await? else {
        return Ok(NapResult { installed: false, error: None, node_pools: Vec::new() });
    };

    // No separate NodeClaim list needed: status.resources on the NodePool
    // itself already carries the node count (and the provisioned CPU/memory
    // the usage/limit columns need), reconciled by Karpenter's own
    // controller rather than re-derived here by matching labels.
    Ok(NapResult {
        installed: true,
        error: None,
        node_pools: pools.into_iter().map(dynamic_object_to_nap_node_pool).collect(),
    })
}

/// Same version-fallback reasoning as `list_karpenter` (Karpenter 1.0
/// promoted these CRDs from v1beta1 to v1, and this fleet has clusters on
/// both), applied to fetching one named object instead of listing all of
/// them.
async fn get_karpenter(client: &Client, kind: &str, plural: &str, name: &str) -> Result<DynamicObject, String> {
    let mut not_found_on = Vec::new();
    for version in KARPENTER_VERSIONS {
        let ar = karpenter_resource(version, kind, plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match api.get(name).await {
            Ok(obj) => return Ok(obj),
            Err(kube::Error::Api(resp)) if resp.code == 404 => not_found_on.push(*version),
            Err(e) => return Err(format!("Failed to get {plural} '{name}': {e}")),
        }
    }
    Err(format!("{plural} '{name}' not found (tried {})", not_found_on.join(", ")))
}

/// Renders one object to YAML both with and without `metadata.managedFields`.
///
/// Both variants are produced in one go rather than re-fetching when the
/// panel's toggle flips: managedFields is pure server bookkeeping that often
/// dwarfs the spec, so it is hidden by default, but the object has already
/// been fetched and stripping a field is far cheaper than another API call.
pub(crate) fn object_manifest(obj: DynamicObject) -> Result<ObjectManifest, String> {
    let yaml_full = serde_yaml::to_string(&obj).map_err(|e| format!("Failed to render YAML: {e}"))?;

    let mut stripped = obj;
    stripped.metadata.managed_fields = None;
    let yaml_without_managed_fields = serde_yaml::to_string(&stripped).map_err(|e| format!("Failed to render YAML: {e}"))?;

    Ok(ObjectManifest { yaml_full, yaml_without_managed_fields })
}

pub async fn get_nap_node_pool_manifest(context_name: &str, name: &str) -> Result<NapNodePoolManifest, String> {
    let client = client_for_context(context_name).await?;
    let obj = get_karpenter(&client, "NodePool", "nodepools", name).await?;
    let detail = crate::nap_detail::nap_detail(&obj);
    let ObjectManifest { yaml_full, yaml_without_managed_fields } = object_manifest(obj)?;
    Ok(NapNodePoolManifest { yaml_full, yaml_without_managed_fields, detail })
}

/// Same reasoning as `get_node_events`: a NodePool is cluster-scoped, so
/// there's no namespace to match against.
pub async fn get_nap_node_pool_events(context_name: &str, name: &str) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;

    Ok(items
        .into_iter()
        .filter(|e| e.involved_object.kind.as_deref() == Some("NodePool") && e.involved_object.name.as_deref() == Some(name))
        .map(event_to_info)
        .collect())
}

/// Everything a NodePool diagnosis reads.
///
/// Only the pool itself is required. Each of the rest fails on its own, so a
/// cluster that refuses one read — RBAC on NodeClaims, say — still gets a
/// diagnosis that says what it could not see rather than none at all.
pub struct NapDiagnostics {
    pub pool: DynamicObject,
    /// The node class the pool launches from; `None` when it names none.
    pub node_class: Result<Option<DynamicObject>, String>,
    pub claims: Result<Vec<DynamicObject>, String>,
    pub nodes: Result<Vec<Node>, String>,
    pub pool_events: Result<Vec<EventInfo>, String>,
    /// Events on this pool's NodeClaims and nodes, newest first.
    pub member_events: Result<Vec<EventInfo>, String>,
    /// Scheduling failures whose message names this pool, newest first.
    pub pod_events: Result<Vec<EventInfo>, String>,
}

/// Events matching an `involvedObject`/`reason` field selector, newest first.
///
/// Field selectors rather than the cluster-wide list `list_events_sorted`
/// returns: on a busy private-link cluster that list takes a quarter of a
/// minute, and a NodePool diagnosis needs four slices of it.
async fn events_matching(client: &Client, fields: &str) -> Result<Vec<Event>, String> {
    let api: Api<Event> = Api::all(client.clone());
    let mut items = api
        .list(&ListParams::default().fields(fields))
        .await
        .map_err(|e| format!("Failed to list events ({fields}): {e}"))?
        .items;
    items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
    Ok(items)
}

/// Whether a scheduling failure is about this pool.
///
/// Karpenter names the pool it tried in quotes — `incompatible with nodepool
/// "gpu"`, `exceed limits for nodepool: "default"` — while the scheduler's own
/// FailedScheduling events name no pool at all.
pub(crate) fn mentions_node_pool(message: &str, pool: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    let quoted = format!("\"{}\"", pool.to_ascii_lowercase());
    // The quoted name must follow the word itself, as `nodepool "x"` or
    // `nodepool: "x"`: elsewhere in the message a quoted string is a label or
    // requirement key, and a pool named after one would claim every failure.
    lower.match_indices("nodepool").any(|(i, word)| {
        let rest = lower[i + word.len()..].trim_start_matches(':').trim_start();
        rest.starts_with(&quoted)
    })
}

/// The node class a pool's template points at, found by discovery.
///
/// Discovered rather than pinned: AKSNodeClass has been served as v1alpha2,
/// v1beta1 and v1 across the AKS releases this fleet spans, and the reference
/// carries the group (v1) or an apiVersion (v1beta1) but never a version the
/// cluster is guaranteed to serve.
async fn get_node_class(client: &Client, pool: &DynamicObject) -> Result<Option<DynamicObject>, String> {
    let Some(r) = pool.data.pointer("/spec/template/spec/nodeClassRef") else { return Ok(None) };
    let (kind, name) = (json_str(Some(r), "kind"), json_str(Some(r), "name"));
    if kind.is_empty() || name.is_empty() {
        return Ok(None);
    }
    let group = match json_str(Some(r), "group") {
        "" => json_str(Some(r), "apiVersion").split('/').next().unwrap_or_default(),
        g => g,
    };
    let group = if group.is_empty() { "karpenter.azure.com" } else { group };
    let served = kube::discovery::oneshot::group(client, group)
        .await
        .map_err(|e| format!("Failed to discover {group}: {e}"))?;
    let (ar, _) = served.recommended_kind(kind).ok_or_else(|| format!("{kind} is not served by {group}"))?;
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
    api.get(name).await.map(Some).map_err(|e| format!("Failed to get {kind} '{name}': {e}"))
}

pub async fn get_nap_diagnostics(context_name: &str, name: &str) -> Result<NapDiagnostics, String> {
    let client = client_for_context(context_name).await?;
    let pool = get_karpenter(&client, "NodePool", "nodepools", name).await?;

    // Karpenter labels every claim and node it launches with its pool, so the
    // apiserver can narrow both lists rather than this side discarding the
    // rest of the cluster.
    let members = ListParams::default().labels(&format!("karpenter.sh/nodepool={name}"));
    let nodes_api: Api<Node> = Api::all(client.clone());
    let pool_fields = format!("involvedObject.kind=NodePool,involvedObject.name={name}");
    let (node_class, claims, nodes, pool_events, claim_events, node_events, pod_events) = tokio::join!(
        get_node_class(&client, &pool),
        list_karpenter_with(&client, "NodeClaim", "nodeclaims", &members),
        nodes_api.list(&members),
        events_matching(&client, &pool_fields),
        events_matching(&client, "involvedObject.kind=NodeClaim"),
        events_matching(&client, "involvedObject.kind=Node"),
        events_matching(&client, "involvedObject.kind=Pod,reason=FailedScheduling"),
    );
    let claims = claims.map(Option::unwrap_or_default);
    let nodes = nodes.map(|l| l.items).map_err(|e| format!("Failed to list nodes of '{name}': {e}"));

    // A claim's node is named on the claim too, so a failed node list still
    // leaves the node events attributable.
    let mut member_names: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for c in claims.iter().flatten() {
        member_names.insert(("NodeClaim".into(), c.name_any()));
        if let Some(n) = c.data.pointer("/status/nodeName").and_then(|v| v.as_str()).filter(|n| !n.is_empty()) {
            member_names.insert(("Node".into(), n.to_string()));
        }
    }
    for n in nodes.iter().flatten() {
        member_names.insert(("Node".into(), n.name_any()));
    }
    let is_member = |e: &Event| {
        let o = &e.involved_object;
        member_names.contains(&(o.kind.clone().unwrap_or_default(), o.name.clone().unwrap_or_default()))
    };
    let member_events = match (claim_events, node_events) {
        // Without the claims there is no knowing which claim events are this
        // pool's, and an empty list would read as "none".
        _ if claims.is_err() => Err(format!(
            "this pool's NodeClaims could not be listed, so their events cannot be attributed ({})",
            claims.as_ref().err().cloned().unwrap_or_default()
        )),
        (Ok(c), Ok(n)) => {
            let mut all: Vec<Event> = c.into_iter().chain(n).filter(|e| is_member(e)).collect();
            all.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
            Ok(all.into_iter().map(event_to_info).collect())
        }
        (Err(e), _) | (_, Err(e)) => Err(e),
    };
    let pod_events = pod_events.map(|list| {
        list.into_iter()
            .filter(|e| mentions_node_pool(e.message.as_deref().unwrap_or_default(), name))
            .map(event_to_info)
            .collect()
    });

    Ok(NapDiagnostics {
        pool,
        node_class,
        claims,
        nodes,
        pool_events: pool_events.map(|l| l.into_iter().map(event_to_info).collect()),
        member_events,
        pod_events,
    })
}

// ---------------------------------------------------------------------------
// HorizontalPodAutoscalers
// ---------------------------------------------------------------------------

/// The HPA's own GVK, for the manifest view.
///
/// The list above reads the generated `HorizontalPodAutoscaler` type, but
/// `object_manifest` takes a `DynamicObject`, so the detail panel fetches it
/// again that way. The plural is stated rather than discovered because this
/// one is not a CRD — it cannot vary between clusters the way an ArgoCD or
/// KEDA kind can.
fn hpa_resource() -> ApiResource {
    ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk("autoscaling", "v2", "HorizontalPodAutoscaler"),
        "horizontalpodautoscalers",
    )
}

/// A metric target as text: `70%` for a utilization target, the raw quantity
/// otherwise.
fn render_metric_target(target: &MetricTarget) -> String {
    if let Some(utilization) = target.average_utilization {
        return format!("{utilization}%");
    }
    if let Some(value) = target.average_value.as_ref().or(target.value.as_ref()) {
        return value.0.clone();
    }
    // A target with none of the three set is not something the API server
    // accepts, but rendering "?" beats rendering an empty half of a pair.
    "?".to_string()
}

/// The same, for the observed side.
fn render_metric_current(current: &MetricValueStatus) -> String {
    if let Some(utilization) = current.average_utilization {
        return format!("{utilization}%");
    }
    if let Some(value) = current.average_value.as_ref().or(current.value.as_ref()) {
        return value.0.clone();
    }
    // Genuinely reachable: the HPA has not gathered this metric yet, or cannot.
    "<unknown>".to_string()
}

/// One metric reduced to what pairing and display each need.
struct HpaMetric {
    /// Full identity: the metric's type, its name, its selector, and — for an
    /// Object metric — the object it describes. Never shown; it exists only to
    /// pair a declared metric with its reading.
    key: String,
    /// What the column shows: `cpu`, `sidecar/memory`, `queue_length`.
    label: String,
    /// The rendered target, or the rendered current reading.
    value: String,
}

/// Field separator for identity keys. A unit separator rather than a printable
/// character, because metric names and label values may contain almost
/// anything, and a separator that can appear inside a field is a separator
/// that can forge a collision.
const KEY_SEP: char = '\u{1f}';

/// A selector as a stable string.
///
/// `match_labels` is a `BTreeMap` and `match_expressions` keeps the author's
/// order, so serializing is deterministic for a given selector rather than
/// dependent on hash iteration order.
fn selector_key(selector: Option<&LabelSelector>) -> String {
    selector.and_then(|s| serde_json::to_string(s).ok()).unwrap_or_default()
}

fn described_object_key(object: &CrossVersionObjectReference) -> String {
    format!("{}/{}/{}", object.api_version.as_deref().unwrap_or_default(), object.kind, object.name)
}

/// One declared metric: its identity, its label, and its target.
fn spec_metric(metric: &MetricSpec) -> Option<HpaMetric> {
    let type_ = metric.type_.as_str();
    match type_ {
        "Resource" => metric.resource.as_ref().map(|r| HpaMetric {
            key: format!("{type_}{KEY_SEP}{}", r.name),
            label: r.name.clone(),
            value: render_metric_target(&r.target),
        }),
        "ContainerResource" => metric.container_resource.as_ref().map(|r| HpaMetric {
            key: format!("{type_}{KEY_SEP}{}{KEY_SEP}{}", r.container, r.name),
            label: format!("{}/{}", r.container, r.name),
            value: render_metric_target(&r.target),
        }),
        "Pods" => metric.pods.as_ref().map(|p| HpaMetric {
            key: format!("{type_}{KEY_SEP}{}{KEY_SEP}{}", p.metric.name, selector_key(p.metric.selector.as_ref())),
            label: p.metric.name.clone(),
            value: render_metric_target(&p.target),
        }),
        "Object" => metric.object.as_ref().map(|o| HpaMetric {
            key: format!(
                "{type_}{KEY_SEP}{}{KEY_SEP}{}{KEY_SEP}{}",
                o.metric.name,
                selector_key(o.metric.selector.as_ref()),
                described_object_key(&o.described_object)
            ),
            label: o.metric.name.clone(),
            value: render_metric_target(&o.target),
        }),
        "External" => metric.external.as_ref().map(|e| HpaMetric {
            key: format!("{type_}{KEY_SEP}{}{KEY_SEP}{}", e.metric.name, selector_key(e.metric.selector.as_ref())),
            label: e.metric.name.clone(),
            value: render_metric_target(&e.target),
        }),
        _ => None,
    }
}

/// The same, for one observed metric. Keys are built identically so the two
/// sides can be matched.
fn status_metric(metric: &MetricStatus) -> Option<HpaMetric> {
    let type_ = metric.type_.as_str();
    match type_ {
        "Resource" => metric.resource.as_ref().map(|r| HpaMetric {
            key: format!("{type_}{KEY_SEP}{}", r.name),
            label: r.name.clone(),
            value: render_metric_current(&r.current),
        }),
        "ContainerResource" => metric.container_resource.as_ref().map(|r| HpaMetric {
            key: format!("{type_}{KEY_SEP}{}{KEY_SEP}{}", r.container, r.name),
            label: format!("{}/{}", r.container, r.name),
            value: render_metric_current(&r.current),
        }),
        "Pods" => metric.pods.as_ref().map(|p| HpaMetric {
            key: format!("{type_}{KEY_SEP}{}{KEY_SEP}{}", p.metric.name, selector_key(p.metric.selector.as_ref())),
            label: p.metric.name.clone(),
            value: render_metric_current(&p.current),
        }),
        "Object" => metric.object.as_ref().map(|o| HpaMetric {
            key: format!(
                "{type_}{KEY_SEP}{}{KEY_SEP}{}{KEY_SEP}{}",
                o.metric.name,
                selector_key(o.metric.selector.as_ref()),
                described_object_key(&o.described_object)
            ),
            label: o.metric.name.clone(),
            value: render_metric_current(&o.current),
        }),
        "External" => metric.external.as_ref().map(|e| HpaMetric {
            key: format!("{type_}{KEY_SEP}{}{KEY_SEP}{}", e.metric.name, selector_key(e.metric.selector.as_ref())),
            label: e.metric.name.clone(),
            value: render_metric_current(&e.current),
        }),
        _ => None,
    }
}

/// `cpu: 1%/70%, memory: 42%/80%`.
///
/// Driven by the spec rather than the status, so a metric the HPA has not
/// managed to read yet still appears — with `<unknown>` on the current side,
/// which is exactly the state worth seeing.
///
/// Paired on full metric identity rather than on the displayed label, and each
/// reading is consumed once. Both matter: `autoscaling/v2` allows two metrics
/// to share a name across types, and within a type to differ only by selector
/// (or, for an Object metric, by the object described). Matching on the label
/// would attribute one metric's reading to another's target, and without
/// consumption two identically-keyed entries would both read the same value —
/// in the one column this tab exists for. The two lists normally arrive in the
/// same order, but nothing in the API promises it.
fn format_hpa_targets(spec: &[MetricSpec], status: &[MetricStatus]) -> String {
    hpa_metric_rows(spec, status)
        .iter()
        .map(|m| format!("{}: {}/{}", m.name, m.current, m.target))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Each declared metric with its reading, paired as `format_hpa_targets`
/// describes. Shared with the HPA panel's Overview, which shows the same
/// pairing as a table — one implementation, so the two cannot disagree.
pub(crate) fn hpa_metric_rows(spec: &[MetricSpec], status: &[MetricStatus]) -> Vec<HpaMetricRow> {
    let mut observed: Vec<(HpaMetric, bool)> = status.iter().filter_map(status_metric).map(|m| (m, false)).collect();

    let mut rows = Vec::new();
    for (declared, metric) in spec.iter().filter_map(|m| spec_metric(m).map(|d| (d, m))) {
        let mut current = "<unknown>".to_string();
        for (reading, taken) in observed.iter_mut() {
            if !*taken && reading.key == declared.key {
                current = reading.value.clone();
                *taken = true;
                break;
            }
        }
        rows.push(HpaMetricRow { kind: metric.type_.clone(), name: declared.label, target: declared.value, current });
    }
    rows
}

/// A condition by type: whether it is True, plus its reason and message.
fn hpa_condition(conditions: &[HorizontalPodAutoscalerCondition], want: &str) -> (bool, String) {
    match conditions.iter().find(|c| c.type_ == want) {
        Some(condition) => {
            let detail = match (condition.reason.as_deref(), condition.message.as_deref()) {
                (Some(reason), Some(message)) => format!("{reason}: {message}"),
                (Some(reason), None) => reason.to_string(),
                (None, Some(message)) => message.to_string(),
                (None, None) => String::new(),
            };
            (condition.status == "True", detail)
        }
        // Absent rather than False: a freshly-created HPA has no conditions
        // for a moment. Treated as "not yet known to be broken" so it does not
        // flash red on creation.
        None => (true, String::new()),
    }
}

fn hpa_to_info(hpa: HorizontalPodAutoscaler) -> HpaInfo {
    let spec = hpa.spec.unwrap_or_default();
    let status = hpa.status.unwrap_or_default();
    let conditions = status.conditions.unwrap_or_default();

    let (able_to_scale, able_detail) = hpa_condition(&conditions, "AbleToScale");
    let (scaling_active, active_detail) = hpa_condition(&conditions, "ScalingActive");
    let (scaling_limited, _) = hpa_condition(&conditions, "ScalingLimited");

    // Whichever thing is actually wrong. `ScalingActive` first: an HPA that
    // cannot read its metrics is the common failure, and its message names the
    // metric, where `AbleToScale`'s tends to restate the same problem.
    let condition_reason = if !scaling_active {
        active_detail
    } else if !able_to_scale {
        able_detail
    } else {
        String::new()
    };

    HpaInfo {
        namespace: hpa.metadata.namespace.clone().unwrap_or_default(),
        name: hpa.metadata.name.clone().unwrap_or_default(),
        target_kind: spec.scale_target_ref.kind,
        target_name: spec.scale_target_ref.name,
        // The API server defaults an unset `minReplicas` to 1.
        min_replicas: spec.min_replicas.unwrap_or(1) as i64,
        max_replicas: spec.max_replicas as i64,
        current_replicas: status.current_replicas.unwrap_or(0) as i64,
        desired_replicas: status.desired_replicas as i64,
        targets: format_hpa_targets(&spec.metrics.unwrap_or_default(), &status.current_metrics.unwrap_or_default()),
        able_to_scale,
        scaling_active,
        scaling_limited,
        condition_reason,
        last_scale_at: status.last_scale_time.map(|t| t.0.to_rfc3339()),
        age_days: age_days(hpa.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(hpa.metadata.creation_timestamp.clone()),
        created_at: created_at(&hpa.metadata.creation_timestamp),
    }
}

pub async fn get_hpas(context_name: &str) -> Result<Vec<HpaInfo>, String> {
    let client = client_for_context(context_name).await?;
    let api: Api<HorizontalPodAutoscaler> = Api::all(client);
    let list = api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list horizontal pod autoscalers: {e}"))?;
    Ok(list.items.into_iter().map(hpa_to_info).collect())
}

pub async fn get_hpa_manifest(context_name: &str, namespace: &str, name: &str) -> Result<HpaManifest, String> {
    let client = client_for_context(context_name).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &hpa_resource());
    let obj = api
        .get(name)
        .await
        .map_err(|e| format!("Failed to get HorizontalPodAutoscaler '{name}': {e}"))?;
    // The Overview's detail from the same object, read as the typed v2 HPA
    // rather than fetched again: hpa_resource asks for autoscaling/v2, which is
    // exactly what HorizontalPodAutoscaler deserializes.
    let typed: HorizontalPodAutoscaler = serde_json::to_value(&obj)
        .and_then(serde_json::from_value)
        .map_err(|e| format!("Failed to read HorizontalPodAutoscaler '{name}': {e}"))?;
    let ObjectManifest { yaml_full, yaml_without_managed_fields } = object_manifest(obj)?;
    Ok(HpaManifest { yaml_full, yaml_without_managed_fields, detail: crate::hpa_detail::hpa_detail(&typed) })
}

/// Everything an HPA diagnosis reads.
///
/// Only the HPA itself is required; the rest each fail on their own, so a
/// target that cannot be read still leaves the conditions and events — which
/// usually carry the error verbatim — to diagnose from.
pub struct HpaDiagnostics {
    pub detail: HpaDetail,
    pub manifest: String,
    pub events: Result<Vec<EventInfo>, String>,
    /// The object it scales, as read through discovery.
    pub target: Result<DynamicObject, String>,
    /// The target's scale subresource: its replica counts as every scalable
    /// kind reports them.
    pub scale: Result<k8s_openapi::api::autoscaling::v1::Scale, String>,
    /// The selector the HPA itself reads, from that scale subresource.
    pub selector: Result<String, String>,
    /// The pods that selector matches — the ones whose metrics the HPA averages.
    pub pods: Result<Vec<Pod>, String>,
    /// Per-container usage from metrics-server, keyed by (pod, container).
    pub usage: Result<HashMap<(String, String), (i64, i64)>, String>,
    /// The metrics APIs registered on the cluster, for the groups this HPA's
    /// metric types are served by.
    pub metrics_apis: Result<Vec<k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService>, String>,
    /// Other HPAs in the namespace scaling the same object: (name, owner as `Kind/name`).
    pub siblings: Result<Vec<(String, String)>, String>,
}

/// The metrics API group each HPA metric type is read from.
pub(crate) fn metrics_api_group(kind: &str) -> &'static str {
    match kind {
        "Resource" | "ContainerResource" => "metrics.k8s.io",
        "External" => "external.metrics.k8s.io",
        _ => "custom.metrics.k8s.io",
    }
}

/// Per-container usage in a namespace, from metrics-server.
///
/// Unlike `fetch_pod_metrics`, an absent or failing metrics-server is an
/// error here rather than "no data": for an HPA on resource metrics it is
/// very likely the answer.
async fn fetch_container_usage(client: &Client, namespace: &str) -> Result<HashMap<(String, String), (i64, i64)>, String> {
    let req = http::Request::builder()
        .uri(format!("/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods"))
        .body(Vec::new())
        .map_err(|e| e.to_string())?;
    let value: serde_json::Value = tokio::time::timeout(METRICS_REQUEST_TIMEOUT, client.request(req))
        .await
        .map_err(|_| "metrics.k8s.io did not answer in time".to_string())?
        .map_err(|e| format!("metrics.k8s.io: {e}"))?;
    let mut out = HashMap::new();
    for item in value.get("items").and_then(|v| v.as_array()).into_iter().flatten() {
        let pod = item.pointer("/metadata/name").and_then(|n| n.as_str()).unwrap_or_default();
        for c in item.get("containers").and_then(|v| v.as_array()).into_iter().flatten() {
            let usage = |k: &str| c.pointer(&format!("/usage/{k}")).and_then(|v| v.as_str());
            out.insert(
                (pod.to_string(), json_str(Some(c), "name").to_string()),
                (usage("cpu").map(parse_cpu_millicores).unwrap_or(0), usage("memory").map(parse_memory_ki).unwrap_or(0)),
            );
        }
    }
    Ok(out)
}

/// The HPA's target and its scale subresource, found by discovery: the
/// reference carries an apiVersion, and a target can be any kind that
/// implements `/scale` — an Argo Rollout as readily as a Deployment.
async fn get_hpa_target(
    client: &Client,
    namespace: &str,
    api_version: &str,
    kind: &str,
    name: &str,
) -> (Result<DynamicObject, String>, Result<k8s_openapi::api::autoscaling::v1::Scale, String>) {
    let (group, version) = match api_version.split_once('/') {
        Some((g, v)) => (g, v),
        None => ("", api_version),
    };
    let gvk = GroupVersionKind::gvk(group, version, kind);
    let ar = match kube::discovery::oneshot::pinned_kind(client, &gvk).await {
        Ok((ar, _)) => ar,
        Err(e) => {
            let e = format!("Failed to discover {kind} in {api_version}: {e}");
            return (Err(e.clone()), Err(e));
        }
    };
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let (target, scale) = tokio::join!(api.get(name), api.get_scale(name));
    let target = target.map_err(|e| get_error(kind, name, e));
    let scale = scale.map_err(|e| scale_error(kind, name, &target, e));
    (target, scale)
}

/// A failed `/scale` read, given how the object's own read went.
///
/// A 404 from `/scale` alone says only that there is no scale to read: a
/// custom resource without the scale subresource answers the same way. The
/// object is missing only when its own read says so too.
pub(crate) fn scale_error(kind: &str, name: &str, target: &Result<DynamicObject, String>, e: kube::Error) -> String {
    let missing = format!("{kind} '{name}' does not exist");
    match (target, e) {
        (Err(t), _) if *t == missing => missing,
        (_, kube::Error::Api(ref resp)) if resp.code == 404 => {
            format!("Failed to read the scale of {kind} '{name}': it has no scale subresource")
        }
        (_, e) => format!("Failed to read the scale of {kind} '{name}': {e}"),
    }
}

/// A failed get, said plainly when the object is simply not there.
pub(crate) fn get_error(kind: &str, name: &str, e: kube::Error) -> String {
    match e {
        kube::Error::Api(ref resp) if resp.code == 404 => format!("{kind} '{name}' does not exist"),
        e => format!("Failed to get {kind} '{name}': {e}"),
    }
}

pub async fn get_hpa_diagnostics(context_name: &str, namespace: &str, name: &str) -> Result<HpaDiagnostics, String> {
    let client = client_for_context(context_name).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &hpa_resource());
    let obj = api.get(name).await.map_err(|e| format!("Failed to get HorizontalPodAutoscaler '{name}': {e}"))?;
    let typed: HorizontalPodAutoscaler = serde_json::to_value(&obj)
        .and_then(serde_json::from_value)
        .map_err(|e| format!("Failed to read HorizontalPodAutoscaler '{name}': {e}"))?;
    let detail = crate::hpa_detail::hpa_detail(&typed);
    let manifest = object_manifest(obj)?.yaml_without_managed_fields;
    let target_ref = typed.spec.as_ref().map(|s| s.scale_target_ref.clone()).unwrap_or_default();

    let event_fields = format!(
        "involvedObject.kind=HorizontalPodAutoscaler,involvedObject.name={name},involvedObject.namespace={namespace}"
    );
    let events_api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let services_api: Api<k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService> =
        Api::all(client.clone());
    let (event_params, all) = (ListParams::default().fields(&event_fields), ListParams::default());
    let hpas_api: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), namespace);
    let ((target, scale), events, usage, metrics_apis, siblings) = tokio::join!(
        get_hpa_target(
            &client,
            namespace,
            target_ref.api_version.as_deref().unwrap_or("apps/v1"),
            &target_ref.kind,
            &target_ref.name,
        ),
        events_api.list(&event_params),
        fetch_container_usage(&client, namespace),
        services_api.list(&all),
        hpas_api.list(&all),
    );
    let siblings = siblings
        .map(|l| {
            l.items
                .into_iter()
                .filter(|h| h.metadata.name.as_deref() != Some(name))
                .filter(|h| {
                    h.spec.as_ref().is_some_and(|s| s.scale_target_ref.kind == target_ref.kind && s.scale_target_ref.name == target_ref.name)
                })
                .map(|h| {
                    let owner = h
                        .metadata
                        .owner_references
                        .iter()
                        .flatten()
                        .find(|o| o.controller == Some(true))
                        .map(|o| format!("{}/{}", o.kind, o.name))
                        .unwrap_or_default();
                    (h.metadata.name.unwrap_or_default(), owner)
                })
                .collect()
        })
        .map_err(|e| format!("Failed to list HPAs in '{namespace}': {e}"));

    let selector = scale.clone().and_then(|s| {
        s.status
            .and_then(|st| st.selector)
            .filter(|sel| !sel.is_empty())
            .ok_or_else(|| format!("{} '{}' reports no selector on its scale subresource", target_ref.kind, target_ref.name))
    });
    let pods = match &selector {
        Ok(sel) => {
            let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
            pods_api
                .list(&ListParams::default().labels(sel))
                .await
                .map(|l| l.items)
                .map_err(|e| format!("Failed to list the target's pods: {e}"))
        }
        Err(e) => Err(format!("no selector to find the pods by ({e})")),
    };

    let groups: Vec<&str> = detail.metrics.iter().map(|m| metrics_api_group(&m.kind)).collect();
    let metrics_apis = metrics_apis
        .map(|l| {
            l.items
                .into_iter()
                .filter(|s| s.spec.as_ref().and_then(|sp| sp.group.as_deref()).is_some_and(|g| groups.contains(&g)))
                .collect()
        })
        .map_err(|e| format!("Failed to list APIServices: {e}"));

    Ok(HpaDiagnostics {
        detail,
        manifest,
        events: events
            .map(|l| {
                let mut items = l.items;
                items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
                items.into_iter().map(event_to_info).collect()
            })
            .map_err(|e| format!("Failed to list events for '{name}': {e}")),
        target,
        scale,
        selector,
        pods,
        usage,
        metrics_apis,
        siblings,
    })
}

/// Same reasoning as `get_keda_events` (filter before the cap).
pub async fn get_hpa_events(context_name: &str, namespace: &str, name: &str) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;

    Ok(items
        .into_iter()
        .filter(|e| {
            e.involved_object.kind.as_deref() == Some("HorizontalPodAutoscaler")
                && e.involved_object.name.as_deref() == Some(name)
                && e.metadata.namespace.as_deref() == Some(namespace)
        })
        .map(event_to_info)
        .collect())
}

fn keda_resource(kind: &str, plural: &str) -> ApiResource {
    ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk("keda.sh", "v1alpha1", kind), plural)
}

fn dynamic_object_to_keda(obj: DynamicObject, kind: &str) -> KedaScaledObjectInfo {
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");
    let is_job = kind == "ScaledJob";

    // ScaledJob templates a Job rather than pointing at an existing workload,
    // so it has no scaleTargetRef kind/name to read.
    let target = spec.and_then(|s| s.get("scaleTargetRef"));
    let target_kind = if is_job {
        "Job".to_string()
    } else {
        match json_str(target, "kind") {
            "" => "Deployment".to_string(), // KEDA's documented default
            k => k.to_string(),
        }
    };

    let triggers = spec
        .and_then(|s| s.get("triggers"))
        .and_then(|t| t.as_array())
        .map(|ts| ts.iter().map(|t| json_str(Some(t), "type")).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();

    // Both kinds use the same field names for their replica bounds.
    let (min_replicas, max_replicas) = (json_i64(spec, "minReplicaCount"), json_i64(spec, "maxReplicaCount"));

    let (ready, _) = json_condition(status, "Ready");
    let (active, _) = json_condition(status, "Active");
    let (paused, _) = json_condition(status, "Paused");

    KedaScaledObjectInfo {
        namespace: obj.metadata.namespace.clone().unwrap_or_default(),
        name: obj.metadata.name.clone().unwrap_or_default(),
        kind: kind.to_string(),
        target_kind,
        target_name: if is_job { String::new() } else { json_str(target, "name").to_string() },
        min_replicas,
        max_replicas,
        triggers,
        ready,
        active,
        paused,
        age_days: age_days(obj.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(obj.metadata.creation_timestamp.clone()),
        created_at: created_at(&obj.metadata.creation_timestamp),
    }
}

pub async fn get_keda_scaled_objects(context_name: &str) -> Result<KedaResult, String> {
    let client = client_for_context(context_name).await?;

    // Both kinds are listed concurrently; ScaledJob is far rarer than
    // ScaledObject, and a cluster can legitimately have the CRD for one and
    // not the other, so each 404s independently.
    let so_ar = keda_resource("ScaledObject", "scaledobjects");
    let sj_ar = keda_resource("ScaledJob", "scaledjobs");
    let so_api: Api<DynamicObject> = Api::all_with(client.clone(), &so_ar);
    let sj_api: Api<DynamicObject> = Api::all_with(client.clone(), &sj_ar);
    let lp = ListParams::default();
    let (so, sj) = tokio::join!(so_api.list(&lp), sj_api.list(&lp));

    let mut installed = false;
    let mut out = Vec::new();

    match so {
        Ok(list) => {
            installed = true;
            out.extend(list.items.into_iter().map(|o| dynamic_object_to_keda(o, "ScaledObject")));
        }
        Err(kube::Error::Api(resp)) if resp.code == 404 => {}
        Err(e) => return Err(format!("Failed to list KEDA scaled objects: {e}")),
    }
    match sj {
        Ok(list) => {
            installed = true;
            out.extend(list.items.into_iter().map(|o| dynamic_object_to_keda(o, "ScaledJob")));
        }
        Err(kube::Error::Api(resp)) if resp.code == 404 => {}
        Err(e) => return Err(format!("Failed to list KEDA scaled jobs: {e}")),
    }

    Ok(KedaResult { installed, error: None, scaled_objects: out })
}

/// The plural for a KEDA kind. The panel is always opened from a row that
/// already knows which of the two kinds it is, so an unknown kind here means
/// a caller bug rather than a cluster that answered oddly.
fn keda_plural(kind: &str) -> Result<&'static str, String> {
    match kind {
        "ScaledObject" => Ok("scaledobjects"),
        "ScaledJob" => Ok("scaledjobs"),
        other => Err(format!("Unknown KEDA kind '{other}'")),
    }
}

pub async fn get_keda_manifest(context_name: &str, namespace: &str, kind: &str, name: &str) -> Result<KedaManifest, String> {
    let client = client_for_context(context_name).await?;
    let ar = keda_resource(kind, keda_plural(kind)?);
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &ar);
    let obj = api.get(name).await.map_err(|e| format!("Failed to get {kind} '{name}': {e}"))?;
    let detail = crate::keda_detail::keda_detail(&obj, kind);
    let ObjectManifest { yaml_full, yaml_without_managed_fields } = object_manifest(obj)?;
    Ok(KedaManifest { yaml_full, yaml_without_managed_fields, detail })
}

/// Everything a KEDA diagnosis reads.
///
/// Only the ScaledObject or ScaledJob itself is required; each of the rest
/// fails on its own and the payload says so.
pub struct KedaDiagnostics {
    pub detail: KedaDetail,
    pub object: DynamicObject,
    pub manifest: String,
    pub events: Result<Vec<EventInfo>, String>,
    /// ScaledObject only: the workload it scales, and its scale subresource.
    pub target: Option<(Result<DynamicObject, String>, Result<k8s_openapi::api::autoscaling::v1::Scale, String>)>,
    /// ScaledObject only: the HPA KEDA generated to do the scaling.
    pub hpa: Option<Result<HpaDetail, String>>,
    /// ScaledJob only: the Jobs it has created, newest first.
    pub jobs: Option<Result<Vec<k8s_openapi::api::batch::v1::Job>, String>>,
    /// Each TriggerAuthentication or ClusterTriggerAuthentication a trigger
    /// names, keyed by `Kind/name`.
    pub auths: Vec<(String, Result<DynamicObject, String>)>,
    /// The containers a trigger's `*FromEnv` metadata is resolved against.
    pub env_containers: Vec<serde_json::Value>,
    /// The keys — never the values — of every Secret and ConfigMap the
    /// credentials resolve through, keyed by (kind, namespace, name).
    pub key_sets: HashMap<(String, String, String), Result<Vec<String>, String>>,
    /// The namespace KEDA's operator runs in, where a
    /// ClusterTriggerAuthentication's secrets are read from.
    pub operator_namespace: Option<String>,
    /// KEDA's own Deployments: operator and metrics apiserver.
    pub operator: Result<Vec<k8s_openapi::api::apps::v1::Deployment>, String>,
    /// The operator's structured log lines about this object, newest last.
    pub operator_logs: Result<Vec<String>, String>,
    pub external_metrics_api: Result<Vec<k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService>, String>,
}

/// How far back into the operator's log to look for this object: an hour.
///
/// By time rather than lines, because the two kinds of error that matter are
/// logged at very different rates. A failing scaler logs on every poll, with a
/// Go stack trace under each line — 3000 lines covered six minutes of one real
/// operator — while a reconcile error ("failed to ensure HPA") backs off to
/// once every quarter of an hour and fell outside those six minutes entirely.
const KEDA_OPERATOR_LOG_SECONDS: i64 = 3600;

/// The most of the operator's log to read for that hour; a busy operator
/// wrote 2 MB in 37 minutes.
const KEDA_OPERATOR_LOG_BYTES: i64 = 8 * 1024 * 1024;

/// Whether one KEDA operator log line is about this object.
///
/// The operator logs as `time\tLEVEL\tcomponent\tmessage\t{json}` — or without
/// the component, for the controller's own lines — and names
/// the object in the JSON two ways: scale_handler as `scaledObject.Namespace`
/// and `scaledObject.Name` (or `scaledJob.…`), the scalers and the controller
/// as `namespace` and `name` (with `type` for the scalers). Lines without the JSON — Go stack traces under an
/// error — are skipped; the error line above them already says what failed.
pub(crate) fn keda_log_line_is_about(line: &str, kind: &str, namespace: &str, name: &str) -> bool {
    let Some(start) = line.find("\t{") else { return false };
    let Ok(fields) = serde_json::from_str::<serde_json::Value>(line[start + 1..].trim_end()) else { return false };
    let field = |k: &str| fields.get(k).and_then(|v| v.as_str());
    let prefix = if kind == "ScaledJob" { "scaledJob" } else { "scaledObject" };
    let handler = field(&format!("{prefix}.Namespace")) == Some(namespace) && field(&format!("{prefix}.Name")) == Some(name);
    // A bare namespace and name can belong to either kind, so whatever the
    // line says about its kind must agree: the scalers' `type`, the
    // controller's `controllerKind` or `controller`, or the object it keys by
    // its kind. Only a line that says nothing of its kind is taken on name.
    let other = if kind == "ScaledJob" { "ScaledObject" } else { "ScaledJob" };
    let of_kind = field("type").is_none_or(|t| t == kind)
        && field("controllerKind").is_none_or(|k| k == kind)
        && field("controller").is_none_or(|c| c.eq_ignore_ascii_case(kind))
        && fields.get(other).is_none();
    let scaler = field("namespace") == Some(namespace) && field("name") == Some(name) && of_kind;
    handler || scaler
}

/// The Secrets and ConfigMaps a KEDA object's credentials resolve through.
///
/// Two routes: a trigger's `*FromEnv` metadata names an environment variable
/// on the target's container, which may come from a Secret or ConfigMap; a
/// TriggerAuthentication's `secretTargetRef` or `configMapTargetRef` names a
/// Secret or ConfigMap and key directly.
pub(crate) fn keda_key_set_refs(
    containers: &[serde_json::Value],
    auths: &[(String, Result<DynamicObject, String>)],
    namespace: &str,
    operator_namespace: Option<&str>,
) -> Vec<(String, String, String)> {
    let mut refs: Vec<(String, String, String)> = Vec::new();
    let mut add = |kind: &str, ns: &str, name: &str| {
        let r = (kind.to_string(), ns.to_string(), name.to_string());
        if !name.is_empty() && !refs.contains(&r) {
            refs.push(r);
        }
    };
    for c in containers {
        for e in c.get("env").and_then(|v| v.as_array()).into_iter().flatten() {
            let from = e.get("valueFrom");
            add("Secret", namespace, json_str(from.and_then(|f| f.get("secretKeyRef")), "name"));
            add("ConfigMap", namespace, json_str(from.and_then(|f| f.get("configMapKeyRef")), "name"));
        }
        for e in c.get("envFrom").and_then(|v| v.as_array()).into_iter().flatten() {
            add("Secret", namespace, json_str(e.get("secretRef"), "name"));
            add("ConfigMap", namespace, json_str(e.get("configMapRef"), "name"));
        }
    }
    for (r, auth) in auths {
        let Ok(auth) = auth else { continue };
        let ns = if r.starts_with("ClusterTriggerAuthentication/") { operator_namespace.unwrap_or("keda") } else { namespace };
        for (kind, at) in [("Secret", "/spec/secretTargetRef"), ("ConfigMap", "/spec/configMapTargetRef")] {
            for t in auth.data.pointer(at).and_then(|v| v.as_array()).into_iter().flatten() {
                add(kind, ns, json_str(Some(t), "name"));
            }
        }
    }
    refs
}

/// The containers KEDA reads `*FromEnv` from: a ScaledJob's own Job
/// template, or the pod template of the workload a ScaledObject scales.
fn keda_env_containers(object: &DynamicObject, target: Option<&DynamicObject>) -> Vec<serde_json::Value> {
    let from = match target {
        Some(t) => t.data.pointer("/spec/template/spec/containers"),
        None => object.data.pointer("/spec/jobTargetRef/template/spec/containers"),
    };
    from.and_then(|c| c.as_array()).cloned().unwrap_or_default()
}

/// The manifest as the diagnosis sends it.
///
/// A ScaledJob carries a whole Job template, and its containers' inline `env`
/// values can be credentials no pattern recognises, so each is replaced
/// outright. `last-applied-configuration` would hold a second copy of them,
/// so it goes too.
pub(crate) fn keda_manifest_for_diagnosis(mut object: DynamicObject) -> DynamicObject {
    if let Some(a) = object.metadata.annotations.as_mut() {
        a.remove(LAST_APPLIED_ANNOTATION);
    }
    for list in ["containers", "initContainers"] {
        let at = format!("/spec/jobTargetRef/template/spec/{list}");
        for c in object.data.pointer_mut(&at).and_then(|v| v.as_array_mut()).into_iter().flatten() {
            for e in c.get_mut("env").and_then(|v| v.as_array_mut()).into_iter().flatten() {
                if let Some(v) = e.get_mut("value") {
                    *v = serde_json::Value::String("(value omitted)".to_string());
                }
            }
        }
    }
    object
}

pub async fn get_keda_diagnostics(context_name: &str, namespace: &str, kind: &str, name: &str) -> Result<KedaDiagnostics, String> {
    let client = client_for_context(context_name).await?;
    let ar = keda_resource(kind, keda_plural(kind)?);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let object = api.get(name).await.map_err(|e| format!("Failed to get {kind} '{name}': {e}"))?;
    let detail = crate::keda_detail::keda_detail(&object, kind);
    let manifest = object_manifest(keda_manifest_for_diagnosis(object.clone()))?.yaml_without_managed_fields;
    let is_job = kind == "ScaledJob";

    let target_ref = object.data.pointer("/spec/scaleTargetRef").cloned().unwrap_or_default();
    let auth_refs: Vec<String> = {
        let mut v: Vec<String> = detail.triggers.iter().map(|t| t.auth_ref.clone()).filter(|r| !r.is_empty()).collect();
        v.sort();
        v.dedup();
        v
    };

    let event_fields = format!("involvedObject.kind={kind},involvedObject.name={name},involvedObject.namespace={namespace}");
    let events_api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let deployments_api: Api<k8s_openapi::api::apps::v1::Deployment> = Api::all(client.clone());
    let services_api: Api<k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService> = Api::all(client.clone());
    let (event_params, all) = (ListParams::default().fields(&event_fields), ListParams::default());

    let target_fut = async {
        if is_job {
            return None;
        }
        Some(
            get_hpa_target(
                &client,
                namespace,
                match json_str(Some(&target_ref), "apiVersion") {
                    "" => "apps/v1",
                    v => v,
                },
                match json_str(Some(&target_ref), "kind") {
                    "" => "Deployment",
                    k => k,
                },
                json_str(Some(&target_ref), "name"),
            )
            .await,
        )
    };
    let hpa_fut = async {
        if is_job || detail.hpa_name.is_empty() {
            return None;
        }
        let api: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), namespace);
        Some(
            api.get(&detail.hpa_name)
                .await
                .map(|h| crate::hpa_detail::hpa_detail(&h))
                .map_err(|e| get_error("HorizontalPodAutoscaler", &detail.hpa_name, e)),
        )
    };
    let jobs_fut = async {
        if !is_job {
            return None;
        }
        let api: Api<k8s_openapi::api::batch::v1::Job> = Api::namespaced(client.clone(), namespace);
        Some(
            api.list(&ListParams::default().labels(&format!("scaledjob.keda.sh/name={name}")))
                .await
                .map(|l| {
                    let mut jobs = l.items;
                    jobs.sort_by(|a, b| b.metadata.creation_timestamp.cmp(&a.metadata.creation_timestamp));
                    jobs
                })
                .map_err(|e| format!("Failed to list the Jobs of '{name}': {e}")),
        )
    };
    let auths_fut = futures::future::join_all(auth_refs.iter().map(|r| {
        let client = client.clone();
        async move {
            let (auth_kind, auth_name) = r.split_once('/').unwrap_or(("TriggerAuthentication", r));
            let (plural, scoped) = match auth_kind {
                "ClusterTriggerAuthentication" => ("clustertriggerauthentications", false),
                _ => ("triggerauthentications", true),
            };
            let ar = keda_resource(auth_kind, plural);
            let api: Api<DynamicObject> = if scoped { Api::namespaced_with(client, namespace, &ar) } else { Api::all_with(client, &ar) };
            (r.clone(), api.get(auth_name).await.map_err(|e| format!("Failed to get {r}: {e}")))
        }
    }));
    // KEDA's Deployments by name, wherever it was installed: `keda` for Helm,
    // `kube-system` for the AKS add-on.
    let operator_fut = async {
        let mut out = Vec::new();
        for n in ["keda-operator", "keda-operator-metrics-apiserver"] {
            let params = ListParams::default().fields(&format!("metadata.name={n}"));
            out.extend(deployments_api.list(&params).await.map_err(|e| format!("Failed to find {n}: {e}"))?.items);
        }
        Ok::<_, String>(out)
    };

    let (events, target, hpa, jobs, auths, operator, apis) = tokio::join!(
        events_api.list(&event_params),
        target_fut,
        hpa_fut,
        jobs_fut,
        auths_fut,
        operator_fut,
        services_api.list(&all),
    );

    let operator_namespace = operator
        .as_ref()
        .ok()
        .and_then(|d| d.iter().find(|d| d.metadata.name.as_deref() == Some("keda-operator")))
        .and_then(|d| d.metadata.namespace.clone());

    let env_containers = keda_env_containers(&object, target.as_ref().and_then(|(t, _)| t.as_ref().ok()));
    let containers = &env_containers;
    let refs = keda_key_set_refs(containers, &auths, namespace, operator_namespace.as_deref());
    let key_sets_fut = futures::future::join_all(refs.into_iter().map(|(k, ns, n)| {
        let client = client.clone();
        async move {
            // Keys only: the values are dropped here and never leave this function.
            let keys = if k == "Secret" {
                let api: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client, &ns);
                api.get(&n).await.map(|s| s.data.unwrap_or_default().into_keys().chain(s.string_data.unwrap_or_default().into_keys()).collect())
            } else {
                let api: Api<k8s_openapi::api::core::v1::ConfigMap> = Api::namespaced(client, &ns);
                api.get(&n).await.map(|c| c.data.unwrap_or_default().into_keys().chain(c.binary_data.unwrap_or_default().into_keys()).collect())
            };
            let keys = match keys {
                Ok(k) => Ok(k),
                Err(kube::Error::Api(resp)) if resp.code == 404 => Err("does not exist".to_string()),
                Err(e) => Err(format!("could not be read: {e}")),
            };
            ((k, ns, n), keys)
        }
    }));
    let operator_selector = operator
        .as_ref()
        .ok()
        .and_then(|d| d.iter().find(|d| d.metadata.name.as_deref() == Some("keda-operator")))
        .and_then(|d| d.spec.as_ref())
        .and_then(|s| s.selector.match_labels.as_ref())
        .map(|m| m.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(","))
        .filter(|s| !s.is_empty());
    let logs_fut = async {
        let ns = operator_namespace.clone().ok_or_else(|| "the KEDA operator was not found".to_string())?;
        // The Deployment's own selector, rather than a label this side assumes:
        // the Helm chart and the AKS add-on label their pods differently.
        let selector = operator_selector.clone().ok_or_else(|| "the KEDA operator's Deployment has no selector".to_string())?;
        let pods: Api<Pod> = Api::namespaced(client.clone(), &ns);
        let operator_pods = pods
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|e| format!("Failed to list the operator's pods: {e}"))?
            .items;
        let mut lines = Vec::new();
        for p in &operator_pods {
            let params = LogParams {
                since_seconds: Some(KEDA_OPERATOR_LOG_SECONDS),
                limit_bytes: Some(KEDA_OPERATOR_LOG_BYTES),
                ..Default::default()
            };
            match pods.logs(&p.name_any(), &params).await {
                Ok(text) => lines.extend(text.lines().filter(|l| keda_log_line_is_about(l, kind, namespace, name)).map(str::to_string)),
                Err(e) => return Err(format!("Failed to read the operator's log: {e}")),
            }
        }
        // Lines start with an RFC 3339 time, so sorting orders replicas together.
        lines.sort();
        Ok(lines)
    };
    let (key_sets, operator_logs) = tokio::join!(key_sets_fut, logs_fut);

    Ok(KedaDiagnostics {
        detail,
        object,
        manifest,
        events: events
            .map(|l| {
                let mut items = l.items;
                items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
                items.into_iter().map(event_to_info).collect()
            })
            .map_err(|e| format!("Failed to list events for '{name}': {e}")),
        target,
        hpa,
        jobs,
        auths,
        env_containers,
        key_sets: key_sets.into_iter().collect(),
        operator_namespace,
        operator,
        operator_logs,
        external_metrics_api: apis
            .map(|l| {
                l.items
                    .into_iter()
                    .filter(|s| s.spec.as_ref().and_then(|sp| sp.group.as_deref()) == Some("external.metrics.k8s.io"))
                    .collect()
            })
            .map_err(|e| format!("Failed to list APIServices: {e}")),
    })
}

/// A Deployment, StatefulSet or DaemonSet whose pod template a Service's
/// selector reaches, or nearly reaches.
pub struct ServiceWorkload {
    pub kind: String,
    pub name: String,
    /// The pod template's labels.
    pub labels: std::collections::BTreeMap<String, String>,
    /// Replicas asked for: `spec.replicas`, or a DaemonSet's desired count.
    pub desired: i32,
    pub ready: i32,
}

/// Everything a Service diagnosis reads.
///
/// Only the Service itself is required; each of the rest fails on its own and
/// the payload says so.
pub struct ServiceDiagnostics {
    pub service: k8s_openapi::api::core::v1::Service,
    pub manifest: String,
    pub events: Result<Vec<EventInfo>, String>,
    /// Its EndpointSlices: what the control plane — or, for a Service without
    /// a selector, whoever maintains them — says is behind it.
    pub slices: Result<Vec<k8s_openapi::api::discovery::v1::EndpointSlice>, String>,
    /// Every pod in the namespace, so the renderer can tell the pods the
    /// selector matches from the near misses a mistyped label leaves outside it.
    pub pods: Result<Vec<Pod>, String>,
    /// The events of one matching pod that is not ready, which is where a
    /// failing readiness probe says what it got.
    pub unready_pod_events: Option<(String, Result<Vec<EventInfo>, String>)>,
    /// The workloads whose pod template shares at least one label with the
    /// selector, and the kinds that could not be listed: each kind is read on
    /// its own, so a forbidden one does not hide the others.
    pub workloads: (Vec<ServiceWorkload>, Vec<String>),
    /// The Ingresses in the namespace that route to it.
    pub ingresses: Result<Vec<k8s_openapi::api::networking::v1::Ingress>, String>,
    pub control_plane: Result<ControlPlane, String>,
}

/// What the nodes say about where the control plane runs.
pub struct ControlPlane {
    /// Nodes labelled with the control-plane role, or its older name `master`.
    pub role_nodes: usize,
    /// Whether the nodes are AKS's: then the control plane is Azure's, and
    /// etcd, the scheduler and the controller manager run no pods here.
    pub aks: bool,
}

/// How many of a selector's terms a set of labels satisfies.
pub(crate) fn selector_terms_met(
    selector: &std::collections::BTreeMap<String, String>,
    labels: Option<&std::collections::BTreeMap<String, String>>,
) -> usize {
    selector.iter().filter(|(k, v)| labels.and_then(|l| l.get(*k)) == Some(*v)).count()
}

pub async fn get_service_diagnostics(context_name: &str, namespace: &str, name: &str) -> Result<ServiceDiagnostics, String> {
    use k8s_openapi::api::core::v1::Service;
    use k8s_openapi::api::discovery::v1::EndpointSlice;
    use k8s_openapi::api::networking::v1::Ingress;

    let client = client_for_context(context_name).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ApiResource::erase::<Service>(&()));
    let mut obj = api.get(name).await.map_err(|e| get_error("Service", name, e))?;
    let service: Service = serde_json::to_value(&obj)
        .and_then(serde_json::from_value)
        .map_err(|e| format!("Failed to read Service '{name}': {e}"))?;
    if let Some(a) = obj.metadata.annotations.as_mut() {
        a.remove(LAST_APPLIED_ANNOTATION);
    }
    let manifest = object_manifest(obj)?.yaml_without_managed_fields;
    let spec = service.spec.clone().unwrap_or_default();
    let selector = spec.selector.clone().unwrap_or_default();
    let external_name = spec.type_.as_deref() == Some("ExternalName");

    let event_fields = format!("involvedObject.kind=Service,involvedObject.name={name},involvedObject.namespace={namespace}");
    let events_api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let slices_api: Api<EndpointSlice> = Api::namespaced(client.clone(), namespace);
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let ingresses_api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
    let nodes_api: Api<Node> = Api::all(client.clone());
    let event_params = ListParams::default().fields(&event_fields);
    let slice_params = ListParams::default().labels(&format!("kubernetes.io/service-name={name}"));
    let control_plane = ListParams::default().labels("node-role.kubernetes.io/control-plane");
    let master = ListParams::default().labels("node-role.kubernetes.io/master");
    let aks = ListParams::default().labels("kubernetes.azure.com/cluster").limit(1);
    let all = ListParams::default();

    let pods_fut = async {
        if selector.is_empty() || external_name {
            return Ok(Vec::new());
        }
        pods_api.list(&all).await.map(|l| l.items).map_err(|e| format!("Failed to list pods in '{namespace}': {e}"))
    };
    let workloads_fut = async {
        if selector.is_empty() || external_name {
            return (Vec::new(), Vec::new());
        }
        let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        let statefulsets_api: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
        let daemonsets_api: Api<DaemonSet> = Api::namespaced(client.clone(), namespace);
        let (deployments, statefulsets, daemonsets) =
            tokio::join!(deployments_api.list(&all), statefulsets_api.list(&all), daemonsets_api.list(&all));
        let mut errors = Vec::new();
        let mut failed = |kind: &str, e: kube::Error| errors.push(format!("Failed to list {kind}s in '{namespace}': {e}"));
        let template_labels = |t: &k8s_openapi::api::core::v1::PodTemplateSpec| t.metadata.as_ref().and_then(|m| m.labels.clone()).unwrap_or_default();
        let deployments = deployments.map(|l| l.items).unwrap_or_else(|e| {
            failed("Deployment", e);
            Vec::new()
        });
        let statefulsets = statefulsets.map(|l| l.items).unwrap_or_else(|e| {
            failed("StatefulSet", e);
            Vec::new()
        });
        let daemonsets = daemonsets.map(|l| l.items).unwrap_or_else(|e| {
            failed("DaemonSet", e);
            Vec::new()
        });
        let mut out = Vec::new();
        for d in deployments {
            let spec = d.spec.unwrap_or_default();
            out.push(ServiceWorkload {
                kind: "Deployment".into(),
                name: d.metadata.name.unwrap_or_default(),
                labels: template_labels(&spec.template),
                desired: spec.replicas.unwrap_or(1),
                ready: d.status.and_then(|s| s.ready_replicas).unwrap_or(0),
            });
        }
        for d in statefulsets {
            let spec = d.spec.unwrap_or_default();
            out.push(ServiceWorkload {
                kind: "StatefulSet".into(),
                name: d.metadata.name.unwrap_or_default(),
                labels: template_labels(&spec.template),
                desired: spec.replicas.unwrap_or(1),
                ready: d.status.and_then(|s| s.ready_replicas).unwrap_or(0),
            });
        }
        for d in daemonsets {
            let spec = d.spec.unwrap_or_default();
            let status = d.status.unwrap_or_default();
            out.push(ServiceWorkload {
                kind: "DaemonSet".into(),
                name: d.metadata.name.unwrap_or_default(),
                labels: template_labels(&spec.template),
                desired: status.desired_number_scheduled,
                ready: status.number_ready,
            });
        }
        out.retain(|w| selector_terms_met(&selector, Some(&w.labels)) > 0);
        (out, errors)
    };
    let control_plane_fut = async {
        let (role, master, aks) =
            tokio::join!(nodes_api.list_metadata(&control_plane), nodes_api.list_metadata(&master), nodes_api.list_metadata(&aks));
        let failed = |e: kube::Error| format!("Failed to list nodes: {e}");
        let mut names: Vec<String> = role.map_err(failed)?.items.into_iter().chain(master.map_err(failed)?.items).map(|n| n.name_any()).collect();
        names.sort();
        names.dedup();
        Ok::<_, String>(ControlPlane { role_nodes: names.len(), aks: !aks.map_err(failed)?.items.is_empty() })
    };

    let (events, slices, pods, workloads, ingresses, control_plane) = tokio::join!(
        events_api.list(&event_params),
        slices_api.list(&slice_params),
        pods_fut,
        workloads_fut,
        ingresses_api.list(&all),
        control_plane_fut,
    );

    // One unready matching pod's events: a failing readiness probe reports
    // what it got there, and nowhere in the pod's status.
    let unready = pods.as_ref().ok().and_then(|pods| {
        pods.iter()
            .filter(|p| selector_terms_met(&selector, p.metadata.labels.as_ref()) == selector.len())
            .filter(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) != Some("Succeeded"))
            .find(|p| {
                !p.status
                    .as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .is_some_and(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
            })
            .map(|p| p.name_any())
    });
    let unready_pod_events = match unready {
        Some(pod) => {
            let fields = format!("involvedObject.kind=Pod,involvedObject.name={pod},involvedObject.namespace={namespace}");
            let events = events_api
                .list(&ListParams::default().fields(&fields))
                .await
                .map(|l| {
                    let mut items = l.items;
                    items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
                    items.into_iter().map(event_to_info).collect()
                })
                .map_err(|e| format!("Failed to list events for pod '{pod}': {e}"));
            Some((pod, events))
        }
        None => None,
    };

    let routes_here = |b: Option<&k8s_openapi::api::networking::v1::IngressBackend>| {
        b.and_then(|b| b.service.as_ref()).is_some_and(|s| s.name == name)
    };
    Ok(ServiceDiagnostics {
        service,
        manifest,
        events: events
            .map(|l| {
                let mut items = l.items;
                items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
                items.into_iter().map(event_to_info).collect()
            })
            .map_err(|e| format!("Failed to list events for '{name}': {e}")),
        slices: slices.map(|l| l.items).map_err(|e| format!("Failed to list the EndpointSlices of '{name}': {e}")),
        pods,
        unready_pod_events,
        workloads,
        ingresses: ingresses
            .map(|l| {
                l.items
                    .into_iter()
                    .filter(|i| {
                        let spec = i.spec.as_ref();
                        routes_here(spec.and_then(|s| s.default_backend.as_ref()))
                            || spec
                                .and_then(|s| s.rules.as_ref())
                                .into_iter()
                                .flatten()
                                .flat_map(|r| r.http.iter().flat_map(|h| h.paths.iter()))
                                .any(|p| routes_here(Some(&p.backend)))
                    })
                    .collect()
            })
            .map_err(|e| format!("Failed to list Ingresses in '{namespace}': {e}")),
        control_plane,
    })
}

/// A volume's usage as the kubelet measures it, from its node's stats summary.
pub struct PvcUsage {
    pub node: String,
    pub used_bytes: Option<u64>,
    pub capacity_bytes: Option<u64>,
    pub inodes_used: Option<u64>,
    pub inodes: Option<u64>,
}

/// Whether the CSI driver that provisions a volume is installed.
pub struct PvcCsiDriver {
    pub name: String,
    /// A CSIDriver object exists for it.
    pub registered: bool,
    /// Nodes whose CSINode lists the driver, of all CSINodes.
    pub on_nodes: usize,
    pub nodes: usize,
}

/// Everything a PersistentVolumeClaim diagnosis reads.
///
/// Only the claim itself is required; each of the rest fails on its own and
/// the payload says so.
pub struct PvcDiagnostics {
    pub pvc: k8s_openapi::api::core::v1::PersistentVolumeClaim,
    pub manifest: String,
    pub events: Result<Vec<EventInfo>, String>,
    pub storage_classes: Result<Vec<k8s_openapi::api::storage::v1::StorageClass>, String>,
    /// The bound PersistentVolume and its events, when the claim names one.
    pub pv: Option<Result<k8s_openapi::api::core::v1::PersistentVolume, String>>,
    pub pv_events: Option<Result<Vec<EventInfo>, String>>,
    /// The provisioner's CSI driver; `None` when no provisioner is known.
    pub csi_driver: Option<Result<PvcCsiDriver, String>>,
    /// The pods in the namespace that mount the claim.
    pub pods: Result<Vec<Pod>, String>,
    /// The events of the pods that mount it and are not ready: where a
    /// failed attach or mount is reported, and nowhere on the claim.
    pub pod_events: Vec<(String, Result<Vec<EventInfo>, String>)>,
    /// The VolumeAttachments of its volume: which node has it, and why an
    /// attach or detach failed.
    pub attachments: Result<Vec<k8s_openapi::api::storage::v1::VolumeAttachment>, String>,
    /// Per node a running pod mounts it on: the volume's usage.
    pub usage: Vec<Result<Option<PvcUsage>, String>>,
}

/// How many not-ready pods' events go into a PVC diagnosis.
const PVC_DIAG_POD_EVENTS: usize = 3;

/// Whether a pod mounts this claim, directly or through an ephemeral volume
/// (whose claim is named `<pod>-<volume>`).
pub(crate) fn pod_mounts_claim(pod: &Pod, claim: &str) -> bool {
    let pod_name = pod.metadata.name.as_deref().unwrap_or_default();
    pod.spec.iter().flat_map(|s| s.volumes.iter().flatten()).any(|v| {
        v.persistent_volume_claim.as_ref().is_some_and(|c| c.claim_name == claim) || (v.ephemeral.is_some() && format!("{pod_name}-{}", v.name) == claim)
    })
}

/// One claim's usage in a node's stats summary.
pub(crate) fn pvc_usage_from_summary(summary: &serde_json::Value, node: &str, namespace: &str, claim: &str) -> Option<PvcUsage> {
    let volumes = summary.get("pods").and_then(|p| p.as_array()).into_iter().flatten().flat_map(|p| p.get("volume").and_then(|v| v.as_array()).into_iter().flatten());
    let n = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_u64());
    volumes
        .filter(|v| {
            v.pointer("/pvcRef/name").and_then(|x| x.as_str()) == Some(claim) && v.pointer("/pvcRef/namespace").and_then(|x| x.as_str()) == Some(namespace)
        })
        .map(|v| PvcUsage {
            node: node.to_string(),
            used_bytes: n(v, "usedBytes"),
            capacity_bytes: n(v, "capacityBytes"),
            inodes_used: n(v, "inodesUsed"),
            inodes: n(v, "inodes"),
        })
        .next()
}

pub async fn get_pvc_diagnostics(context_name: &str, namespace: &str, name: &str) -> Result<PvcDiagnostics, String> {
    use k8s_openapi::api::core::v1::{PersistentVolume, PersistentVolumeClaim};
    use k8s_openapi::api::storage::v1::{CSIDriver, CSINode, StorageClass, VolumeAttachment};

    let client = client_for_context(context_name).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ApiResource::erase::<PersistentVolumeClaim>(&()));
    let mut obj = api.get(name).await.map_err(|e| get_error("PersistentVolumeClaim", name, e))?;
    let pvc: PersistentVolumeClaim = serde_json::to_value(&obj)
        .and_then(serde_json::from_value)
        .map_err(|e| format!("Failed to read PersistentVolumeClaim '{name}': {e}"))?;
    if let Some(a) = obj.metadata.annotations.as_mut() {
        a.remove(LAST_APPLIED_ANNOTATION);
    }
    let manifest = object_manifest(obj)?.yaml_without_managed_fields;
    let volume_name = pvc.spec.as_ref().and_then(|s| s.volume_name.clone()).filter(|v| !v.is_empty());

    let event_params = ListParams::default().fields(&format!(
        "involvedObject.kind=PersistentVolumeClaim,involvedObject.name={name},involvedObject.namespace={namespace}"
    ));
    let events_api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let classes_api: Api<StorageClass> = Api::all(client.clone());
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let attachments_api: Api<VolumeAttachment> = Api::all(client.clone());
    let all = ListParams::default();
    let sorted_events = |l: Result<ObjectList<Event>, kube::Error>, what: &str| {
        l.map(|l| {
            let mut items = l.items;
            items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
            items.into_iter().map(event_to_info).collect::<Vec<_>>()
        })
        .map_err(|e| format!("Failed to list events for {what}: {e}"))
    };

    let pv_fut = async {
        let Some(pv) = &volume_name else { return (None, None) };
        let api: Api<PersistentVolume> = Api::all(client.clone());
        let pv_events: Api<Event> = Api::all(client.clone());
        let params = ListParams::default().fields(&format!("involvedObject.kind=PersistentVolume,involvedObject.name={pv}"));
        let (got, events) = tokio::join!(api.get(pv), pv_events.list(&params));
        (Some(got.map_err(|e| get_error("PersistentVolume", pv, e))), Some(sorted_events(events, &format!("PersistentVolume '{pv}'"))))
    };

    let (events, classes, pods, attachments, (pv, pv_events)) =
        tokio::join!(events_api.list(&event_params), classes_api.list(&all), pods_api.list(&all), attachments_api.list(&all), pv_fut);
    let storage_classes = classes.map(|l| l.items).map_err(|e| format!("Failed to list StorageClasses: {e}"));
    let pods: Result<Vec<Pod>, String> = pods
        .map(|l| l.items.into_iter().filter(|p| pod_mounts_claim(p, name)).collect())
        .map_err(|e| format!("Failed to list pods in '{namespace}': {e}"));
    let attachments = attachments
        .map(|l| {
            l.items
                .into_iter()
                .filter(|a| volume_name.is_some() && a.spec.source.persistent_volume_name == volume_name)
                .collect()
        })
        .map_err(|e| format!("Failed to list VolumeAttachments: {e}"));

    // The provisioner, from wherever it is written: the bound volume's CSI
    // driver, the claim's own annotation, or its class.
    let class_name = pvc.spec.as_ref().and_then(|s| s.storage_class_name.clone());
    let provisioner = pv
        .as_ref()
        .and_then(|p| p.as_ref().ok())
        .and_then(|p| p.spec.as_ref())
        .and_then(|s| s.csi.as_ref())
        .map(|c| c.driver.clone())
        .or_else(|| {
            pvc.metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("volume.kubernetes.io/storage-provisioner").or_else(|| a.get("volume.beta.kubernetes.io/storage-provisioner")))
                .cloned()
        })
        .or_else(|| {
            storage_classes
                .as_ref()
                .ok()
                .and_then(|cs| cs.iter().find(|c| class_name.is_some() && c.metadata.name == class_name))
                .map(|c| c.provisioner.clone())
        })
        .filter(|p| !p.is_empty());
    let csi_fut = async {
        let driver = provisioner.clone()?;
        let drivers: Api<CSIDriver> = Api::all(client.clone());
        let nodes: Api<CSINode> = Api::all(client.clone());
        let (registered, csi_nodes) = tokio::join!(drivers.get_opt(&driver), nodes.list(&all));
        Some((|| {
            let registered = registered.map_err(|e| format!("Failed to read CSIDriver '{driver}': {e}"))?.is_some();
            let csi_nodes = csi_nodes.map_err(|e| format!("Failed to list CSINodes: {e}"))?.items;
            let on_nodes = csi_nodes.iter().filter(|n| n.spec.drivers.iter().any(|d| d.name == driver)).count();
            Ok(PvcCsiDriver { name: driver.clone(), registered, on_nodes, nodes: csi_nodes.len() })
        })())
    };

    // The events of pods that mount it and are not ready.
    let unready: Vec<String> = pods
        .iter()
        .flatten()
        .filter(|p| !p.status.as_ref().and_then(|s| s.conditions.as_ref()).is_some_and(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True")))
        .filter(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) != Some("Succeeded"))
        .take(PVC_DIAG_POD_EVENTS)
        .map(|p| p.name_any())
        .collect();
    let pod_events_fut = futures::future::join_all(unready.iter().map(|pod| {
        let events_api = events_api.clone();
        async move {
            let params = ListParams::default().fields(&format!("involvedObject.kind=Pod,involvedObject.name={pod},involvedObject.namespace={namespace}"));
            (pod.clone(), sorted_events(events_api.list(&params).await, &format!("pod '{pod}'")))
        }
    }));

    // Usage, from the kubelet of each node a running pod mounts it on.
    let mut nodes: Vec<String> = pods
        .iter()
        .flatten()
        .filter(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running"))
        .filter_map(|p| p.spec.as_ref().and_then(|s| s.node_name.clone()))
        .collect();
    nodes.sort();
    nodes.dedup();
    let usage_fut = futures::future::join_all(nodes.iter().map(|node| {
        let client = client.clone();
        async move {
            let req = http::Request::builder()
                .uri(format!("/api/v1/nodes/{node}/proxy/stats/summary"))
                .body(Vec::new())
                .map_err(|e| e.to_string())?;
            let summary: serde_json::Value = tokio::time::timeout(METRICS_REQUEST_TIMEOUT, client.request(req))
                .await
                .map_err(|_| format!("the kubelet on {node} did not answer in time"))?
                .map_err(|e| format!("Failed to read the kubelet's stats on {node}: {e}"))?;
            Ok(pvc_usage_from_summary(&summary, node, namespace, name))
        }
    }));

    let (csi_driver, pod_events, usage) = tokio::join!(csi_fut, pod_events_fut, usage_fut);

    Ok(PvcDiagnostics {
        pvc,
        manifest,
        events: sorted_events(events, &format!("'{name}'")),
        storage_classes,
        pv,
        pv_events,
        csi_driver,
        pods,
        pod_events,
        attachments,
        usage,
    })
}

/// Everything a StatefulSet diagnosis reads beyond what every workload's
/// does: its pods by ordinal, the nodes they sit on, the claims its volume
/// templates make, its governing Service and the budgets over its pods.
///
/// Only the StatefulSet itself is required; each of the rest fails on its own
/// and the payload says so.
pub struct StatefulSetDiagnostics {
    pub sts: StatefulSet,
    /// The pods it controls, by owner rather than by selector.
    pub pods: Result<Vec<Pod>, String>,
    /// The readiness of the node under each pod that is not ready or is
    /// terminating: `None` when the node no longer exists.
    pub nodes: Vec<(String, Result<Option<bool>, String>)>,
    /// The claims named `<template>-<statefulset>-<ordinal>`.
    pub claims: Result<Vec<k8s_openapi::api::core::v1::PersistentVolumeClaim>, String>,
    /// The events of its Pending claims, where provisioning failures are said.
    pub claim_events: Vec<(String, Result<Vec<EventInfo>, String>)>,
    /// Its governing Service; `None` when `serviceName` is empty.
    pub service: Option<Result<Option<k8s_openapi::api::core::v1::Service>, String>>,
    /// The PodDisruptionBudgets over its pods, each with the pods it covers;
    /// `None` when no pod could be read and it was matched against the pod
    /// template instead.
    pub pdbs: Result<Vec<(k8s_openapi::api::policy::v1::PodDisruptionBudget, Option<Vec<String>>)>, String>,
}

/// How many Pending claims' events go into a StatefulSet diagnosis.
const STS_DIAG_CLAIM_EVENTS: usize = 3;

/// Whether a label selector selects these labels. An empty selector selects
/// everything, as a PodDisruptionBudget's does.
pub(crate) fn label_selector_matches(sel: &LabelSelector, labels: Option<&std::collections::BTreeMap<String, String>>) -> bool {
    let get = |k: &str| labels.and_then(|l| l.get(k));
    sel.match_labels.iter().flatten().all(|(k, v)| get(k) == Some(v))
        && sel.match_expressions.iter().flatten().all(|e| {
            let values = e.values.clone().unwrap_or_default();
            match e.operator.as_str() {
                "In" => get(&e.key).is_some_and(|v| values.contains(v)),
                "NotIn" => get(&e.key).is_none_or(|v| !values.contains(v)),
                "Exists" => get(&e.key).is_some(),
                "DoesNotExist" => get(&e.key).is_none(),
                _ => false,
            }
        })
}

/// The ordinal in a StatefulSet pod's or claim's name: the number after
/// `<prefix>-`.
pub(crate) fn sts_ordinal(name: &str, prefix: &str) -> Option<i32> {
    name.strip_prefix(prefix)?.strip_prefix('-').filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))?.parse().ok()
}

pub async fn get_statefulset_diagnostics(context_name: &str, namespace: &str, name: &str) -> Result<StatefulSetDiagnostics, String> {
    use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Service};
    use k8s_openapi::api::policy::v1::PodDisruptionBudget;

    let client = client_for_context(context_name).await?;
    let sts = Api::<StatefulSet>::namespaced(client.clone(), namespace).get(name).await.map_err(|e| get_error("StatefulSet", name, e))?;
    let spec = sts.spec.clone().unwrap_or_default();
    let templates: Vec<String> = spec.volume_claim_templates.iter().flatten().filter_map(|t| t.metadata.name.clone()).collect();

    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let claims_api: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), namespace);
    let pdbs_api: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), namespace);
    let services_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    let events_api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let pod_params = ListParams::default().labels(&label_selector_query(&spec.selector));
    let all = ListParams::default();
    let service_fut = async {
        if spec.service_name.is_empty() {
            None
        } else {
            Some(services_api.get_opt(&spec.service_name).await.map_err(|e| format!("Failed to get Service '{}': {e}", spec.service_name)))
        }
    };
    let claims_fut = async {
        // Only when there are templates: a list of every claim in the
        // namespace is wasted on a StatefulSet that makes none.
        if templates.is_empty() {
            Ok(Vec::new())
        } else {
            claims_api.list(&all).await.map(|l| l.items)
        }
    };
    let (pods, claims, pdbs, service) = tokio::join!(pods_api.list(&pod_params), claims_fut, pdbs_api.list(&all), service_fut);

    let pods: Result<Vec<Pod>, String> = pods
        .map(|l| l.items.into_iter().filter(|p| controlled_by(&p.metadata.owner_references, "StatefulSet", name, sts.metadata.uid.as_deref())).collect())
        .map_err(|e| format!("Failed to list pods in '{namespace}': {e}"));
    let claims: Result<Vec<PersistentVolumeClaim>, String> = claims
        .map(|items| {
            items
                .into_iter()
                .filter(|c| {
                    let claim = c.metadata.name.as_deref().unwrap_or_default();
                    templates.iter().any(|t| sts_ordinal(claim, &format!("{t}-{name}")).is_some())
                })
                .collect()
        })
        .map_err(|e| format!("Failed to list PersistentVolumeClaims in '{namespace}': {e}"));
    // Budgets are matched against the pods' own labels, which carry those the
    // controller adds (pod-name, pod-index) and the template lacks; against
    // the template only when there is no pod to read.
    let template_labels = spec.template.metadata.as_ref().and_then(|m| m.labels.as_ref());
    let live = pods.as_ref().ok().filter(|p| !p.is_empty());
    let pdbs = pdbs
        .map(|l| {
            l.items
                .into_iter()
                .filter_map(|b| {
                    // A budget with no selector selects no pods.
                    let sel = b.spec.as_ref()?.selector.as_ref()?;
                    match live {
                        Some(pods) => {
                            let covered: Vec<String> = pods
                                .iter()
                                .filter(|p| label_selector_matches(sel, p.metadata.labels.as_ref()))
                                .filter_map(|p| p.metadata.name.clone())
                                .collect();
                            (!covered.is_empty()).then_some((b, Some(covered)))
                        }
                        None => label_selector_matches(sel, template_labels).then_some((b, None)),
                    }
                })
                .collect()
        })
        .map_err(|e| format!("Failed to list PodDisruptionBudgets in '{namespace}': {e}"));

    // The nodes under pods that are stuck: a pod on a node that has gone away
    // or stopped reporting is never replaced on its own.
    let mut node_names: Vec<String> = pods
        .iter()
        .flatten()
        .filter(|p| p.metadata.deletion_timestamp.is_some() || !pod_ready_condition(p))
        .filter_map(|p| p.spec.as_ref().and_then(|s| s.node_name.clone()))
        .collect();
    node_names.sort();
    node_names.dedup();
    let nodes_api: Api<Node> = Api::all(client.clone());
    let nodes_fut = futures::future::join_all(node_names.into_iter().map(|node| {
        let nodes_api = nodes_api.clone();
        async move {
            let ready = nodes_api.get_opt(&node).await.map(|n| n.as_ref().map(node_is_ready)).map_err(|e| format!("Failed to get node '{node}': {e}"));
            (node, ready)
        }
    }));
    let pending: Vec<String> = claims
        .iter()
        .flatten()
        .filter(|c| c.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Pending"))
        .take(STS_DIAG_CLAIM_EVENTS)
        .filter_map(|c| c.metadata.name.clone())
        .collect();
    let claim_events_fut = futures::future::join_all(pending.into_iter().map(|claim| {
        let events_api = events_api.clone();
        async move {
            let params = ListParams::default().fields(&format!(
                "involvedObject.kind=PersistentVolumeClaim,involvedObject.name={claim},involvedObject.namespace={namespace}"
            ));
            let events = events_api
                .list(&params)
                .await
                .map(|l| {
                    let mut items = l.items;
                    items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
                    items.into_iter().map(event_to_info).collect()
                })
                .map_err(|e| format!("Failed to list events for claim '{claim}': {e}"));
            (claim, events)
        }
    }));
    let (nodes, claim_events) = tokio::join!(nodes_fut, claim_events_fut);

    Ok(StatefulSetDiagnostics { sts, pods, nodes, claims, claim_events, service, pdbs })
}

/// Whether a pod's Ready condition is True.
fn pod_ready_condition(p: &Pod) -> bool {
    p.status.as_ref().and_then(|s| s.conditions.as_ref()).is_some_and(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
}

/// What a DaemonSet diagnosis reads beyond the generic workload view.
pub struct DaemonSetDiagnostics {
    pub ds: DaemonSet,
    /// The pods it controls, by owner rather than by selector.
    pub pods: Result<Vec<Pod>, String>,
    /// Every node: which of them should run its pod is worked out from these.
    pub nodes: Result<Vec<Node>, String>,
    /// The hash of its newest ControllerRevision, which pods on the current
    /// template carry as `controller-revision-hash`.
    pub latest_revision: Result<Option<String>, String>,
}

/// The tolerations the DaemonSet controller adds to every pod it makes, so
/// that its pods stay through node conditions that evict everything else.
fn daemon_default_tolerations(host_network: bool) -> Vec<k8s_openapi::api::core::v1::Toleration> {
    let mut taints = vec![
        ("node.kubernetes.io/not-ready", "NoExecute"),
        ("node.kubernetes.io/unreachable", "NoExecute"),
        ("node.kubernetes.io/disk-pressure", "NoSchedule"),
        ("node.kubernetes.io/memory-pressure", "NoSchedule"),
        ("node.kubernetes.io/pid-pressure", "NoSchedule"),
        ("node.kubernetes.io/unschedulable", "NoSchedule"),
    ];
    if host_network {
        taints.push(("node.kubernetes.io/network-unavailable", "NoSchedule"));
    }
    taints
        .into_iter()
        .map(|(key, effect)| k8s_openapi::api::core::v1::Toleration {
            key: Some(key.into()),
            operator: Some("Exists".into()),
            effect: Some(effect.into()),
            ..Default::default()
        })
        .collect()
}

/// Whether a toleration tolerates a taint, as the scheduler decides it.
pub(crate) fn tolerates(t: &k8s_openapi::api::core::v1::Toleration, taint: &k8s_openapi::api::core::v1::Taint) -> bool {
    if t.effect.as_deref().is_some_and(|e| !e.is_empty() && e != taint.effect) {
        return false;
    }
    match t.operator.as_deref().unwrap_or("Equal") {
        "Exists" => t.key.as_deref().is_none_or(|k| k.is_empty() || k == taint.key),
        _ => t.key.as_deref() == Some(taint.key.as_str()) && t.value.as_deref().unwrap_or("") == taint.value.as_deref().unwrap_or(""),
    }
}

/// Whether a node selector requirement holds for a value (a label's, or the
/// node's name for `matchFields`).
fn node_requirement_met(r: &k8s_openapi::api::core::v1::NodeSelectorRequirement, value: Option<&str>) -> bool {
    let values = r.values.as_deref().unwrap_or_default();
    match r.operator.as_str() {
        "In" => value.is_some_and(|v| values.iter().any(|x| x == v)),
        "NotIn" => value.is_none_or(|v| !values.iter().any(|x| x == v)),
        "Exists" => value.is_some(),
        "DoesNotExist" => value.is_none(),
        op @ ("Gt" | "Lt") => match (value.and_then(|v| v.parse::<i64>().ok()), values.first().and_then(|x| x.parse::<i64>().ok())) {
            (Some(v), Some(x)) => if op == "Gt" { v > x } else { v < x },
            _ => false,
        },
        _ => false,
    }
}

/// Whether a node selector term selects a node. An empty term selects none.
pub(crate) fn node_term_matches(term: &k8s_openapi::api::core::v1::NodeSelectorTerm, node: &Node) -> bool {
    let exprs = term.match_expressions.as_deref().unwrap_or_default();
    let fields = term.match_fields.as_deref().unwrap_or_default();
    let labels = node.metadata.labels.as_ref();
    (!exprs.is_empty() || !fields.is_empty())
        && exprs.iter().all(|r| node_requirement_met(r, labels.and_then(|l| l.get(&r.key)).map(String::as_str)))
        && fields.iter().all(|r| r.key == "metadata.name" && node_requirement_met(r, node.metadata.name.as_deref()))
}

/// Why a DaemonSet's pod does not belong on a node, or `None` when it does,
/// as the controller decides it. With `scheduling`, a NoSchedule taint counts
/// too: it keeps a new pod off the node, but does not remove one running.
pub(crate) fn daemon_pod_misfit(spec: &k8s_openapi::api::core::v1::PodSpec, node: &Node, scheduling: bool) -> Option<String> {
    let node_name = node.metadata.name.as_deref().unwrap_or_default();
    if let Some(n) = spec.node_name.as_deref().filter(|n| !n.is_empty() && *n != node_name) {
        return Some(format!("the template's nodeName is {n}"));
    }
    let labels = node.metadata.labels.as_ref();
    if let Some((k, v)) = spec.node_selector.iter().flatten().find(|(k, v)| labels.and_then(|l| l.get(*k)) != Some(*v)) {
        return Some(format!("nodeSelector {k}={v} not matched"));
    }
    let required = spec.affinity.as_ref().and_then(|a| a.node_affinity.as_ref()).and_then(|a| a.required_during_scheduling_ignored_during_execution.as_ref());
    if required.is_some_and(|r| !r.node_selector_terms.iter().any(|t| node_term_matches(t, node))) {
        return Some("required node affinity not matched".to_string());
    }
    let tolerations: Vec<_> =
        spec.tolerations.iter().flatten().cloned().chain(daemon_default_tolerations(spec.host_network == Some(true))).collect();
    node.spec
        .as_ref()
        .and_then(|s| s.taints.as_ref())
        .into_iter()
        .flatten()
        .filter(|t| t.effect == "NoExecute" || (scheduling && t.effect == "NoSchedule"))
        .find(|t| !tolerations.iter().any(|tol| tolerates(tol, t)))
        .map(|t| format!("taint {}{}:{} not tolerated", t.key, t.value.as_deref().filter(|v| !v.is_empty()).map(|v| format!("={v}")).unwrap_or_default(), t.effect))
}

/// The node a DaemonSet pod is for: where it runs, or, while it is Pending,
/// the node its controller-set affinity names.
pub(crate) fn daemon_pod_node(p: &Pod) -> Option<String> {
    let spec = p.spec.as_ref()?;
    spec.node_name.clone().filter(|n| !n.is_empty()).or_else(|| {
        spec.affinity
            .as_ref()?
            .node_affinity
            .as_ref()?
            .required_during_scheduling_ignored_during_execution
            .as_ref()?
            .node_selector_terms
            .iter()
            .flat_map(|t| t.match_fields.iter().flatten())
            .find(|r| r.key == "metadata.name" && r.operator == "In")
            .and_then(|r| r.values.as_ref()?.first().cloned())
    })
}

pub async fn get_daemonset_diagnostics(context_name: &str, namespace: &str, name: &str) -> Result<DaemonSetDiagnostics, String> {
    let client = client_for_context(context_name).await?;
    let ds = Api::<DaemonSet>::namespaced(client.clone(), namespace).get(name).await.map_err(|e| get_error("DaemonSet", name, e))?;
    let spec = ds.spec.clone().unwrap_or_default();
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let nodes_api: Api<Node> = Api::all(client.clone());
    let revisions_api: Api<ControllerRevision> = Api::namespaced(client.clone(), namespace);
    // Its ControllerRevisions carry its template's labels, so its selector
    // finds them as it finds its pods.
    let params = ListParams::default().labels(&label_selector_query(&spec.selector));
    let all = ListParams::default();
    let (pods, nodes, revisions) = tokio::join!(pods_api.list(&params), nodes_api.list(&all), revisions_api.list(&params));

    let owned = |refs: &Option<Vec<OwnerReference>>| controlled_by(refs, "DaemonSet", name, ds.metadata.uid.as_deref());
    let pods = pods
        .map(|l| l.items.into_iter().filter(|p| owned(&p.metadata.owner_references)).collect())
        .map_err(|e| format!("Failed to list pods in '{namespace}': {e}"));
    let nodes = nodes.map(|l| l.items).map_err(|e| format!("Failed to list nodes: {e}"));
    let latest_revision = revisions
        .map(|l| {
            l.items.into_iter().filter(|r| owned(&r.metadata.owner_references)).max_by_key(|r| r.revision).and_then(|r| {
                r.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("controller-revision-hash").cloned())
                    .or_else(|| r.metadata.name.as_deref()?.strip_prefix(&format!("{name}-")).map(str::to_string))
            })
        })
        .map_err(|e| format!("Failed to list ControllerRevisions in '{namespace}': {e}"));

    Ok(DaemonSetDiagnostics { ds, pods, nodes, latest_revision })
}

/// A Service an Ingress routes to, as the diagnosis read it.
pub struct IngressBackend {
    pub name: String,
    pub service: Result<k8s_openapi::api::core::v1::Service, String>,
    /// Its EndpointSlices, kept whole: readiness is per Service port, and a
    /// multi-port Service can have endpoints for one port and none for another.
    pub slices: Result<Vec<k8s_openapi::api::discovery::v1::EndpointSlice>, String>,
}

/// What an Ingress's TLS Secret holds, read without its values: its type, its
/// key names, and the public fields of the certificate in `tls.crt`.
pub struct IngressTlsSecret {
    pub secret_type: String,
    pub keys: Vec<String>,
    pub leaf: Option<crate::x509::CertificateInfo>,
}

/// A Deployment or DaemonSet that looks like the Ingress's controller.
pub struct IngressControllerWorkload {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub desired: i32,
    pub ready: i32,
    /// Why it was taken for the controller: a class flag in its args names
    /// the class or the controller, or — when nothing does — only its name
    /// says ingress.
    pub matched_by: String,
    /// Its pod selector as a label-selector query, expressions included.
    pub selector: String,
    /// The container whose args matched, whose log is the controller's.
    pub container: String,
}

/// Everything an Ingress diagnosis reads.
///
/// Only the Ingress itself is required; each of the rest fails on its own and
/// the payload says so.
pub struct IngressDiagnostics {
    pub ingress: k8s_openapi::api::networking::v1::Ingress,
    pub manifest: String,
    pub events: Result<Vec<EventInfo>, String>,
    /// Every IngressClass, to tell a named class from a missing one and to
    /// find the default when none is named.
    pub classes: Result<Vec<k8s_openapi::api::networking::v1::IngressClass>, String>,
    pub backends: Vec<IngressBackend>,
    /// Per TLS entry's Secret, in the order the spec names them.
    pub tls: Vec<(String, Result<IngressTlsSecret, String>)>,
    /// cert-manager's Certificates for those Secrets; `None` when cert-manager
    /// is not installed.
    pub certificates: Option<Result<Vec<DynamicObject>, String>>,
    /// Other Ingresses, anywhere in the cluster, with a host this one has.
    pub same_host: Result<Vec<k8s_openapi::api::networking::v1::Ingress>, String>,
    pub controllers: Result<Vec<IngressControllerWorkload>, String>,
    /// How many controller pods were read, and their log lines about this
    /// Ingress, its Services and its Secrets. `None` when no workload was
    /// found by its args to be the controller, so there is no log to read.
    pub controller_logs: Option<Result<(usize, Vec<String>), String>>,
}

/// How far back into the ingress controller's log to look, and how much of
/// it to read: the same hour as KEDA's operator, for the same reason — a
/// reload error is logged once, among a great many lines about everything else.
const INGRESS_CONTROLLER_LOG_SECONDS: i64 = 3600;
const INGRESS_CONTROLLER_LOG_BYTES: i64 = 8 * 1024 * 1024;

/// The class an Ingress names: `ingressClassName`, or the older annotation.
pub(crate) fn ingress_class_of(ing: &k8s_openapi::api::networking::v1::Ingress) -> Option<String> {
    ing.spec
        .as_ref()
        .and_then(|s| s.ingress_class_name.clone())
        .or_else(|| ing.metadata.annotations.as_ref().and_then(|a| a.get("kubernetes.io/ingress.class").cloned()))
        .filter(|c| !c.is_empty())
}

/// The class an Ingress names, and whether it names it through the legacy
/// annotation — which, unlike `ingressClassName`, needs no IngressClass
/// object: a controller started with `--ingress-class=X` claims it either way.
pub(crate) fn ingress_class_ref(ing: &k8s_openapi::api::networking::v1::Ingress) -> Option<(String, bool)> {
    match ing.spec.as_ref().and_then(|s| s.ingress_class_name.clone()).filter(|c| !c.is_empty()) {
        Some(c) => Some((c, false)),
        None => ing
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("kubernetes.io/ingress.class").cloned())
            .filter(|c| !c.is_empty())
            .map(|c| (c, true)),
    }
}

/// A label selector as the API's query syntax: `k=v`, `k in (a,b)`,
/// `k notin (a,b)`, `k`, `!k`.
pub(crate) fn label_selector_query(sel: &LabelSelector) -> String {
    let mut terms: Vec<String> = sel.match_labels.iter().flatten().map(|(k, v)| format!("{k}={v}")).collect();
    for e in sel.match_expressions.iter().flatten() {
        let values = e.values.clone().unwrap_or_default().join(",");
        terms.push(match e.operator.as_str() {
            "In" => format!("{} in ({values})", e.key),
            "NotIn" => format!("{} notin ({values})", e.key),
            "Exists" => e.key.clone(),
            "DoesNotExist" => format!("!{}", e.key),
            op => format!("{} {op} ({values})", e.key),
        });
    }
    terms.join(",")
}

/// Whether a container's flags make it the controller for this class.
///
/// Only a flag whose name says `class` counts — ingress-nginx's
/// `--ingress-class` and `--controller-class`, Traefik's
/// `--providers.kubernetesingress.ingressclass`, Contour's
/// `--ingress-class-name` — and only when its value is the class or the
/// controller string. A bare matching word, such as an `nginx` command, is
/// not a flag. With no class, it is the flag ingress-nginx uses to claim
/// class-less Ingresses.
pub(crate) fn controller_flags_match(args: &[String], class: Option<&str>, controller: Option<&str>) -> bool {
    let mut flags: Vec<(String, Option<String>)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(flag) = args[i].strip_prefix("--").or_else(|| args[i].strip_prefix('-')) {
            match flag.split_once('=') {
                Some((k, v)) => flags.push((k.to_ascii_lowercase(), Some(v.to_string()))),
                None => {
                    let value = args.get(i + 1).filter(|v| !v.starts_with('-')).cloned();
                    if value.is_some() {
                        i += 1;
                    }
                    flags.push((flag.to_ascii_lowercase(), value));
                }
            }
        }
        i += 1;
    }
    flags.iter().any(|(k, v)| match class {
        Some(class) => k.contains("class") && v.as_deref().is_some_and(|v| v == class || controller == Some(v)),
        None => k == "watch-ingress-without-class" && v.as_deref().is_none_or(|v| v == "true"),
    })
}

/// Every Service an Ingress routes to: its rules' backends and its default.
pub(crate) fn ingress_backend_services(ing: &k8s_openapi::api::networking::v1::Ingress) -> Vec<String> {
    let spec = ing.spec.as_ref();
    let mut names: Vec<String> = spec
        .and_then(|s| s.default_backend.as_ref())
        .into_iter()
        .chain(spec.and_then(|s| s.rules.as_ref()).into_iter().flatten().flat_map(|r| r.http.iter().flat_map(|h| h.paths.iter().map(|p| &p.backend))))
        .filter_map(|b| b.service.as_ref().map(|s| s.name.clone()))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Whether one ingress controller log line is about these objects.
///
/// Controllers name what they are complaining about as `namespace/name` —
/// ingress-nginx's `Service "ns/api" does not have any active Endpoint` — or
/// as separate fields, as Traefik's `namespace=ns ingress=web` does. Access
/// log lines are skipped: they carry client addresses and request paths, and
/// say nothing a diagnosis needs that the controller's own errors do not.
pub(crate) fn ingress_log_line_is_about(line: &str, namespace: &str, names: &[String]) -> bool {
    if line.contains(" HTTP/1.") || line.contains(" HTTP/2") || line.contains("\"GET ") || line.contains("\"POST ") {
        return false;
    }
    // Whole names only: `ns/api` must not match `other-ns/api` or `ns/api-old`.
    let word = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_';
    let qualified = |n: &str| {
        let needle = format!("{namespace}/{n}");
        line.match_indices(&needle).any(|(at, _)| {
            let before = line[..at].chars().next_back();
            let after = line[at + needle.len()..].chars().next();
            !before.is_some_and(|c| word(c) || c == '/') && !after.is_some_and(|c| word(c) || c == '/')
        })
    };
    // As fields: the namespace in a field of its own, and the name as a whole token.
    let tokens: Vec<&str> = line.split(|c: char| !word(c)).collect();
    let in_namespace = [format!("namespace={namespace}"), format!("namespace=\"{namespace}\""), format!("\"namespace\":\"{namespace}\""), format!("\"namespace\": \"{namespace}\"")]
        .iter()
        .any(|f| line.match_indices(f.as_str()).any(|(at, _)| !line[at + f.len()..].chars().next().is_some_and(word)));
    names.iter().any(|n| qualified(n) || (in_namespace && tokens.contains(&n.as_str())))
}

pub async fn get_ingress_diagnostics(context_name: &str, namespace: &str, name: &str) -> Result<IngressDiagnostics, String> {
    use k8s_openapi::api::core::v1::{Secret, Service};
    use k8s_openapi::api::discovery::v1::EndpointSlice;
    use k8s_openapi::api::networking::v1::{Ingress, IngressClass};

    let client = client_for_context(context_name).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ApiResource::erase::<Ingress>(&()));
    let mut obj = api.get(name).await.map_err(|e| get_error("Ingress", name, e))?;
    let ingress: Ingress = serde_json::to_value(&obj)
        .and_then(serde_json::from_value)
        .map_err(|e| format!("Failed to read Ingress '{name}': {e}"))?;
    if let Some(a) = obj.metadata.annotations.as_mut() {
        a.remove(LAST_APPLIED_ANNOTATION);
    }
    let manifest = object_manifest(obj)?.yaml_without_managed_fields;
    let spec = ingress.spec.clone().unwrap_or_default();
    let backend_names = ingress_backend_services(&ingress);
    let tls_secrets: Vec<String> = spec.tls.iter().flatten().filter_map(|t| t.secret_name.clone()).filter(|s| !s.is_empty()).collect();
    let hosts: Vec<String> = spec.rules.iter().flatten().filter_map(|r| r.host.clone()).filter(|h| !h.is_empty()).collect();

    let event_fields = format!("involvedObject.kind=Ingress,involvedObject.name={name},involvedObject.namespace={namespace}");
    let events_api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let classes_api: Api<IngressClass> = Api::all(client.clone());
    let all_ingresses_api: Api<Ingress> = Api::all(client.clone());
    let deployments_api: Api<Deployment> = Api::all(client.clone());
    let daemonsets_api: Api<DaemonSet> = Api::all(client.clone());
    let event_params = ListParams::default().fields(&event_fields);
    let all = ListParams::default();

    let backends_fut = futures::future::join_all(backend_names.iter().map(|svc| {
        let client = client.clone();
        async move {
            let services: Api<Service> = Api::namespaced(client.clone(), namespace);
            let slices: Api<EndpointSlice> = Api::namespaced(client, namespace);
            let params = ListParams::default().labels(&format!("kubernetes.io/service-name={svc}"));
            let (service, slices) = tokio::join!(services.get(svc), slices.list(&params));
            IngressBackend {
                name: svc.clone(),
                service: service.map_err(|e| get_error("Service", svc, e)),
                slices: slices.map(|l| l.items).map_err(|e| format!("Failed to list the EndpointSlices of '{svc}': {e}")),
            }
        }
    }));
    let tls_fut = futures::future::join_all(tls_secrets.iter().map(|secret| {
        let client = client.clone();
        async move {
            let api: Api<Secret> = Api::namespaced(client, namespace);
            // Keys and the certificate's public fields only: the values are
            // read here and dropped, and the private key is never parsed.
            let read = api
                .get(secret)
                .await
                .map(|s| IngressTlsSecret {
                    secret_type: s.type_.clone().unwrap_or_else(|| "Opaque".to_string()),
                    keys: s.data.iter().flatten().map(|(k, _)| k.clone()).collect(),
                    leaf: s
                        .data
                        .as_ref()
                        .and_then(|d| d.get("tls.crt"))
                        .and_then(|v| std::str::from_utf8(&v.0).ok())
                        .map(crate::x509::parse_pem_bundle)
                        .and_then(|all| crate::secrets::leaf_of(&all).cloned()),
                })
                .map_err(|e| get_error("Secret", secret, e));
            (secret.clone(), read)
        }
    }));
    let certificates_fut = async {
        if tls_secrets.is_empty() {
            return None;
        }
        // Not installed is an answer; any other discovery failure is a gap.
        let ar = match kube::discovery::group(&client, "cert-manager.io").await {
            Ok(g) => match g.recommended_kind("Certificate") {
                Some((ar, _)) => ar,
                None => return None,
            },
            Err(kube::Error::Discovery(_)) => return None,
            Err(kube::Error::Api(resp)) if resp.code == 404 => return None,
            Err(e) => return Some(Err(format!("Failed to discover cert-manager: {e}"))),
        };
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
        Some(
            api.list(&all)
                .await
                .map(|l| {
                    l.items
                        .into_iter()
                        .filter(|c| c.data.pointer("/spec/secretName").and_then(|v| v.as_str()).is_some_and(|s| tls_secrets.iter().any(|t| t == s)))
                        .collect()
                })
                .map_err(|e| format!("Failed to list Certificates in '{namespace}': {e}")),
        )
    };

    let (events, classes, backends, tls, certificates, all_ingresses, deployments, daemonsets) = tokio::join!(
        events_api.list(&event_params),
        classes_api.list(&all),
        backends_fut,
        tls_fut,
        certificates_fut,
        all_ingresses_api.list(&all),
        deployments_api.list(&all),
        daemonsets_api.list(&all),
    );
    let classes = classes.map(|l| l.items).map_err(|e| format!("Failed to list IngressClasses: {e}"));

    // The class it names, and nothing else: a default class is applied when
    // an Ingress is admitted, not afterwards, so one without a class is
    // claimed only by a controller set to watch class-less Ingresses.
    let class_name = ingress_class_of(&ingress);
    let controller = class_name.as_ref().and_then(|n| {
        classes.as_ref().ok().and_then(|cs| cs.iter().find(|c| c.metadata.name.as_ref() == Some(n))).and_then(|c| c.spec.as_ref()).and_then(|s| s.controller.clone())
    });

    // The controller, by the class flag its container's args carry.
    let workload = |kind: &str, meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta, template: &k8s_openapi::api::core::v1::PodTemplateSpec, selector: &LabelSelector, desired: i32, ready: i32| {
        let name = meta.name.clone().unwrap_or_default();
        let matching = template.spec.iter().flat_map(|s| s.containers.iter()).find(|c| {
            let args: Vec<String> = c.command.iter().flatten().chain(c.args.iter().flatten()).cloned().collect();
            controller_flags_match(&args, class_name.as_deref(), controller.as_deref())
        });
        let (matched_by, container) = match matching {
            Some(c) if class_name.is_some() => ("its args name this class or controller", c.name.clone()),
            Some(c) => ("its args watch class-less Ingresses", c.name.clone()),
            None if name.contains("ingress") => ("name only", String::new()),
            None => return None,
        };
        Some(IngressControllerWorkload {
            kind: kind.to_string(),
            namespace: meta.namespace.clone().unwrap_or_default(),
            name,
            desired,
            ready,
            matched_by: matched_by.to_string(),
            selector: label_selector_query(selector),
            container,
        })
    };
    let controllers = deployments
        .map_err(|e| format!("Failed to list Deployments: {e}"))
        .and_then(|d| daemonsets.map(|s| (d, s)).map_err(|e| format!("Failed to list DaemonSets: {e}")))
        .map(|(deployments, daemonsets)| {
            let mut found: Vec<IngressControllerWorkload> = deployments
                .items
                .iter()
                .filter_map(|d| {
                    let spec = d.spec.as_ref()?;
                    workload("Deployment", &d.metadata, &spec.template, &spec.selector, spec.replicas.unwrap_or(1), d.status.as_ref().and_then(|s| s.ready_replicas).unwrap_or(0))
                })
                .chain(daemonsets.items.iter().filter_map(|d| {
                    let spec = d.spec.as_ref()?;
                    let status = d.status.clone().unwrap_or_default();
                    workload("DaemonSet", &d.metadata, &spec.template, &spec.selector, status.desired_number_scheduled, status.number_ready)
                }))
                .collect();
            // By name only when nothing names the class: a cluster has many
            // workloads called something-ingress that serve other classes.
            if found.iter().any(|w| w.matched_by != "name only") {
                found.retain(|w| w.matched_by != "name only");
            }
            found
        });

    let mut about: Vec<String> = vec![name.to_string()];
    about.extend(backend_names.iter().cloned());
    about.extend(tls_secrets.iter().cloned());
    let named: Vec<&IngressControllerWorkload> =
        controllers.iter().flatten().filter(|w| w.matched_by != "name only" && !w.selector.is_empty()).collect();
    let controller_logs = if named.is_empty() {
        None
    } else {
        let mut lines = Vec::new();
        let mut failure = None;
        let mut read = 0;
        for w in named {
            let pods: Api<Pod> = Api::namespaced(client.clone(), &w.namespace);
            let list = match pods.list(&ListParams::default().labels(&w.selector)).await {
                Ok(l) => l.items,
                Err(e) => {
                    failure = Some(format!("Failed to list the pods of {}/{}: {e}", w.namespace, w.name));
                    continue;
                }
            };
            for p in list {
                // Its own container: a pod with an injected sidecar has
                // several, and a log request without one is refused.
                let params = LogParams {
                    container: Some(w.container.clone()),
                    since_seconds: Some(INGRESS_CONTROLLER_LOG_SECONDS),
                    limit_bytes: Some(INGRESS_CONTROLLER_LOG_BYTES),
                    ..Default::default()
                };
                match pods.logs(&p.name_any(), &params).await {
                    Ok(text) => {
                        read += 1;
                        lines.extend(text.lines().filter(|l| ingress_log_line_is_about(l, namespace, &about)).map(str::to_string));
                    }
                    Err(e) => failure = Some(format!("Failed to read the log of {}/{}: {e}", w.namespace, p.name_any())),
                }
            }
        }
        Some(match failure {
            Some(e) if lines.is_empty() => Err(e),
            _ => Ok((read, lines)),
        })
    };

    let same_host = all_ingresses
        .map(|l| {
            l.items
                .into_iter()
                .filter(|i| !(i.metadata.namespace.as_deref() == Some(namespace) && i.metadata.name.as_deref() == Some(name)))
                .filter(|i| i.spec.as_ref().and_then(|s| s.rules.as_ref()).into_iter().flatten().any(|r| r.host.as_ref().is_some_and(|h| hosts.contains(h))))
                .collect()
        })
        .map_err(|e| format!("Failed to list Ingresses: {e}"));

    Ok(IngressDiagnostics {
        ingress,
        manifest,
        events: events
            .map(|l| {
                let mut items = l.items;
                items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));
                items.into_iter().map(event_to_info).collect()
            })
            .map_err(|e| format!("Failed to list events for '{name}': {e}")),
        classes,
        backends,
        tls,
        certificates,
        same_host,
        controllers,
        controller_logs,
    })
}

/// Same reasoning as `get_workload_events` (filter by involved object before
/// the cluster-wide cap, and match the namespace since both KEDA kinds are
/// namespaced). KEDA's own events are the useful half of diagnosing a
/// misbehaving autoscaler — a trigger that cannot authenticate to its scaler
/// reports it here and nowhere in the object's status.
pub async fn get_keda_events(context_name: &str, namespace: &str, kind: &str, name: &str) -> Result<Vec<EventInfo>, String> {
    // Called for its validation, not its result: events are matched on the
    // involvedObject kind string rather than fetched from a collection, so the
    // plural is unused here. Without this an unexpected kind would filter
    // everything out and report a healthy "No events found", hiding the
    // caller bug that `get_keda_manifest` would have surfaced outright.
    keda_plural(kind)?;

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

pub async fn get_gitops_manifest(context_name: &str, namespace: &str, name: &str) -> Result<GitOpsAppManifest, String> {
    let client = client_for_context(context_name).await?;
    let ar = argocd_application_resource();
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &ar);
    let obj = api.get(name).await.map_err(|e| format!("Failed to get Application '{name}': {e}"))?;
    let detail = crate::gitops_detail::gitops_detail(&obj);
    let ObjectManifest { yaml_full, yaml_without_managed_fields } = object_manifest(obj)?;
    Ok(GitOpsAppManifest { yaml_full, yaml_without_managed_fields, detail })
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

// ---------------------------------------------------------------------------
// Drift diff for an Application's not-Synced resources
// ---------------------------------------------------------------------------
//
// Worth stating plainly what this computes, because it is *not* what
// `argocd app diff` computes. ArgoCD renders the manifests from Git and
// compares them against the live cluster, in its repo-server, caching the
// result in Redis. None of that reaches the `Application` resource:
// `status.resources[]` names each drifted resource and stops there. An app
// holding only a kubeconfig therefore cannot reproduce ArgoCD's answer.
//
// What a kubeconfig *can* read is each resource's `last-applied-configuration`
// annotation — the manifest most recently applied to it. Comparing that with
// the live object shows drift: what changed in the cluster since the last
// apply. That answers a real and different question ("who edited my cluster"),
// and it is the one implemented here. The UI labels it as such rather than
// letting it be mistaken for the Git diff.

/// The annotation holding the manifest most recently applied to a resource.
const LAST_APPLIED_ANNOTATION: &str = "kubectl.kubernetes.io/last-applied-configuration";

/// Metadata the server or a controller owns, which a manifest does not declare.
///
/// Removed from the live side *only when the desired manifest is silent about
/// it* — the same value-matched discipline the default suppressor below uses,
/// and for the same reason. `finalizers` and `ownerReferences` are the entries
/// that make the condition earn its keep: both are usually controller-written,
/// but both are legitimately declarable, and stripping them from one side
/// unconditionally would leave a permanent phantom deletion on every diff of a
/// manifest that does declare them.
const DIFF_STRIP_METADATA: &[&str] = &[
    "managedFields",
    "resourceVersion",
    "uid",
    "generation",
    "creationTimestamp",
    "deletionTimestamp",
    "selfLink",
    "ownerReferences",
    "finalizers",
];

/// Annotations that are pure controller bookkeeping. `last-applied` is handled
/// separately and unconditionally — it *is* the other side of the diff.
const DIFF_STRIP_ANNOTATIONS: &[&str] = &["deployment.kubernetes.io/revision"];

/// Pod-spec fields the API server defaults, as (field, default as JSON).
const POD_SPEC_DEFAULTS: &[(&str, &str)] = &[
    ("dnsPolicy", "\"ClusterFirst\""),
    ("schedulerName", "\"default-scheduler\""),
    ("terminationGracePeriodSeconds", "30"),
    ("securityContext", "{}"),
];

/// Per-container fields the API server defaults.
const CONTAINER_DEFAULTS: &[(&str, &str)] = &[
    ("terminationMessagePath", "\"/dev/termination-log\""),
    ("terminationMessagePolicy", "\"File\""),
];

/// Drops keys whose value is an explicit null, recursively.
///
/// Run on *both* sides. Helm charts routinely render an unset block as
/// `livenessProbe: null`, which the API server then drops entirely — so the
/// annotation keeps the null and the live object does not. In an apply, an
/// explicit null means "unset", so the two are the same statement and pruning
/// both is what makes them compare equal. Pruning one side would manufacture a
/// deletion on every single diff.
fn prune_explicit_nulls(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                prune_explicit_nulls(v);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items.iter_mut() {
                prune_explicit_nulls(v);
            }
        }
        _ => {}
    }
}

/// Renders quantity values as strings, recursively, on both sides.
///
/// Kubernetes' `Quantity` accepts `1` and `"1"` as the same value and the API
/// server always hands it back as a string, so a chart that writes a bare
/// number — `nvidia.com/gpu: 1` — diffs against a live `'1'` forever. Seen on
/// a real app the moment the view was pointed at a second one: four of its ten
/// changed lines were this and nothing else.
///
/// Scoped to `limits` and `requests` maps rather than stringifying every
/// number in the object, because outside those maps a number and a string are
/// genuinely different things — `replicas: 3` is not `replicas: "3"`, and
/// flattening that distinction would hide a real (if unlikely) change.
///
/// This equalises representation, not magnitude: `1024Mi` and `1Gi` are the
/// same quantity and would still diff. That needs Quantity's own parsing
/// rather than a string, and has not been seen in practice, so it is left
/// alone deliberately — but it is the next thing to suspect if a false
/// positive is reported here.
fn stringify_quantities(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if matches!(key.as_str(), "limits" | "requests") {
                    if let Some(quantities) = child.as_object_mut() {
                        for quantity in quantities.values_mut() {
                            // `is_number`, not `as_f64`: this is a type test, and
                            // routing it through a float would imply the value's
                            // magnitude mattered here. It does not — the rendering
                            // is `to_string`, which reproduces the number as
                            // written and cannot lose precision on a large one.
                            if quantity.is_number() {
                                let rendered = quantity.to_string();
                                *quantity = serde_json::Value::String(rendered);
                            }
                        }
                    }
                }
                stringify_quantities(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                stringify_quantities(item);
            }
        }
        _ => {}
    }
}

/// `serde_json` can read through a JSON pointer but not delete through one.
fn remove_at_pointer(root: &mut serde_json::Value, pointer: &str) {
    let Some((parent, key)) = pointer.rsplit_once('/') else { return };
    if let Some(serde_json::Value::Object(map)) = root.pointer_mut(parent) {
        map.remove(key);
    }
}

/// Drops `metadata.annotations`/`metadata.labels` once empty, on both sides, so
/// a map emptied by stripping does not diff as `annotations: {}` against a side
/// that never had one.
fn drop_empty_metadata_maps(value: &mut serde_json::Value) {
    let Some(meta) = value.pointer_mut("/metadata").and_then(|m| m.as_object_mut()) else { return };
    for key in ["annotations", "labels"] {
        if meta.get(key).and_then(|m| m.as_object()).is_some_and(|m| m.is_empty()) {
            meta.remove(key);
        }
    }
}

/// Removes server-owned bookkeeping from the live side, skipping anything the
/// desired manifest declares for itself.
fn strip_server_bookkeeping(live: &mut serde_json::Value, desired: &serde_json::Value) {
    if desired.get("status").is_none() {
        if let Some(map) = live.as_object_mut() {
            map.remove("status");
        }
    }

    let desired_meta = desired.get("metadata");
    let desired_annotations = desired_meta.and_then(|m| m.get("annotations"));
    let Some(meta) = live.pointer_mut("/metadata").and_then(|m| m.as_object_mut()) else { return };

    for key in DIFF_STRIP_METADATA {
        if desired_meta.and_then(|m| m.get(*key)).is_none() {
            meta.remove(*key);
        }
    }

    if let Some(annotations) = meta.get_mut("annotations").and_then(|a| a.as_object_mut()) {
        for key in DIFF_STRIP_ANNOTATIONS {
            if desired_annotations.and_then(|a| a.get(*key)).is_none() {
                annotations.remove(*key);
            }
        }
    }
}

/// Removes a field from the live side only when the desired manifest is silent
/// about it **and** the live value equals `default_json`.
///
/// The value match is the whole safety property, and it was measured rather
/// than assumed. Suppressing by key alone — "the manifest never mentions
/// `restartPolicy`, so hide it" — was tested against 15 injected drifts and hid
/// 7 of them, including `paused: true`, `runAsUser: 0`, and every case where a
/// defaulted field had been set to a *non*-default value. Matching the value
/// means the only fact this can ever hide is "the field still has its default",
/// which is the one fact nobody is looking for.
fn suppress_default(live: &mut serde_json::Value, desired: &serde_json::Value, pointer: &str, default_json: &str) {
    if desired.pointer(pointer).is_some() {
        return;
    }
    // The live lookup comes before parsing the default because most pointers
    // in the tables below are absent from any given resource — a Deployment
    // never has `/spec/clusterIP`, and every container pointer is walked per
    // index — so the cheap check should decide it.
    let Some(actual) = live.pointer(pointer) else { return };
    let Ok(expected) = serde_json::from_str::<serde_json::Value>(default_json) else { return };
    if *actual != expected {
        return;
    }
    remove_at_pointer(live, pointer);
}

/// Kind-level defaults. Empty for anything not listed, including every CRD.
fn kind_default_fields(kind: &str) -> &'static [(&'static str, &'static str)] {
    match kind {
        "Deployment" => &[("/spec/revisionHistoryLimit", "10"), ("/spec/progressDeadlineSeconds", "600")],
        "StatefulSet" | "DaemonSet" => &[("/spec/revisionHistoryLimit", "10")],
        "Service" => &[
            ("/spec/sessionAffinity", "\"None\""),
            ("/spec/internalTrafficPolicy", "\"Cluster\""),
            ("/spec/ipFamilyPolicy", "\"SingleStack\""),
        ],
        "CronJob" => &[
            ("/spec/concurrencyPolicy", "\"Allow\""),
            ("/spec/failedJobsHistoryLimit", "1"),
            ("/spec/successfulJobsHistoryLimit", "3"),
            ("/spec/suspend", "false"),
        ],
        _ => &[],
    }
}

/// Where a kind keeps its pod spec, if it has one.
///
/// Keyed per kind because the path genuinely moves: a CronJob's is nested one
/// Job template deeper. A table written for a Deployment and applied blindly to
/// a CronJob is worse than no table at all — nothing would match, so the
/// CronJob's own defaults would go unsuppressed while the code reported success.
fn pod_spec_pointer(kind: &str) -> Option<&'static str> {
    match kind {
        "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Job" => Some("/spec/template/spec"),
        "CronJob" => Some("/spec/jobTemplate/spec/template/spec"),
        "Pod" => Some("/spec"),
        _ => None,
    }
}

/// True when a value looks like an address the cluster assigned rather than one
/// an author wrote.
///
/// This exists for one specific value: `clusterIP: None`. `clusterIP` and
/// `clusterIPs` are normally filled in by the API server, so a manifest silent
/// about them should not show them as drift — but `None` is the exception,
/// because `None` is not an assignment, it is an author declaring a headless
/// Service. Suppressing those keys unconditionally would render a
/// headless-conversion — which breaks DNS and every consumer's routing — as a
/// completely empty diff.
fn looks_cluster_assigned(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s.parse::<std::net::IpAddr>().is_ok(),
        serde_json::Value::Array(items) => !items.is_empty() && items.iter().all(looks_cluster_assigned),
        _ => false,
    }
}

/// `ipFamilies` is server-assigned too, but its values are never addresses, so
/// it needs its own value check rather than sharing the address one.
fn is_ip_family_list(value: &serde_json::Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| !items.is_empty() && items.iter().all(|v| matches!(v.as_str(), Some("IPv4") | Some("IPv6"))))
}

/// Suppresses the ports' defaulted `protocol`, wherever the ports live.
///
/// Shared because `protocol: TCP` is defaulted in two unrelated places — a
/// Service's own `spec.ports[]` and a container's `ports[]` — and the first
/// was missed at first precisely because a Service has no pod spec, so the
/// container path never reached it.
fn suppress_port_protocols(live: &mut serde_json::Value, desired: &serde_json::Value, ports_pointer: &str) {
    let count = live.pointer(ports_pointer).and_then(|p| p.as_array()).map_or(0, |p| p.len());
    for index in 0..count {
        suppress_default(live, desired, &format!("{ports_pointer}/{index}/protocol"), "\"TCP\"");
    }
}

fn suppress_service_addresses(live: &mut serde_json::Value, desired: &serde_json::Value) {
    suppress_port_protocols(live, desired, "/spec/ports");
    for pointer in ["/spec/clusterIP", "/spec/clusterIPs"] {
        if desired.pointer(pointer).is_none() && live.pointer(pointer).is_some_and(looks_cluster_assigned) {
            remove_at_pointer(live, pointer);
        }
    }
    if desired.pointer("/spec/ipFamilies").is_none() && live.pointer("/spec/ipFamilies").is_some_and(is_ip_family_list) {
        remove_at_pointer(live, "/spec/ipFamilies");
    }
}

/// Suppresses fields the API server defaulted, for kinds whose defaults are
/// known. A kind that is not in the tables comes back untouched — honest and
/// slightly noisy, rather than quietly incomplete.
fn suppress_server_defaults(live: &mut serde_json::Value, desired: &serde_json::Value, kind: &str) {
    for (pointer, default_json) in kind_default_fields(kind) {
        suppress_default(live, desired, pointer, default_json);
    }
    if kind == "Service" {
        suppress_service_addresses(live, desired);
    }

    let Some(prefix) = pod_spec_pointer(kind) else { return };

    for (field, default_json) in POD_SPEC_DEFAULTS {
        suppress_default(live, desired, &format!("{prefix}/{field}"), default_json);
    }

    // `restartPolicy: Always` is only a default where a controller restarts
    // pods for you. A Job or CronJob has to say `OnFailure` or `Never`, so
    // there the field is authored and must never be hidden.
    if matches!(kind, "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Pod") {
        suppress_default(live, desired, &format!("{prefix}/restartPolicy"), "\"Always\"");
    }

    // `serviceAccount` is a deprecated mirror of `serviceAccountName` that the
    // server keeps in step, so it is only noise while the two agree.
    if let Some(account) = live.pointer(&format!("{prefix}/serviceAccountName")).cloned() {
        let mirror = format!("{prefix}/serviceAccount");
        if desired.pointer(&mirror).is_none() && live.pointer(&mirror) == Some(&account) {
            remove_at_pointer(live, &mirror);
        }
    }

    // A volume that projects a ConfigMap or Secret gets `defaultMode: 420`
    // (0644) filled in. Same value match as everything else, so a chart that
    // sets its own mode still shows.
    let volumes = live
        .pointer(&format!("{prefix}/volumes"))
        .and_then(|v| v.as_array())
        .map_or(0, |v| v.len());
    for index in 0..volumes {
        for source in ["configMap", "secret", "projected", "downwardAPI"] {
            suppress_default(live, desired, &format!("{prefix}/volumes/{index}/{source}/defaultMode"), "420");
        }
    }

    // Containers are addressed by index, which assumes both sides list them in
    // the same order — true for anything ArgoCD applied. If a webhook injects a
    // sidecar and shifts the indexes, the value match simply stops matching and
    // the defaults are shown rather than wrongly hidden.
    for list in ["containers", "initContainers"] {
        let containers = live
            .pointer(&format!("{prefix}/{list}"))
            .and_then(|c| c.as_array())
            .map_or(0, |c| c.len());
        for index in 0..containers {
            let base = format!("{prefix}/{list}/{index}");
            for (field, default_json) in CONTAINER_DEFAULTS {
                suppress_default(live, desired, &format!("{base}/{field}"), default_json);
            }
            suppress_port_protocols(live, desired, &format!("{base}/ports"));
        }
    }
}

/// Renders a normalised value as YAML for line-diffing.
///
/// Both sides reach this as a `serde_json::Value`, and that is load-bearing
/// rather than incidental: `serde_json`'s map is a `BTreeMap` here — the
/// crate's `preserve_order` feature is enabled nowhere in the tree — so keys
/// iterate sorted and both sides come out in the same order for free, with no
/// explicit sort. Serializing a `DynamicObject` directly, the way
/// `object_manifest` does (correctly, for display), would emit `metadata`
/// through `ObjectMeta`'s derived `Serialize` in struct-field order; the two
/// sides would then disagree on key order and the diff would be pure noise.
fn diff_yaml(value: &serde_json::Value) -> Result<String, String> {
    let text = serde_yaml::to_string(value).map_err(|e| format!("Failed to render YAML: {e}"))?;
    // `serde_yaml` always terminates with a newline. Trimming it on both sides
    // keeps a trailing blank line out of every diff.
    Ok(text.trim_end_matches('\n').to_string())
}

/// The identity fields of one `status.resources[]` entry.
fn resource_identity(entry: &serde_json::Value) -> (String, String, String, String, String, String) {
    (
        // Absent *entirely* for core resources rather than null, so "" means
        // the core group and must not be read as "missing".
        json_str(Some(entry), "group").to_string(),
        json_str(Some(entry), "version").to_string(),
        json_str(Some(entry), "kind").to_string(),
        json_str(Some(entry), "namespace").to_string(),
        json_str(Some(entry), "name").to_string(),
        json_str(Some(entry), "status").to_string(),
    )
}

/// One resource that could not be read at all.
fn unavailable_resource_diff(entry: &serde_json::Value, error: String) -> GitOpsResourceDiff {
    let (group, version, kind, namespace, name, sync_status) = resource_identity(entry);
    GitOpsResourceDiff {
        group,
        version,
        kind,
        namespace,
        name,
        sync_status,
        desired_yaml: String::new(),
        live_yaml: String::new(),
        live_yaml_full: String::new(),
        suppressed_lines: 0,
        desired_available: false,
        error: Some(error),
    }
}

/// Builds one resource's diff payload. Pure, so every normalisation rule above
/// is testable against real fixtures without a cluster.
fn build_resource_diff(entry: &serde_json::Value, live_object: &serde_json::Value) -> Result<GitOpsResourceDiff, String> {
    let (group, version, kind, namespace, name, sync_status) = resource_identity(entry);

    let desired_raw = live_object
        .pointer("/metadata/annotations")
        .and_then(|a| a.get(LAST_APPLIED_ANNOTATION))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let mut live = live_object.clone();
    // Unconditional, unlike everything in `DIFF_STRIP_ANNOTATIONS`: this
    // annotation *is* the other side of the diff, so leaving it in would diff
    // the desired manifest against itself as one enormous line.
    if let Some(annotations) = live.pointer_mut("/metadata/annotations").and_then(|a| a.as_object_mut()) {
        annotations.remove(LAST_APPLIED_ANNOTATION);
    }

    let Some(desired_raw) = desired_raw else {
        // No annotation: nothing to compare against. Reported as its own state
        // rather than as an empty diff, which would read as "no drift".
        prune_explicit_nulls(&mut live);
        drop_empty_metadata_maps(&mut live);
        let live_yaml_full = diff_yaml(&live)?;
        return Ok(GitOpsResourceDiff {
            group,
            version,
            kind,
            namespace,
            name,
            sync_status,
            desired_yaml: String::new(),
            live_yaml: live_yaml_full.clone(),
            live_yaml_full,
            suppressed_lines: 0,
            desired_available: false,
            error: None,
        });
    };

    let mut desired: serde_json::Value = serde_json::from_str(&desired_raw)
        .map_err(|e| format!("The last-applied-configuration annotation on {kind}/{name} is not valid JSON: {e}"))?;

    prune_explicit_nulls(&mut desired);
    prune_explicit_nulls(&mut live);
    stringify_quantities(&mut desired);
    stringify_quantities(&mut live);
    strip_server_bookkeeping(&mut live, &desired);
    drop_empty_metadata_maps(&mut desired);
    drop_empty_metadata_maps(&mut live);

    let mut suppressed = live.clone();
    suppress_server_defaults(&mut suppressed, &desired, &kind);

    let desired_yaml = diff_yaml(&desired)?;
    let live_yaml_full = diff_yaml(&live)?;
    let live_yaml = diff_yaml(&suppressed)?;

    // The line-count delta, not a count of rules that fired: one rule can
    // remove a list-valued field worth several lines (`clusterIPs`,
    // `ipFamilies`), so counting rules would understate what is hidden.
    let suppressed_lines = live_yaml_full.lines().count().saturating_sub(live_yaml.lines().count());

    Ok(GitOpsResourceDiff {
        group,
        version,
        kind,
        namespace,
        name,
        sync_status,
        desired_yaml,
        live_yaml,
        live_yaml_full,
        suppressed_lines,
        desired_available: true,
        error: None,
    })
}

/// Whether a `status.resources[]` entry is worth reading for a drift diff.
///
/// Pure, and shared by the counting pass and the reading loop so a bounded
/// scan's "examined N of M" can never describe a different population than
/// the one it actually walked.
fn is_diff_candidate(entry: &serde_json::Value) -> bool {
    let (_, _, kind, _, child_name, sync_status) = resource_identity(entry);
    // Anything ArgoCD is content with has no drift worth showing, and an
    // entry with no status at all is one it has not compared yet.
    !sync_status.is_empty() && sync_status != "Synced" && !kind.is_empty() && !child_name.is_empty()
}

/// How far a bounded diff scan may go.
///
/// Every candidate costs its own sequential GET, so a caller that wants a
/// handful of examples should not pay for an Application that manages two
/// hundred of them. `max_reads` is the hard ceiling — it is what bounds an
/// app whose resources are all OutOfSync but none comparable, where no amount
/// of reading yields drift. `enough` stops sooner in the case the ceiling
/// exists for: a heavily drifted app, where the first few candidates are
/// drifted the same way as the rest.
#[derive(Clone, Copy, Debug)]
pub struct DiffScanLimit {
    pub max_reads: usize,
    pub enough: usize,
}

/// A diff scan's results together with what it declined to look at.
///
/// `candidates` counts every not-Synced resource the Application lists;
/// `examined` counts the ones actually walked. They differ only for a bounded
/// scan, and that gap is precisely the part a caller must not present as the
/// whole picture.
pub struct GitOpsDiffScan {
    pub diffs: Vec<GitOpsResourceDiff>,
    pub candidates: usize,
    pub examined: usize,
}

/// True once a bounded scan has done all it was asked to.
///
/// Split out and pure because the loop it governs needs a live cluster and
/// this does not: the stopping rule is the part worth testing.
fn diff_scan_done(limit: Option<DiffScanLimit>, examined: usize, drifted: usize) -> bool {
    match limit {
        None => false,
        Some(limit) => examined >= limit.max_reads || drifted >= limit.enough,
    }
}

/// Every not-Synced resource an Application manages, with both sides of its
/// drift diff normalised and ready to line-diff.
pub async fn get_gitops_diff(context_name: &str, namespace: &str, name: &str) -> Result<Vec<GitOpsResourceDiff>, String> {
    Ok(get_gitops_diff_scan(context_name, namespace, name, None).await?.diffs)
}

/// The same scan, optionally bounded.
///
/// `limit` bounds cluster work, not just output: the loop stops reading, so a
/// caller that only needs examples does not make the Application's resource
/// count into its own latency. `None` reads everything, which is what the
/// detail view wants — it renders all of them.
pub async fn get_gitops_diff_scan(
    context_name: &str,
    namespace: &str,
    name: &str,
    limit: Option<DiffScanLimit>,
) -> Result<GitOpsDiffScan, String> {
    let client = client_for_context(context_name).await?;
    let ar = argocd_application_resource();
    let app_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let app = app_api
        .get(name)
        .await
        .map_err(|e| format!("Failed to get Application '{name}': {e}"))?;

    let entries = app
        .data
        .pointer("/status/resources")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    // One discovery round trip per distinct GVK rather than per resource: an
    // app with twenty drifted Deployments should ask the cluster what a
    // Deployment is once. `None` caches a kind the cluster does not recognise,
    // so that is not re-asked either.
    let mut resolved: HashMap<GroupVersionKind, Option<(ApiResource, Scope)>> = HashMap::new();
    let mut diffs = Vec::new();

    // Counted up front, over the same predicate the loop uses, so stopping
    // early still knows how much it skipped.
    let candidates = entries.iter().filter(|e| is_diff_candidate(e)).count();
    let mut examined = 0usize;
    let mut drifted = 0usize;

    for entry in &entries {
        if !is_diff_candidate(entry) {
            continue;
        }
        if diff_scan_done(limit, examined, drifted) {
            break;
        }
        examined += 1;

        let (group, version, kind, child_namespace, child_name, _) = resource_identity(entry);

        let gvk = GroupVersionKind::gvk(&group, &version, &kind);
        if !resolved.contains_key(&gvk) {
            // Asked rather than guessed, the same reasoning as `apply_manifest`:
            // the plural is not derivable from the kind (Ingress → ingresses,
            // PodDisruptionBudget → poddisruptionbudgets), and this has to work
            // for CRDs the app has never seen.
            let found = kube::discovery::pinned_kind(&client, &gvk)
                .await
                .ok()
                .map(|(resource, capabilities)| (resource, capabilities.scope));
            resolved.insert(gvk.clone(), found);
        }

        let Some(Some((resource, scope))) = resolved.get(&gvk) else {
            diffs.push(unavailable_resource_diff(
                entry,
                format!("The cluster doesn't recognise {kind} ({group}/{version})"),
            ));
            continue;
        };

        let api: Api<DynamicObject> = match scope {
            Scope::Namespaced => Api::namespaced_with(client.clone(), &child_namespace, resource),
            Scope::Cluster => Api::all_with(client.clone(), resource),
        };

        // One unreadable resource must not blank the whole panel: an app can
        // manage many, and a read-only token commonly lacks `get` on a few of
        // their kinds.
        match api.get(&child_name).await {
            Ok(live) => {
                let live_value = match serde_json::to_value(&live) {
                    Ok(value) => value,
                    Err(e) => {
                        diffs.push(unavailable_resource_diff(entry, format!("Failed to read {kind}/{child_name}: {e}")));
                        continue;
                    }
                };
                match build_resource_diff(entry, &live_value) {
                    Ok(diff) => {
                        if diff.has_drift() {
                            drifted += 1;
                        }
                        diffs.push(diff);
                    }
                    Err(e) => diffs.push(unavailable_resource_diff(entry, e)),
                }
            }
            Err(e) => diffs.push(unavailable_resource_diff(entry, format!("Failed to get {kind}/{child_name}: {e}"))),
        }
    }

    Ok(GitOpsDiffScan { diffs, candidates, examined })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_at_is_utc_to_the_second() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        let t = chrono::DateTime::parse_from_rfc3339("2026-04-29T19:37:04.6162361+03:00").unwrap().with_timezone(&Utc);
        assert_eq!(created_at(&Some(Time(t))), Some("2026-04-29T16:37:04Z".to_string()));
        assert_eq!(created_at(&None), None);
    }

    #[test]
    fn pod_counts_split_into_running_and_not_ready() {
        // The real figures from this app's own dev cluster, where the
        // unfiltered total and the not-Running field selector agreed exactly:
        // 35 + 1,146 == 1,181.
        assert_eq!(split_pod_counts(1181, 35), (1146, 35));
    }

    #[test]
    fn pod_counts_clamp_when_concurrent_reads_disagree() {
        // The total and the not-Running count are separate round trips to a
        // live cluster, so a burst of deletions between them can leave the
        // complement larger than the total. That has to clamp rather than
        // underflow `running` into a huge bogus number.
        assert_eq!(split_pod_counts(10, 12), (0, 10));
    }

    #[test]
    fn pod_counts_handle_a_cluster_with_no_pods() {
        assert_eq!(split_pod_counts(0, 0), (0, 0));
    }

    #[test]
    fn pod_counts_treat_every_pod_running_as_none_not_ready() {
        assert_eq!(split_pod_counts(7, 0), (7, 0));
    }

    /// Builds a `DynamicObject` from the JSON shape the API server actually
    /// returns, so the parsers are exercised against real CRD layout rather
    /// than hand-built structs that could drift from it.
    fn dynamic(json: serde_json::Value) -> DynamicObject {
        serde_json::from_value(json).expect("valid DynamicObject")
    }

    // -----------------------------------------------------------------
    // Drift diff normalisation
    //
    // Shaped after the real thing throughout: the fixtures below are trimmed
    // from a live `cbp-service` Deployment whose OutOfSync cause is the
    // Reloader operator injecting an env var, plus its own Service. A
    // hand-simplified fixture would not exercise the cases that actually bite.
    // -----------------------------------------------------------------

    /// A `status.resources[]` entry for a drifted Deployment.
    fn drifted_entry() -> serde_json::Value {
        serde_json::json!({
            "group": "apps", "version": "v1", "kind": "Deployment",
            "namespace": "sbx-weu", "name": "cbp-service", "status": "OutOfSync"
        })
    }

    /// Wraps a manifest as the live object that carries it as its own
    /// last-applied annotation — i.e. a resource with no drift at all.
    fn live_matching(manifest: &serde_json::Value, extra_live: serde_json::Value) -> serde_json::Value {
        let mut live = manifest.clone();
        merge(&mut live, &extra_live);
        live["metadata"]["annotations"][LAST_APPLIED_ANNOTATION] =
            serde_json::Value::String(serde_json::to_string(manifest).unwrap());
        live
    }

    /// Deep-merges a patch into a fixture. Arrays merge element-wise rather
    /// than replacing, so a patch adding server defaults to `containers[0]`
    /// keeps the container the manifest declared.
    fn merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
        match (target, patch) {
            (serde_json::Value::Object(t), serde_json::Value::Object(p)) => {
                for (k, v) in p {
                    merge(t.entry(k.clone()).or_insert(serde_json::Value::Null), v);
                }
            }
            (serde_json::Value::Array(t), serde_json::Value::Array(p)) => {
                for (i, v) in p.iter().enumerate() {
                    match t.get_mut(i) {
                        Some(slot) => merge(slot, v),
                        None => t.push(v.clone()),
                    }
                }
            }
            (t, p) => *t = p.clone(),
        }
    }

    fn deployment_manifest() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "cbp-service",
                "namespace": "sbx-weu",
                "annotations": { "reloader.stakater.com/auto": "true" }
            },
            "spec": {
                "replicas": 2,
                "template": {
                    "metadata": { "creationTimestamp": null },
                    "spec": {
                        "serviceAccountName": "cbp-service",
                        "containers": [{
                            "name": "cbp-service",
                            "image": "example.azurecr.io/cbp-service:latest",
                            // This chart renders unset probe blocks as explicit
                            // nulls; the API server drops them.
                            "livenessProbe": null,
                            "startupProbe": null,
                            "env": [{ "name": "DB_USERNAME" }],
                            "ports": [{ "containerPort": 8080 }]
                        }]
                    }
                }
            }
        })
    }

    /// THE oracle. A resource whose live object is its own manifest plus
    /// nothing but API-server defaults must diff to exactly zero. Every
    /// normalisation rule either earns its place here or is noise, and this is
    /// the test that fails first if one of them regresses.
    #[test]
    fn gitops_diff_of_an_undrifted_resource_is_empty() {
        let manifest = deployment_manifest();
        let live = live_matching(
            &manifest,
            serde_json::json!({
                // Everything a real live object accretes.
                "metadata": {
                    "uid": "3f1c9c1e-0000-4000-8000-000000000000",
                    "resourceVersion": "884213319",
                    "generation": 7,
                    "creationTimestamp": "2026-03-11T09:14:02Z",
                    "managedFields": [{ "manager": "argocd-controller", "operation": "Update" }],
                    "annotations": { "deployment.kubernetes.io/revision": "12" }
                },
                "spec": {
                    "revisionHistoryLimit": 10,
                    "progressDeadlineSeconds": 600,
                    "template": { "spec": {
                        "dnsPolicy": "ClusterFirst",
                        "restartPolicy": "Always",
                        "schedulerName": "default-scheduler",
                        "terminationGracePeriodSeconds": 30,
                        "securityContext": {},
                        "serviceAccount": "cbp-service",
                        "containers": [{
                            "terminationMessagePath": "/dev/termination-log",
                            "terminationMessagePolicy": "File",
                            "ports": [{ "protocol": "TCP" }]
                        }]
                    }}
                },
                "status": { "readyReplicas": 2, "observedGeneration": 7 }
            }),
        );

        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert!(diff.desired_available);
        assert_eq!(
            diff.desired_yaml, diff.live_yaml,
            "an undrifted resource must diff to nothing.\n--- desired ---\n{}\n--- live ---\n{}",
            diff.desired_yaml, diff.live_yaml
        );
        // And the toggle's other side is the honest one: turning suppression
        // off is expected to show those defaults again.
        assert!(diff.suppressed_lines > 0, "the defaults above should have been suppressed, not absent");
    }

    /// The real OutOfSync cause on this fleet: Reloader inserts an env var at
    /// `env[0]`, shifting every later entry. It has to survive normalisation as
    /// one visible addition.
    #[test]
    fn gitops_diff_shows_an_injected_env_var() {
        let manifest = deployment_manifest();
        let mut live = live_matching(&manifest, serde_json::json!({}));
        live["spec"]["template"]["spec"]["containers"][0]["env"] = serde_json::json!([
            { "name": "STAKATER_CBP_SERVICE_CONFIGMAP", "value": "d41d8cd9" },
            { "name": "DB_USERNAME" }
        ]);

        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert!(diff.live_yaml.contains("STAKATER_CBP_SERVICE_CONFIGMAP"));
        assert!(!diff.desired_yaml.contains("STAKATER_CBP_SERVICE_CONFIGMAP"));
        // The pre-existing entry must still be present on both sides, so the
        // line diff can align them and render the insertion as one block
        // rather than as a rewrite of the whole list.
        assert!(diff.desired_yaml.contains("DB_USERNAME") && diff.live_yaml.contains("DB_USERNAME"));
    }

    /// A projected volume's mode is server-filled and is noise at its default.
    #[test]
    fn gitops_diff_hides_a_defaulted_volume_mode_but_not_a_chosen_one() {
        let mut manifest = deployment_manifest();
        manifest["spec"]["template"]["spec"]["volumes"] =
            serde_json::json!([{ "name": "config", "configMap": { "name": "cbp-service" } }]);
        let live = live_matching(
            &manifest,
            serde_json::json!({ "spec": { "template": { "spec": {
                "volumes": [{ "configMap": { "defaultMode": 420 } }]
            }}}}),
        );
        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert_eq!(diff.desired_yaml, diff.live_yaml, "0644 is the default and is noise");

        // A chart that picks its own mode is not noise.
        let mut chosen = manifest.clone();
        chosen["spec"]["template"]["spec"]["volumes"][0]["configMap"]["defaultMode"] = serde_json::json!(493);
        let mut live = live_matching(&chosen, serde_json::json!({}));
        live["spec"]["template"]["spec"]["volumes"][0]["configMap"]["defaultMode"] = serde_json::json!(420);
        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert_ne!(diff.desired_yaml, diff.live_yaml, "0755 -> 0644 is real drift");
    }

    /// A quantity written as a bare number must not diff against the string
    /// the API server hands back for the same value.
    #[test]
    fn gitops_diff_treats_a_numeric_quantity_as_its_string_form() {
        let mut manifest = deployment_manifest();
        manifest["spec"]["template"]["spec"]["containers"][0]["resources"] = serde_json::json!({
            "limits": { "cpu": "3", "memory": "4Gi", "nvidia.com/gpu": 1 },
            "requests": { "cpu": "500m", "memory": "2Gi", "nvidia.com/gpu": 1 }
        });
        let mut live = live_matching(&manifest, serde_json::json!({}));
        // What the API server actually stores: Quantity, always as a string.
        for section in ["limits", "requests"] {
            live["spec"]["template"]["spec"]["containers"][0]["resources"][section]["nvidia.com/gpu"] =
                serde_json::json!("1");
        }

        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert_eq!(
            diff.desired_yaml, diff.live_yaml,
            "a numeric quantity and its string form are the same value\n--- desired ---\n{}\n--- live ---\n{}",
            diff.desired_yaml, diff.live_yaml
        );
    }

    /// ...but a real change to a quantity still shows.
    #[test]
    fn gitops_diff_still_shows_a_changed_quantity() {
        let mut manifest = deployment_manifest();
        manifest["spec"]["template"]["spec"]["containers"][0]["resources"] =
            serde_json::json!({ "limits": { "nvidia.com/gpu": 1 } });
        let mut live = live_matching(&manifest, serde_json::json!({}));
        live["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["nvidia.com/gpu"] =
            serde_json::json!("2");

        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert_ne!(diff.desired_yaml, diff.live_yaml, "1 -> 2 is real drift");
    }

    /// And the coercion stays inside quantity maps: a number elsewhere is not
    /// the same thing as its string form.
    #[test]
    fn gitops_diff_does_not_stringify_numbers_outside_quantity_maps() {
        let manifest = deployment_manifest();
        let mut live = live_matching(&manifest, serde_json::json!({}));
        live["spec"]["replicas"] = serde_json::json!("2");

        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert_ne!(diff.desired_yaml, diff.live_yaml, "replicas 2 vs \"2\" must not be flattened");
    }

    /// Explicit nulls are pruned on BOTH sides. Pruning one would leave these
    /// two lines as a permanent phantom deletion on every diff of this chart.
    #[test]
    fn gitops_diff_prunes_explicit_nulls_symmetrically() {
        let diff = build_resource_diff(&drifted_entry(), &live_matching(&deployment_manifest(), serde_json::json!({})))
            .expect("diff");
        assert!(!diff.desired_yaml.contains("livenessProbe"));
        assert!(!diff.desired_yaml.contains("startupProbe"));
        assert_eq!(diff.desired_yaml, diff.live_yaml);
    }

    /// Metadata the server owns is stripped only where the manifest is silent.
    /// A manifest that declares `finalizers` must not have them stripped from
    /// the live side alone — that would be a phantom deletion forever.
    #[test]
    fn gitops_diff_keeps_metadata_the_manifest_declares() {
        let mut manifest = deployment_manifest();
        manifest["metadata"]["finalizers"] = serde_json::json!(["example.com/cleanup"]);
        let diff = build_resource_diff(&drifted_entry(), &live_matching(&manifest, serde_json::json!({}))).expect("diff");
        assert!(diff.desired_yaml.contains("example.com/cleanup"));
        assert_eq!(diff.desired_yaml, diff.live_yaml, "declared finalizers must not diff against themselves");
    }

    /// ...while a finalizer only the cluster added stays out of the way.
    #[test]
    fn gitops_diff_strips_metadata_the_manifest_never_mentions() {
        let live = live_matching(
            &deployment_manifest(),
            serde_json::json!({ "metadata": { "finalizers": ["kubernetes.io/pvc-protection"] } }),
        );
        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert!(!diff.live_yaml.contains("pvc-protection"));
    }

    fn service_entry() -> serde_json::Value {
        serde_json::json!({
            "version": "v1", "kind": "Service",
            "namespace": "sbx-weu", "name": "cbp-service", "status": "OutOfSync"
        })
    }

    fn service_manifest() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": { "name": "cbp-service", "namespace": "sbx-weu" },
            "spec": { "ports": [{ "port": 80, "targetPort": 8080 }], "selector": { "app": "cbp-service" } }
        })
    }

    /// An address the cluster assigned is noise, and is suppressed.
    #[test]
    fn gitops_diff_hides_an_assigned_cluster_ip() {
        let live = live_matching(
            &service_manifest(),
            serde_json::json!({ "spec": {
                "clusterIP": "10.0.114.23",
                "clusterIPs": ["10.0.114.23"],
                "ipFamilies": ["IPv4"],
                "ipFamilyPolicy": "SingleStack",
                "sessionAffinity": "None",
                "internalTrafficPolicy": "Cluster",
                "ports": [{ "protocol": "TCP" }]
            }}),
        );
        let diff = build_resource_diff(&service_entry(), &live).expect("diff");
        assert_eq!(diff.desired_yaml, diff.live_yaml, "a Service with only assigned addresses has no drift");
    }

    /// `clusterIP: None` is the exception that makes suppressing these keys by
    /// name alone unsafe: `None` is not an assignment, it is an author
    /// declaring a headless Service. Hiding it would render a change that
    /// breaks DNS and every consumer's routing as a completely empty diff.
    #[test]
    fn gitops_diff_shows_a_headless_service_conversion() {
        let live = live_matching(
            &service_manifest(),
            serde_json::json!({ "spec": { "clusterIP": "None", "clusterIPs": ["None"] } }),
        );
        let diff = build_resource_diff(&service_entry(), &live).expect("diff");
        assert!(diff.live_yaml.contains("None"), "a headless conversion must be visible:\n{}", diff.live_yaml);
        assert_ne!(diff.desired_yaml, diff.live_yaml);
    }

    /// Suppression is by VALUE, never by key. A defaulted field set to a
    /// non-default value is real drift and must survive.
    #[test]
    fn gitops_diff_never_hides_a_non_default_value() {
        for (pointer, value) in [
            ("/spec/template/spec/terminationGracePeriodSeconds", serde_json::json!(5)),
            ("/spec/template/spec/restartPolicy", serde_json::json!("OnFailure")),
            ("/spec/revisionHistoryLimit", serde_json::json!(1)),
            ("/spec/paused", serde_json::json!(true)),
        ] {
            let mut live = live_matching(&deployment_manifest(), serde_json::json!({}));
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            live.pointer_mut(parent).unwrap().as_object_mut().unwrap().insert(key.to_string(), value.clone());

            let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
            assert_ne!(
                diff.desired_yaml, diff.live_yaml,
                "{pointer} = {value} is drift and must not be suppressed"
            );
        }
    }

    /// An unlisted kind — every CRD — gets no default suppression at all,
    /// rather than a Deployment's table applied where its paths mean nothing.
    #[test]
    fn gitops_diff_suppresses_nothing_for_an_unknown_kind() {
        let entry = serde_json::json!({
            "group": "external-secrets.io", "version": "v1", "kind": "ExternalSecret",
            "namespace": "sbx-weu", "name": "cbp-service-secret", "status": "OutOfSync"
        });
        let manifest = serde_json::json!({
            "apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
            "metadata": { "name": "cbp-service-secret", "namespace": "sbx-weu" },
            "spec": { "target": { "name": "cbp-service-secret" } }
        });
        let live = live_matching(&manifest, serde_json::json!({ "spec": { "target": { "creationPolicy": "Owner" } } }));
        let diff = build_resource_diff(&entry, &live).expect("diff");
        assert_eq!(diff.suppressed_lines, 0, "an unlisted kind must not be silently trimmed");
        assert!(diff.live_yaml.contains("creationPolicy"));
    }

    /// A server-side-applied resource has no annotation to compare against.
    /// That is its own state, not an empty diff — an empty diff would read as
    /// "no drift" and be wrong.
    #[test]
    fn gitops_diff_reports_a_missing_last_applied_annotation() {
        let mut live = deployment_manifest();
        live["metadata"]["managedFields"] = serde_json::json!([{ "manager": "argocd-controller" }]);
        let diff = build_resource_diff(&drifted_entry(), &live).expect("diff");
        assert!(!diff.desired_available);
        assert!(diff.desired_yaml.is_empty());
        assert!(diff.error.is_none(), "this is an explanation, not a failure");
        assert!(!diff.live_yaml.is_empty(), "the live object is still worth showing");
    }

    /// Both sides must come out with keys in the same order or the diff is
    /// pure noise. Sorted order is what `serde_json`'s BTreeMap gives, and it
    /// is load-bearing rather than incidental.
    #[test]
    fn gitops_diff_emits_both_sides_with_sorted_keys() {
        let yaml = diff_yaml(&serde_json::json!({ "zebra": 1, "apple": 2, "Mango": 3 })).expect("yaml");
        let keys: Vec<&str> = yaml.lines().filter_map(|l| l.split(':').next()).collect();
        assert_eq!(keys, vec!["Mango", "apple", "zebra"]);
        // And no trailing blank line on either side.
        assert!(!yaml.ends_with('\n'));
    }

    /// The identity of a core resource: `status.resources[]` omits `group`
    /// entirely rather than setting it null, so "" has to mean core/v1.
    #[test]
    fn gitops_diff_reads_a_core_resource_identity() {
        let (group, version, kind, namespace, name, status) = resource_identity(&serde_json::json!({
            "version": "v1", "kind": "ConfigMap", "namespace": "sbx-weu",
            "name": "cbp-service-config", "status": "OutOfSync"
        }));
        assert_eq!(group, "");
        assert_eq!((version.as_str(), kind.as_str()), ("v1", "ConfigMap"));
        assert_eq!((namespace.as_str(), name.as_str(), status.as_str()), ("sbx-weu", "cbp-service-config", "OutOfSync"));
    }

    /// End to end against a real Application, because everything the unit tests
    /// above cannot reach lives in the parts that talk to a cluster: GVK
    /// discovery for an arbitrary child kind, namespaced-versus-cluster scope,
    /// and whether `last-applied-configuration` is actually there in practice.
    ///
    ///   GITOPS_DIFF_TEST_CONTEXT=aks-sbx-example GITOPS_DIFF_TEST_NS=argocd \
    ///   GITOPS_DIFF_TEST_APP=cbp-service \
    ///   cargo test --manifest-path src-tauri/Cargo.toml gitops_diff_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set GITOPS_DIFF_TEST_* to run"]
    async fn gitops_diff_against_a_live_cluster() {
        let (Ok(context), Ok(namespace), Ok(app)) = (
            std::env::var("GITOPS_DIFF_TEST_CONTEXT"),
            std::env::var("GITOPS_DIFF_TEST_NS"),
            std::env::var("GITOPS_DIFF_TEST_APP"),
        ) else {
            eprintln!("GITOPS_DIFF_TEST_* not set — skipping");
            return;
        };

        let diffs = get_gitops_diff(&context, &namespace, &app).await.expect("diff should be readable");
        eprintln!("{} not-Synced resource(s) in {app}", diffs.len());

        for d in &diffs {
            eprintln!(
                "\n=== {}/{} ({}{}) ns={} status={} desired_available={} suppressed={} error={:?}",
                d.kind,
                d.name,
                if d.group.is_empty() { "core" } else { &d.group },
                format!("/{}", d.version),
                d.namespace,
                d.sync_status,
                d.desired_available,
                d.suppressed_lines,
                d.error,
            );
            if d.error.is_none() && d.desired_available {
                // Both sides must be sorted-key YAML of the same shape, or the
                // line diff on the frontend is noise.
                assert!(d.desired_yaml.starts_with("apiVersion:"), "desired should start at apiVersion");
                assert!(d.live_yaml.starts_with("apiVersion:"), "live should start at apiVersion");
                assert!(!d.desired_yaml.ends_with('\n') && !d.live_yaml.ends_with('\n'));
                assert!(
                    !d.live_yaml.contains(LAST_APPLIED_ANNOTATION),
                    "the annotation must never appear on the live side — it IS the other side"
                );
                assert!(!d.live_yaml.contains("managedFields"), "managedFields must be stripped");
                assert!(d.live_yaml.lines().count() <= d.live_yaml_full.lines().count());
                eprintln!("--- last applied ---\n{}", d.desired_yaml);
                eprintln!("--- live ---\n{}", d.live_yaml);
            }
        }
    }

    #[test]
    fn gitops_app_reads_last_synced_from_operation_state_finished_at() {
        let obj = dynamic(serde_json::json!({
            "metadata": { "namespace": "argocd", "name": "aks-nodepool-exporter" },
            "spec": { "source": { "repoURL": "https://example/repo.git", "path": "chart" } },
            "status": {
                "sync": { "status": "Synced" },
                "health": { "status": "Healthy" },
                "reconciledAt": "2026-08-30T07:32:58Z",
                "operationState": {
                    "phase": "Succeeded",
                    "startedAt": "2026-08-26T07:54:55Z",
                    "finishedAt": "2026-08-26T07:55:00Z"
                }
            }
        }));

        let app = dynamic_object_to_gitops_app(obj);
        // finishedAt, not the much-more-recent reconciledAt — reconciledAt
        // advances on every diff pass regardless of whether a sync happened,
        // so using it would make a genuinely-stale app read as just-synced.
        assert_eq!(app.last_synced_at, Some("2026-08-26T07:55:00Z".to_string()));
    }

    #[test]
    fn gitops_app_falls_back_to_started_at_for_a_sync_still_running() {
        let obj = dynamic(serde_json::json!({
            "metadata": { "namespace": "argocd", "name": "in-flight" },
            "spec": {},
            "status": {
                "operationState": { "phase": "Running", "startedAt": "2026-08-30T09:00:00Z" }
            }
        }));

        let app = dynamic_object_to_gitops_app(obj);
        assert_eq!(app.last_synced_at, Some("2026-08-30T09:00:00Z".to_string()));
    }

    /// A multi-source app leaves `status.sync.revision` null and records the
    /// per-source SHAs in `status.sync.revisions`. Reading only the singular
    /// field showed a blank Revision column for nearly every app on a
    /// multi-source fleet.
    #[test]
    fn gitops_app_reads_revision_from_the_plural_field_for_a_multi_source_app() {
        let obj = dynamic(serde_json::json!({
            "metadata": { "namespace": "argocd", "name": "cbp-service" },
            "spec": { "sources": [
                { "repoURL": "git@ssh.dev.azure.com:v3/org/proj/argocd", "path": "helm", "targetRevision": "HEAD" },
                { "repoURL": "git@ssh.dev.azure.com:v3/org/proj/values", "ref": "devteam", "targetRevision": "HEAD" }
            ]},
            "status": {
                "sync": {
                    "status": "OutOfSync",
                    "revisions": [
                        "e8f6111f96db5353ad2364b09cd3e6264ab2210a",
                        "5c71a7d48c1790ab5b6a6c094ce0825b0fa379d1"
                    ]
                },
                "health": { "status": "Healthy" }
            }
        }));

        let app = dynamic_object_to_gitops_app(obj);
        // The first source's SHA, because the first source is the one whose
        // repo and path this row shows.
        assert_eq!(app.revision, "e8f6111");
        assert_eq!(app.path, "helm");
    }

    /// A single-source app still reads the singular field.
    #[test]
    fn gitops_app_still_reads_the_singular_revision_for_a_single_source_app() {
        let obj = dynamic(serde_json::json!({
            "metadata": { "namespace": "argocd", "name": "aks-nodepool-exporter" },
            "spec": { "source": { "repoURL": "https://example/repo.git", "path": "chart" } },
            "status": {
                "sync": { "status": "Synced", "revision": "c704fac36d5f698df2b7b36461f963bbc7d419db" },
                "health": { "status": "Healthy" }
            }
        }));

        assert_eq!(dynamic_object_to_gitops_app(obj).revision, "c704fac");
    }

    #[test]
    fn gitops_app_never_synced_reports_none_not_empty_string() {
        let obj = dynamic(serde_json::json!({
            "metadata": { "namespace": "argocd", "name": "never-synced" },
            "spec": {},
            "status": {}
        }));

        let app = dynamic_object_to_gitops_app(obj);
        assert_eq!(app.last_synced_at, None);
    }

    #[test]
    fn a_scheduling_failure_is_matched_to_the_pool_it_names() {
        assert!(mentions_node_pool(r#"Failed to schedule pod, incompatible with nodepool "gpu", daemonset overhead={}"#, "gpu"));
        assert!(mentions_node_pool(r#"all available instance types exceed limits for nodepool: "gpu""#, "gpu"));
        assert!(mentions_node_pool(r#"incompatible with NodePool "gpu""#, "gpu"));
        assert!(!mentions_node_pool(r#"incompatible with nodepool "gpu-large""#, "gpu"));
        assert!(!mentions_node_pool("0/12 nodes are available: 3 Insufficient cpu", "default"));
        assert!(!mentions_node_pool(r#"volume "default" not found"#, "default"));
        assert!(!mentions_node_pool(r#"incompatible with nodepool "gpu", incompatible requirements, label "team" does not have known values"#, "team"));
    }

    #[test]
    fn nap_node_pool_reads_the_karpenter_v1_shape() {
        // Every field under status.resources — including the integer-looking
        // "nodes" and "cpu" — is a JSON STRING on the real API server, since
        // all of them are resource.Quantity. Deliberately shaped as strings
        // here (not JSON numbers) so this fixture would catch a regression
        // back to `.as_i64()`-style number-only reads.
        let obj = dynamic(serde_json::json!({
            "metadata": { "name": "general" },
            "spec": {
                "template": {
                    "spec": {
                        "nodeClassRef": { "group": "karpenter.azure.com", "kind": "AKSNodeClass", "name": "default" },
                        "requirements": [
                            { "key": "kubernetes.io/arch", "operator": "In", "values": ["amd64"] },
                            { "key": "karpenter.sh/capacity-type", "operator": "In", "values": ["on-demand", "spot"] }
                        ]
                    }
                },
                "limits": { "cpu": "500", "memory": "1392Gi" },
                "weight": 10
            },
            "status": {
                "conditions": [{ "type": "Ready", "status": "True" }],
                "resources": { "cpu": "224", "memory": "469314727936", "nodes": "29", "pods": "3190" }
            }
        }));

        let pool = dynamic_object_to_nap_node_pool(obj);
        assert_eq!(pool.name, "general");
        assert_eq!(pool.node_class, "default");
        assert_eq!(pool.weight, 10);
        assert!(pool.ready);
        assert_eq!(pool.status_reason, "");
        // Only the capacity-type requirement is surfaced, not every requirement.
        assert_eq!(pool.capacity_types, "on-demand, spot");

        // The subtle part: "nodes" parses as the string "29", not a JSON
        // number 29 — this is what `json_i64` would have silently read as 0.
        assert_eq!(pool.nodes, 29);
        assert_eq!(pool.cpu_used_millicores, 224_000); // bare "224" = 224 whole cores
        assert_eq!(pool.cpu_limit_millicores, Some(500_000));
        // "469314727936" bytes, no suffix, same shape the real API server
        // uses for a large exact value rather than a Gi-rounded one.
        assert_eq!(pool.memory_used_ki, 469_314_727_936 / 1024);
        assert_eq!(pool.memory_limit_ki, Some(1392 * 1024 * 1024));
    }

    #[test]
    fn nap_node_pool_treats_absent_limit_as_unbounded_not_zero() {
        // Karpenter treats a NodePool with no spec.limits as uncapped. That
        // must come through as `None`, not as a limit of literal zero — the
        // two render completely differently ("no limit" vs "0 allowed").
        let obj = dynamic(serde_json::json!({
            "metadata": { "name": "unbounded" },
            "spec": {},
            "status": { "conditions": [{ "type": "Ready", "status": "True" }] }
        }));

        let pool = dynamic_object_to_nap_node_pool(obj);
        assert_eq!(pool.cpu_limit_millicores, None);
        assert_eq!(pool.memory_limit_ki, None);
        // Nothing provisioned yet reads as zero, not as absent — there's no
        // "unbounded" reading for how much is currently in use.
        assert_eq!(pool.nodes, 0);
        assert_eq!(pool.cpu_used_millicores, 0);
        assert_eq!(pool.memory_used_ki, 0);
    }

    #[test]
    fn nap_node_pool_surfaces_why_it_is_not_ready() {
        let obj = dynamic(serde_json::json!({
            "metadata": { "name": "gpu" },
            "spec": {},
            "status": { "conditions": [{ "type": "Ready", "status": "False", "reason": "NodeClassNotReady" }] }
        }));

        let pool = dynamic_object_to_nap_node_pool(obj);
        assert!(!pool.ready);
        assert_eq!(pool.status_reason, "NodeClassNotReady");
        // A pool with no spec at all must not panic, just report empties.
        assert_eq!(pool.node_class, "");
        assert_eq!(pool.capacity_types, "");
        assert_eq!(pool.weight, 0);
    }

    // -----------------------------------------------------------------
    // HorizontalPodAutoscalers
    // -----------------------------------------------------------------

    fn resource_metric(name: &str, utilization: i32) -> MetricSpec {
        MetricSpec {
            type_: "Resource".to_string(),
            resource: Some(k8s_openapi::api::autoscaling::v2::ResourceMetricSource {
                name: name.to_string(),
                target: MetricTarget {
                    type_: "Utilization".to_string(),
                    average_utilization: Some(utilization),
                    ..Default::default()
                },
            }),
            ..Default::default()
        }
    }

    fn resource_metric_status(name: &str, utilization: i32) -> MetricStatus {
        MetricStatus {
            type_: "Resource".to_string(),
            resource: Some(k8s_openapi::api::autoscaling::v2::ResourceMetricStatus {
                name: name.to_string(),
                current: MetricValueStatus { average_utilization: Some(utilization), ..Default::default() },
            }),
            ..Default::default()
        }
    }

    /// The shape `kubectl get hpa` prints, which is what makes this column
    /// worth having. Taken from a real HPA on this fleet: two resource metrics
    /// on one autoscaler.
    #[test]
    fn hpa_targets_render_current_against_target_per_metric() {
        let spec = vec![resource_metric("cpu", 70), resource_metric("memory", 80)];
        let status = vec![resource_metric_status("cpu", 1), resource_metric_status("memory", 42)];
        assert_eq!(format_hpa_targets(&spec, &status), "cpu: 1%/70%, memory: 42%/80%");
    }

    /// Order comes from the spec, and pairing from the metric's identity — so
    /// a status list in a different order still lines up. Nothing in the API
    /// promises the two agree, and mispairing would quietly attribute one
    /// metric's reading to another's target.
    #[test]
    fn hpa_targets_pair_by_identity_not_by_position() {
        let spec = vec![resource_metric("cpu", 70), resource_metric("memory", 80)];
        let status = vec![resource_metric_status("memory", 42), resource_metric_status("cpu", 1)];
        assert_eq!(format_hpa_targets(&spec, &status), "cpu: 1%/70%, memory: 42%/80%");
    }

    fn external_metric(name: &str, selector: Option<&str>, target: &str) -> MetricSpec {
        MetricSpec {
            type_: "External".to_string(),
            external: Some(k8s_openapi::api::autoscaling::v2::ExternalMetricSource {
                metric: k8s_openapi::api::autoscaling::v2::MetricIdentifier {
                    name: name.to_string(),
                    selector: selector.map(|q| LabelSelector {
                        match_labels: Some([("queue".to_string(), q.to_string())].into_iter().collect()),
                        ..Default::default()
                    }),
                },
                target: MetricTarget {
                    type_: "AverageValue".to_string(),
                    average_value: Some(k8s_openapi::apimachinery::pkg::api::resource::Quantity(target.to_string())),
                    ..Default::default()
                },
            }),
            ..Default::default()
        }
    }

    fn external_metric_status(name: &str, selector: Option<&str>, current: &str) -> MetricStatus {
        MetricStatus {
            type_: "External".to_string(),
            external: Some(k8s_openapi::api::autoscaling::v2::ExternalMetricStatus {
                metric: k8s_openapi::api::autoscaling::v2::MetricIdentifier {
                    name: name.to_string(),
                    selector: selector.map(|q| LabelSelector {
                        match_labels: Some([("queue".to_string(), q.to_string())].into_iter().collect()),
                        ..Default::default()
                    }),
                },
                current: MetricValueStatus {
                    average_value: Some(k8s_openapi::apimachinery::pkg::api::resource::Quantity(current.to_string())),
                    ..Default::default()
                },
            }),
            ..Default::default()
        }
    }

    /// Two metrics may share a name across types. Pairing on the displayed
    /// label alone would hand the Resource target the External reading.
    #[test]
    fn hpa_targets_do_not_cross_pair_metrics_of_different_types() {
        let spec = vec![resource_metric("cpu", 70), external_metric("cpu", None, "100")];
        // Deliberately reversed, so a positional or label-only match is wrong.
        let status = vec![external_metric_status("cpu", None, "12"), resource_metric_status("cpu", 3)];
        assert_eq!(format_hpa_targets(&spec, &status), "cpu: 3%/70%, cpu: 12/100");
    }

    /// Within a type, `autoscaling/v2` allows two metrics that differ only by
    /// selector — the shape KEDA emits for a multi-trigger ScaledObject.
    #[test]
    fn hpa_targets_distinguish_metrics_by_selector() {
        let spec = vec![
            external_metric("queue_length", Some("orders"), "100"),
            external_metric("queue_length", Some("invoices"), "500"),
        ];
        let status = vec![
            external_metric_status("queue_length", Some("invoices"), "480"),
            external_metric_status("queue_length", Some("orders"), "7"),
        ];
        assert_eq!(
            format_hpa_targets(&spec, &status),
            "queue_length: 7/100, queue_length: 480/500",
            "each selector's reading must land on its own target"
        );
    }

    /// A reading is consumed once. Two indistinguishable spec entries must not
    /// both claim the same observation and read as agreeing.
    #[test]
    fn hpa_targets_consume_each_reading_once() {
        let spec = vec![external_metric("dupe", None, "100"), external_metric("dupe", None, "200")];
        let status = vec![external_metric_status("dupe", None, "9")];
        assert_eq!(format_hpa_targets(&spec, &status), "dupe: 9/100, dupe: <unknown>/200");
    }

    /// A metric the HPA has not read yet still has to appear: that gap is the
    /// symptom of the most common HPA failure, and dropping the row would hide
    /// it behind a plausible-looking replica count.
    #[test]
    fn hpa_targets_show_a_metric_with_no_reading() {
        let spec = vec![resource_metric("cpu", 70)];
        assert_eq!(format_hpa_targets(&spec, &[]), "cpu: <unknown>/70%");
    }

    /// An unset `minReplicas` means 1, and a missing condition must not read
    /// as a failure — a freshly-created HPA has none for a moment.
    #[test]
    fn hpa_defaults_min_replicas_and_treats_absent_conditions_as_healthy() {
        let hpa: HorizontalPodAutoscaler = serde_json::from_value(serde_json::json!({
            "metadata": { "namespace": "prod-ejp", "name": "amlv-service" },
            "spec": { "maxReplicas": 20, "scaleTargetRef": { "kind": "Deployment", "name": "amlv-service" } },
            "status": { "desiredReplicas": 3 }
        }))
        .expect("HPA fixture");

        let info = hpa_to_info(hpa);
        assert_eq!(info.min_replicas, 1);
        assert_eq!(info.max_replicas, 20);
        assert_eq!((info.target_kind.as_str(), info.target_name.as_str()), ("Deployment", "amlv-service"));
        assert!(info.able_to_scale && info.scaling_active);
        assert_eq!(info.condition_reason, "");
    }

    /// The condition that actually explains a broken HPA is `ScalingActive`,
    /// and its message names the metric. Preferred over `AbleToScale`, which
    /// tends to restate the same problem less usefully.
    #[test]
    fn hpa_reports_why_it_cannot_scale() {
        let hpa: HorizontalPodAutoscaler = serde_json::from_value(serde_json::json!({
            "metadata": { "namespace": "prod-ejp", "name": "df-service" },
            "spec": { "maxReplicas": 4, "minReplicas": 3, "scaleTargetRef": { "kind": "Deployment", "name": "df-service" } },
            "status": {
                "desiredReplicas": 3, "currentReplicas": 3,
                "conditions": [
                    { "type": "AbleToScale", "status": "True", "reason": "SucceededGetScale" },
                    { "type": "ScalingActive", "status": "False", "reason": "FailedGetResourceMetric",
                      "message": "did not receive metrics for any ready pods" },
                    { "type": "ScalingLimited", "status": "True", "reason": "TooFewReplicas" }
                ]
            }
        }))
        .expect("HPA fixture");

        let info = hpa_to_info(hpa);
        assert!(info.able_to_scale, "the scale subresource itself was reachable");
        assert!(!info.scaling_active);
        assert!(info.scaling_limited);
        assert_eq!(info.condition_reason, "FailedGetResourceMetric: did not receive metrics for any ready pods");
    }

    /// End to end against a real cluster, for the parts a fixture cannot
    /// reach: that `autoscaling/v2` is what gets served, and that real
    /// autoscalers produce the summary this tab is built around.
    ///
    ///   HPA_TEST_CONTEXT=aks-prod-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml hpas_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set HPA_TEST_CONTEXT to run"]
    async fn hpas_against_a_live_cluster() {
        let Ok(context) = std::env::var("HPA_TEST_CONTEXT") else {
            eprintln!("HPA_TEST_CONTEXT not set — skipping");
            return;
        };

        let hpas = get_hpas(&context).await.expect("HPAs should be listable");
        eprintln!("{} HorizontalPodAutoscaler(s) in {context}", hpas.len());
        assert!(!hpas.is_empty(), "this fleet has HPAs; an empty list means the read is wrong");

        for h in &hpas {
            eprintln!(
                "  {}/{} -> {}/{}  {}..{} (now {}, want {})  [{}]  able={} active={} limited={} {}",
                h.namespace, h.name, h.target_kind, h.target_name,
                h.min_replicas, h.max_replicas, h.current_replicas, h.desired_replicas,
                h.targets, h.able_to_scale, h.scaling_active, h.scaling_limited, h.condition_reason,
            );
            assert!(!h.name.is_empty() && !h.target_name.is_empty());
            assert!(h.max_replicas >= h.min_replicas, "max must not be below min");
        }
    }

    /// Builds a core/v1 Event the way `events.k8s.io/v1` writers emit it:
    /// `eventTime` set, `count` and both `Time` fields absent.
    fn modern_event(reason: &str, at: &str) -> Event {
        Event {
            reason: Some(reason.into()),
            event_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(
                at.parse().expect("test timestamp"),
            )),
            ..Default::default()
        }
    }

    /// The legacy core/v1 shape: `count` and `lastTimestamp` set.
    fn legacy_event(reason: &str, at: &str, count: i32) -> Event {
        Event {
            reason: Some(reason.into()),
            count: Some(count),
            last_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                at.parse().expect("test timestamp"),
            )),
            ..Default::default()
        }
    }

    #[test]
    fn an_event_with_no_count_fired_once_not_zero() {
        // `events.k8s.io/v1` omits `count` for a single occurrence. Reporting
        // that as 0 told the reader a FailedScheduling had not happened.
        assert_eq!(event_count(&modern_event("FailedScheduling", "2026-09-17T11:10:06Z")), 1);
        // An explicit count still wins.
        assert_eq!(event_count(&legacy_event("BackOff", "2026-09-17T11:10:06Z", 42)), 42);
        // And a series count outranks both, being the aggregated total.
        let mut series = modern_event("Unhealthy", "2026-09-17T11:10:06Z");
        series.series = Some(k8s_openapi::api::core::v1::EventSeries { count: Some(9), ..Default::default() });
        assert_eq!(event_count(&series), 9);
    }

    #[test]
    fn last_seen_falls_back_to_event_time() {
        let modern = modern_event("Scheduled", "2026-09-17T11:10:06Z");
        assert!(
            event_last_seen(&modern).is_some(),
            "an event carrying only eventTime still has a time; a blank column is a bug"
        );
        assert_eq!(
            event_last_seen(&legacy_event("Pulled", "2026-09-17T09:00:00Z", 1))
                .map(|t| t.to_rfc3339()),
            Some("2026-09-17T09:00:00+00:00".to_string())
        );
        // series.lastObservedTime is the most recent of a repeating series, so
        // it outranks the rest.
        let mut series = legacy_event("BackOff", "2026-09-17T09:00:00Z", 5);
        series.series = Some(k8s_openapi::api::core::v1::EventSeries {
            count: Some(5),
            last_observed_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(
                "2026-09-17T12:00:00Z".parse().expect("test timestamp"),
            )),
        });
        assert_eq!(
            event_last_seen(&series).map(|t| t.to_rfc3339()),
            Some("2026-09-17T12:00:00+00:00".to_string())
        );
    }

    #[test]
    fn a_recent_event_without_last_timestamp_still_sorts_first() {
        // The regression that mattered most: keyed on `last_timestamp` alone,
        // `None` sorts below `Some`, so a FailedScheduling from now ordered
        // below a Killing from hours earlier and was the first thing the
        // cluster-wide `take(300)` discarded.
        let mut items = vec![
            legacy_event("Killing", "2026-09-17T09:00:00Z", 1),
            modern_event("FailedScheduling", "2026-09-17T12:00:00Z"),
            legacy_event("Pulled", "2026-09-17T10:00:00Z", 1),
        ];
        items.sort_by(|a, b| event_last_seen(b).cmp(&event_last_seen(a)));

        let order: Vec<&str> = items.iter().map(|e| e.reason.as_deref().unwrap_or("")).collect();
        assert_eq!(order, vec!["FailedScheduling", "Pulled", "Killing"]);
    }

    /// End to end against a real cluster, for the part the frontend harness
    /// has to stub: that the pod Events tab's backing read actually reaches a
    /// cluster, and that everything it returns belongs to the pod asked for.
    ///
    /// Candidates come from one cluster-wide `get_events` rather than from a
    /// prefix of the pod list. Kubernetes does not order pods by whether they
    /// have events, so taking the first N and demanding one of them be noisy
    /// fails on a quiet namespace while the read is perfectly correct — and
    /// events expire after roughly an hour, so "no events anywhere" is a real
    /// state, not a defect. Asking the cluster which pods have events also
    /// costs one list instead of one per candidate.
    ///
    ///   POD_EVENTS_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml pod_events_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set POD_EVENTS_TEST_CONTEXT to run"]
    async fn pod_events_against_a_live_cluster() {
        let Ok(context) = std::env::var("POD_EVENTS_TEST_CONTEXT") else {
            eprintln!("POD_EVENTS_TEST_CONTEXT not set — skipping");
            return;
        };

        // One cluster-wide read, used only to choose pods worth asking about.
        let all = get_events(&context, false).await.expect("events should be listable");
        let mut candidates: Vec<(String, String)> = Vec::new();
        for e in &all {
            let Some(pod) = e.involved_object.strip_prefix("Pod/") else {
                continue;
            };
            let key = (e.namespace.clone(), pod.to_string());
            if !candidates.contains(&key) {
                candidates.push(key);
            }
            if candidates.len() == 3 {
                break;
            }
        }

        if candidates.is_empty() {
            eprintln!("no Pod events anywhere in {context} right now — nothing to verify, skipping");
            return;
        }

        for (namespace, pod) in &candidates {
            let events = get_pod_events(&context, namespace, pod)
                .await
                .expect("pod events should be readable");

            eprintln!("{namespace}/{pod} -> {} event(s)", events.len());
            assert!(
                !events.is_empty(),
                "{namespace}/{pod} had events in the cluster-wide list but none of its own"
            );

            for e in &events {
                eprintln!(
                    "    [{}] {} x{} last_seen={:?} {}",
                    e.event_type, e.reason, e.count, e.last_seen, e.message
                );
                assert!(!e.reason.is_empty(), "an event with no reason means the mapping is wrong");

                // The actual guarantee. Without these two, dropping the
                // name/namespace predicates from `get_pod_events` — or
                // returning the cluster-wide list outright — still passes.
                assert_eq!(
                    e.involved_object,
                    format!("Pod/{pod}"),
                    "{namespace}/{pod} was handed an event belonging to {}",
                    e.involved_object
                );
                assert_eq!(
                    &e.namespace, namespace,
                    "{namespace}/{pod} was handed an event from namespace {}",
                    e.namespace
                );

                // These two are the point of `event_count`/`event_last_seen`.
                // `events.k8s.io/v1` events (Scheduled, FailedScheduling,
                // Preempted) arrive with `count`, `firstTimestamp` and
                // `lastTimestamp` all unset, and used to surface as `x0` with a
                // blank Last seen. The unit tests pin the fallbacks against
                // synthetic events; this pins them against whatever the cluster
                // is actually emitting today, which is where the shapes that
                // prompted the fix came from in the first place.
                assert!(e.count >= 1, "{} fired, so it cannot have a count of 0", e.reason);
                assert!(
                    e.last_seen.is_some(),
                    "{} has no timestamp from any of the four sources",
                    e.reason
                );
            }
        }
        eprintln!("verified {} pod(s), every event owned by the pod asked for", candidates.len());
    }

    #[test]
    fn keda_scaled_object_defaults_its_target_kind_to_deployment() {
        // KEDA treats an omitted scaleTargetRef.kind as Deployment, so a
        // ScaledObject that leaves it out must not render a blank target.
        let obj = dynamic(serde_json::json!({
            "metadata": { "namespace": "prod", "name": "queue-worker" },
            "spec": {
                "scaleTargetRef": { "name": "worker" },
                "minReplicaCount": 1,
                "maxReplicaCount": 30,
                "triggers": [{ "type": "azure-servicebus" }, { "type": "cron" }]
            },
            "status": { "conditions": [
                { "type": "Ready", "status": "True" },
                { "type": "Active", "status": "False" }
            ]}
        }));

        let so = dynamic_object_to_keda(obj, "ScaledObject");
        assert_eq!(so.namespace, "prod");
        assert_eq!(so.name, "queue-worker");
        assert_eq!(so.kind, "ScaledObject");
        assert_eq!(so.target_kind, "Deployment");
        assert_eq!(so.target_name, "worker");
        assert_eq!(so.min_replicas, 1);
        assert_eq!(so.max_replicas, 30);
        assert_eq!(so.triggers, "azure-servicebus, cron");
        // Ready and Active are independent: wired up, but nothing firing.
        assert!(so.ready);
        assert!(!so.active);
        assert!(!so.paused);
    }

    #[test]
    fn keda_scaled_job_reports_a_job_target_rather_than_a_workload() {
        // A ScaledJob templates its own Job, so there's no scaleTargetRef to
        // read — it must not fall through to the Deployment default.
        let obj = dynamic(serde_json::json!({
            "metadata": { "namespace": "batch", "name": "importer" },
            "spec": {
                "jobTargetRef": { "template": {} },
                "maxReplicaCount": 5,
                "triggers": [{ "type": "azure-queue" }]
            },
            "status": { "conditions": [{ "type": "Paused", "status": "True" }] }
        }));

        let sj = dynamic_object_to_keda(obj, "ScaledJob");
        assert_eq!(sj.kind, "ScaledJob");
        assert_eq!(sj.target_kind, "Job");
        assert_eq!(sj.target_name, "");
        assert_eq!(sj.max_replicas, 5);
        assert_eq!(sj.triggers, "azure-queue");
        assert!(sj.paused);
        assert!(!sj.ready);
    }

    /// Both KEDA detail fetches route their `kind` through this, so an
    /// unexpected one fails loudly instead of the events filter quietly
    /// matching nothing and reporting a healthy "No events found".
    #[test]
    fn keda_plural_rejects_a_kind_it_does_not_serve() {
        assert_eq!(keda_plural("ScaledObject").unwrap(), "scaledobjects");
        assert_eq!(keda_plural("ScaledJob").unwrap(), "scaledjobs");
        assert!(keda_plural("Deployment").is_err());
        assert!(keda_plural("scaledobject").is_err(), "kind is case-sensitive");
        assert!(keda_plural("").is_err());
    }

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

    #[test]
    fn parse_memory_ki_handles_lowercase_decimal_kilo_as_well_as_uppercase() {
        // Kubernetes' canonical Quantity serialization only ever emits
        // lowercase "k" for decimal kilo; "K" is accepted too, but a real
        // API-server-reported value uses "k". Both must resolve to the same
        // amount, not silently become 0 from an unmatched suffix.
        assert_eq!(parse_memory_ki("16k"), 15);
        assert_eq!(parse_memory_ki("16K"), 15);
    }

    // -- pod failure detection ------------------------------------------------

    fn cs(name: &str, ready: bool, state: k8s_openapi::api::core::v1::ContainerState) -> k8s_openapi::api::core::v1::ContainerStatus {
        k8s_openapi::api::core::v1::ContainerStatus { name: name.into(), ready, state: Some(state), ..Default::default() }
    }
    fn waiting_state(reason: &str, message: &str) -> k8s_openapi::api::core::v1::ContainerState {
        k8s_openapi::api::core::v1::ContainerState {
            waiting: Some(k8s_openapi::api::core::v1::ContainerStateWaiting {
                reason: Some(reason.into()),
                message: if message.is_empty() { None } else { Some(message.into()) },
            }),
            ..Default::default()
        }
    }
    fn terminated_state(reason: &str, exit_code: i32) -> k8s_openapi::api::core::v1::ContainerState {
        k8s_openapi::api::core::v1::ContainerState {
            terminated: Some(k8s_openapi::api::core::v1::ContainerStateTerminated {
                reason: Some(reason.into()),
                exit_code,
                ..Default::default()
            }),
            ..Default::default()
        }
    }
    fn status_of(containers: Vec<k8s_openapi::api::core::v1::ContainerStatus>) -> k8s_openapi::api::core::v1::PodStatus {
        k8s_openapi::api::core::v1::PodStatus { container_statuses: Some(containers), ..Default::default() }
    }

    #[test]
    fn a_failing_container_reports_its_reason_and_message() {
        let st = status_of(vec![cs("mcp-server", false, waiting_state("ImagePullBackOff", "Back-off pulling image"))]);
        assert_eq!(
            pod_failure(&st).map(|(_, m)| m).as_deref(),
            Some("mcp-server: ImagePullBackOff: Back-off pulling image")
        );
    }

    fn status_with_phase(phase: &str, reason: &str, containers: Vec<k8s_openapi::api::core::v1::ContainerStatus>) -> k8s_openapi::api::core::v1::PodStatus {
        k8s_openapi::api::core::v1::PodStatus {
            phase: Some(phase.into()),
            reason: if reason.is_empty() { None } else { Some(reason.into()) },
            container_statuses: Some(containers),
            ..Default::default()
        }
    }

    #[test]
    fn a_succeeded_pod_with_a_pod_level_reason_is_still_not_a_failure() {
        // The container-level exclusion skips the exit-0 container, and the
        // pod-level fallback then has to not undo it: a CronJob pod reporting
        // `Succeeded` / `Completed` must yield nothing, or the most common
        // not-ready pod in the fleet would be reported as a failure.
        let st = status_with_phase("Succeeded", "Completed", vec![cs("cronjob", false, terminated_state("Completed", 0))]);
        assert_eq!(pod_failure(&st), None);
    }

    #[test]
    fn an_evicted_pod_is_a_failure() {
        // The case the pod-level fallback exists for: no container to blame,
        // and `phase` is Failed.
        let st = status_with_phase("Failed", "Evicted", vec![]);
        assert_eq!(pod_failure(&st).map(|(_, m)| m).as_deref(), Some("Evicted"));
    }

    #[test]
    fn a_named_replica_failure_outranks_boilerplate_that_came_first() {
        // ReplicaFailure is the condition *type*; its reason names the cause
        // (`FailedCreate`). Prioritising on the reason never matched, so with
        // the boilerplate first this returned the boilerplate.
        let conds = vec![
            ("Available", "False", "MinimumReplicasUnavailable", "Deployment does not have minimum availability."),
            ("ReplicaFailure", "True", "FailedCreate", "pods is forbidden: exceeded quota"),
        ];
        assert_eq!(
            pick_failure_condition(conds.into_iter()).as_deref(),
            Some("FailedCreate: pods is forbidden: exceeded quota")
        );
    }

    #[test]
    fn a_finished_job_is_not_a_failure() {
        // A completed CronJob pod sits at exit 0 and never becomes ready. On a
        // real cluster those were half the not-ready pods; offering to explain
        // a job that worked is worse than offering nothing.
        let done = status_of(vec![cs("cronjob-alerts", false, terminated_state("Completed", 0))]);
        assert_eq!(pod_failure(&done), None);

        let failed = status_of(vec![cs("worker", false, terminated_state("Error", 137))]);
        assert_eq!(pod_failure(&failed).map(|(_, m)| m).as_deref(), Some("worker: Error (exit 137)"));
    }

    #[test]
    fn still_starting_is_not_a_failure() {
        for reason in TRANSIENT_WAITING_REASONS {
            let st = status_of(vec![cs("app", false, waiting_state(reason, ""))]);
            assert_eq!(pod_failure(&st), None, "{reason} should not read as a failure");
        }
    }

    #[test]
    fn an_evicted_pod_keeps_its_pod_level_reason_despite_retained_container_status() {
        // The node leaves terminated container statuses behind on eviction —
        // typically ContainerStatusUnknown, exit 137. Scanning containers
        // first claimed one of those, which both buried the eviction reason
        // and made the row ask for logs from a container already reclaimed.
        let mut st = status_with_phase(
            "Failed",
            "Evicted",
            vec![cs("app", false, terminated_state("ContainerStatusUnknown", 137))],
        );
        st.message = Some("The node was low on resource: memory.".into());

        let (container, message) = pod_failure(&st).expect("an evicted pod is a failure");
        assert_eq!(container, None, "no container should be named for a pod-level failure");
        assert_eq!(message, "Evicted: The node was low on resource: memory.");
    }

    #[test]
    fn a_failed_pod_without_a_pod_level_reason_still_uses_its_container() {
        // A Job pod that failed through its container carries no pod-level
        // reason, so the container scan must still run for it.
        let st = status_with_phase("Failed", "", vec![cs("worker", false, terminated_state("Error", 1))]);
        assert_eq!(
            pod_failure(&st),
            Some((Some("worker".to_string()), "worker: Error (exit 1)".to_string()))
        );
    }

    #[test]
    fn the_container_returned_is_the_failing_one_not_the_first() {
        // A diagnosis targets this container, so returning the wrong one
        // sends a healthy sidecar's logs to explain a broken app.
        let st = status_of(vec![
            cs("istio-proxy", true, waiting_state("ImagePullBackOff", "ignore me")),
            cs("app", false, waiting_state("CrashLoopBackOff", "back-off restarting")),
        ]);
        assert_eq!(pod_failure(&st).and_then(|(c, _)| c).as_deref(), Some("app"));
        // An evicted pod belongs to no container.
        let evicted = status_with_phase("Failed", "Evicted", vec![]);
        assert_eq!(pod_failure(&evicted).and_then(|(c, _)| c), None);
    }

    #[test]
    fn a_ready_container_cannot_mask_a_failing_one() {
        let st = status_of(vec![
            cs("istio-proxy", true, waiting_state("ImagePullBackOff", "ignore me")),
            cs("app", false, waiting_state("CrashLoopBackOff", "back-off 5m0s restarting")),
        ]);
        assert_eq!(
            pod_failure(&st).map(|(_, m)| m).as_deref(),
            Some("app: CrashLoopBackOff: back-off 5m0s restarting")
        );
    }

    /// Exercises the production `workload_healthy`, which is the only thing
    /// the three readers call. An earlier version of this test defined its own
    /// copy of the comparison inside `#[cfg(test)]`, so it passed no matter
    /// what the readers did — and "reverting it to `==` makes the test fail"
    /// proved only that the test tested itself.
    #[test]
    fn a_surging_rollout_is_not_unhealthy() {
        // maxSurge runs more ready replicas than desired for the length of a
        // rollout, and a scale-down does the same while old pods drain. Under
        // `==` both read as unhealthy: a red dot and a Diagnose button on a
        // workload that is serving fine. Measured on a live fleet at 5/3.
        assert!(workload_healthy(5, 3), "a surging rollout is serving, not degraded");
        assert!(workload_healthy(4, 3), "one surge replica is still healthy");
        assert!(workload_healthy(3, 3), "the ordinary case");
        // Genuinely degraded is still degraded.
        assert!(!workload_healthy(0, 3));
        assert!(!workload_healthy(2, 3));
        // Deliberately scaled to zero is not a failure.
        assert!(workload_healthy(0, 0));
    }

    #[test]
    fn a_named_cause_outranks_the_availability_boilerplate() {
        // Every unready Deployment carries MinimumReplicasUnavailable, which
        // only restates the ready count; ProgressDeadlineExceeded names a
        // cause, so it wins regardless of the order they appear in.
        let conds = vec![
            ("Available", "False", "MinimumReplicasUnavailable", "Deployment does not have minimum availability."),
            ("Progressing", "False", "ProgressDeadlineExceeded", "ReplicaSet has timed out progressing."),
        ];
        assert_eq!(
            pick_failure_condition(conds.into_iter()).as_deref(),
            Some("ProgressDeadlineExceeded: ReplicaSet has timed out progressing.")
        );
    }

    #[test]
    fn the_boilerplate_is_still_returned_when_nothing_better_exists() {
        let only = vec![("Available", "False", "MinimumReplicasUnavailable", "Deployment does not have minimum availability.")];
        assert_eq!(
            pick_failure_condition(only.into_iter()).as_deref(),
            Some("MinimumReplicasUnavailable: Deployment does not have minimum availability.")
        );
        let healthy = vec![("Available", "True", "MinimumReplicasAvailable", "Deployment has minimum availability.")];
        assert_eq!(pick_failure_condition(healthy.into_iter()), None);
    }

    #[test]
    fn replica_failure_counts_as_failing_when_true() {
        // The one condition where True means broken rather than fine.
        let conds = vec![("ReplicaFailure", "True", "FailedCreate", "forbidden: exceeded quota")];
        assert_eq!(
            pick_failure_condition(conds.into_iter()).as_deref(),
            Some("FailedCreate: forbidden: exceeded quota")
        );
    }

    fn resource_entry(kind: &str, name: &str, status: &str) -> serde_json::Value {
        serde_json::json!({ "kind": kind, "name": name, "namespace": "ns", "version": "v1", "status": status })
    }

    #[test]
    fn diff_candidates_are_the_resources_argocd_is_unhappy_with() {
        assert!(is_diff_candidate(&resource_entry("Deployment", "api", "OutOfSync")));
        // Synced needs no diff, and no status at all means ArgoCD has not
        // compared it yet — neither is worth a round trip.
        assert!(!is_diff_candidate(&resource_entry("Deployment", "api", "Synced")));
        assert!(!is_diff_candidate(&resource_entry("Deployment", "api", "")));
        // Unaddressable: nothing to GET.
        assert!(!is_diff_candidate(&resource_entry("", "api", "OutOfSync")));
        assert!(!is_diff_candidate(&resource_entry("Deployment", "", "OutOfSync")));
    }

    #[test]
    fn unbounded_scan_never_stops_early() {
        // The detail view renders every resource, so it must not inherit the
        // diagnosis budget by accident.
        assert!(!diff_scan_done(None, 10_000, 10_000));
    }

    #[test]
    fn bounded_scan_stops_on_either_bound() {
        let limit = Some(DiffScanLimit { max_reads: 20, enough: 5 });
        assert!(!diff_scan_done(limit, 0, 0));
        assert!(!diff_scan_done(limit, 19, 4));
        // Enough examples in hand: the heavily-drifted case.
        assert!(diff_scan_done(limit, 5, 5));
        // Ceiling reached with nothing to show for it: the all-server-side
        // case, which is exactly what `enough` alone fails to bound.
        assert!(diff_scan_done(limit, 20, 0));
    }

    /// A throwaway apiserver serving exactly the surface one diff scan
    /// touches, and counting the only thing under test: how many resource
    /// GETs the scan actually issues.
    ///
    /// `diff_scan_done` is tested above as a pure rule, but nothing there
    /// proves the loop *obeys* it — a `break` on the far side of the GET, or
    /// `examined` incremented in the wrong branch, would leave every other
    /// test in this file green while the bound saved no round trips at all.
    /// That is the entire claim, so it is measured rather than read.
    struct FakeApiServer {
        port: u16,
        resource_gets: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn start_fake_apiserver(resources: usize, last_applied: bool) -> FakeApiServer {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let resource_gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = resource_gets.clone();

        let entries: Vec<serde_json::Value> = (0..resources)
            .map(|i| {
                serde_json::json!({
                    "group": "", "version": "v1", "kind": "ConfigMap",
                    "namespace": "default", "name": format!("cm-{i}"), "status": "OutOfSync"
                })
            })
            .collect();
        let app = serde_json::json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": { "name": "app", "namespace": "argocd" },
            "status": { "resources": entries }
        })
        .to_string();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let counter = counter.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    // Read until the headers end: one `read` usually suffices
                    // for a bodyless GET, but "usually" is how a test starts
                    // failing on a busy machine only.
                    let mut req = Vec::new();
                    let mut chunk = [0u8; 2048];
                    loop {
                        match socket.read(&mut chunk).await {
                            Ok(0) => return,
                            Ok(n) => {
                                req.extend_from_slice(&chunk[..n]);
                                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    let text = String::from_utf8_lossy(&req).to_string();
                    let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();

                    let body = if path.contains("/applications/") {
                        app
                    } else if path.starts_with("/api/v1/namespaces/") && path.contains("/configmaps/") {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let name = path.rsplit('/').next().unwrap_or("cm").to_string();
                        let mut metadata = serde_json::json!({ "name": name, "namespace": "default" });
                        if last_applied {
                            // Differs from the live body, so this resource has drifted.
                            let desired = serde_json::json!({
                                "apiVersion": "v1", "kind": "ConfigMap",
                                "metadata": { "name": name, "namespace": "default" },
                                "data": { "k": "old" }
                            })
                            .to_string();
                            metadata["annotations"] = serde_json::json!({ LAST_APPLIED_ANNOTATION: desired });
                        }
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "ConfigMap",
                            "metadata": metadata, "data": { "k": "new" }
                        })
                        .to_string()
                    } else if path == "/api/v1" {
                        serde_json::json!({
                            "kind": "APIResourceList", "groupVersion": "v1",
                            "resources": [{
                                "name": "configmaps", "singularName": "", "namespaced": true,
                                "kind": "ConfigMap", "verbs": ["get"]
                            }]
                        })
                        .to_string()
                    } else if path == "/api" {
                        serde_json::json!({ "kind": "APIVersions", "versions": ["v1"] }).to_string()
                    } else if path == "/apis" {
                        serde_json::json!({ "kind": "APIGroupList", "groups": [] }).to_string()
                    } else {
                        serde_json::json!({ "kind": "Status", "status": "Failure", "code": 404 }).to_string()
                    };

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        FakeApiServer { port, resource_gets }
    }

    /// Writes a kubeconfig pointing at the fake, runs `f`, restores the env.
    async fn against_fake<F, Fut, T>(context_name: &str, port: u16, f: F) -> T
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let _guard = crate::kubeconfig::KUBECONFIG_ENV_LOCK.lock().unwrap();
        let mut path = std::env::temp_dir();
        path.push(format!("aks-dashboard-diffscan-{}-{context_name}", std::process::id()));
        std::fs::write(
            &path,
            format!(
                "apiVersion: v1\nkind: Config\ncurrent-context: {context_name}\n\
                 clusters:\n- name: {context_name}\n  cluster:\n    server: http://127.0.0.1:{port}\n\
                 contexts:\n- name: {context_name}\n  context:\n    cluster: {context_name}\n    user: {context_name}\n    namespace: default\n\
                 users:\n- name: {context_name}\n  user:\n    token: faketoken\n"
            ),
        )
        .expect("write kubeconfig");

        let previous = std::env::var("KUBECONFIG").ok();
        std::env::set_var("KUBECONFIG", &path);
        let result = f(context_name.to_string()).await;
        match previous {
            Some(v) => std::env::set_var("KUBECONFIG", v),
            None => std::env::remove_var("KUBECONFIG"),
        }
        std::fs::remove_file(&path).ok();
        result
    }

    #[tokio::test]
    async fn the_bound_saves_round_trips_on_a_heavily_drifted_app() {
        let server = start_fake_apiserver(40, true).await;
        let gets = server.resource_gets.clone();

        let scan = against_fake("drifted", server.port, |ctx| async move {
            get_gitops_diff_scan(&ctx, "argocd", "app", Some(DiffScanLimit { max_reads: 20, enough: 5 }))
                .await
                .expect("scan")
        })
        .await;

        // Five examples were asked for, so five resources were read — not
        // forty read and thirty-five thrown away, which is what capping only
        // the serialisation did.
        assert_eq!(gets.load(std::sync::atomic::Ordering::SeqCst), 5);
        assert_eq!(scan.examined, 5);
        assert_eq!(scan.candidates, 40, "it still knows how much it skipped");
        assert_eq!(scan.diffs.iter().filter(|d| d.has_drift()).count(), 5);
    }

    #[tokio::test]
    async fn the_hard_ceiling_is_what_bounds_an_app_that_never_yields_drift() {
        // Every resource OutOfSync but applied server-side: no amount of
        // reading produces a drifted one, so the "enough drifted" stop never
        // fires and only `max_reads` ends the scan.
        let server = start_fake_apiserver(40, false).await;
        let gets = server.resource_gets.clone();

        let scan = against_fake("serverside", server.port, |ctx| async move {
            get_gitops_diff_scan(&ctx, "argocd", "app", Some(DiffScanLimit { max_reads: 20, enough: 5 }))
                .await
                .expect("scan")
        })
        .await;

        assert_eq!(gets.load(std::sync::atomic::Ordering::SeqCst), 20);
        assert_eq!(scan.examined, 20);
        assert_eq!(scan.diffs.iter().filter(|d| d.has_drift()).count(), 0);
        assert!(scan.diffs.iter().all(|d| !d.desired_available && d.error.is_none()));
    }

    #[tokio::test]
    async fn an_unbounded_scan_still_reads_everything() {
        // The detail view renders every resource, so it must not inherit the
        // diagnosis budget.
        let server = start_fake_apiserver(40, true).await;
        let gets = server.resource_gets.clone();

        let scan = against_fake("unbounded", server.port, |ctx| async move {
            get_gitops_diff_scan(&ctx, "argocd", "app", None).await.expect("scan")
        })
        .await;

        assert_eq!(gets.load(std::sync::atomic::Ordering::SeqCst), 40);
        assert_eq!(scan.examined, scan.candidates);
    }

    /// Opens the newest events the way the panel does: each one's siblings
    /// and its own YAML. Prints counts only.
    ///
    ///   EVENT_DETAIL_TEST_CONTEXT=aks-dev-example \
    ///   cargo test --manifest-path src-tauri/Cargo.toml event_detail_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set EVENT_DETAIL_TEST_CONTEXT to run"]
    async fn event_detail_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("EVENT_DETAIL_TEST_CONTEXT") else { return };
        let events = get_events(&ctx, false).await.expect("events");
        // One full list, to check the server-side object filter against a client-side match.
        let client = client_for_context(&ctx).await.expect("client");
        let all = list_events_sorted(&client).await.expect("all events");
        let (mut opened, mut with_source, mut with_field, mut siblings, mut gone, mut mismatched) = (0, 0, 0, 0, 0, 0);
        for e in events.iter().take(20) {
            assert!(!e.name.is_empty(), "every event carries its name");
            let same = get_object_events(&ctx, &e.object_kind, &e.object_namespace, &e.object_name, &e.object_uid).await.expect("object events");
            // An event can expire between the list and this call; that is not a failure.
            if !same.iter().any(|x| x.name == e.name) {
                gone += 1;
                continue;
            }
            siblings += same.len() - 1;
            let expected = all
                .iter()
                .filter(|x| {
                    let o = &x.involved_object;
                    o.kind.as_deref() == Some(e.object_kind.as_str())
                        && o.name.as_deref() == Some(e.object_name.as_str())
                        && (e.object_uid.is_empty() || o.uid.as_deref() == Some(e.object_uid.as_str()))
                        && (e.object_namespace.is_empty() || o.namespace.as_deref().unwrap_or_default() == e.object_namespace)
                })
                .count();
            // Events keep arriving between the two lists, so a small drift is not a fault.
            mismatched += usize::from(expected.abs_diff(same.len()) > 2);
            match crate::resources::get_resource_manifest(&ctx, "Event", &e.namespace, &e.name).await {
                Ok(_) => opened += 1,
                Err(err) if err.contains("not found") => gone += 1,
                Err(err) => panic!("manifest: {err}"),
            }
            with_source += usize::from(!e.source.is_empty());
            with_field += usize::from(!e.field_path.is_empty());
        }
        println!(
            "events={} opened={opened} with_source={with_source} with_field_path={with_field} siblings={siblings} expired_meanwhile={gone} filter_mismatches={mismatched}",
            events.len()
        );
        assert_eq!(mismatched, 0, "the field-selector filter disagrees with a client-side match");
    }

    #[test]
    fn an_event_names_its_source_field_and_first_sighting() {
        let core: Event = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "api-x.1", "namespace": "prod" },
            "involvedObject": { "apiVersion": "v1", "kind": "Pod", "namespace": "prod", "name": "api-x", "fieldPath": "spec.containers{api}" },
            "source": { "component": "kubelet", "host": "aks-node-1" },
            "firstTimestamp": "2026-10-10T08:00:00Z", "lastTimestamp": "2026-10-10T09:00:00Z", "count": 12,
            "reason": "BackOff", "type": "Warning"
        }))
        .unwrap();
        let i = event_to_info(core);
        assert_eq!((i.source.as_str(), i.field_path.as_str()), ("kubelet on aks-node-1", "spec.containers{api}"));
        assert_eq!(i.first_seen.as_deref(), Some("2026-10-10T08:00:00+00:00"));
        // events.k8s.io reports through reportingController/Instance and sets an action and related object.
        let modern: Event = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "api-x.2", "namespace": "prod" },
            "involvedObject": { "kind": "Pod", "name": "api-x" },
            "reportingComponent": "default-scheduler", "reportingInstance": "",
            "action": "Scheduling", "related": { "kind": "Node", "name": "aks-node-2" },
            "eventTime": "2026-10-10T08:30:00.000000Z", "reason": "Scheduled", "type": "Normal"
        }))
        .unwrap();
        let m = event_to_info(modern);
        assert_eq!((m.source.as_str(), m.action.as_str(), m.related.as_str()), ("default-scheduler", "Scheduling", "Node/aks-node-2"));
        assert!(m.first_seen.as_deref().is_some_and(|t| t.starts_with("2026-10-10T08:30:00")));
    }

    #[test]
    fn an_event_carries_its_object_structured() {
        let e: Event = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "x.1", "namespace": "prod" },
            "involvedObject": { "apiVersion": "apps/v1", "kind": "Deployment", "namespace": "prod", "name": "api" },
            "reason": "ScalingReplicaSet", "type": "Normal"
        }))
        .unwrap();
        let i = event_to_info(e);
        assert_eq!(i.involved_object, "Deployment/api");
        assert_eq!((i.object_api_version.as_str(), i.object_kind.as_str(), i.object_namespace.as_str(), i.object_name.as_str()), ("apps/v1", "Deployment", "prod", "api"));
        assert_eq!(i.name, "x.1");
    }
}
