//! Auto-discovery of an in-cluster Prometheus-API-compatible time-series
//! backend (Prometheus or VictoriaMetrics), and range queries against it.
//!
//! Discovery scans Services cluster-wide (not just a `monitoring` namespace —
//! real deployments name it `observability`, `kube-prometheus-stack`, etc.)
//! and matches common Helm chart / operator naming conventions. Queries go
//! through the API server's service-proxy subresource
//! (`/api/v1/namespaces/{ns}/services/{name}:{port}/proxy/...`), the same
//! technique `k8s::fetch_node_metrics` uses for `metrics.k8s.io` — this means
//! no direct network route to the in-cluster Service is needed, only the
//! kubeconfig's existing API server access.

use crate::k8s;
use crate::kubeconfig::client_for_context;
use crate::models::{
    MetricSample, MetricsBackendInfo, MetricsBackendKind, MetricsBackendTestResult, MetricsOverTimeResult,
};
use chrono::Utc;
use k8s_openapi::api::core::v1::Service;
use kube::api::{Api, ListParams, ResourceExt};
use kube::Client;
use std::time::Duration;

/// A proxied request to an in-cluster Prometheus/VictoriaMetrics Service can
/// hang instead of erroring if the target pod is unreachable — without a
/// request-level timeout that would freeze the whole Metrics tab for the
/// client's full (multi-minute) read timeout instead of surfacing a clear
/// error. Mirrors `k8s::METRICS_REQUEST_TIMEOUT`'s reasoning.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

struct Candidate {
    kind: MetricsBackendKind,
    namespace: String,
    service_name: String,
    port: i32,
    api_path_prefix: String,
    score: u8,
}

/// Services that merely accompany a metrics stack (exporters, the operator
/// itself, alerting, dashboards) but aren't a queryable Prometheus-API
/// endpoint. Matched as a substring of the lowercased service name.
const EXCLUDED_NAME_SUBSTRINGS: &[&str] = &[
    "operator",
    "exporter",
    "alertmanager",
    "pushgateway",
    "kube-state-metrics",
    "grafana",
    "adapter",
    "admission",
    "webhook",
];

fn pick_port(svc: &Service, preferred_names: &[&str]) -> Option<i32> {
    let ports = svc.spec.as_ref()?.ports.as_ref()?;
    for pn in preferred_names {
        if let Some(p) = ports.iter().find(|p| p.name.as_deref() == Some(*pn)) {
            return Some(p.port);
        }
    }
    ports.first().map(|p| p.port)
}

fn classify_service(svc: &Service) -> Option<Candidate> {
    let name = svc.name_any();
    let namespace = svc.namespace().unwrap_or_default();
    let lname = name.to_lowercase();

    if EXCLUDED_NAME_SUBSTRINGS.iter().any(|e| lname.contains(e)) {
        return None;
    }

    let labels = svc.labels();
    let app_name = labels
        .get("app.kubernetes.io/name")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // "monitoring" is the conventional namespace for these stacks; nudge
    // matches there ahead of same-named services living elsewhere.
    let ns_bonus: u8 = if namespace == "monitoring" { 2 } else { 0 };

    // VictoriaMetrics cluster mode: vmselect is the component that serves
    // the Prometheus-compatible query API, nested under /select/0/prometheus.
    if lname.contains("vmselect") || app_name == "vmselect" {
        let port = pick_port(svc, &["http"])?;
        return Some(Candidate {
            kind: MetricsBackendKind::VictoriaMetrics,
            namespace,
            service_name: name,
            port,
            api_path_prefix: "/select/0/prometheus".to_string(),
            score: 10 + ns_bonus,
        });
    }

    // VictoriaMetrics single-node (vmsingle, or the victoria-metrics-single chart).
    if lname.contains("vmsingle") || lname.contains("victoria-metrics") || app_name == "vmsingle" {
        let port = pick_port(svc, &["http"])?;
        return Some(Candidate {
            kind: MetricsBackendKind::VictoriaMetrics,
            namespace,
            service_name: name,
            port,
            api_path_prefix: String::new(),
            score: 9 + ns_bonus,
        });
    }

    // Prometheus: covers "prometheus-server" (community chart), "prometheus-operated"
    // (Prometheus Operator's governing headless service), "kube-prometheus-stack-prometheus",
    // "prometheus-k8s", etc.
    if lname.contains("prometheus") {
        let port = pick_port(svc, &["web", "http"])?;
        return Some(Candidate {
            kind: MetricsBackendKind::Prometheus,
            namespace,
            service_name: name,
            port,
            api_path_prefix: String::new(),
            score: 8 + ns_bonus,
        });
    }

    None
}

/// Every Service that looks like a queryable Prometheus-API endpoint, best
/// candidate first. Exposed so the UI can offer the alternatives rather than
/// making the user type a service/port by hand when the heuristic guesses
/// wrong — the scoring is only a heuristic, and on a cluster running the
/// VictoriaMetrics k8s-stack several scrape-target Services match the same
/// name substrings as the real query endpoint.
async fn candidates_with_client(client: &Client) -> Result<Vec<MetricsBackendInfo>, String> {
    let services_api: Api<Service> = Api::all(client.clone());
    let services = services_api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list services: {e}"))?
        .items;

    let mut found: Vec<Candidate> = services.iter().filter_map(classify_service).collect();
    // Descending score; ties broken by name so the order is stable between
    // calls rather than depending on Service list order.
    found.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| a.service_name.cmp(&b.service_name))
    });

    Ok(found
        .into_iter()
        .map(|c| MetricsBackendInfo {
            kind: c.kind,
            namespace: c.namespace,
            service_name: c.service_name,
            port: c.port,
            api_path_prefix: c.api_path_prefix,
        })
        .collect())
}

async fn discover_with_client(client: &Client) -> Result<Option<MetricsBackendInfo>, String> {
    Ok(candidates_with_client(client).await?.into_iter().next())
}

/// An explicit override wins outright — no discovery call at all, which also
/// means an override keeps working on a cluster where the heuristic would
/// find nothing.
async fn resolve_backend(
    client: &Client,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<Option<MetricsBackendInfo>, String> {
    match override_backend {
        Some(b) => Ok(Some(b)),
        None => discover_with_client(client).await,
    }
}

/// Percent-encode a query-string value. Hand-rolled rather than pulling in a
/// URL crate: the only inputs are our own fixed PromQL strings, and this is
/// the same "small stable shape, not worth a dependency" call already made
/// for `metrics.k8s.io` parsing in `k8s.rs`.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn query_range(
    client: &Client,
    backend: &MetricsBackendInfo,
    promql: &str,
    start: i64,
    end: i64,
    step_secs: i64,
) -> Result<Vec<MetricSample>, String> {
    let uri = format!(
        "/api/v1/namespaces/{}/services/{}:{}/proxy{}/api/v1/query_range?query={}&start={start}&end={end}&step={step_secs}s",
        backend.namespace,
        backend.service_name,
        backend.port,
        backend.api_path_prefix,
        percent_encode(promql),
    );
    let req = http::Request::builder()
        .uri(uri)
        .body(Vec::new())
        .map_err(|e| format!("Failed to build metrics query request: {e}"))?;
    let value: serde_json::Value = match tokio::time::timeout(QUERY_TIMEOUT, client.request(req)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(format!("Metrics query failed: {e}")),
        Err(_) => return Err("Metrics query timed out".to_string()),
    };

    if value.get("status").and_then(|s| s.as_str()) != Some("success") {
        let err_msg = value
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("query returned a non-success status");
        return Err(err_msg.to_string());
    }

    let mut samples = Vec::new();
    let first_series = value
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first());
    if let Some(series) = first_series {
        if let Some(values) = series.get("values").and_then(|v| v.as_array()) {
            for pair in values {
                let Some(pair) = pair.as_array() else { continue };
                if pair.len() != 2 {
                    continue;
                }
                let timestamp = pair[0].as_f64().unwrap_or(0.0) as i64;
                let value = pair[1]
                    .as_str()
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                samples.push(MetricSample { timestamp, value });
            }
        }
    }
    Ok(samples)
}

const CPU_CORES_QUERY: &str = r#"sum(rate(container_cpu_usage_seconds_total{container!="",container!="POD"}[5m]))"#;
const MEMORY_BYTES_QUERY: &str = r#"sum(container_memory_working_set_bytes{container!="",container!="POD"})"#;
// Not `container_fs_usage_bytes`: that name exists on most cAdvisor-backed
// setups but is commonly left unpopulated (no series at all) since per-container
// writable-layer usage collection is disabled by default on many container
// runtimes. `container_ephemeral_storage_usage_bytes` is cAdvisor's own
// dedicated ephemeral-storage metric (verified against a live cluster to
// actually carry data, unlike the former) and lines up with Kubernetes' own
// ephemeral-storage accounting more closely.
const EPHEMERAL_STORAGE_BYTES_QUERY: &str = r#"sum(container_ephemeral_storage_usage_bytes{container!="",container!="POD"})"#;

async fn resource_usage_over_time(
    client: &Client,
    backend: MetricsBackendInfo,
    cpu_query: &str,
    mem_query: &str,
    ephemeral_storage_query: &str,
    range_minutes: i64,
) -> MetricsOverTimeResult {
    let range_minutes = range_minutes.clamp(5, 24 * 60);
    let end = Utc::now().timestamp();
    let start = end - range_minutes * 60;
    // ~120 points across the window regardless of range, floor of 15s so a
    // short 5m window doesn't request an absurdly fine step.
    let step_secs = ((range_minutes * 60) / 120).max(15);

    let (cpu, mem, ephemeral_storage) = tokio::join!(
        query_range(client, &backend, cpu_query, start, end, step_secs),
        query_range(client, &backend, mem_query, start, end, step_secs),
        query_range(client, &backend, ephemeral_storage_query, start, end, step_secs),
    );

    let error = cpu
        .as_ref()
        .err()
        .or(mem.as_ref().err())
        .or(ephemeral_storage.as_ref().err())
        .cloned();

    MetricsOverTimeResult {
        backend: Some(backend),
        error,
        cpu_cores: cpu.unwrap_or_default(),
        memory_bytes: mem.unwrap_or_default(),
        ephemeral_storage_bytes: ephemeral_storage.unwrap_or_default(),
    }
}

pub async fn get_metrics_over_time(
    context_name: &str,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    let client = client_for_context(context_name).await?;
    let backend = match resolve_backend(&client, override_backend).await? {
        Some(b) => b,
        None => return Ok(MetricsOverTimeResult::default()),
    };
    Ok(resource_usage_over_time(
        &client,
        backend,
        CPU_CORES_QUERY,
        MEMORY_BYTES_QUERY,
        EPHEMERAL_STORAGE_BYTES_QUERY,
        range_minutes,
    )
    .await)
}

/// Same shape as `get_metrics_over_time`, scoped to a single pod via PromQL
/// label matchers rather than the cluster-wide sums above. `namespace` and
/// `pod_name` are Kubernetes resource names (DNS-label charset only, no
/// quotes/braces possible), so they're interpolated directly with no PromQL
/// injection risk — same trust level as the rest of this file's static
/// queries.
pub async fn get_pod_metrics_over_time(
    context_name: &str,
    namespace: &str,
    pod_name: &str,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    let client = client_for_context(context_name).await?;
    let backend = match resolve_backend(&client, override_backend).await? {
        Some(b) => b,
        None => return Ok(MetricsOverTimeResult::default()),
    };
    let cpu_query = format!(
        r#"sum(rate(container_cpu_usage_seconds_total{{namespace="{namespace}",pod="{pod_name}",container!="",container!="POD"}}[5m]))"#
    );
    let mem_query = format!(
        r#"sum(container_memory_working_set_bytes{{namespace="{namespace}",pod="{pod_name}",container!="",container!="POD"}})"#
    );
    let ephemeral_storage_query = format!(
        r#"sum(container_ephemeral_storage_usage_bytes{{namespace="{namespace}",pod="{pod_name}",container!="",container!="POD"}})"#
    );
    Ok(resource_usage_over_time(&client, backend, &cpu_query, &mem_query, &ephemeral_storage_query, range_minutes).await)
}

/// Escapes the only regex metacharacter a Kubernetes object name can legally
/// contain. Names are RFC-1123 (subdomain) — lowercase alphanumerics, `-` and
/// `.` — and of those only `.` means anything to a regex engine, where left
/// unescaped it would match any character and could pull in a same-shaped
/// sibling's series.
fn escape_regex_dots(name: &str) -> String {
    name.replace('.', r"\.")
}

/// The pod-name shape each workload kind produces, as an anchored regex body.
///
/// Preferred over listing the workload's *current* pods: a pod list is a
/// snapshot, so over a 24h window every pod replaced by a rollout would drop
/// out and the graph would start only as far back as the newest pods. Matching
/// by name shape keeps the history of since-replaced pods.
///
/// Sibling names don't collide, because PromQL anchors `=~` (`^…$`) and
/// `[a-z0-9]+` excludes `-`: verified live against a real same-prefix pair —
/// `cbp-service` and `cbp-service-secondary` each matched only their own 3
/// container series, not each other's.
fn workload_pod_regex(kind: &str, name: &str) -> Result<String, String> {
    let name = escape_regex_dots(name);
    Ok(match kind {
        // <deployment>-<replicaset-hash>-<pod-suffix>
        "Deployment" => format!("{name}-[a-z0-9]+-[a-z0-9]+"),
        // <statefulset>-<ordinal>
        "StatefulSet" => format!("{name}-[0-9]+"),
        // <daemonset>-<pod-suffix>
        "DaemonSet" => format!("{name}-[a-z0-9]+"),
        other => return Err(format!("Unsupported workload kind '{other}'")),
    })
}

/// Same shape as `get_pod_metrics_over_time`, scoped to every container
/// running on one node.
///
/// Node identity isn't carried consistently across metrics stacks: this
/// cluster's kubelet/cAdvisor scrape puts the node name in `instance` and has
/// no `node` label on those series at all, while other setups relabel it to
/// `node`. Rather than pick one and silently render an empty graph on the
/// other, each query tries `instance` and falls back to `node` via PromQL
/// `or` — which yields the right-hand side only when the left matches nothing.
///
/// Note this sums *container* usage on the node, matching the cluster-wide
/// Metrics tab, so it reads lower than `kubectl top node` — that figure also
/// counts kubelet, the container runtime and OS overhead, which live outside
/// any container's cgroup.
pub async fn get_node_metrics_over_time(
    context_name: &str,
    node_name: &str,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    let client = client_for_context(context_name).await?;
    let backend = match resolve_backend(&client, override_backend).await? {
        Some(b) => b,
        None => return Ok(MetricsOverTimeResult::default()),
    };
    let common = r#"container!="",container!="POD""#;
    let cpu_query = format!(
        r#"sum(rate(container_cpu_usage_seconds_total{{instance="{node_name}",{common}}}[5m])) or sum(rate(container_cpu_usage_seconds_total{{node="{node_name}",{common}}}[5m]))"#
    );
    let mem_query = format!(
        r#"sum(container_memory_working_set_bytes{{instance="{node_name}",{common}}}) or sum(container_memory_working_set_bytes{{node="{node_name}",{common}}})"#
    );
    let ephemeral_storage_query = format!(
        r#"sum(container_ephemeral_storage_usage_bytes{{instance="{node_name}",{common}}}) or sum(container_ephemeral_storage_usage_bytes{{node="{node_name}",{common}}})"#
    );
    Ok(resource_usage_over_time(&client, backend, &cpu_query, &mem_query, &ephemeral_storage_query, range_minutes).await)
}

/// Same shape as `get_pod_metrics_over_time`, summed across every pod the
/// workload owns (see `workload_pod_regex` for how those are matched).
pub async fn get_workload_metrics_over_time(
    context_name: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    let pod_regex = workload_pod_regex(kind, name)?;
    let client = client_for_context(context_name).await?;
    let backend = match resolve_backend(&client, override_backend).await? {
        Some(b) => b,
        None => return Ok(MetricsOverTimeResult::default()),
    };
    let scope = format!(r#"namespace="{namespace}",pod=~"{pod_regex}",container!="",container!="POD""#);
    let cpu_query = format!(r#"sum(rate(container_cpu_usage_seconds_total{{{scope}}}[5m]))"#);
    let mem_query = format!(r#"sum(container_memory_working_set_bytes{{{scope}}})"#);
    let ephemeral_storage_query = format!(r#"sum(container_ephemeral_storage_usage_bytes{{{scope}}})"#);
    Ok(resource_usage_over_time(&client, backend, &cpu_query, &mem_query, &ephemeral_storage_query, range_minutes).await)
}

/// Same shape as `get_node_metrics_over_time`, summed across every node the
/// NodePool currently owns. Unlike a workload's pods (`workload_pod_regex`),
/// Karpenter node names carry no predictable pattern derivable from the pool
/// name alone (they're generated by the cloud provider), so this asks
/// `k8s::get_nodes` for the pool's actual current membership rather than
/// guessing at a naming scheme.
pub async fn get_nap_node_pool_metrics_over_time(
    context_name: &str,
    pool_name: &str,
    range_minutes: i64,
    override_backend: Option<MetricsBackendInfo>,
) -> Result<MetricsOverTimeResult, String> {
    let nodes = k8s::get_nodes(context_name).await?;
    let node_names: Vec<String> =
        nodes.into_iter().filter(|n| n.node_pool.as_deref() == Some(pool_name)).map(|n| n.name).collect();
    // A pool that hasn't provisioned anything yet (or just lost its last
    // node) has nothing to query — same empty-result convention as "no
    // metrics backend found", rather than an error over an empty graph.
    if node_names.is_empty() {
        return Ok(MetricsOverTimeResult::default());
    }

    let client = client_for_context(context_name).await?;
    let backend = match resolve_backend(&client, override_backend).await? {
        Some(b) => b,
        None => return Ok(MetricsOverTimeResult::default()),
    };

    let names_pattern = node_names.iter().map(|n| escape_regex_dots(n)).collect::<Vec<_>>().join("|");
    let common = r#"container!="",container!="POD""#;
    let cpu_query = format!(
        r#"sum(rate(container_cpu_usage_seconds_total{{instance=~"{names_pattern}",{common}}}[5m])) or sum(rate(container_cpu_usage_seconds_total{{node=~"{names_pattern}",{common}}}[5m]))"#
    );
    let mem_query = format!(
        r#"sum(container_memory_working_set_bytes{{instance=~"{names_pattern}",{common}}}) or sum(container_memory_working_set_bytes{{node=~"{names_pattern}",{common}}})"#
    );
    let ephemeral_storage_query = format!(
        r#"sum(container_ephemeral_storage_usage_bytes{{instance=~"{names_pattern}",{common}}}) or sum(container_ephemeral_storage_usage_bytes{{node=~"{names_pattern}",{common}}})"#
    );
    Ok(resource_usage_over_time(&client, backend, &cpu_query, &mem_query, &ephemeral_storage_query, range_minutes).await)
}

/// Instant query against a candidate, used only by `test_metrics_backend`.
async fn query_instant(client: &Client, backend: &MetricsBackendInfo, promql: &str) -> Result<f64, String> {
    let uri = format!(
        "/api/v1/namespaces/{}/services/{}:{}/proxy{}/api/v1/query?query={}",
        backend.namespace,
        backend.service_name,
        backend.port,
        backend.api_path_prefix,
        percent_encode(promql),
    );
    let req = http::Request::builder()
        .uri(uri)
        .body(Vec::new())
        .map_err(|e| format!("Failed to build request: {e}"))?;
    let value: serde_json::Value = match tokio::time::timeout(QUERY_TIMEOUT, client.request(req)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(format!("{e}")),
        Err(_) => return Err(format!("timed out after {}s", QUERY_TIMEOUT.as_secs())),
    };
    if value.get("status").and_then(|v| v.as_str()) != Some("success") {
        return Err(value
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("endpoint returned a non-success status")
            .to_string());
    }
    Ok(value
        .pointer("/data/result/0/value/1")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0))
}

/// Every candidate the heuristic found, best first. The frontend shows these
/// as the choices when overriding, so a wrong auto-pick can be corrected by
/// selection rather than by typing a service name and port.
pub async fn list_metrics_backends(context_name: &str) -> Result<Vec<MetricsBackendInfo>, String> {
    let client = client_for_context(context_name).await?;
    candidates_with_client(&client).await
}

/// Probes a candidate before it's saved as an override.
///
/// Two distinct failure modes are worth telling apart, so this reports them
/// differently: the endpoint not answering PromQL at all (wrong service, wrong
/// port, wrong path prefix), versus answering fine but carrying none of the
/// cAdvisor container series the graphs are built from — which would look like
/// a working config that silently renders empty charts.
pub async fn test_metrics_backend(
    context_name: &str,
    backend: MetricsBackendInfo,
) -> Result<MetricsBackendTestResult, String> {
    let client = client_for_context(context_name).await?;

    // `vector(1)` needs no data to exist — it only proves the PromQL API is there.
    if let Err(e) = query_instant(&client, &backend, "vector(1)").await {
        return Ok(MetricsBackendTestResult {
            ok: false,
            message: format!("Not a reachable Prometheus-compatible endpoint: {e}"),
            container_series: None,
        });
    }

    let series = query_instant(&client, &backend, r#"count(container_memory_working_set_bytes{container!=""})"#)
        .await
        .unwrap_or(0.0) as i64;

    Ok(if series > 0 {
        MetricsBackendTestResult {
            ok: true,
            message: format!("Connected. {series} container series available."),
            container_series: Some(series),
        }
    } else {
        MetricsBackendTestResult {
            ok: false,
            message: "Endpoint answers PromQL but has no container_memory_working_set_bytes series, \
                      so graphs would be empty. This is usually a scrape target rather than the \
                      query endpoint."
                .to_string(),
            container_series: Some(0),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServicePort;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::api::core::v1::ServiceSpec;
    use std::collections::BTreeMap;

    fn make_service(name: &str, namespace: &str, labels: &[(&str, &str)], ports: &[(&str, i32)]) -> Service {
        let mut label_map = BTreeMap::new();
        for (k, v) in labels {
            label_map.insert(k.to_string(), v.to_string());
        }
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(label_map),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(
                    ports
                        .iter()
                        .map(|(pname, pport)| ServicePort {
                            name: Some(pname.to_string()),
                            port: *pport,
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn matches_prometheus_community_chart_service() {
        let svc = make_service("prometheus-server", "monitoring", &[], &[("http", 80)]);
        let c = classify_service(&svc).expect("should match");
        assert_eq!(c.kind, MetricsBackendKind::Prometheus);
        assert_eq!(c.port, 80);
        assert_eq!(c.api_path_prefix, "");
    }

    #[test]
    fn matches_prometheus_operator_governing_service_over_web_port() {
        let svc = make_service(
            "prometheus-operated",
            "monitoring",
            &[],
            &[("http", 9091), ("web", 9090)],
        );
        let c = classify_service(&svc).expect("should match");
        assert_eq!(c.kind, MetricsBackendKind::Prometheus);
        // "web" is preferred over "http" for Prometheus per pick_port's priority order.
        assert_eq!(c.port, 9090);
    }

    #[test]
    fn excludes_prometheus_operator_own_service() {
        let svc = make_service("kube-prometheus-stack-operator", "monitoring", &[], &[("https", 443)]);
        assert!(classify_service(&svc).is_none());
    }

    #[test]
    fn excludes_exporters_and_dashboards() {
        for name in ["node-exporter", "kube-state-metrics", "grafana"] {
            let svc = make_service(name, "monitoring", &[], &[("http", 80)]);
            assert!(classify_service(&svc).is_none(), "{name} should be excluded");
        }
    }

    #[test]
    fn matches_victoriametrics_single_node() {
        let svc = make_service(
            "vmsingle-victoria-metrics-k8s-stack",
            "monitoring",
            &[("app.kubernetes.io/name", "vmsingle")],
            &[("http", 8429)],
        );
        let c = classify_service(&svc).expect("should match");
        assert_eq!(c.kind, MetricsBackendKind::VictoriaMetrics);
        assert_eq!(c.api_path_prefix, "");
    }

    #[test]
    fn matches_victoriametrics_cluster_vmselect_with_api_prefix() {
        let svc = make_service(
            "vmselect-victoria-metrics-cluster",
            "monitoring",
            &[("app.kubernetes.io/name", "vmselect")],
            &[("http", 8481)],
        );
        let c = classify_service(&svc).expect("should match");
        assert_eq!(c.kind, MetricsBackendKind::VictoriaMetrics);
        assert_eq!(c.api_path_prefix, "/select/0/prometheus");
    }

    #[test]
    fn prefers_monitoring_namespace_when_scores_tie() {
        let in_monitoring = classify_service(&make_service("prometheus-server", "monitoring", &[], &[("http", 80)]))
            .expect("should match");
        let elsewhere = classify_service(&make_service("prometheus-server", "custom-ns", &[], &[("http", 80)]))
            .expect("should match");
        assert!(in_monitoring.score > elsewhere.score);
    }

    #[test]
    fn workload_pod_regex_matches_each_kinds_pod_naming() {
        assert_eq!(workload_pod_regex("Deployment", "inx-service").unwrap(), "inx-service-[a-z0-9]+-[a-z0-9]+");
        assert_eq!(workload_pod_regex("StatefulSet", "camunda-zeebe").unwrap(), "camunda-zeebe-[0-9]+");
        assert_eq!(workload_pod_regex("DaemonSet", "kube-proxy").unwrap(), "kube-proxy-[a-z0-9]+");
        assert!(workload_pod_regex("CronJob", "x").is_err());
    }

    /// The regexes are used anchored (PromQL wraps `=~` in `^…$`), so assert
    /// against that same anchoring here — this is what keeps a workload from
    /// absorbing a longer-named sibling's series, verified live against the
    /// real `cbp-service` / `cbp-service-secondary` pair.
    #[test]
    fn workload_pod_regex_does_not_absorb_a_same_prefix_sibling() {
        let own = workload_pod_regex("Deployment", "cbp-service").unwrap();
        assert!(regex_lite_fullmatch(&own, "cbp-service-6956b69c57-abc12"), "must match its own pods");
        assert!(
            !regex_lite_fullmatch(&own, "cbp-service-secondary-6956b69c57-abc12"),
            "must not match the sibling deployment's pods"
        );

        let sibling = workload_pod_regex("Deployment", "cbp-service-secondary").unwrap();
        assert!(regex_lite_fullmatch(&sibling, "cbp-service-secondary-6956b69c57-abc12"));
        assert!(!regex_lite_fullmatch(&sibling, "cbp-service-6956b69c57-abc12"));

        // A StatefulSet must not absorb a longer-named sibling either.
        let sts = workload_pod_regex("StatefulSet", "camunda-zeebe").unwrap();
        assert!(regex_lite_fullmatch(&sts, "camunda-zeebe-0"));
        assert!(regex_lite_fullmatch(&sts, "camunda-zeebe-10"));
        assert!(!regex_lite_fullmatch(&sts, "camunda-zeebe-gateway-0"));
    }

    #[test]
    fn workload_pod_regex_escapes_dots_in_names() {
        let body = workload_pod_regex("DaemonSet", "a.b").unwrap();
        assert!(body.starts_with(r"a\.b"), "dot must be escaped, got {body}");
        assert!(regex_lite_fullmatch(&body, "a.b-xyz12"));
        assert!(!regex_lite_fullmatch(&body, "axb-xyz12"), "unescaped dot would have matched this");
    }

    /// Minimal anchored matcher for the two constructs `workload_pod_regex`
    /// emits — `[a-z0-9]+` / `[0-9]+` classes and literal text (with `\.`) —
    /// so the anchoring guarantees can be asserted without adding a regex
    /// dependency, in keeping with this crate's hand-rolled-over-dependency
    /// approach elsewhere.
    fn regex_lite_fullmatch(pattern: &str, text: &str) -> bool {
        enum Tok {
            Lit(char),
            Class { digits_only: bool },
        }
        let mut toks = Vec::new();
        let mut it = pattern.chars().peekable();
        while let Some(c) = it.next() {
            match c {
                '\\' => toks.push(Tok::Lit(it.next().expect("trailing backslash"))),
                '[' => {
                    let mut body = String::new();
                    for c in it.by_ref() {
                        if c == ']' {
                            break;
                        }
                        body.push(c);
                    }
                    assert_eq!(it.next(), Some('+'), "only one-or-more classes are emitted");
                    toks.push(Tok::Class {
                        digits_only: body == "0-9",
                    });
                }
                other => toks.push(Tok::Lit(other)),
            }
        }

        // Backtracking match, anchored at both ends.
        fn m(toks: &[Tok], text: &[char]) -> bool {
            match toks.first() {
                None => text.is_empty(),
                Some(Tok::Lit(c)) => text.first() == Some(c) && m(&toks[1..], &text[1..]),
                Some(Tok::Class { digits_only }) => {
                    let ok = |c: char| c.is_ascii_digit() || (!digits_only && c.is_ascii_lowercase());
                    let mut taken = 0;
                    while taken < text.len() && ok(text[taken]) {
                        taken += 1;
                        if m(&toks[1..], &text[taken..]) {
                            return true;
                        }
                    }
                    false
                }
            }
        }
        let chars: Vec<char> = text.chars().collect();
        m(&toks, &chars)
    }

    #[test]
    fn percent_encode_escapes_promql_special_characters() {
        let encoded = percent_encode(r#"sum(rate(x{a="b",c!=""}[5m]))"#);
        assert!(!encoded.contains(['{', '}', '"', '(', ')', '=', '!', ',']));
        assert!(encoded.contains("%7B")); // {
        assert!(encoded.contains("%22")); // "
    }
}
