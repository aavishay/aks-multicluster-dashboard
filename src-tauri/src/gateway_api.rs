//! Gateway API (`gateway.networking.k8s.io`): GatewayClasses, Gateways and
//! the routes that attach to them — HTTPRoute and GRPCRoute, and the
//! experimental channel's TLSRoute, TCPRoute and UDPRoute. One read lists
//! them all, for the Gateways and Routes tabs and their panels.
//!
//! The group is found by discovery, which also says at which version each
//! kind is served (a TCPRoute is still `v1alpha2` where an HTTPRoute is `v1`).
//! A cluster without the CRDs costs one request, and an experimental kind
//! that is not installed is simply absent.
//!
//! Status is read as the API's conventions define it: a condition is
//! positive-polarity, so any that is not True is worth naming, except the few
//! the API defines the other way round (`NEGATIVE`), where True is the fault.
//! That covers the standard ones (Accepted, Programmed, ResolvedRefs) and an
//! implementation's own (Envoy Gateway's BackendsAvailable) alike, and the
//! CRDs' own default — Accepted and Programmed Unknown, reason Pending —
//! reads as "no controller has picked it up". A condition written for an
//! older generation of the object than its current spec says nothing about
//! that spec, so it reads as Unknown too, until the controller catches up.
//!
//! Nothing here carries a value worth redacting: a listener names its
//! certificate Secrets, and only their names are kept.

use crate::k8s::{self, age_days, age_seconds, created_at, json_str};
use crate::kubeconfig::client_for_context;
use crate::models::{
    EventInfo, GatewayApiResult, GatewayClassInfo, GatewayInfo, GatewayListenerInfo, PodConditionInfo, RouteBackendInfo, RouteInfo,
    RouteParentInfo, RouteRuleInfo,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::api::{Api, ApiResource, DynamicObject, ListParams, LogParams};
use std::collections::BTreeMap;
use kube::error::DiscoveryError;
use serde_json::Value;

pub(crate) const GROUP: &str = "gateway.networking.k8s.io";

/// The route kinds, in the order the Routes tab lists them.
pub(crate) const ROUTE_KINDS: &[&str] = &["HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute"];

/// For fetching one object by kind without discovery (its panel's YAML):
/// newest first, falling back on 404.
pub(crate) const VERSIONS: &[&str] = &["v1", "v1beta1", "v1alpha3", "v1alpha2"];

fn items(v: Option<&Value>, key: &str) -> Vec<Value> {
    v.and_then(|v| v.get(key)).and_then(Value::as_array).cloned().unwrap_or_default()
}

fn strings(v: Option<&Value>, key: &str) -> Vec<String> {
    items(v, key).iter().filter_map(|s| s.as_str().map(str::to_string)).collect()
}

/// The conditions the API defines with negative polarity, where True is the
/// fault: a listener's Conflicted and OverlappingTLSConfig, a route parent's
/// PartiallyInvalid. Mirrors `GATEWAY_NEGATIVE_CONDITIONS` in main.ts.
const NEGATIVE: &[&str] = &["Conflicted", "OverlappingTLSConfig", "PartiallyInvalid"];

pub(crate) fn condition_ok(c: &PodConditionInfo) -> bool {
    c.status == if NEGATIVE.contains(&c.condition_type.as_str()) { "False" } else { "True" }
}

/// The conditions under `status`, judged against the object's `generation`:
/// one the controller wrote for an older spec than the current one is shown
/// as Unknown, reason Stale, with what it said then, rather than as the
/// current spec's verdict. A controller that does not record
/// `observedGeneration` is taken at its word.
fn conditions(status: Option<&Value>, generation: Option<i64>) -> Vec<PodConditionInfo> {
    items(status, "conditions")
        .iter()
        .map(|c| {
            let mut info = PodConditionInfo {
                condition_type: json_str(Some(c), "type").to_string(),
                status: json_str(Some(c), "status").to_string(),
                reason: json_str(Some(c), "reason").to_string(),
                message: json_str(Some(c), "message").to_string(),
                last_transition: Some(json_str(Some(c), "lastTransitionTime")).filter(|t| !t.is_empty()).map(str::to_string),
            };
            let observed = c.get("observedGeneration").and_then(Value::as_i64);
            if let (Some(observed), Some(current)) = (observed, generation) {
                if observed < current {
                    let then = if info.reason.is_empty() { info.status.clone() } else { format!("{} ({})", info.status, info.reason) };
                    info.message = format!("{then} for generation {observed}; the spec is at generation {current}, which its controller has not reported on yet");
                    info.status = "Unknown".to_string();
                    info.reason = "Stale".to_string();
                }
            }
            info
        })
        .collect()
}

/// `Accepted is False: NotAllowedByListeners — no listener allows this route`.
fn describe(c: &PodConditionInfo) -> String {
    let state = match c.status.as_str() {
        "True" | "False" => c.status.clone(),
        "" => "Unknown (not yet decided)".to_string(),
        other => format!("{other} (not yet decided)"),
    };
    let mut out = format!("{} is {state}", c.condition_type);
    if !c.reason.is_empty() {
        out.push_str(&format!(": {}", c.reason));
    }
    if !c.message.is_empty() && c.message != c.reason {
        out.push_str(&format!(" — {}", c.message));
    }
    out
}

/// The first condition that reports a fault or is undecided, or none
/// reported at all.
fn failing(conds: &[PodConditionInfo], none: &str) -> Option<String> {
    if conds.is_empty() {
        return Some(none.to_string());
    }
    conds.iter().find(|c| !condition_ok(c)).map(describe)
}

fn age(obj: &DynamicObject) -> (i64, i64, Option<String>) {
    let t = obj.metadata.creation_timestamp.clone();
    (age_days(t.clone()), age_seconds(t.clone()), created_at(&t))
}

pub(crate) fn class_info(obj: &DynamicObject) -> GatewayClassInfo {
    let spec = obj.data.get("spec");
    let conditions = conditions(obj.data.get("status"), obj.metadata.generation);
    let problem = failing(&conditions, "No controller has accepted it: is the controller it names running?");
    let (age_days, age_seconds, created_at) = age(obj);
    GatewayClassInfo {
        name: obj.metadata.name.clone().unwrap_or_default(),
        controller: json_str(spec, "controllerName").to_string(),
        description: json_str(spec, "description").to_string(),
        healthy: problem.is_none(),
        problem,
        conditions,
        age_days,
        age_seconds,
        created_at,
    }
}

/// A certificate reference by name: `name`, `ns/name` across namespaces, or
/// `Kind/name` (`Kind.group/name` outside the core group) for something
/// other than a core Secret.
fn certificate_ref(r: &Value, own_ns: &str) -> String {
    let kind = json_str(Some(r), "kind");
    let ns = json_str(Some(r), "namespace");
    let name = json_str(Some(r), "name");
    let base = match (json_str(Some(r), "group"), if kind.is_empty() { "Secret" } else { kind }) {
        ("", "Secret") => name.to_string(),
        ("", kind) => format!("{kind}/{name}"),
        (group, kind) => format!("{kind}.{group}/{name}"),
    };
    if ns.is_empty() || ns == own_ns {
        base
    } else {
        format!("{ns}/{base}")
    }
}

pub(crate) fn gateway_info(obj: &DynamicObject) -> GatewayInfo {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");
    let listener_status = items(status, "listeners");
    let listeners: Vec<GatewayListenerInfo> = items(spec, "listeners")
        .iter()
        .map(|l| {
            let name = json_str(Some(l), "name").to_string();
            let st = listener_status.iter().find(|s| json_str(Some(s), "name") == name);
            let conditions = conditions(st, obj.metadata.generation);
            let protocol = json_str(Some(l), "protocol").to_string();
            let tls = l.get("tls");
            let tls_mode = match (tls, json_str(tls, "mode")) {
                (None, _) => String::new(),
                (Some(_), "") => "Terminate".to_string(), // the API's default
                (Some(_), m) => m.to_string(),
            };
            let allowed = json_str(l.get("allowedRoutes").and_then(|a| a.get("namespaces")), "from");
            GatewayListenerInfo {
                port: l.get("port").and_then(Value::as_i64).unwrap_or_default(),
                hostname: json_str(Some(l), "hostname").to_string(),
                tls_mode,
                certificates: items(tls, "certificateRefs").iter().map(|r| certificate_ref(r, &namespace)).collect(),
                allowed_namespaces: if allowed.is_empty() { "Same".to_string() } else { allowed.to_string() },
                attached_routes: st.and_then(|s| s.get("attachedRoutes")).and_then(Value::as_i64),
                problem: failing(&conditions, "Its controller has not reported on this listener"),
                conditions,
                protocol,
                name,
            }
        })
        .collect();
    let conditions = conditions(status, obj.metadata.generation);
    let problem = failing(&conditions, "No controller has reported on it: is its GatewayClass's controller running?").or_else(|| {
        listeners.iter().find_map(|l| l.problem.as_ref().map(|p| format!("Listener {}: {p}", l.name)))
    });
    let (age_days, age_seconds, created_at) = age(obj);
    GatewayInfo {
        name: obj.metadata.name.clone().unwrap_or_default(),
        class: json_str(spec, "gatewayClassName").to_string(),
        addresses: items(status, "addresses").iter().map(|a| json_str(Some(a), "value").to_string()).filter(|a| !a.is_empty()).collect(),
        attached_routes: listeners.iter().filter_map(|l| l.attached_routes).sum(),
        healthy: problem.is_none(),
        problem,
        conditions,
        listeners,
        namespace,
        age_days,
        age_seconds,
        created_at,
    }
}

/// A parent reference with the API's defaults filled in, so the spec's and
/// the status's copies compare equal however much of it either spelled out.
#[derive(PartialEq, Debug)]
struct ParentRef {
    group: String,
    kind: String,
    namespace: String,
    name: String,
    section: String,
    port: Option<i64>,
}

fn parent_ref(r: Option<&Value>, route_ns: &str) -> ParentRef {
    let or = |v: &str, d: &str| if v.is_empty() { d.to_string() } else { v.to_string() };
    ParentRef {
        group: or(json_str(r, "group"), GROUP),
        kind: or(json_str(r, "kind"), "Gateway"),
        namespace: or(json_str(r, "namespace"), route_ns),
        name: json_str(r, "name").to_string(),
        section: json_str(r, "sectionName").to_string(),
        port: r.and_then(|r| r.get("port")).and_then(Value::as_i64),
    }
}

/// A route's parent as listed, back as the reference its spec gave.
fn parent_ref_of(p: &RouteParentInfo) -> ParentRef {
    ParentRef { group: p.group.clone(), kind: p.kind.clone(), namespace: p.namespace.clone(), name: p.name.clone(), section: p.section_name.clone(), port: p.port }
}

/// `GET PathPrefix /api header x-env=canary query v=2`; an empty match is
/// the API's default, every path.
fn http_match(m: &Value) -> String {
    let mut parts = Vec::new();
    let method = json_str(Some(m), "method");
    if !method.is_empty() {
        parts.push(method.to_string());
    }
    let path = m.get("path");
    let (kind, value) = (json_str(path, "type"), json_str(path, "value"));
    parts.push(format!("{} {}", if kind.is_empty() { "PathPrefix" } else { kind }, if value.is_empty() { "/" } else { value }));
    parts.extend(header_matches(m, "headers", "header"));
    parts.extend(header_matches(m, "queryParams", "query"));
    parts.join(" ")
}

/// `service/method`, a `*` for whichever is left out.
fn grpc_match(m: &Value) -> String {
    let method = m.get("method");
    let (service, name) = (json_str(method, "service"), json_str(method, "method"));
    let mut parts = vec![match (service, name) {
        ("", "") => "any method".to_string(),
        (s, "") => format!("{s}/*"),
        ("", n) => format!("*/{n}"),
        (s, n) => format!("{s}/{n}"),
    }];
    if json_str(method, "type") == "RegularExpression" {
        parts[0].push_str(" (regex)");
    }
    parts.extend(header_matches(m, "headers", "header"));
    parts.join(" ")
}

/// A match's headers or query parameters as sorted `type name=value`, with
/// the names lowercased where they are header names, which compare without
/// regard to case.
fn predicate_keys(m: &Value, key: &str, fold_names: bool) -> String {
    let mut keys: Vec<String> = items(Some(m), key)
        .iter()
        .map(|h| {
            let kind = json_str(Some(h), "type");
            let name = json_str(Some(h), "name");
            let name = if fold_names { name.to_ascii_lowercase() } else { name.to_string() };
            format!("{} {name}={}", if kind.is_empty() { "Exact" } else { kind }, json_str(Some(h), "value"))
        })
        .collect();
    keys.sort();
    keys.join(",")
}

/// An HTTPRoute match as a key that two matches selecting the same requests
/// share, however their headers and query parameters are ordered, their
/// header names cased, or their defaults spelled out. A PathPrefix ignores a
/// trailing `/`, as the API defines it.
fn http_match_key(m: &Value) -> String {
    let path = m.get("path");
    let kind = Some(json_str(path, "type")).filter(|k| !k.is_empty()).unwrap_or("PathPrefix");
    let mut value = Some(json_str(path, "value")).filter(|v| !v.is_empty()).unwrap_or("/");
    if kind == "PathPrefix" {
        value = Some(value.trim_end_matches('/')).filter(|v| !v.is_empty()).unwrap_or("/");
    }
    format!("{}|{kind} {value}|{}|{}", json_str(Some(m), "method"), predicate_keys(m, "headers", true), predicate_keys(m, "queryParams", false))
}

/// A GRPCRoute match as a key, as `http_match_key` is.
fn grpc_match_key(m: &Value) -> String {
    let method = m.get("method");
    let kind = Some(json_str(method, "type")).filter(|k| !k.is_empty()).unwrap_or("Exact");
    format!("{kind} {}/{}|{}", json_str(method, "service"), json_str(method, "method"), predicate_keys(m, "headers", true))
}

fn header_matches(m: &Value, key: &str, label: &str) -> Vec<String> {
    items(Some(m), key)
        .iter()
        .map(|h| {
            let op = if json_str(Some(h), "type") == "RegularExpression" { "~" } else { "=" };
            format!("{label} {}{op}{}", json_str(Some(h), "name"), json_str(Some(h), "value"))
        })
        .collect()
}

fn backend(b: &Value, route_ns: &str) -> RouteBackendInfo {
    let kind = json_str(Some(b), "kind");
    let ns = json_str(Some(b), "namespace");
    RouteBackendInfo {
        group: json_str(Some(b), "group").to_string(),
        kind: if kind.is_empty() { "Service".to_string() } else { kind.to_string() },
        namespace: if ns.is_empty() { route_ns.to_string() } else { ns.to_string() },
        name: json_str(Some(b), "name").to_string(),
        port: b.get("port").and_then(Value::as_i64),
        weight: b.get("weight").and_then(Value::as_i64),
    }
}

/// The backends a rule mirrors requests to, by its own RequestMirror filters
/// and its backends'.
fn mirror_backends(rule: &Value, route_ns: &str) -> Vec<RouteBackendInfo> {
    let of_backends: Vec<Value> = items(Some(rule), "backendRefs").iter().flat_map(|b| items(Some(b), "filters")).collect();
    items(Some(rule), "filters")
        .into_iter()
        .chain(of_backends)
        .filter(|f| json_str(Some(f), "type") == "RequestMirror")
        .filter_map(|f| f.get("requestMirror").and_then(|m| m.get("backendRef")).map(|b| backend(b, route_ns)))
        .collect()
}

fn filter_text(f: &Value) -> String {
    let kind = json_str(Some(f), "type").to_string();
    match kind.as_str() {
        "ExtensionRef" => {
            let r = f.get("extensionRef");
            format!("ExtensionRef {}/{}", json_str(r, "kind"), json_str(r, "name"))
        }
        "RequestRedirect" => {
            let r = f.get("requestRedirect");
            let code = r.and_then(|r| r.get("statusCode")).and_then(Value::as_i64);
            let to = [json_str(r, "scheme"), json_str(r, "hostname")].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("://");
            match (to.is_empty(), code) {
                (true, None) => kind,
                (true, Some(c)) => format!("RequestRedirect {c}"),
                (false, None) => format!("RequestRedirect to {to}"),
                (false, Some(c)) => format!("RequestRedirect {c} to {to}"),
            }
        }
        _ => kind,
    }
}

pub(crate) fn route_info(kind: &str, obj: &DynamicObject) -> RouteInfo {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let spec = obj.data.get("spec");
    let reported = items(obj.data.get("status"), "parents");
    let parents: Vec<RouteParentInfo> = items(spec, "parentRefs")
        .iter()
        .map(|p| {
            let r = parent_ref(Some(p), &namespace);
            // Each controller that serves the parent reports its own entry.
            let entries: Vec<&Value> = reported.iter().filter(|s| parent_ref(s.get("parentRef"), &namespace) == r).collect();
            let conditions: Vec<PodConditionInfo> = entries.iter().flat_map(|s| conditions(Some(s), obj.metadata.generation)).collect();
            let section = match (r.section.as_str(), r.port) {
                ("", None) => String::new(),
                (s, None) => s.to_string(),
                ("", Some(port)) => format!("port {port}"),
                (s, Some(port)) => format!("{s}, port {port}"),
            };
            RouteParentInfo {
                controller: entries.first().map(|s| json_str(Some(s), "controllerName").to_string()).unwrap_or_default(),
                problem: failing(&conditions, "No controller has reported on it: the parent may not exist, or its controller is not running"),
                conditions,
                section,
                section_name: r.section.clone(),
                port: r.port,
                group: r.group,
                kind: r.kind,
                namespace: r.namespace,
                name: r.name,
            }
        })
        .collect();
    let rules: Vec<RouteRuleInfo> = items(spec, "rules")
        .iter()
        .map(|rule| {
            let matches = items(Some(rule), "matches");
            RouteRuleInfo {
                name: json_str(Some(rule), "name").to_string(),
                matches: match kind {
                    "HTTPRoute" if matches.is_empty() => vec![http_match(&Value::Null)],
                    "HTTPRoute" => matches.iter().map(http_match).collect(),
                    "GRPCRoute" if matches.is_empty() => vec!["any method".to_string()],
                    "GRPCRoute" => matches.iter().map(grpc_match).collect(),
                    _ => Vec::new(),
                },
                match_keys: match kind {
                    "HTTPRoute" if matches.is_empty() => vec![http_match_key(&Value::Null)],
                    "HTTPRoute" => matches.iter().map(http_match_key).collect(),
                    "GRPCRoute" if matches.is_empty() => vec![grpc_match_key(&Value::Null)],
                    "GRPCRoute" => matches.iter().map(grpc_match_key).collect(),
                    // A TLS, TCP or UDP rule takes every connection its
                    // listener gives it.
                    _ => vec!["*".to_string()],
                },
                filters: items(Some(rule), "filters").iter().map(filter_text).collect(),
                backends: items(Some(rule), "backendRefs").iter().map(|b| backend(b, &namespace)).collect(),
            }
        })
        .collect();
    let problem = if parents.is_empty() {
        Some("It names no parent, so no Gateway serves it".to_string())
    } else {
        parents.iter().find_map(|p| p.problem.as_ref().map(|m| format!("{}/{}: {m}", p.namespace, p.name)))
    };
    let (age_days, age_seconds, created_at) = age(obj);
    RouteInfo {
        kind: kind.to_string(),
        name: obj.metadata.name.clone().unwrap_or_default(),
        hostnames: strings(spec, "hostnames"),
        healthy: problem.is_none(),
        problem,
        parents,
        rules,
        namespace,
        age_days,
        age_seconds,
        created_at,
    }
}

/// Lists one kind at the version discovery found, or nothing when the kind
/// is not served here (an experimental route on a standard-channel install).
async fn list_kind(client: &kube::Client, served: &[ApiResource], kind: &str) -> Result<Vec<DynamicObject>, String> {
    let Some(ar) = served.iter().find(|ar| ar.kind == kind) else {
        return Ok(Vec::new());
    };
    let api: Api<DynamicObject> = Api::all_with(client.clone(), ar);
    api.list(&ListParams::default()).await.map(|l| l.items).map_err(|e| format!("Failed to list {kind}s: {e}"))
}

/// The kinds the group serves, each at its most stable version (v1 for an
/// HTTPRoute, v1alpha2 for a TCPRoute on the same cluster); `None` when the
/// group is not served at all.
async fn discover(client: &kube::Client) -> Result<Option<Vec<ApiResource>>, String> {
    match kube::discovery::group(client, GROUP).await {
        Ok(g) => Ok(Some(g.resources_by_stability().into_iter().map(|(ar, _)| ar).collect())),
        Err(kube::Error::Discovery(DiscoveryError::MissingApiGroup(_))) => Ok(None),
        Err(e) => Err(format!("Failed to discover the Gateway API: {e}")),
    }
}

/// Every class, Gateway and route the group serves, each kind on its own:
/// one that fails to list is named in `error` and the rest are still here.
async fn read_all(client: &kube::Client, served: &[ApiResource]) -> GatewayApiResult {
    let (classes, gateways, http, grpc, tls, tcp, udp) = tokio::join!(
        list_kind(client, served, "GatewayClass"),
        list_kind(client, served, "Gateway"),
        list_kind(client, served, ROUTE_KINDS[0]),
        list_kind(client, served, ROUTE_KINDS[1]),
        list_kind(client, served, ROUTE_KINDS[2]),
        list_kind(client, served, ROUTE_KINDS[3]),
        list_kind(client, served, ROUTE_KINDS[4]),
    );
    let mut errors = Vec::new();
    let mut take = |r: Result<Vec<DynamicObject>, String>| r.unwrap_or_else(|e| {
        errors.push(e);
        Vec::new()
    });
    let classes = take(classes).iter().map(class_info).collect();
    let gateways = take(gateways).iter().map(gateway_info).collect();
    let mut routes = Vec::new();
    for (kind, list) in ROUTE_KINDS.iter().zip([http, grpc, tls, tcp, udp]) {
        routes.extend(take(list).iter().map(|o| route_info(kind, o)));
    }
    GatewayApiResult {
        // The group is served; a kind it does not serve is simply empty.
        installed: true,
        error: if errors.is_empty() { None } else { Some(errors.join("; ")) },
        classes,
        gateways,
        routes,
    }
}

pub async fn get_gateway_api(context_name: &str) -> Result<GatewayApiResult, String> {
    let client = client_for_context(context_name).await?;
    Ok(match discover(&client).await? {
        Some(served) => read_all(&client, &served).await,
        None => GatewayApiResult::default(),
    })
}

// ---- Diagnosis -------------------------------------------------------------

/// The labels an implementation puts on what it creates for one Gateway (its
/// proxies and the Service in front of them) as label selectors, and whether
/// to look in the Gateway's own namespace only: Envoy Gateway's, which names
/// the Gateway's namespace because the proxies live in its own; the API's
/// `gateway-name` (Istio, NGINX Gateway Fabric); Cilium's; Contour's.
fn data_plane_selectors(namespace: &str, name: &str) -> Vec<(String, bool)> {
    // A label value is at most 63 characters, so a longer name is on nothing.
    if name.len() > 63 {
        return Vec::new();
    }
    vec![
        (format!("gateway.envoyproxy.io/owning-gateway-name={name},gateway.envoyproxy.io/owning-gateway-namespace={namespace}"), false),
        (format!("gateway.networking.k8s.io/gateway-name={name}"), true),
        (format!("io.cilium.gateway/owning-gateway={name}"), true),
        (format!("projectcontour.io/owning-gateway-name={name}"), true),
    ]
}

/// The label keys that mark a workload as one Gateway's data plane, not a controller.
const DATA_PLANE_KEYS: &[&str] =
    &["gateway.envoyproxy.io/owning-gateway-name", "gateway.networking.k8s.io/gateway-name", "io.cilium.gateway/owning-gateway", "projectcontour.io/owning-gateway-name"];

/// Well-known controllers' images, by the prefix of the controller name
/// their GatewayClasses carry, for one whose args do not name it: Envoy
/// Gateway reads it from a config file, istiod and the Cilium operator have
/// it built in.
const KNOWN_CONTROLLER_IMAGES: &[(&str, &str)] = &[
    ("gateway.envoyproxy.io/", "envoyproxy/gateway"),
    ("istio.io/", "istio/pilot"),
    ("io.cilium/", "cilium/operator"),
    ("gateway.nginx.org/", "nginx-gateway-fabric"),
    ("projectcontour.io/", "projectcontour/contour"),
    ("traefik.io/", "traefik"),
    ("konghq.com/", "kubernetes-ingress-controller"),
    ("alb.networking.azure.io/", "alb-controller"),
];

const NAMED_IN_ARGS: &str = "its args name the controller";
const BY_IMAGE: &str = "its image is this controller's";

/// How far back into a controller's log to look and how much of it to read.
/// Envoy Gateway logs every object it processes at info, megabytes an hour
/// on a busy cluster, so the newest lines are taken rather than the first.
const CONTROLLER_LOG_SECONDS: i64 = 3600;
const CONTROLLER_LOG_LINES: i64 = 40_000;
const CONTROLLER_LOG_BYTES: i64 = 8 * 1024 * 1024;

/// A proxy workload a controller created for one Gateway.
pub struct DataPlaneWorkload {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub desired: i32,
    pub ready: i32,
}

/// What a controller created for one Gateway, found by its labels.
#[derive(Default)]
pub struct GatewayDataPlane {
    pub workloads: Vec<DataPlaneWorkload>,
    pub services: Vec<k8s_openapi::api::core::v1::Service>,
    pub pods: Vec<k8s_openapi::api::core::v1::Pod>,
    /// The events of a LoadBalancer Service still without an address, which
    /// say why the cloud has not given it one.
    pub service_events: Vec<EventInfo>,
    pub errors: Vec<String>,
}

/// A listener's certificate reference, read.
pub struct GatewayCertificate {
    pub listener: String,
    /// The hostname the listener serves, which the certificate must cover;
    /// empty for any.
    pub hostname: String,
    /// Empty for the core group.
    pub group: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    /// The Secret by its keys and certificate; `None` for another kind.
    pub secret: Option<Result<k8s::IngressTlsSecret, String>>,
    /// For a reference into another namespace: the ReferenceGrant that
    /// permits it, `None` inside if none does.
    pub grant: Option<Result<Option<String>, String>>,
}

/// Everything a Gateway diagnosis reads. Only the Gateway is required; each
/// of the rest fails on its own and the payload says so.
pub struct GatewayDiagnostics {
    pub gateway: GatewayInfo,
    pub manifest: String,
    /// Its class as listed; `None` when no GatewayClass has that name.
    pub class: Option<GatewayClassInfo>,
    /// Kinds that failed to list, which may leave the class or routes short.
    pub read_error: Option<String>,
    pub certificates: Vec<GatewayCertificate>,
    pub data_plane: GatewayDataPlane,
    /// The routes that name it as a parent, failing first.
    pub routes: Vec<RouteInfo>,
    pub controller: String,
    pub controllers: Result<Vec<k8s::IngressControllerWorkload>, String>,
    pub controller_logs: Option<Result<(usize, Vec<String>), String>>,
    pub events: Result<Vec<EventInfo>, String>,
}

/// One listener of a parent Gateway, checked against a route.
pub struct ListenerFit {
    pub name: String,
    pub protocol: String,
    pub port: i64,
    pub hostname: String,
    /// The parentRef's sectionName and port pick it, or name none.
    pub selected: bool,
    /// Why its allowedRoutes refuses the route's namespace or kind.
    pub refusal: Option<String>,
    /// The hostnames the route is served for on it, each the narrower of the
    /// route's and the listener's; `""` is any host. Empty for a TCP or UDP
    /// route, which has none to match.
    pub hostnames: Vec<String>,
    /// Why it serves none of the route's hostnames.
    pub hostname_refusal: Option<String>,
}

/// A parent a route names, with the Gateway it is and its listeners' fit.
pub struct ParentFit {
    pub parent: RouteParentInfo,
    /// The Gateway, as listed; `None` when it names another kind, or no such
    /// Gateway exists (`missing`).
    pub gateway: Option<GatewayInfo>,
    pub missing: bool,
    /// Why the Gateway could not be read, when it could not.
    pub read_error: Option<String>,
    pub listeners: Vec<ListenerFit>,
}

/// A backend a route sends to, read.
pub struct RouteBackendCheck {
    pub backend: RouteBackendInfo,
    /// Only a RequestMirror filter sends to it: requests are copied to it
    /// and its answers dropped.
    pub mirror: bool,
    /// The Service and its endpoints, for a core Service.
    pub service: Option<k8s::IngressBackend>,
    /// For a backend in another namespace: the ReferenceGrant that permits
    /// it, `None` inside if none does.
    pub grant: Option<Result<Option<String>, String>>,
}

/// Another route on a listener that admits this one, for a hostname both
/// are served for.
pub struct SharedRoute {
    pub route: RouteInfo,
    /// Each such listener, as `namespace/gateway listener name`, with the
    /// hostnames both are served for on it (`""`: any host).
    pub listeners: Vec<(String, Vec<String>)>,
}

/// Everything a route diagnosis reads. Only the route is required.
pub struct RouteDiagnostics {
    pub route: RouteInfo,
    pub manifest: String,
    pub read_error: Option<String>,
    pub parents: Vec<ParentFit>,
    pub backends: Vec<RouteBackendCheck>,
    /// Other routes a listener that admits this one also admits, for a
    /// hostname both are served for, with a match this one also has: the
    /// ones claiming the same requests.
    pub same_match: Vec<SharedRoute>,
    /// How many other routes share such a listener and hostname at all.
    pub sharing_hostname: usize,
    /// Why routes in other namespaces could not be checked against a
    /// listener that admits namespaces by label.
    pub sharing_error: Option<String>,
    pub controllers: Result<Vec<k8s::IngressControllerWorkload>, String>,
    pub controller_logs: Option<Result<(usize, Vec<String>), String>>,
    pub events: Result<Vec<EventInfo>, String>,
}

/// Whether two hostnames, either of them a `*.` wildcard, can name the same
/// host. A wildcard matches any name ending in its suffix, at any depth: the
/// API's rule, unlike a certificate's one label.
pub(crate) fn hostnames_intersect(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    match (a.strip_prefix('*'), b.strip_prefix('*')) {
        (None, None) => a == b,
        (Some(suffix), None) => b.ends_with(suffix),
        (None, Some(suffix)) => a.ends_with(suffix),
        (Some(x), Some(y)) => x.ends_with(y) || y.ends_with(x),
    }
}

/// The hosts two hostnames both name, as the narrower of the two: `""` is
/// any host. `None` when they name none in common.
pub(crate) fn hostname_overlap(a: &str, b: &str) -> Option<String> {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    if a.is_empty() || b.is_empty() {
        return Some(if a.is_empty() { b } else { a });
    }
    if !hostnames_intersect(&a, &b) {
        return None;
    }
    Some(match (a.starts_with('*'), b.starts_with('*')) {
        (true, false) => b,
        (false, _) => a,
        (true, true) => if a.len() >= b.len() { a } else { b },
    })
}

/// Each host both lists name, once.
fn hostnames_overlap(a: &[String], b: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for h in a.iter().flat_map(|x| b.iter().filter_map(move |y| hostname_overlap(x, y))) {
        if !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// Why a listener's `allowedRoutes.namespaces` refuses a route, if it does.
fn namespace_refusal(namespaces: Option<&Value>, gateway_ns: &str, route_ns: &str, labels: &Result<BTreeMap<String, String>, String>) -> Option<String> {
    match json_str(namespaces, "from") {
        "All" => None,
        "Selector" => {
            let selector: LabelSelector = namespaces.and_then(|n| n.get("selector")).and_then(|s| serde_json::from_value(s.clone()).ok()).unwrap_or_default();
            let query = k8s::label_selector_query(&selector);
            match labels {
                Ok(l) if k8s::label_selector_matches(&selector, Some(l)) => None,
                Ok(_) => Some(format!("it admits routes from namespaces labelled {query}, and {route_ns}'s labels do not match")),
                Err(e) => Some(format!("it admits routes from namespaces labelled {query}, and {route_ns}'s labels could not be read: {e}")),
            }
        }
        // Same, the default.
        _ => (route_ns != gateway_ns).then(|| format!("it admits routes from its own namespace ({gateway_ns}) only, and the route is in {route_ns}")),
    }
}

/// Why a listener refuses a route's kind, if it does: by the kinds its
/// allowedRoutes lists, else those its controller reports supporting on it,
/// else its protocol's defaults.
fn kind_refusal(allowed: Option<&Value>, status: Option<&Value>, protocol: &str, kind: &str) -> Option<String> {
    let ours = |k: &&Value| matches!(json_str(Some(k), "group"), "" | GROUP);
    let names = |list: Vec<Value>| list.iter().filter(ours).map(|k| json_str(Some(k), "kind").to_string()).collect::<Vec<_>>();
    let (kinds, source) = if !items(allowed, "kinds").is_empty() {
        (names(items(allowed, "kinds")), "its allowedRoutes.kinds")
    } else if !items(status, "supportedKinds").is_empty() {
        (names(items(status, "supportedKinds")), "the kinds its controller supports on it")
    } else {
        let defaults: &[&str] = match protocol {
            "HTTP" | "HTTPS" => &["HTTPRoute", "GRPCRoute"],
            "TLS" => &["TLSRoute", "TCPRoute"],
            "TCP" => &["TCPRoute"],
            "UDP" => &["UDPRoute"],
            _ => return None,
        };
        (defaults.iter().map(|k| k.to_string()).collect(), "its protocol's route kinds")
    };
    (!kinds.iter().any(|k| k == kind)).then(|| format!("{source} ({}) do not include {kind}", if kinds.is_empty() { "none".to_string() } else { kinds.join(", ") }))
}

/// The hostnames a route is served for on a listener, or why there are
/// none: each of the route's narrowed to the listener's (`*.example.com`
/// under `a.example.com` is served for `a.example.com`), or the listener's
/// own for a route that names none, `""` being any host. TCP and UDP routes
/// have no hostnames to match.
fn hostname_fit(listener: &str, route: &[String], kind: &str) -> (Vec<String>, Option<String>) {
    if !matches!(kind, "HTTPRoute" | "GRPCRoute" | "TLSRoute") {
        return (Vec::new(), None);
    }
    if route.is_empty() {
        return (vec![listener.to_ascii_lowercase()], None);
    }
    let fit = hostnames_overlap(&[listener.to_string()], route);
    let refusal = fit.is_empty().then(|| format!("none of the route's hostnames is under its hostname {listener}"));
    (fit, refusal)
}

/// Whether a listener admits routes from namespaces by their labels.
fn selects_namespaces(gateway: &DynamicObject, listener: &str) -> bool {
    items(gateway.data.get("spec"), "listeners")
        .iter()
        .any(|l| json_str(Some(l), "name") == listener && json_str(l.get("allowedRoutes").and_then(|a| a.get("namespaces")), "from") == "Selector")
}

/// Each listener of a parent Gateway, checked against the route.
fn listener_fits(gateway: &DynamicObject, r: &ParentRef, kind: &str, route_ns: &str, labels: &Result<BTreeMap<String, String>, String>, hostnames: &[String]) -> Vec<ListenerFit> {
    let gateway_ns = gateway.metadata.namespace.clone().unwrap_or_default();
    let status = items(gateway.data.get("status"), "listeners");
    items(gateway.data.get("spec"), "listeners")
        .iter()
        .map(|l| {
            let name = json_str(Some(l), "name").to_string();
            let port = l.get("port").and_then(Value::as_i64).unwrap_or_default();
            let protocol = json_str(Some(l), "protocol").to_string();
            let hostname = json_str(Some(l), "hostname").to_string();
            let allowed = l.get("allowedRoutes");
            let st = status.iter().find(|s| json_str(Some(s), "name") == name);
            let refusal = namespace_refusal(allowed.and_then(|a| a.get("namespaces")), &gateway_ns, route_ns, labels).or_else(|| kind_refusal(allowed, st, &protocol, kind));
            let (fit, hostname_refusal) = hostname_fit(&hostname, hostnames, kind);
            ListenerFit {
                selected: (r.section.is_empty() || r.section == name) && r.port.is_none_or(|p| p == port),
                refusal,
                hostnames: fit,
                hostname_refusal,
                name,
                protocol,
                port,
                hostname,
            }
        })
        .collect()
}

/// The ReferenceGrant in `to_ns` that lets a `from_kind` in `from_ns` refer
/// to the named object, if any does.
fn permitting_grant(grants: &[DynamicObject], from_kind: &str, from_ns: &str, to_group: &str, to_kind: &str, to_ns: &str, to_name: &str) -> Option<String> {
    grants
        .iter()
        .filter(|g| g.metadata.namespace.as_deref() == Some(to_ns))
        .find(|g| {
            let spec = g.data.get("spec");
            items(spec, "from").iter().any(|f| json_str(Some(f), "group") == GROUP && json_str(Some(f), "kind") == from_kind && json_str(Some(f), "namespace") == from_ns)
                && items(spec, "to").iter().any(|t| {
                    let name = json_str(Some(t), "name");
                    json_str(Some(t), "group") == to_group && json_str(Some(t), "kind") == to_kind && (name.is_empty() || name == to_name)
                })
        })
        .map(|g| g.metadata.name.clone().unwrap_or_default())
}

/// Every ReferenceGrant, when a reference crosses namespaces. Not served is
/// an empty list: then nothing can permit one.
async fn read_grants(client: &kube::Client, served: &[ApiResource], needed: bool) -> Result<Vec<DynamicObject>, String> {
    if !needed {
        return Ok(Vec::new());
    }
    list_kind(client, served, "ReferenceGrant").await
}

fn grant_for(grants: &Result<Vec<DynamicObject>, String>, from_kind: &str, from_ns: &str, to_group: &str, to_kind: &str, to_ns: &str, to_name: &str) -> Option<Result<Option<String>, String>> {
    if from_ns == to_ns {
        return None;
    }
    Some(match grants {
        Ok(g) => Ok(permitting_grant(g, from_kind, from_ns, to_group, to_kind, to_ns, to_name)),
        Err(e) => Err(e.clone()),
    })
}

async fn object_events(client: &kube::Client, kind: &str, namespace: &str, name: &str) -> Result<Vec<EventInfo>, String> {
    use k8s_openapi::api::core::v1::Event;
    let api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let fields = format!("involvedObject.kind={kind},involvedObject.name={name},involvedObject.namespace={namespace}");
    api.list(&ListParams::default().fields(&fields))
        .await
        .map(|l| {
            let mut items = l.items;
            items.sort_by(|a, b| k8s::event_last_seen(b).cmp(&k8s::event_last_seen(a)));
            items.into_iter().map(k8s::event_to_info).collect()
        })
        .map_err(|e| format!("Failed to list events for '{name}': {e}"))
}

/// The proxies and Services a controller created for one Gateway.
async fn read_data_plane(client: &kube::Client, namespace: &str, name: &str) -> GatewayDataPlane {
    use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
    use k8s_openapi::api::core::v1::{Pod, Service};
    fn api<K>(client: &kube::Client, namespace: &str, own: bool) -> Api<K>
    where
        K: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope, DynamicType = ()> + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
    {
        if own {
            Api::namespaced(client.clone(), namespace)
        } else {
            Api::all(client.clone())
        }
    }
    let mut dp = GatewayDataPlane::default();
    let mut seen = std::collections::HashSet::new();
    for (selector, own) in data_plane_selectors(namespace, name) {
        let params = ListParams::default().labels(&selector);
        let (deployment_api, daemonset_api) = (api::<Deployment>(client, namespace, own), api::<DaemonSet>(client, namespace, own));
        let (service_api, pod_api) = (api::<Service>(client, namespace, own), api::<Pod>(client, namespace, own));
        let (deployments, daemonsets, services, pods) =
            tokio::join!(deployment_api.list(&params), daemonset_api.list(&params), service_api.list(&params), pod_api.list(&params));
        let key = |kind: &str, m: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta| {
            format!("{kind}/{}/{}", m.namespace.as_deref().unwrap_or_default(), m.name.as_deref().unwrap_or_default())
        };
        let mut failed = |what: &str, e: kube::Error| dp.errors.push(format!("Failed to list {what} labelled {selector}: {e}"));
        let deployments = deployments.map_err(|e| failed("Deployments", e)).map(|l| l.items).unwrap_or_default();
        let daemonsets = daemonsets.map_err(|e| failed("DaemonSets", e)).map(|l| l.items).unwrap_or_default();
        let services = services.map_err(|e| failed("Services", e)).map(|l| l.items).unwrap_or_default();
        let pods = pods.map_err(|e| failed("pods", e)).map(|l| l.items).unwrap_or_default();
        for d in deployments {
            if seen.insert(key("Deployment", &d.metadata)) {
                dp.workloads.push(DataPlaneWorkload {
                    kind: "Deployment".to_string(),
                    namespace: d.metadata.namespace.clone().unwrap_or_default(),
                    name: d.metadata.name.clone().unwrap_or_default(),
                    desired: d.spec.replicas.unwrap_or(1),
                    ready: d.status.as_ref().and_then(|s| s.ready_replicas).unwrap_or(0),
                });
            }
        }
        for d in daemonsets {
            if seen.insert(key("DaemonSet", &d.metadata)) {
                let status = d.status.clone().unwrap_or_default();
                dp.workloads.push(DataPlaneWorkload {
                    kind: "DaemonSet".to_string(),
                    namespace: d.metadata.namespace.clone().unwrap_or_default(),
                    name: d.metadata.name.clone().unwrap_or_default(),
                    desired: status.desired_number_scheduled,
                    ready: status.number_ready,
                });
            }
        }
        for svc in services {
            if seen.insert(key("Service", &svc.metadata)) {
                dp.services.push(svc);
            }
        }
        for p in pods {
            if seen.insert(key("Pod", &p.metadata)) {
                dp.pods.push(p);
            }
        }
    }
    // Why a LoadBalancer has no address is in its events.
    for svc in &dp.services {
        let pending = svc.spec.as_ref().and_then(|s| s.type_.as_deref()) == Some("LoadBalancer")
            && svc.status.as_ref().and_then(|s| s.load_balancer.as_ref()).and_then(|l| l.ingress.as_ref()).is_none_or(Vec::is_empty);
        if pending {
            let (ns, name) = (svc.metadata.namespace.clone().unwrap_or_default(), svc.metadata.name.clone().unwrap_or_default());
            match object_events(client, "Service", &ns, &name).await {
                Ok(events) => dp.service_events.extend(events),
                Err(e) => dp.errors.push(e),
            }
        }
    }
    dp
}

/// The container that makes a Deployment one of these controllers, and why:
/// its args or env name the controller, or its image is a well-known one's.
fn controller_container(d: &k8s_openapi::api::apps::v1::Deployment, controller: &str) -> Option<(String, &'static str)> {
    let containers = &d.spec.template.spec.as_ref()?.containers;
    let named = containers.iter().find(|c| {
        c.command.iter().flatten().chain(c.args.iter().flatten()).any(|a| a.contains(controller))
            || c.env.iter().flatten().any(|e| e.value.as_deref().is_some_and(|v| v.contains(controller)))
    });
    if let Some(c) = named {
        return Some((c.name.clone(), NAMED_IN_ARGS));
    }
    let image = KNOWN_CONTROLLER_IMAGES.iter().find(|(prefix, _)| controller.starts_with(prefix)).map(|(_, image)| *image)?;
    containers.iter().find(|c| c.image.as_deref().is_some_and(|i| i.contains(image))).map(|c| (c.name.clone(), BY_IMAGE))
}

/// The Deployments that run these controllers, leaving out every Gateway's
/// data plane. For each controller, one found by an image is kept only when
/// none names it in its args.
async fn find_controllers(client: &kube::Client, controllers: &[String]) -> Result<Vec<k8s::IngressControllerWorkload>, String> {
    use k8s_openapi::api::apps::v1::Deployment;
    if controllers.is_empty() {
        return Ok(Vec::new());
    }
    let api: Api<Deployment> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.map_err(|e| format!("Failed to list Deployments: {e}"))?;
    let candidates: Vec<&Deployment> = list.items.iter().filter(|d| !d.metadata.labels.as_ref().is_some_and(|l| DATA_PLANE_KEYS.iter().any(|k| l.contains_key(*k)))).collect();
    let mut found: Vec<k8s::IngressControllerWorkload> = Vec::new();
    for controller in controllers {
        let mut these: Vec<k8s::IngressControllerWorkload> = candidates
            .iter()
            .filter_map(|d| {
                let (container, matched_by) = controller_container(d, controller)?;
                let spec = &d.spec;
                Some(k8s::IngressControllerWorkload {
                    kind: "Deployment".to_string(),
                    namespace: d.metadata.namespace.clone().unwrap_or_default(),
                    name: d.metadata.name.clone().unwrap_or_default(),
                    desired: spec.replicas.unwrap_or(1),
                    ready: d.status.as_ref().and_then(|s| s.ready_replicas).unwrap_or(0),
                    matched_by: matched_by.to_string(),
                    selector: k8s::label_selector_query(&spec.selector),
                    container,
                })
            })
            .collect();
        if these.iter().any(|w| w.matched_by == NAMED_IN_ARGS) {
            these.retain(|w| w.matched_by == NAMED_IN_ARGS);
        }
        for w in these {
            if !found.iter().any(|f| f.namespace == w.namespace && f.name == w.name) {
                found.push(w);
            }
        }
    }
    Ok(found)
}

/// Whether a controller's log line is about these objects: as an Ingress
/// controller's would be, by `namespace/name` or by namespace and name
/// fields, or by the `kind/namespace/name` Envoy Gateway names a route by in
/// its translated configuration (`httproute/app/web/rule/0`).
pub(crate) fn log_line_is_about(line: &str, kind: &str, namespace: &str, names: &[String]) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_';
    let translated = names.first().is_some_and(|name| {
        let needle = format!("{}/{namespace}/{name}", kind.to_ascii_lowercase());
        line.match_indices(&needle).any(|(at, _)| !line[at + needle.len()..].chars().next().is_some_and(word))
    });
    translated || k8s::ingress_log_line_is_about(line, namespace, names)
}

async fn controller_logs(client: &kube::Client, controllers: &Result<Vec<k8s::IngressControllerWorkload>, String>, is_about: impl Fn(&str) -> bool) -> Option<Result<(usize, Vec<String>), String>> {
    let workloads: Vec<&k8s::IngressControllerWorkload> = controllers.iter().flatten().filter(|w| !w.selector.is_empty()).collect();
    let params = LogParams {
        since_seconds: Some(CONTROLLER_LOG_SECONDS),
        tail_lines: Some(CONTROLLER_LOG_LINES),
        limit_bytes: Some(CONTROLLER_LOG_BYTES),
        ..Default::default()
    };
    k8s::read_controller_logs(client, &workloads, &params, is_about).await
}

/// The object with last-applied dropped, as YAML without managed fields: a
/// manifest for the payload, read after its info was taken.
fn manifest_of(mut obj: DynamicObject) -> Result<String, String> {
    if let Some(a) = obj.metadata.annotations.as_mut() {
        a.remove(k8s::LAST_APPLIED_ANNOTATION);
    }
    Ok(k8s::object_manifest(obj)?.yaml_without_managed_fields)
}

async fn served_and_get(client: &kube::Client, kind: &str, namespace: &str, name: &str) -> Result<(Vec<ApiResource>, DynamicObject), String> {
    let served = discover(client).await?.ok_or_else(|| "The Gateway API is not installed on this cluster".to_string())?;
    let ar = served.iter().find(|ar| ar.kind == kind).ok_or_else(|| format!("{kind} is not served on this cluster"))?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, ar);
    let obj = api.get(name).await.map_err(|e| k8s::get_error(kind, name, e))?;
    Ok((served, obj))
}

fn admits(l: &ListenerFit) -> bool {
    l.selected && l.refusal.is_none() && l.hostname_refusal.is_none()
}

fn object_key(o: &DynamicObject) -> (&str, &str) {
    (o.metadata.namespace.as_deref().unwrap_or_default(), o.metadata.name.as_deref().unwrap_or_default())
}

/// Each parent Gateway that was read, with its listeners that admit the
/// route; a Gateway two parentRefs name is listed once.
fn admitting_listeners<'a>(parents: &'a [ParentFit], gateways: &'a [Result<Option<DynamicObject>, String>]) -> Vec<(&'a DynamicObject, Vec<&'a ListenerFit>)> {
    let mut ours: Vec<(&DynamicObject, Vec<&ListenerFit>)> = Vec::new();
    for (f, raw) in parents.iter().zip(gateways) {
        let Ok(Some(g)) = raw else { continue };
        let admitting = f.listeners.iter().filter(|l| admits(l));
        match ours.iter_mut().find(|(x, _)| object_key(x) == object_key(g)) {
            Some((_, listeners)) => {
                for l in admitting {
                    if !listeners.iter().any(|x| x.name == l.name) {
                        listeners.push(l);
                    }
                }
            }
            None => ours.push((g, admitting.collect())),
        }
    }
    ours.retain(|(_, listeners)| !listeners.is_empty());
    ours
}

/// The Gateway and admitting listeners a parent of another route names, if
/// it is one of these.
fn on_gateway<'a, 'b>(ours: &'b [(&'a DynamicObject, Vec<&'a ListenerFit>)], p: &RouteParentInfo) -> Option<&'b (&'a DynamicObject, Vec<&'a ListenerFit>)> {
    if p.group != GROUP || p.kind != "Gateway" {
        return None;
    }
    ours.iter().find(|(g, _)| object_key(g) == (p.namespace.as_str(), p.name.as_str()))
}

/// The other routes that claim a route's traffic: on a listener that admits
/// it, admitted there themselves, and served there for a host it is too.
/// Each with whether it has one of the route's matches, which makes the two
/// claim the same requests. `labels` are the route's namespace's;
/// `namespace_labels` the others', read when a listener admits by label.
fn shared_routes(
    route: &RouteInfo,
    ours: &[(&DynamicObject, Vec<&ListenerFit>)],
    candidates: &[&RouteInfo],
    labels: &Result<BTreeMap<String, String>, String>,
    namespace_labels: &Result<BTreeMap<String, BTreeMap<String, String>>, String>,
) -> Vec<(SharedRoute, bool)> {
    let any_host = |l: &ListenerFit| if l.hostnames.is_empty() { vec![String::new()] } else { l.hostnames.clone() };
    let match_keys: Vec<&String> = route.rules.iter().flat_map(|r| &r.match_keys).collect();
    let mut sharing: Vec<(SharedRoute, bool)> = Vec::new();
    for o in candidates {
        let their_labels = match (namespace_labels, o.namespace == route.namespace) {
            (_, true) => labels.clone(),
            (Ok(all), false) => Ok(all.get(&o.namespace).cloned().unwrap_or_default()),
            (Err(e), false) => Err(e.clone()),
        };
        let mut on: Vec<(String, Vec<String>)> = Vec::new();
        for p in &o.parents {
            let Some((g, mine)) = on_gateway(ours, p) else { continue };
            let theirs = listener_fits(g, &parent_ref_of(p), &o.kind, &o.namespace, &their_labels, &o.hostnames);
            for l in mine {
                let Some(t) = theirs.iter().find(|t| t.name == l.name && admits(t)) else { continue };
                let hosts = hostnames_overlap(&any_host(l), &any_host(t));
                let at = format!("{}/{} listener {}", p.namespace, p.name, l.name);
                if !hosts.is_empty() && !on.iter().any(|(x, _)| *x == at) {
                    on.push((at, hosts));
                }
            }
        }
        if !on.is_empty() {
            let same = o.kind == route.kind && o.rules.iter().flat_map(|r| &r.match_keys).any(|k| match_keys.contains(&k));
            sharing.push((SharedRoute { route: (*o).clone(), listeners: on }, same));
        }
    }
    sharing
}

fn attached_to(r: &RouteInfo, namespace: &str, name: &str) -> bool {
    r.parents.iter().any(|p| p.group == GROUP && p.kind == "Gateway" && p.namespace == namespace && p.name == name)
}

pub async fn get_gateway_diagnostics(context_name: &str, namespace: &str, name: &str) -> Result<GatewayDiagnostics, String> {
    let client = client_for_context(context_name).await?;
    let (served, obj) = served_and_get(&client, "Gateway", namespace, name).await?;
    let gateway = gateway_info(&obj);

    // Each listener's certificate references, as the spec gives them.
    let mut certificates: Vec<GatewayCertificate> = Vec::new();
    for l in items(obj.data.get("spec"), "listeners") {
        for r in items(l.get("tls"), "certificateRefs") {
            let kind = json_str(Some(&r), "kind");
            let ns = json_str(Some(&r), "namespace");
            certificates.push(GatewayCertificate {
                listener: json_str(Some(&l), "name").to_string(),
                hostname: json_str(Some(&l), "hostname").to_string(),
                group: json_str(Some(&r), "group").to_string(),
                kind: if kind.is_empty() { "Secret".to_string() } else { kind.to_string() },
                namespace: if ns.is_empty() { namespace.to_string() } else { ns.to_string() },
                name: json_str(Some(&r), "name").to_string(),
                secret: None,
                grant: None,
            });
        }
    }
    let is_secret = |c: &GatewayCertificate| c.group.is_empty() && c.kind == "Secret";
    let secrets_fut = futures::future::join_all(certificates.iter().filter(|c| is_secret(c)).map(|c| k8s::read_tls_secret(&client, &c.namespace, &c.name)));
    let crosses = certificates.iter().any(|c| c.namespace != namespace);
    let (all, data_plane, events, secrets, grants) = tokio::join!(
        read_all(&client, &served),
        read_data_plane(&client, namespace, name),
        object_events(&client, "Gateway", namespace, name),
        secrets_fut,
        read_grants(&client, &served, crosses),
    );
    let mut secrets = secrets.into_iter();
    for c in certificates.iter_mut() {
        if is_secret(c) {
            c.secret = secrets.next();
        }
        c.grant = grant_for(&grants, "Gateway", namespace, &c.group, &c.kind, &c.namespace, &c.name);
    }

    let class = all.classes.iter().find(|c| c.name == gateway.class).cloned();
    let controller = class.as_ref().map(|c| c.controller.clone()).unwrap_or_default();
    let mut routes: Vec<RouteInfo> = all.routes.iter().filter(|r| attached_to(r, namespace, name)).cloned().collect();
    routes.sort_by(|a, b| a.healthy.cmp(&b.healthy).then_with(|| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name))));
    let controllers = find_controllers(&client, &[controller.clone()].into_iter().filter(|c| !c.is_empty()).collect::<Vec<_>>()).await;
    let mut about = vec![name.to_string()];
    about.extend(certificates.iter().filter(|c| c.namespace == namespace).map(|c| c.name.clone()));
    let controller_logs = controller_logs(&client, &controllers, |l| log_line_is_about(l, "Gateway", namespace, &about)).await;

    Ok(GatewayDiagnostics {
        manifest: manifest_of(obj)?,
        gateway,
        class,
        read_error: all.error,
        certificates,
        data_plane,
        routes,
        controller,
        controllers,
        controller_logs,
        events,
    })
}

pub async fn get_route_diagnostics(context_name: &str, kind: &str, namespace: &str, name: &str) -> Result<RouteDiagnostics, String> {
    use k8s_openapi::api::core::v1::Namespace;
    if !ROUTE_KINDS.contains(&kind) {
        return Err(format!("{kind} is not a Gateway API route kind"));
    }
    let client = client_for_context(context_name).await?;
    let (served, obj) = served_and_get(&client, kind, namespace, name).await?;
    let route = route_info(kind, &obj);
    let refs: Vec<ParentRef> = items(obj.data.get("spec"), "parentRefs").iter().map(|p| parent_ref(Some(p), namespace)).collect();

    // Each backend once, however many rules send to it, then those only
    // mirrored to.
    let mirrors: Vec<RouteBackendInfo> = items(obj.data.get("spec"), "rules").iter().flat_map(|r| mirror_backends(r, namespace)).collect();
    let mut backends: Vec<(RouteBackendInfo, bool)> = Vec::new();
    for (b, mirror) in route.rules.iter().flat_map(|r| r.backends.iter().cloned()).map(|b| (b, false)).chain(mirrors.into_iter().map(|b| (b, true))) {
        if !backends.iter().any(|(x, _)| x.group == b.group && x.kind == b.kind && x.namespace == b.namespace && x.name == b.name && x.port == b.port) {
            backends.push((b, mirror));
        }
    }
    let core = |b: &RouteBackendInfo| b.group.is_empty() && b.kind == "Service";
    let services_fut = futures::future::join_all(backends.iter().filter(|(b, _)| core(b)).map(|(b, _)| k8s::read_service_backend(&client, &b.namespace, &b.name)));
    let gateway_ar = served.iter().find(|ar| ar.kind == "Gateway").cloned();
    let gateways_fut = futures::future::join_all(refs.iter().map(|r| {
        let client = client.clone();
        let ar = gateway_ar.clone();
        async move {
            match ar {
                Some(ar) if r.group == GROUP && r.kind == "Gateway" => {
                    Api::<DynamicObject>::namespaced_with(client, &r.namespace, &ar).get_opt(&r.name).await.map_err(|e| k8s::get_error("Gateway", &r.name, e))
                }
                _ => Ok(None),
            }
        }
    }));
    let labels_fut = async {
        Api::<Namespace>::all(client.clone())
            .get(namespace)
            .await
            .map(|n| n.metadata.labels.unwrap_or_default())
            .map_err(|e| k8s::get_error("Namespace", namespace, e))
    };
    let crosses = backends.iter().any(|(b, _)| b.namespace != namespace);
    let (all, services, gateways, labels, events, grants) = tokio::join!(
        read_all(&client, &served),
        services_fut,
        gateways_fut,
        labels_fut,
        object_events(&client, kind, namespace, name),
        read_grants(&client, &served, crosses),
    );

    let parents: Vec<ParentFit> = refs
        .iter()
        .zip(route.parents.iter())
        .zip(gateways.iter())
        .map(|((r, p), raw)| {
            let is_gateway = r.group == GROUP && r.kind == "Gateway";
            ParentFit {
                parent: p.clone(),
                // As read, which needs no right to list Gateways everywhere.
                gateway: raw
                    .as_ref()
                    .ok()
                    .and_then(Option::as_ref)
                    .map(gateway_info)
                    .or_else(|| all.gateways.iter().find(|g| is_gateway && g.namespace == r.namespace && g.name == r.name).cloned()),
                missing: is_gateway && matches!(raw, Ok(None)),
                read_error: raw.as_ref().err().cloned(),
                listeners: raw.as_ref().ok().and_then(Option::as_ref).map(|g| listener_fits(g, r, kind, namespace, &labels, &route.hostnames)).unwrap_or_default(),
            }
        })
        .collect();

    let mut services = services.into_iter();
    let backends: Vec<RouteBackendCheck> = backends
        .into_iter()
        .map(|(b, mirror)| RouteBackendCheck {
            service: if core(&b) { services.next() } else { None },
            grant: grant_for(&grants, kind, namespace, &b.group, &b.kind, &b.namespace, &b.name),
            mirror,
            backend: b,
        })
        .collect();

    // The other routes that claim its traffic.
    let ours = admitting_listeners(&parents, &gateways);
    let candidates: Vec<&RouteInfo> = all
        .routes
        .iter()
        .filter(|r| !(r.kind == kind && r.namespace == namespace && r.name == name))
        .filter(|r| r.parents.iter().any(|p| on_gateway(&ours, p).is_some()))
        .collect();
    // A listener that admits namespaces by label needs the other routes'.
    let by_label = ours.iter().any(|(g, listeners)| listeners.iter().any(|l| selects_namespaces(g, &l.name)));
    let namespace_labels: Result<BTreeMap<String, BTreeMap<String, String>>, String> = if by_label && candidates.iter().any(|r| r.namespace != namespace) {
        Api::<Namespace>::all(client.clone())
            .list(&ListParams::default())
            .await
            .map(|l| l.items.into_iter().map(|n| (n.metadata.name.unwrap_or_default(), n.metadata.labels.unwrap_or_default())).collect())
            .map_err(|e| format!("Failed to list namespaces: {e}"))
    } else {
        Ok(BTreeMap::new())
    };
    let sharing = shared_routes(&route, &ours, &candidates, &labels, &namespace_labels);
    let sharing_hostname = sharing.len();
    let same_match: Vec<SharedRoute> = sharing.into_iter().filter(|(_, same)| *same).map(|(s, _)| s).collect();

    // The controllers of the classes its Gateways belong to.
    let mut controller_names: Vec<String> = Vec::new();
    for g in parents.iter().filter_map(|p| p.gateway.as_ref()) {
        if let Some(c) = all.classes.iter().find(|c| c.name == g.class) {
            if !c.controller.is_empty() && !controller_names.contains(&c.controller) {
                controller_names.push(c.controller.clone());
            }
        }
    }
    let controllers = find_controllers(&client, &controller_names).await;
    let mut about = vec![name.to_string()];
    about.extend(backends.iter().filter(|b| core(&b.backend) && b.backend.namespace == namespace).map(|b| b.backend.name.clone()));
    let controller_logs = controller_logs(&client, &controllers, |l| log_line_is_about(l, kind, namespace, &about)).await;

    Ok(RouteDiagnostics {
        manifest: manifest_of(obj)?,
        route,
        read_error: all.error,
        parents,
        backends,
        sharing_hostname,
        same_match,
        sharing_error: namespace_labels.err(),
        controllers,
        controller_logs,
        events,
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> DynamicObject {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn a_route_is_healthy_only_when_every_parent_reports_every_condition_true() {
        let route = |status: Value| {
            route_info(
                "HTTPRoute",
                &obj(json!({
                    "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
                    "metadata": {"name": "web", "namespace": "app"},
                    "spec": {
                        "hostnames": ["web.example.com"],
                        "parentRefs": [{"name": "gw", "namespace": "infra", "sectionName": "https"}],
                        "rules": [{"backendRefs": [{"name": "web", "port": 80}]}]
                    },
                    "status": status
                })),
            )
        };
        // The status copy spells out the defaults the spec left implicit.
        let parent = json!({"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "gw", "namespace": "infra", "sectionName": "https"});
        let ok = route(json!({"parents": [{"parentRef": parent, "controllerName": "gateway.envoyproxy.io/gatewayclass-controller", "conditions": [
            {"type": "Accepted", "status": "True", "reason": "Accepted"},
            {"type": "ResolvedRefs", "status": "True", "reason": "ResolvedRefs"}
        ]}]}));
        assert!(ok.healthy, "{:?}", ok.problem);
        assert_eq!(ok.parents[0].controller, "gateway.envoyproxy.io/gatewayclass-controller");
        assert_eq!(ok.parents[0].section, "https");
        assert_eq!(ok.hostnames, vec!["web.example.com"]);
        assert_eq!(ok.rules[0].matches, vec!["PathPrefix /"]);
        assert_eq!(ok.rules[0].backends[0], RouteBackendInfo { group: String::new(), kind: "Service".into(), namespace: "app".into(), name: "web".into(), port: Some(80), weight: None });

        // An implementation's own condition counts like the standard ones.
        let no_endpoints = route(json!({"parents": [{"parentRef": parent, "conditions": [
            {"type": "Accepted", "status": "True", "reason": "Accepted"},
            {"type": "BackendsAvailable", "status": "False", "reason": "EndpointsNotFound", "message": "no ready endpoints for app/web"}
        ]}]}));
        assert!(!no_endpoints.healthy);
        assert_eq!(no_endpoints.problem.as_deref(), Some("infra/gw: BackendsAvailable is False: EndpointsNotFound — no ready endpoints for app/web"));

        let unreported = route(json!({}));
        assert!(!unreported.healthy);
        assert!(unreported.problem.unwrap().starts_with("infra/gw: No controller has reported on it"));

        // A status entry for another listener of the same Gateway is not this parent's.
        let other_section = route(json!({"parents": [{"parentRef": {"name": "gw", "namespace": "infra", "sectionName": "http"}, "conditions": [
            {"type": "Accepted", "status": "True"}
        ]}]}));
        assert!(!other_section.healthy);
    }

    #[test]
    fn a_condition_for_an_older_spec_is_not_the_current_verdict() {
        let route = |observed: i64| {
            route_info(
                "HTTPRoute",
                &obj(json!({
                    "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
                    "metadata": {"name": "web", "namespace": "app", "generation": 2},
                    "spec": {"parentRefs": [{"name": "gw"}]},
                    "status": {"parents": [{"parentRef": {"name": "gw"}, "conditions": [
                        {"type": "Accepted", "status": "True", "reason": "Accepted", "observedGeneration": observed}
                    ]}]}
                })),
            )
        };
        assert!(route(2).healthy);
        let stale = route(1);
        assert!(!stale.healthy);
        assert_eq!(
            stale.problem.as_deref(),
            Some("app/gw: Accepted is Unknown (not yet decided): Stale — True (Accepted) for generation 1; the spec is at generation 2, which its controller has not reported on yet")
        );
        // The parent keeps its group, for telling a Gateway API Gateway from another group's.
        assert_eq!(stale.parents[0].group, GROUP);
    }

    #[test]
    fn a_negative_polarity_condition_is_a_fault_when_true() {
        let gw = |conflicted: &str| {
            gateway_info(&obj(json!({
                "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
                "metadata": {"name": "gw", "namespace": "infra"},
                "spec": {"gatewayClassName": "envoy", "listeners": [{"name": "http", "protocol": "HTTP", "port": 80}]},
                "status": {"conditions": [{"type": "Accepted", "status": "True"}, {"type": "Programmed", "status": "True"}], "listeners": [
                    {"name": "http", "attachedRoutes": 1, "conditions": [
                        {"type": "Programmed", "status": "True"},
                        {"type": "Conflicted", "status": conflicted, "reason": if conflicted == "True" { "HostnameConflict" } else { "NoConflicts" }}
                    ]}
                ]}
            })))
        };
        assert!(gw("False").healthy, "{:?}", gw("False").problem);
        assert_eq!(gw("True").problem.as_deref(), Some("Listener http: Conflicted is True: HostnameConflict"));
    }

    #[test]
    fn a_route_without_parents_is_served_by_nothing() {
        let r = route_info("GRPCRoute", &obj(json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GRPCRoute", "metadata": {"name": "g", "namespace": "a"}, "spec": {}})));
        assert_eq!(r.problem.as_deref(), Some("It names no parent, so no Gateway serves it"));
    }

    #[test]
    fn matches_read_as_one_line_each() {
        assert_eq!(http_match(&json!({})), "PathPrefix /");
        assert_eq!(
            http_match(&json!({"method": "GET", "path": {"type": "Exact", "value": "/healthz"}, "headers": [{"name": "x-env", "value": "canary"}], "queryParams": [{"type": "RegularExpression", "name": "v", "value": "^2"}]})),
            "GET Exact /healthz header x-env=canary query v~^2"
        );
        assert_eq!(grpc_match(&json!({"method": {"service": "pkg.Svc"}})), "pkg.Svc/*");
        assert_eq!(grpc_match(&json!({"method": {"service": "pkg.Svc", "method": "Get"}})), "pkg.Svc/Get");
        assert_eq!(grpc_match(&json!({})), "any method");
        assert_eq!(filter_text(&json!({"type": "RequestRedirect", "requestRedirect": {"scheme": "https", "statusCode": 301}})), "RequestRedirect 301 to https");
        assert_eq!(filter_text(&json!({"type": "URLRewrite", "urlRewrite": {}})), "URLRewrite");
    }

    #[test]
    fn backends_name_their_namespace_and_weight() {
        let b = backend(&json!({"kind": "Service", "name": "api", "namespace": "other", "port": 8080, "weight": 90}), "app");
        assert_eq!((b.namespace.as_str(), b.port, b.weight), ("other", Some(8080), Some(90)));
        let s3 = backend(&json!({"group": "example.com", "kind": "Bucket", "name": "b"}), "app");
        assert_eq!((s3.group.as_str(), s3.kind.as_str(), s3.namespace.as_str(), s3.port), ("example.com", "Bucket", "app", None));
        // A Service of another API group is not a core Service.
        let imported = backend(&json!({"group": "multicluster.x-k8s.io", "kind": "Service", "name": "api"}), "app");
        assert_eq!((imported.group.as_str(), imported.kind.as_str()), ("multicluster.x-k8s.io", "Service"));
    }

    #[test]
    fn a_gateway_reports_its_own_problem_before_a_listeners() {
        let gw = |conds: Value, https: Value| {
            gateway_info(&obj(json!({
                "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
                "metadata": {"name": "gw", "namespace": "infra"},
                "spec": {"gatewayClassName": "envoy", "listeners": [
                    {"name": "http", "protocol": "HTTP", "port": 80},
                    {"name": "https", "protocol": "HTTPS", "port": 443, "hostname": "*.example.com",
                     "tls": {"certificateRefs": [{"name": "wild"}, {"name": "shared", "namespace": "certs"}]},
                     "allowedRoutes": {"namespaces": {"from": "All"}}}
                ]},
                "status": {"addresses": [{"type": "IPAddress", "value": "10.0.0.7"}], "conditions": conds, "listeners": [
                    {"name": "http", "attachedRoutes": 3, "conditions": [{"type": "Programmed", "status": "True"}]},
                    {"name": "https", "attachedRoutes": 95, "conditions": https}
                ]}
            })))
        };
        let up = [json!({"type": "Accepted", "status": "True"}), json!({"type": "Programmed", "status": "True"})];
        let ok = gw(json!(up), json!([{"type": "Programmed", "status": "True"}, {"type": "ResolvedRefs", "status": "True"}]));
        assert!(ok.healthy, "{:?}", ok.problem);
        assert_eq!(ok.attached_routes, 98);
        assert_eq!(ok.addresses, vec!["10.0.0.7"]);
        let https = &ok.listeners[1];
        assert_eq!((https.tls_mode.as_str(), https.allowed_namespaces.as_str()), ("Terminate", "All"));
        assert_eq!(https.certificates, vec!["wild", "certs/shared"]);
        assert_eq!((ok.listeners[0].tls_mode.as_str(), ok.listeners[0].allowed_namespaces.as_str()), ("", "Same"));

        let bad_cert = gw(json!(up), json!([{"type": "ResolvedRefs", "status": "False", "reason": "InvalidCertificateRef", "message": "secret certs/shared not permitted"}]));
        assert_eq!(bad_cert.problem.as_deref(), Some("Listener https: ResolvedRefs is False: InvalidCertificateRef — secret certs/shared not permitted"));

        // The CRD's own default status: nothing has picked it up.
        let pending = gw(json!([{"type": "Accepted", "status": "Unknown", "reason": "Pending", "message": "Waiting for controller"}]), json!([]));
        assert_eq!(pending.problem.as_deref(), Some("Accepted is Unknown (not yet decided): Pending — Waiting for controller"));
    }

    #[test]
    fn a_class_needs_its_controller_to_accept_it() {
        let class = |status: Value| class_info(&obj(json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass", "metadata": {"name": "envoy"}, "spec": {"controllerName": "gateway.envoyproxy.io/gatewayclass-controller"}, "status": status})));
        assert!(class(json!({"conditions": [{"type": "Accepted", "status": "True"}]})).healthy);
        assert!(class(json!({})).problem.unwrap().starts_with("No controller has accepted it"));
    }

    #[test]
    fn hostnames_intersect_by_the_apis_rule() {
        assert!(hostnames_intersect("*.example.com", "a.example.com"));
        assert!(hostnames_intersect("*.example.com", "a.b.example.com"), "a wildcard matches at any depth");
        assert!(!hostnames_intersect("*.example.com", "example.com"));
        assert!(hostnames_intersect("A.Example.com", "a.example.COM"));
        assert!(hostnames_intersect("*.example.com", "*.b.example.com"));
        assert!(!hostnames_intersect("*.example.com", "*.example.org"));
        assert!(!hostnames_intersect("a.example.com", "b.example.com"));
    }

    fn gateway_obj(listeners: Value, status: Value) -> DynamicObject {
        obj(json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "infra"},
            "spec": {"gatewayClassName": "envoy", "listeners": listeners},
            "status": status
        }))
    }

    #[test]
    fn each_listener_is_checked_against_the_route() {
        let gw = gateway_obj(
            json!([
                {"name": "https", "protocol": "HTTPS", "port": 443, "hostname": "*.dev.example.com", "allowedRoutes": {"namespaces": {"from": "All"}}},
                {"name": "internal", "protocol": "HTTP", "port": 80},
                {"name": "labelled", "protocol": "HTTP", "port": 8080, "allowedRoutes": {"namespaces": {"from": "Selector", "selector": {"matchLabels": {"gateway-access": "yes"}}}}},
                {"name": "grpc-only", "protocol": "HTTPS", "port": 8443, "allowedRoutes": {"namespaces": {"from": "All"}, "kinds": [{"kind": "GRPCRoute"}]}},
                {"name": "prod", "protocol": "HTTPS", "port": 9443, "hostname": "*.prod.example.com", "allowedRoutes": {"namespaces": {"from": "All"}}}
            ]),
            json!({}),
        );
        let labels: Result<BTreeMap<String, String>, String> = Ok(BTreeMap::from([("team".to_string(), "web".to_string())]));
        let any = parent_ref(Some(&json!({"name": "gw", "namespace": "infra"})), "app");
        let fits = listener_fits(&gw, &any, "HTTPRoute", "app", &labels, &["web.dev.example.com".to_string()]);
        let by = |n: &str| fits.iter().find(|f| f.name == n).unwrap();
        assert!(by("https").refusal.is_none() && by("https").hostname_refusal.is_none());
        assert_eq!(by("https").hostnames, vec!["web.dev.example.com"]);
        assert_eq!(by("internal").refusal.as_deref(), Some("it admits routes from its own namespace (infra) only, and the route is in app"));
        assert_eq!(by("labelled").refusal.as_deref(), Some("it admits routes from namespaces labelled gateway-access=yes, and app's labels do not match"));
        assert_eq!(by("grpc-only").refusal.as_deref(), Some("its allowedRoutes.kinds (GRPCRoute) do not include HTTPRoute"));
        assert_eq!(by("prod").hostname_refusal.as_deref(), Some("none of the route's hostnames is under its hostname *.prod.example.com"));
        assert!(fits.iter().all(|f| f.selected), "a parentRef without sectionName or port picks every listener");

        // sectionName picks one; a TCPRoute has no hostnames to match, and
        // an HTTP listener's protocol does not take it.
        let https = parent_ref(Some(&json!({"name": "gw", "namespace": "infra", "sectionName": "https"})), "app");
        let fits = listener_fits(&gw, &https, "TCPRoute", "app", &labels, &[]);
        assert_eq!(fits.iter().filter(|f| f.selected).map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["https"]);
        assert_eq!(fits[0].refusal.as_deref(), Some("its protocol's route kinds (HTTPRoute, GRPCRoute) do not include TCPRoute"));
        assert!(fits[0].hostname_refusal.is_none());
    }

    #[test]
    fn the_host_two_hostnames_share_is_the_narrower() {
        assert_eq!(hostname_overlap("*.example.com", "api.example.com").as_deref(), Some("api.example.com"));
        assert_eq!(hostname_overlap("API.example.com", "*.example.com").as_deref(), Some("api.example.com"));
        assert_eq!(hostname_overlap("*.example.com", "*.a.example.com").as_deref(), Some("*.a.example.com"));
        assert_eq!(hostname_overlap("", "api.example.com").as_deref(), Some("api.example.com"), "no hostname is any host");
        assert_eq!(hostname_overlap("", "").as_deref(), Some(""));
        assert_eq!(hostname_overlap("a.example.com", "b.example.com"), None);
        // A route's wildcard under a listener's name is served for that name.
        assert_eq!(hostname_fit("a.example.com", &["*.example.com".to_string()], "HTTPRoute"), (vec!["a.example.com".to_string()], None));
        assert_eq!(hostname_fit("*.example.com", &[], "HTTPRoute"), (vec!["*.example.com".to_string()], None), "a route without hostnames takes the listener's");
        assert_eq!(hostname_fit("*.example.com", &[], "TCPRoute"), (vec![], None));
    }

    #[test]
    fn two_matches_that_select_the_same_requests_have_one_key() {
        let key = |m: Value| http_match_key(&m);
        let api = key(json!({"path": {"type": "PathPrefix", "value": "/api"}, "headers": [{"name": "X-Env", "value": "canary"}, {"name": "x-team", "value": "web"}],
            "queryParams": [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]}));
        let reordered = key(json!({"headers": [{"name": "x-team", "value": "web", "type": "Exact"}, {"name": "x-env", "value": "canary"}], "path": {"value": "/api/"},
            "queryParams": [{"name": "b", "value": "2"}, {"name": "a", "value": "1"}]}));
        assert_eq!(api, reordered, "order, header-name case, defaults and a prefix's trailing slash do not matter");
        let shouted = key(json!({"path": {"value": "/api"}, "headers": [{"name": "x-env", "value": "CANARY"}, {"name": "x-team", "value": "web"}],
            "queryParams": [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]}));
        assert_ne!(api, shouted, "a header's value keeps its case");
        assert_ne!(key(json!({"queryParams": [{"name": "A", "value": "1"}]})), key(json!({"queryParams": [{"name": "a", "value": "1"}]})), "so does a query parameter's name");
        assert_ne!(key(json!({"path": {"type": "Exact", "value": "/api/"}})), key(json!({"path": {"type": "Exact", "value": "/api"}})), "an exact path keeps its slash");
        assert_eq!(key(Value::Null), key(json!({"path": {"type": "PathPrefix", "value": "/"}})), "no match is every path");
        assert_eq!(
            grpc_match_key(&json!({"method": {"service": "pkg.Orders"}, "headers": [{"name": "A", "value": "1"}, {"name": "b", "value": "2"}]})),
            grpc_match_key(&json!({"method": {"type": "Exact", "service": "pkg.Orders"}, "headers": [{"name": "B", "value": "2"}, {"name": "a", "value": "1"}]})),
        );
    }

    #[test]
    fn mirrored_backends_and_certificates_keep_their_references() {
        let rule = json!({
            "filters": [{"type": "RequestMirror", "requestMirror": {"backendRef": {"name": "shadow", "port": 8080}}}, {"type": "URLRewrite"}],
            "backendRefs": [{"name": "web", "port": 80, "filters": [{"type": "RequestMirror", "requestMirror": {"backendRef": {"name": "audit", "namespace": "audit", "port": 9000}}}]}]
        });
        let mirrors = mirror_backends(&rule, "app");
        assert_eq!(mirrors.iter().map(|b| (b.namespace.as_str(), b.name.as_str(), b.port)).collect::<Vec<_>>(), vec![("app", "shadow", Some(8080)), ("audit", "audit", Some(9000))]);
        assert_eq!(certificate_ref(&json!({"name": "wild"}), "infra"), "wild");
        assert_eq!(certificate_ref(&json!({"group": "cert-manager.io", "kind": "Certificate", "name": "wild"}), "infra"), "Certificate.cert-manager.io/wild");
        assert_eq!(certificate_ref(&json!({"group": "example.com", "name": "wild", "namespace": "certs"}), "infra"), "certs/Secret.example.com/wild");
    }

    fn listed_route(kind: &str, namespace: &str, name: &str, spec: Value) -> RouteInfo {
        route_info(kind, &obj(json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": kind, "metadata": {"name": name, "namespace": namespace}, "spec": spec})))
    }

    #[test]
    fn routes_compete_only_on_a_listener_that_admits_both_for_a_host_both_are_served_for() {
        let gw = gateway_obj(
            json!([
                {"name": "http", "protocol": "HTTP", "port": 80, "allowedRoutes": {"namespaces": {"from": "All"}}},
                {"name": "https", "protocol": "HTTPS", "port": 443, "hostname": "*.dev.example.com", "allowedRoutes": {"namespaces": {"from": "All"}}},
                {"name": "tls", "protocol": "TLS", "port": 8443, "tls": {"mode": "Passthrough"}, "allowedRoutes": {"namespaces": {"from": "All"}}},
                {"name": "own", "protocol": "HTTP", "port": 8080}
            ]),
            json!({}),
        );
        let parent = |section: &str| if section.is_empty() { json!({"name": "gw", "namespace": "infra"}) } else { json!({"name": "gw", "namespace": "infra", "sectionName": section}) };
        let http = |name: &str, section: &str, hostnames: Value, matches: Value| {
            listed_route("HTTPRoute", "web", name, json!({"parentRefs": [parent(section)], "hostnames": hostnames, "rules": [{"matches": matches, "backendRefs": [{"name": "web", "port": 80}]}]}))
        };
        let tls = |name: &str, hostnames: Value| listed_route("TLSRoute", "web", name, json!({"parentRefs": [parent("tls")], "hostnames": hostnames, "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]}));
        let labels: Result<BTreeMap<String, String>, String> = Ok(BTreeMap::new());
        let gateways = vec![Ok(Some(gw.clone()))];
        let shared = |me: &RouteInfo, others: &[&RouteInfo]| -> Vec<(String, bool, Vec<(String, Vec<String>)>)> {
            let parents = vec![ParentFit {
                parent: me.parents[0].clone(),
                gateway: None,
                missing: false,
                read_error: None,
                listeners: listener_fits(&gw, &parent_ref_of(&me.parents[0]), &me.kind, &me.namespace, &labels, &me.hostnames),
            }];
            let ours = admitting_listeners(&parents, &gateways);
            shared_routes(me, &ours, others, &labels, &Ok(BTreeMap::new())).into_iter().map(|(s, same)| (s.route.name, same, s.listeners)).collect()
        };
        let api = json!([{"path": {"value": "/api"}, "headers": [{"name": "X-Env", "value": "canary"}, {"name": "x-team", "value": "web"}]}]);
        let me = http("me", "https", json!(["api.dev.example.com"]), api.clone());
        let on_http = http("on-http", "http", json!(["api.dev.example.com"]), api.clone());
        let reordered = http("reordered", "", json!(["*.dev.example.com"]), json!([{"path": {"value": "/api/"}, "headers": [{"name": "x-team", "value": "web"}, {"name": "x-env", "value": "canary"}]}]));
        let inherits = http("inherits", "https", json!([]), json!([{"path": {"value": "/other"}}]));
        let elsewhere = http("elsewhere", "https", json!(["web.dev.example.com"]), api.clone());
        let at_https = |host: &str| vec![("infra/gw listener https".to_string(), vec![host.to_string()])];
        assert_eq!(
            shared(&me, &[&on_http, &reordered, &inherits, &elsewhere]),
            vec![("reordered".to_string(), true, at_https("api.dev.example.com")), ("inherits".to_string(), false, at_https("api.dev.example.com"))],
            "the http listener does not admit this route, and web.dev.example.com is another host"
        );
        // A TLSRoute's rules match every connection for its hostnames.
        let db = tls("db", json!(["db.dev.example.com"]));
        let wild = tls("wild", json!(["*.dev.example.com"]));
        assert_eq!(shared(&db, &[&wild]), vec![("wild".to_string(), true, vec![("infra/gw listener tls".to_string(), vec!["db.dev.example.com".to_string()])])]);
        // A listener that admits its own namespace only admits neither.
        let own = http("own", "own", json!([]), api.clone());
        assert!(shared(&own, &[&http("twin", "own", json!([]), api.clone())]).is_empty());
    }

    #[test]
    fn the_controllers_supported_kinds_overrule_the_protocols() {
        let gw = gateway_obj(
            json!([{"name": "http", "protocol": "HTTP", "port": 80, "allowedRoutes": {"namespaces": {"from": "All"}}}]),
            json!({"listeners": [{"name": "http", "supportedKinds": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}]}]}),
        );
        let r = parent_ref(Some(&json!({"name": "gw", "namespace": "infra"})), "app");
        let fits = listener_fits(&gw, &r, "GRPCRoute", "app", &Ok(BTreeMap::new()), &[]);
        assert_eq!(fits[0].refusal.as_deref(), Some("the kinds its controller supports on it (HTTPRoute) do not include GRPCRoute"));
    }

    #[test]
    fn a_reference_grant_must_name_the_source_and_the_target() {
        let grant = obj(json!({
            "apiVersion": "gateway.networking.k8s.io/v1beta1", "kind": "ReferenceGrant",
            "metadata": {"name": "allow-app", "namespace": "shared"},
            "spec": {"from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "app"}], "to": [{"group": "", "kind": "Service", "name": "api"}]}
        }));
        let grants = [grant];
        assert_eq!(permitting_grant(&grants, "HTTPRoute", "app", "", "Service", "shared", "api").as_deref(), Some("allow-app"));
        assert_eq!(permitting_grant(&grants, "HTTPRoute", "app", "", "Service", "shared", "other"), None, "it names one Service");
        assert_eq!(permitting_grant(&grants, "GRPCRoute", "app", "", "Service", "shared", "api"), None, "it lets HTTPRoutes only");
        assert_eq!(permitting_grant(&grants, "HTTPRoute", "web", "", "Service", "shared", "api"), None, "it lets app only");
        assert_eq!(permitting_grant(&grants, "HTTPRoute", "app", "", "Service", "elsewhere", "api"), None, "a grant permits into its own namespace");
        assert!(grant_for(&Ok(grants.to_vec()), "HTTPRoute", "app", "", "Service", "app", "api").is_none(), "the same namespace needs none");
    }

    #[test]
    fn a_controller_is_found_by_its_args_or_its_image() {
        let deployment = |args: Value, image: &str| -> k8s_openapi::api::apps::v1::Deployment {
            serde_json::from_value(json!({
                "metadata": {"name": "c", "namespace": "ns"},
                "spec": {"selector": {"matchLabels": {"app": "c"}}, "template": {"spec": {"containers": [{"name": "main", "image": image, "args": args}]}}}
            }))
            .unwrap()
        };
        let ngf = deployment(json!(["controller", "--gateway-ctlr-name=gateway.nginx.org/nginx-gateway-controller"]), "ghcr.io/nginx/nginx-gateway-fabric:2.0");
        assert_eq!(controller_container(&ngf, "gateway.nginx.org/nginx-gateway-controller"), Some(("main".to_string(), NAMED_IN_ARGS)));
        let eg = deployment(json!(["server", "--config-path=/config/envoy-gateway.yaml"]), "docker.io/envoyproxy/gateway:v1.8.3");
        assert_eq!(controller_container(&eg, "gateway.envoyproxy.io/gatewayclass-controller"), Some(("main".to_string(), BY_IMAGE)));
        assert_eq!(controller_container(&eg, "istio.io/gateway-controller"), None);
    }

    #[test]
    fn controller_log_lines_are_matched_by_the_names_envoy_gateway_uses() {
        let names = vec!["web".to_string(), "web-svc".to_string()];
        let zap = |fields: &str| format!("2026-11-23T10:00:00.000Z\tinfo\tgateway-api\tgatewayapi/route.go:12\tsetting 503 direct response\t{fields}");
        assert!(log_line_is_about(&zap(r#"{"routes":["httproute/app/web/rule/0/match/0/web_dev_example_com"]}"#), "HTTPRoute", "app", &names));
        assert!(!log_line_is_about(&zap(r#"{"routes":["httproute/app/web-old/rule/0"]}"#), "HTTPRoute", "app", &names));
        assert!(!log_line_is_about(&zap(r#"{"routes":["httproute/other/web/rule/0"]}"#), "HTTPRoute", "app", &names));
        assert!(log_line_is_about(&zap(r#"{"runner":"provider","namespace":"app","name":"web-svc"}"#), "HTTPRoute", "app", &names));
    }

    /// Prints counts only. Run against a cluster with and one without the
    /// Gateway API: GATEWAY_TEST_CONTEXT=<context> cargo test --lib
    /// gateway_api_against_a_live_cluster -- --ignored --exact --nocapture
    #[tokio::test]
    #[ignore]
    async fn gateway_api_against_a_live_cluster() {
        let ctx = std::env::var("GATEWAY_TEST_CONTEXT").expect("set GATEWAY_TEST_CONTEXT");
        let r = get_gateway_api(&ctx).await.unwrap();
        println!(
            "installed={} error={} classes={} gateways={} (unhealthy {}) routes={} (unhealthy {}) by kind={:?} listeners={} attached={} stale conditions={}",
            r.installed,
            r.error.is_some(),
            r.classes.len(),
            r.gateways.len(),
            r.gateways.iter().filter(|g| !g.healthy).count(),
            r.routes.len(),
            r.routes.iter().filter(|x| !x.healthy).count(),
            ROUTE_KINDS.iter().map(|k| (*k, r.routes.iter().filter(|x| x.kind == *k).count())).collect::<Vec<_>>(),
            r.gateways.iter().map(|g| g.listeners.len()).sum::<usize>(),
            r.gateways.iter().map(|g| g.attached_routes).sum::<i64>(),
            r.classes.iter().flat_map(|c| &c.conditions)
                .chain(r.gateways.iter().flat_map(|g| g.conditions.iter().chain(g.listeners.iter().flat_map(|l| &l.conditions))))
                .chain(r.routes.iter().flat_map(|x| x.parents.iter().flat_map(|p| &p.conditions)))
                .filter(|c| c.reason == "Stale")
                .count(),
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        // Every unhealthy object says why.
        assert!(r.gateways.iter().all(|g| g.healthy == g.problem.is_none()));
        assert!(r.routes.iter().all(|x| x.healthy == x.problem.is_none()));
        // Every backend a rule sends to has a name.
        assert!(r.routes.iter().flat_map(|x| &x.rules).flat_map(|rule| &rule.backends).all(|b| !b.name.is_empty()));
    }

    /// Builds the diagnosis payloads for every Gateway and for a sample of
    /// routes, failing ones first, and prints counts only:
    /// GATEWAY_TEST_CONTEXT=<context> cargo test --lib
    /// gateway_api::tests::gateway_diagnosis_against_a_live_cluster -- --ignored --exact --nocapture
    #[tokio::test]
    #[ignore]
    async fn gateway_diagnosis_against_a_live_cluster() {
        let ctx = std::env::var("GATEWAY_TEST_CONTEXT").expect("set GATEWAY_TEST_CONTEXT");
        let all = get_gateway_api(&ctx).await.unwrap();
        for g in &all.gateways {
            let d = get_gateway_diagnostics(&ctx, &g.namespace, &g.name).await.unwrap();
            let p = crate::claude::build_gateway_diagnosis_payload(&ctx, &g.namespace, &g.name).await.unwrap();
            println!(
                "gateway: class found={} certs={} (secrets read {}) data plane: workloads={} services={} pods={} errors={} routes={} controllers={:?} log lines={:?} events={:?} tokens={} unavailable sections={}",
                d.class.is_some(),
                d.certificates.len(),
                d.certificates.iter().filter(|c| matches!(c.secret, Some(Ok(_)))).count(),
                d.data_plane.workloads.len(),
                d.data_plane.services.len(),
                d.data_plane.pods.len(),
                d.data_plane.errors.len(),
                d.routes.len(),
                d.controllers.as_ref().map(|c| c.iter().map(|w| w.matched_by.clone()).collect::<Vec<_>>()),
                d.controller_logs.as_ref().map(|l| l.as_ref().map(|(pods, lines)| (*pods, lines.len()))),
                d.events.as_ref().map(Vec::len),
                p.approx_tokens,
                p.prompt.matches("unavailable").count(),
            );
            let sections: Vec<(String, usize)> = p.prompt.split("\n## ").skip(1).map(|sec| (sec.lines().next().unwrap_or_default().chars().take(40).collect(), sec.lines().count() - 1)).collect();
            println!("  section lines: {sections:?}");
            assert!(d.class.is_some());
            assert_eq!(d.routes.len() as i64 >= 1, g.attached_routes >= 1);
        }
        let mut routes: Vec<&RouteInfo> = all.routes.iter().collect();
        routes.sort_by_key(|r| r.healthy);
        for r in routes.iter().take(4) {
            let d = get_route_diagnostics(&ctx, &r.kind, &r.namespace, &r.name).await.unwrap();
            let p = crate::claude::build_route_diagnosis_payload(&ctx, &r.kind, &r.namespace, &r.name).await.unwrap();
            println!(
                "route: healthy={} parents={} (gateways found {}, listeners {} admitting {}) backends={} (services read {}, ready-less {}) same match={} of {} sharing a hostname, controllers={:?} log lines={:?} tokens={} unavailable sections={}",
                r.healthy,
                d.parents.len(),
                d.parents.iter().filter(|p| p.gateway.is_some()).count(),
                d.parents.iter().map(|p| p.listeners.len()).sum::<usize>(),
                d.parents.iter().flat_map(|p| &p.listeners).filter(|l| l.selected && l.refusal.is_none() && l.hostname_refusal.is_none()).count(),
                d.backends.len(),
                d.backends.iter().filter(|b| matches!(&b.service, Some(s) if s.service.is_ok())).count(),
                p.prompt.matches("NO READY ENDPOINT").count() + p.prompt.matches("NO ENDPOINTS").count(),
                d.same_match.len(),
                d.sharing_hostname,
                d.controllers.as_ref().map(Vec::len),
                d.controller_logs.as_ref().map(|l| l.as_ref().map(|(pods, lines)| (*pods, lines.len()))),
                p.approx_tokens,
                p.prompt.matches("unavailable").count(),
            );
            let sections: Vec<(String, usize)> = p.prompt.split("\n## ").skip(1).map(|sec| (sec.lines().next().unwrap_or_default().chars().take(40).collect(), sec.lines().count() - 1)).collect();
            println!("  section lines: {sections:?}");
            // Every route the dashboard flags is attached to some listener
            // here, so a failing one fails for another reason.
            assert!(d.parents.iter().any(|p| p.listeners.iter().any(|l| l.selected && l.refusal.is_none() && l.hostname_refusal.is_none())));
        }
    }
}
