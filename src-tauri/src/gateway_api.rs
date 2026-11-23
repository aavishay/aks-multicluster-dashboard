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
//! Status is read as the API's conventions define it: every condition is
//! positive-polarity, so any condition that is not True is worth naming. That
//! covers the standard ones (Accepted, Programmed, ResolvedRefs) and an
//! implementation's own (Envoy Gateway's BackendsAvailable) alike, and the
//! CRDs' own default — Accepted and Programmed Unknown, reason Pending —
//! reads as "no controller has picked it up".
//!
//! Nothing here carries a value worth redacting: a listener names its
//! certificate Secrets, and only their names are kept.

use crate::k8s::{age_days, age_seconds, created_at, json_str};
use crate::kubeconfig::client_for_context;
use crate::models::{
    GatewayApiResult, GatewayClassInfo, GatewayInfo, GatewayListenerInfo, PodConditionInfo, RouteBackendInfo, RouteInfo, RouteParentInfo,
    RouteRuleInfo,
};
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
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

fn conditions(status: Option<&Value>) -> Vec<PodConditionInfo> {
    items(status, "conditions")
        .iter()
        .map(|c| PodConditionInfo {
            condition_type: json_str(Some(c), "type").to_string(),
            status: json_str(Some(c), "status").to_string(),
            reason: json_str(Some(c), "reason").to_string(),
            message: json_str(Some(c), "message").to_string(),
            last_transition: Some(json_str(Some(c), "lastTransitionTime")).filter(|t| !t.is_empty()).map(str::to_string),
        })
        .collect()
}

/// `Accepted is False: NotAllowedByListeners — no listener allows this route`.
fn describe(c: &PodConditionInfo) -> String {
    let state = if c.status == "False" { "False".to_string() } else { format!("{} (not yet decided)", if c.status.is_empty() { "Unknown" } else { &c.status }) };
    let mut out = format!("{} is {state}", c.condition_type);
    if !c.reason.is_empty() {
        out.push_str(&format!(": {}", c.reason));
    }
    if !c.message.is_empty() && c.message != c.reason {
        out.push_str(&format!(" — {}", c.message));
    }
    out
}

/// The first condition that is not True, or none reported at all.
fn failing(conds: &[PodConditionInfo], none: &str) -> Option<String> {
    if conds.is_empty() {
        return Some(none.to_string());
    }
    conds.iter().find(|c| c.status != "True").map(describe)
}

fn age(obj: &DynamicObject) -> (i64, i64, Option<String>) {
    let t = obj.metadata.creation_timestamp.clone();
    (age_days(t.clone()), age_seconds(t.clone()), created_at(&t))
}

pub(crate) fn class_info(obj: &DynamicObject) -> GatewayClassInfo {
    let spec = obj.data.get("spec");
    let conditions = conditions(obj.data.get("status"));
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
/// `Kind/name` for something other than a Secret.
fn certificate_ref(r: &Value, own_ns: &str) -> String {
    let kind = json_str(Some(r), "kind");
    let ns = json_str(Some(r), "namespace");
    let name = json_str(Some(r), "name");
    let base = if kind.is_empty() || kind == "Secret" { name.to_string() } else { format!("{kind}/{name}") };
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
            let conditions = conditions(st);
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
    let conditions = conditions(status);
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
        kind: if kind.is_empty() { "Service".to_string() } else { kind.to_string() },
        namespace: if ns.is_empty() { route_ns.to_string() } else { ns.to_string() },
        name: json_str(Some(b), "name").to_string(),
        port: b.get("port").and_then(Value::as_i64),
        weight: b.get("weight").and_then(Value::as_i64),
    }
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
            let conditions: Vec<PodConditionInfo> = entries.iter().flat_map(|s| conditions(Some(s))).collect();
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

pub async fn get_gateway_api(context_name: &str) -> Result<GatewayApiResult, String> {
    let client = client_for_context(context_name).await?;
    let group = match kube::discovery::group(&client, GROUP).await {
        Ok(g) => g,
        Err(kube::Error::Discovery(DiscoveryError::MissingApiGroup(_))) => return Ok(GatewayApiResult::default()),
        Err(e) => return Err(format!("Failed to discover the Gateway API: {e}")),
    };
    // Each kind at its most stable served version: v1 for an HTTPRoute,
    // v1alpha2 for a TCPRoute on the same cluster.
    let served: Vec<ApiResource> = group.resources_by_stability().into_iter().map(|(ar, _)| ar).collect();
    let (classes, gateways, http, grpc, tls, tcp, udp) = tokio::join!(
        list_kind(&client, &served, "GatewayClass"),
        list_kind(&client, &served, "Gateway"),
        list_kind(&client, &served, ROUTE_KINDS[0]),
        list_kind(&client, &served, ROUTE_KINDS[1]),
        list_kind(&client, &served, ROUTE_KINDS[2]),
        list_kind(&client, &served, ROUTE_KINDS[3]),
        list_kind(&client, &served, ROUTE_KINDS[4]),
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
    Ok(GatewayApiResult {
        installed: served.iter().any(|ar| ar.kind == "Gateway"),
        error: if errors.is_empty() { None } else { Some(errors.join("; ")) },
        classes,
        gateways,
        routes,
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
        assert_eq!(ok.rules[0].backends[0], RouteBackendInfo { kind: "Service".into(), namespace: "app".into(), name: "web".into(), port: Some(80), weight: None });

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
        assert_eq!((s3.kind.as_str(), s3.namespace.as_str(), s3.port), ("Bucket", "app", None));
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

    /// Prints counts only. Run against a cluster with and one without the
    /// Gateway API: GATEWAY_TEST_CONTEXT=<context> cargo test --lib
    /// gateway_api_against_a_live_cluster -- --ignored --exact --nocapture
    #[tokio::test]
    #[ignore]
    async fn gateway_api_against_a_live_cluster() {
        let ctx = std::env::var("GATEWAY_TEST_CONTEXT").expect("set GATEWAY_TEST_CONTEXT");
        let r = get_gateway_api(&ctx).await.unwrap();
        println!(
            "installed={} error={} classes={} gateways={} (unhealthy {}) routes={} (unhealthy {}) by kind={:?} listeners={} attached={}",
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
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        // Every unhealthy object says why.
        assert!(r.gateways.iter().all(|g| g.healthy == g.problem.is_none()));
        assert!(r.routes.iter().all(|x| x.healthy == x.problem.is_none()));
        // Every backend a rule sends to has a name.
        assert!(r.routes.iter().flat_map(|x| &x.rules).flat_map(|rule| &rule.backends).all(|b| !b.name.is_empty()));
    }
}
