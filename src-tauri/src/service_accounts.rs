//! A ServiceAccount's diagnosis: what runs as it, and whether it can sign in
//! where it needs to — to Azure through Workload Identity, to the API server
//! through the roles bound to it, to a registry through its pull secrets.
//!
//! Workload Identity has three halves, and only two are visible from the
//! cluster. The account names an identity (`azure.workload.identity/client-id`)
//! and a pod opts in (`azure.workload.identity/use: "true"`), after which the
//! webhook injects a projected token and the `AZURE_*` variables into each
//! container. The third half — the identity's federated credential, which
//! must name this cluster's issuer and `system:serviceaccount:<ns>:<name>` —
//! lives in Azure. So the diagnosis reads the issuer and states the subject
//! the credential has to carry, and reads the pods' own log lines, where
//! Entra ID says which of the two it did not find (AADSTS70021).
//!
//! Nothing here reads a value: Secrets by type only, logs as excerpts from
//! the error onwards, redacted like every payload.

use crate::k8s::{self, event_to_info, object_manifest};
use crate::kubeconfig::client_for_context;
use crate::models::EventInfo;
use k8s_openapi::api::core::v1::{Pod, PodSpec, Secret, ServiceAccount};
use kube::api::{Api, ApiResource, DynamicObject, ListParams, LogParams};
use kube::Client;
use std::collections::BTreeMap;

const ANNOTATION_CLIENT_ID: &str = "azure.workload.identity/client-id";
const LABEL_USE: &str = "azure.workload.identity/use";
const ANNOTATION_SKIP: &str = "azure.workload.identity/skip-containers";
/// The variable the webhook injects into each container it mutates, holding
/// the projected token's path.
const ENV_TOKEN_FILE: &str = "AZURE_FEDERATED_TOKEN_FILE";
const ENV_CLIENT_ID: &str = "AZURE_CLIENT_ID";
/// The webhook's name in its MutatingWebhookConfiguration, the AKS add-on's
/// and the upstream chart's alike.
const WEBHOOK_NAME: &str = "mutation.azure-workload-identity.io";

/// How many of its pods have their logs read: the not-ready first.
const PODS_LOGGED: usize = 5;
/// How far back, and how much, of each container's log to read.
const LOG_SECONDS: i64 = 3600;
const LOG_BYTES: i64 = 2 * 1024 * 1024;
/// An excerpt's longest, from the error onwards.
const EXCERPT_CHARS: usize = 400;

/// A pod that runs as the account, checked.
pub struct PodIdentity {
    pub name: String,
    pub owner: String,
    pub ready: bool,
    pub phase: String,
    /// The `azure.workload.identity/use` label's value, if it has one.
    pub use_label: Option<String>,
    /// Containers the webhook injected its token into, those it did not, and
    /// those the pod told it to skip.
    pub injected: Vec<String>,
    pub not_injected: Vec<String>,
    pub skipped: Vec<String>,
    /// Whether the injected `AZURE_CLIENT_ID` is the account's current
    /// client ID; `None` where nothing was injected. A pod started before the
    /// annotation changed keeps the old one until it is recreated.
    pub client_id_current: Option<bool>,
    /// Why its containers are waiting or were last terminated, as
    /// `container: Reason`.
    pub waiting: Vec<String>,
}

/// A workload whose pod template runs as the account.
pub struct TemplateIdentity {
    pub kind: String,
    pub name: String,
    pub use_label: Option<String>,
}

/// A role bound to the account, directly or through a group every service
/// account (or every one in its namespace) is in.
pub struct Binding {
    pub kind: &'static str,
    pub namespace: String,
    pub name: String,
    pub role: String,
    /// The group it is granted through, when not the account itself.
    pub via: Option<String>,
}

/// Everything a ServiceAccount diagnosis reads. Only the account is
/// required; each of the rest fails on its own.
pub struct ServiceAccountDiagnostics {
    pub account: ServiceAccount,
    pub manifest: String,
    pub events: Result<Vec<EventInfo>, String>,
    /// Every pod that runs as it, not-ready first.
    pub pods: Result<Vec<PodIdentity>, String>,
    pub templates: Result<Vec<TemplateIdentity>, String>,
    /// Each imagePullSecret and its type; `None` inside when it does not exist.
    pub pull_secrets: Vec<(String, Result<Option<String>, String>)>,
    pub bindings: Result<Vec<Binding>, String>,
    /// Why RoleBindings outside the account's namespace could not be read,
    /// when only its own namespace's were.
    pub bindings_note: Option<String>,
    /// The Workload Identity webhook's configurations and whether its
    /// Deployment is ready; `None` when the account names no client ID.
    pub webhook: Option<Result<Vec<String>, String>>,
    /// The issuer the API server signs its tokens as.
    pub issuer: Result<String, String>,
    /// Excerpts of its pods' log lines about signing in to Azure or being
    /// refused by RBAC, with how many pods were read.
    pub log_excerpts: Result<(usize, Vec<String>), String>,
    /// The Warning events of its pods that are not ready, by pod.
    pub pod_events: Vec<(String, Result<Vec<EventInfo>, String>)>,
}

fn pod_ready(p: &Pod) -> bool {
    p.status.as_ref().and_then(|s| s.conditions.as_ref()).is_some_and(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
}

/// The account a pod spec runs as: `default` when it names none.
fn runs_as(spec: Option<&PodSpec>) -> &str {
    spec.and_then(|s| s.service_account_name.as_deref()).filter(|s| !s.is_empty()).unwrap_or("default")
}

/// A pod checked for what the webhook did to it.
pub(crate) fn pod_identity(p: &Pod, client_id: Option<&str>) -> PodIdentity {
    let labels = p.metadata.labels.clone().unwrap_or_default();
    let skip: Vec<String> = p
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(ANNOTATION_SKIP))
        .map(|s| s.split(';').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    let spec = p.spec.clone().unwrap_or_default();
    let (mut injected, mut not_injected, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
    let mut client_id_current = None;
    for c in spec.init_containers.iter().flatten().chain(spec.containers.iter()) {
        let env: BTreeMap<&str, Option<&str>> = c.env.iter().flatten().map(|e| (e.name.as_str(), e.value.as_deref())).collect();
        if skip.contains(&c.name) {
            skipped.push(c.name.clone());
        } else if env.contains_key(ENV_TOKEN_FILE) {
            injected.push(c.name.clone());
            if let (Some(want), Some(Some(got))) = (client_id, env.get(ENV_CLIENT_ID)) {
                client_id_current = Some(client_id_current.unwrap_or(true) && want == *got);
            }
        } else {
            not_injected.push(c.name.clone());
        }
    }
    let status = p.status.clone().unwrap_or_default();
    let waiting = status
        .init_container_statuses
        .iter()
        .flatten()
        .chain(status.container_statuses.iter().flatten())
        .filter_map(|c| {
            let state = c.state.as_ref();
            let reason = state
                .and_then(|s| s.waiting.as_ref())
                .and_then(|w| w.reason.clone())
                .or_else(|| (!c.ready).then(|| c.last_state.as_ref().and_then(|l| l.terminated.as_ref()).and_then(|t| t.reason.clone())).flatten())?;
            Some(format!("{}: {reason}", c.name))
        })
        .collect();
    PodIdentity {
        name: p.metadata.name.clone().unwrap_or_default(),
        owner: p.metadata.owner_references.iter().flatten().find(|o| o.controller == Some(true)).map(|o| format!("{}/{}", o.kind, o.name)).unwrap_or_default(),
        ready: pod_ready(p),
        phase: status.phase.clone().unwrap_or_default(),
        use_label: labels.get(LABEL_USE).cloned(),
        injected,
        not_injected,
        skipped,
        client_id_current,
        waiting,
    }
}

/// The roles a binding grants the account: through it as a subject, or
/// through `system:serviceaccounts`, `system:serviceaccounts:<ns>` or
/// `system:authenticated`. A ServiceAccount subject that names no namespace
/// is in the binding's.
pub(crate) fn binds(subjects: &[k8s_openapi::api::rbac::v1::Subject], binding_ns: &str, namespace: &str, name: &str) -> Option<Option<String>> {
    let groups = ["system:serviceaccounts".to_string(), format!("system:serviceaccounts:{namespace}"), "system:authenticated".to_string()];
    let direct = subjects.iter().any(|s| s.kind == "ServiceAccount" && s.name == name && s.namespace.as_deref().filter(|n| !n.is_empty()).unwrap_or(binding_ns) == namespace);
    if direct {
        return Some(None);
    }
    subjects.iter().find(|s| s.kind == "Group" && groups.contains(&s.name)).map(|s| Some(s.name.clone()))
}

/// The part of a log line worth keeping: from where it says it could not
/// sign in to Azure, or was refused by RBAC as this account, to before the
/// trace and correlation IDs and timestamp Entra ID appends, which differ on
/// every attempt and would keep one error from grouping with its repeats.
pub(crate) fn log_excerpt(line: &str, namespace: &str, name: &str) -> Option<String> {
    // A JSON logger writes the refusal inside a string, its quotes escaped:
    // taken to the end of that string, and unescaped.
    let escaped = format!("User \\\"system:serviceaccount:{namespace}:{name}\\\"");
    if let Some(at) = line.find(&escaped) {
        let rest = &line[at..];
        let mut end = rest.len();
        let bytes = rest.as_bytes();
        for i in escaped.len()..bytes.len() {
            if bytes[i] == b'"' && bytes[i - 1] != b'\\' {
                end = i;
                break;
            }
        }
        return Some(cap(&rest[..end].replace("\\\"", "\"")));
    }
    let user = format!("User \"system:serviceaccount:{namespace}:{name}\"");
    const MARKERS: &[&str] = &[
        "AADSTS",
        "Caller is not authorized",
        "AuthorizationFailed",
        "WorkloadIdentityCredential",
        "ManagedIdentityCredential",
        "ClientAssertionCredential",
        "DefaultAzureCredential",
        ENV_TOKEN_FILE,
        "unable to load in-cluster configuration",
    ];
    let start = line.find(&user).or_else(|| MARKERS.iter().filter_map(|m| line.find(m)).min())?;
    let rest = &line[start..];
    let end = [" Trace ID:", " Correlation ID:", " Timestamp:"].iter().filter_map(|m| rest.find(m)).min().unwrap_or(rest.len());
    Some(cap(rest[..end].trim_end()))
}

fn cap(excerpt: &str) -> String {
    match excerpt.char_indices().nth(EXCERPT_CHARS) {
        Some((at, _)) => format!("{} …", &excerpt[..at]),
        None => excerpt.to_string(),
    }
}

async fn events_of(client: &Client, kind: &str, namespace: &str, name: &str, warnings_only: bool) -> Result<Vec<EventInfo>, String> {
    use k8s_openapi::api::core::v1::Event;
    let warning = if warnings_only { ",type=Warning" } else { "" };
    let params = ListParams::default().fields(&format!("involvedObject.kind={kind},involvedObject.name={name}{warning}"));
    Api::<Event>::namespaced(client.clone(), namespace)
        .list(&params)
        .await
        .map(|l| {
            let mut items = l.items;
            items.sort_by(|a, b| k8s::event_last_seen(b).cmp(&k8s::event_last_seen(a)));
            items.into_iter().map(event_to_info).collect()
        })
        .map_err(|e| format!("Failed to list events for {kind} '{name}': {e}"))
}

/// The issuer this cluster's service account tokens carry: what a federated
/// credential must name.
async fn read_issuer(client: &Client) -> Result<String, String> {
    let req = http::Request::builder().uri("/.well-known/openid-configuration").body(Vec::new()).map_err(|e| e.to_string())?;
    let v: serde_json::Value = client.request(req).await.map_err(|e| format!("the API server's OpenID configuration could not be read: {e}"))?;
    v.get("issuer").and_then(|i| i.as_str()).map(str::to_string).ok_or_else(|| "the API server's OpenID configuration names no issuer".to_string())
}

/// The webhook's configurations, each with whether the Deployment behind
/// its Service is ready.
async fn read_webhook(client: &Client) -> Result<Vec<String>, String> {
    use k8s_openapi::api::admissionregistration::v1::MutatingWebhookConfiguration;
    use k8s_openapi::api::apps::v1::Deployment;
    let configs = Api::<MutatingWebhookConfiguration>::all(client.clone())
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list MutatingWebhookConfigurations: {e}"))?;
    let mut out = Vec::new();
    for c in &configs.items {
        for w in c.webhooks.iter().flatten().filter(|w| w.name == WEBHOOK_NAME) {
            let config = c.metadata.name.clone().unwrap_or_default();
            let policy = w.failure_policy.clone().unwrap_or_else(|| "Fail".to_string());
            let selector = w.object_selector.as_ref().map(k8s::label_selector_query).filter(|s| !s.is_empty());
            let backend = match w.client_config.service.as_ref() {
                Some(svc) => {
                    let deployments = Api::<Deployment>::namespaced(client.clone(), &svc.namespace).list(&ListParams::default()).await;
                    match deployments {
                        Ok(list) => {
                            let found: Vec<String> = list
                                .items
                                .iter()
                                .filter(|d| d.metadata.name.as_deref().is_some_and(|n| n.starts_with("azure-wi-webhook")))
                                .map(|d| {
                                    let want = d.spec.replicas.unwrap_or(1);
                                    let ready = d.status.as_ref().and_then(|s| s.ready_replicas).unwrap_or(0);
                                    let name = d.metadata.name.clone().unwrap_or_default();
                                    if ready < want.max(1) {
                                        format!("ITS DEPLOYMENT {}/{name} HAS {ready} OF {want} READY", svc.namespace)
                                    } else {
                                        format!("its Deployment {}/{name} has {ready} of {want} ready", svc.namespace)
                                    }
                                })
                                .collect();
                            if found.is_empty() {
                                format!("served by Service {}/{} (its Deployment was not found by name)", svc.namespace, svc.name)
                            } else {
                                found.join(", ")
                            }
                        }
                        Err(e) => format!("served by Service {}/{} (its Deployment unavailable: {e})", svc.namespace, svc.name),
                    }
                }
                None => "served from outside the cluster".to_string(),
            };
            out.push(format!(
                "{config}: failurePolicy {policy}{}; {backend}",
                selector.map(|s| format!(", mutates only pods labelled {s}")).unwrap_or_default()
            ));
        }
    }
    Ok(out)
}

/// The workloads whose pod template runs as the account.
async fn read_templates(client: &Client, namespace: &str, name: &str) -> Result<Vec<TemplateIdentity>, String> {
    use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
    use k8s_openapi::api::batch::v1::CronJob;
    let params = ListParams::default();
    let (deployment_api, statefulset_api) = (Api::<Deployment>::namespaced(client.clone(), namespace), Api::<StatefulSet>::namespaced(client.clone(), namespace));
    let (daemonset_api, cronjob_api) = (Api::<DaemonSet>::namespaced(client.clone(), namespace), Api::<CronJob>::namespaced(client.clone(), namespace));
    let (deployments, statefulsets, daemonsets, cronjobs) =
        tokio::join!(deployment_api.list(&params), statefulset_api.list(&params), daemonset_api.list(&params), cronjob_api.list(&params));
    let failed = |what: &str, e: kube::Error| format!("Failed to list {what}: {e}");
    let mut out = Vec::new();
    let mut add = |kind: &str, meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta, template: Option<&k8s_openapi::api::core::v1::PodTemplateSpec>| {
        let Some(t) = template else { return };
        if runs_as(t.spec.as_ref()) == name {
            out.push(TemplateIdentity {
                kind: kind.to_string(),
                name: meta.name.clone().unwrap_or_default(),
                use_label: t.metadata.as_ref().and_then(|m| m.labels.as_ref()).and_then(|l| l.get(LABEL_USE)).cloned(),
            });
        }
    };
    for d in deployments.map_err(|e| failed("Deployments", e))?.items {
        add("Deployment", &d.metadata, Some(&d.spec.template));
    }
    for s in statefulsets.map_err(|e| failed("StatefulSets", e))?.items {
        add("StatefulSet", &s.metadata, Some(&s.spec.template));
    }
    for d in daemonsets.map_err(|e| failed("DaemonSets", e))?.items {
        add("DaemonSet", &d.metadata, Some(&d.spec.template));
    }
    for c in cronjobs.map_err(|e| failed("CronJobs", e))?.items {
        add("CronJob", &c.metadata, c.spec.job_template.spec.as_ref().map(|s| &s.template));
    }
    Ok(out)
}

/// The roles bound to the account: by RoleBindings in any namespace — one
/// in another namespace can grant it access there — and ClusterRoleBindings.
/// Where RoleBindings cannot be listed everywhere, its own namespace's are
/// read, and the note says what was left out.
async fn read_bindings(client: &Client, namespace: &str, name: &str) -> (Result<Vec<Binding>, String>, Option<String>) {
    use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleBinding};
    let params = ListParams::default();
    let (role_api, cluster_api) = (Api::<RoleBinding>::all(client.clone()), Api::<ClusterRoleBinding>::all(client.clone()));
    let (roles, cluster) = tokio::join!(role_api.list(&params), cluster_api.list(&params));
    let (roles, note) = match roles {
        Ok(l) => (Ok(l.items), None),
        Err(everywhere) => {
            let own = Api::<RoleBinding>::namespaced(client.clone(), namespace).list(&params).await;
            (own.map(|l| l.items).map_err(|e| format!("Failed to list RoleBindings: {e}")), Some(format!("RoleBindings outside {namespace} could not be listed: {everywhere}")))
        }
    };
    let result = (|| {
        let mut out = Vec::new();
        for b in roles? {
            let binding_ns = b.metadata.namespace.clone().unwrap_or_default();
            if let Some(via) = binds(b.subjects.as_deref().unwrap_or_default(), &binding_ns, namespace, name) {
                out.push(Binding { kind: "RoleBinding", namespace: binding_ns, name: b.metadata.name.unwrap_or_default(), role: format!("{} {}", b.role_ref.kind, b.role_ref.name), via });
            }
        }
        for b in cluster.map_err(|e| format!("Failed to list ClusterRoleBindings: {e}"))?.items {
            if let Some(via) = binds(b.subjects.as_deref().unwrap_or_default(), "", namespace, name) {
                out.push(Binding { kind: "ClusterRoleBinding", namespace: String::new(), name: b.metadata.name.unwrap_or_default(), role: format!("{} {}", b.role_ref.kind, b.role_ref.name), via });
            }
        }
        Ok(out)
    })();
    (result, note)
}

/// Which log of each of a pod's containers to read, init containers too:
/// the current instance's, or for one waiting to restart — crash-looping on
/// the sign-in it cannot make — its previous instance's.
pub(crate) fn logs_to_read(p: &Pod) -> Vec<(String, bool)> {
    let status = p.status.clone().unwrap_or_default();
    status
        .init_container_statuses
        .iter()
        .flatten()
        .chain(status.container_statuses.iter().flatten())
        .filter_map(|c| {
            let waiting = c.state.as_ref().is_some_and(|s| s.waiting.is_some());
            let crashed = c.last_state.as_ref().is_some_and(|l| l.terminated.is_some());
            match (waiting, crashed) {
                (false, _) => Some((c.name.clone(), false)),
                (true, true) => Some((c.name.clone(), true)),
                (true, false) => None,
            }
        })
        .collect()
}

/// Excerpts from the logs of its pods, active not-ready ones first. A pod
/// counts as read when at least one of its logs could be.
async fn read_log_excerpts(client: &Client, namespace: &str, name: &str, pods: &[Pod]) -> Result<(usize, Vec<String>), String> {
    let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let mut excerpts = Vec::new();
    let mut read = 0;
    for p in pods.iter().take(PODS_LOGGED) {
        let pod = p.metadata.name.clone().unwrap_or_default();
        let mut any = false;
        for (container, previous) in logs_to_read(p) {
            // A previous instance ended when it ended, which may be more
            // than the hour ago the current one's window starts.
            let params = LogParams { container: Some(container), previous, since_seconds: (!previous).then_some(LOG_SECONDS), limit_bytes: Some(LOG_BYTES), ..Default::default() };
            match api.logs(&pod, &params).await {
                Ok(text) => {
                    any = true;
                    excerpts.extend(text.lines().filter_map(|l| log_excerpt(l, namespace, name)));
                }
                // A container that has not written yet, or a pod gone meanwhile.
                Err(kube::Error::Api(r)) if r.code == 400 || r.code == 404 => {}
                Err(e) => return Err(format!("Failed to read the log of pod '{pod}': {e}")),
            }
        }
        read += usize::from(any);
    }
    Ok((read, excerpts))
}

fn completed(p: &Pod) -> bool {
    p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Succeeded")
}

pub async fn get_service_account_diagnostics(context_name: &str, namespace: &str, name: &str) -> Result<ServiceAccountDiagnostics, String> {
    let client = client_for_context(context_name).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ApiResource::erase::<ServiceAccount>(&()));
    let mut obj = api.get(name).await.map_err(|e| k8s::get_error("ServiceAccount", name, e))?;
    let account: ServiceAccount = serde_json::to_value(&obj).and_then(serde_json::from_value).map_err(|e| format!("Failed to read ServiceAccount '{name}': {e}"))?;
    if let Some(a) = obj.metadata.annotations.as_mut() {
        a.remove(k8s::LAST_APPLIED_ANNOTATION);
    }
    let manifest = object_manifest(obj)?.yaml_without_managed_fields;
    let client_id = account.metadata.annotations.as_ref().and_then(|a| a.get(ANNOTATION_CLIENT_ID)).cloned().filter(|c| !c.is_empty());

    let pods_fut = async {
        Api::<Pod>::namespaced(client.clone(), namespace).list(&ListParams::default()).await.map_err(|e| format!("Failed to list pods: {e}")).map(|l| {
            let mut mine: Vec<Pod> = l.items.into_iter().filter(|p| runs_as(p.spec.as_ref()) == name).collect();
            // A completed Job's pod is not ready either, but has nothing to say:
            // active pods first, not-ready before ready, completed last.
            mine.sort_by_key(|p| (completed(p), pod_ready(p), p.metadata.name.clone()));
            mine
        })
    };
    let pull_fut = futures::future::join_all(account.image_pull_secrets.iter().flatten().map(|r| {
        let client = client.clone();
        let secret = r.name.clone();
        async move {
            let found = Api::<Secret>::namespaced(client, namespace)
                .get_opt(&secret)
                .await
                .map(|got| got.map(|s| s.type_.unwrap_or_else(|| "Opaque".to_string())))
                .map_err(|e| format!("Failed to get Secret '{secret}': {e}"));
            (secret, found)
        }
    }));
    let webhook_fut = async {
        match client_id {
            Some(_) => Some(read_webhook(&client).await),
            None => None,
        }
    };
    let (pods, templates, pull_secrets, (bindings, bindings_note), webhook, issuer, events) = tokio::join!(
        pods_fut,
        read_templates(&client, namespace, name),
        pull_fut,
        read_bindings(&client, namespace, name),
        webhook_fut,
        read_issuer(&client),
        events_of(&client, "ServiceAccount", namespace, name, false),
    );

    let (log_excerpts, pod_events) = match &pods {
        Ok(list) => {
            let unready: Vec<&Pod> = list.iter().filter(|p| !pod_ready(p) && !completed(p)).take(3).collect();
            let events_fut = futures::future::join_all(unready.iter().map(|p| {
                let pod = p.metadata.name.clone().unwrap_or_default();
                let client = client.clone();
                async move {
                    let events = events_of(&client, "Pod", namespace, &pod, true).await;
                    (pod, events)
                }
            }));
            tokio::join!(read_log_excerpts(&client, namespace, name, list), events_fut)
        }
        Err(e) => (Err(e.clone()), Vec::new()),
    };
    let pods = pods.map(|list| list.iter().map(|p| pod_identity(p, client_id.as_deref())).collect());

    Ok(ServiceAccountDiagnostics { account, manifest, events, pods, templates, pull_secrets, bindings, bindings_note, webhook, issuer, log_excerpts, pod_events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod(v: serde_json::Value) -> Pod {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn a_pod_says_which_containers_the_webhook_injected() {
        let env = |client: &str| json!([{ "name": "AZURE_CLIENT_ID", "value": client }, { "name": "AZURE_FEDERATED_TOKEN_FILE", "value": "/var/run/secrets/azure/tokens/azure-identity-token" }]);
        let p = pod(json!({
            "metadata": { "name": "web-1", "labels": { "azure.workload.identity/use": "true" }, "annotations": { "azure.workload.identity/skip-containers": "istio-proxy" },
                "ownerReferences": [{ "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "web-5d8f", "uid": "u", "controller": true }] },
            "spec": { "serviceAccountName": "web", "containers": [
                { "name": "app", "image": "app", "env": env("new-id") },
                { "name": "worker", "image": "worker" },
                { "name": "istio-proxy", "image": "proxy" }
            ] },
            "status": { "phase": "Running", "conditions": [{ "type": "Ready", "status": "False" }],
                "containerStatuses": [{ "name": "worker", "ready": false, "restartCount": 3, "image": "worker", "imageID": "", "state": { "waiting": { "reason": "CrashLoopBackOff" } } }] }
        }));
        let i = pod_identity(&p, Some("new-id"));
        assert_eq!((i.injected, i.not_injected, i.skipped), (vec!["app".to_string()], vec!["worker".to_string()], vec!["istio-proxy".to_string()]));
        assert_eq!((i.use_label.as_deref(), i.client_id_current, i.ready), (Some("true"), Some(true), false));
        assert_eq!((i.owner.as_str(), i.waiting), ("ReplicaSet/web-5d8f", vec!["worker: CrashLoopBackOff".to_string()]));
        // Started before the annotation changed: the old client ID is still injected.
        assert_eq!(pod_identity(&p, Some("newer-id")).client_id_current, Some(false));
        assert_eq!(runs_as(None), "default");
    }

    #[test]
    fn a_crash_looping_containers_previous_log_is_read_and_init_containers_too() {
        let status = |name: &str, state: serde_json::Value, last: serde_json::Value| json!({ "name": name, "ready": false, "restartCount": 1, "image": "i", "imageID": "", "state": state, "lastState": last });
        let p = pod(json!({
            "metadata": { "name": "web-1" }, "spec": { "containers": [] },
            "status": {
                "initContainerStatuses": [status("token-check", json!({ "terminated": { "exitCode": 1 } }), json!({}))],
                "containerStatuses": [
                    status("app", json!({ "waiting": { "reason": "CrashLoopBackOff" } }), json!({ "terminated": { "exitCode": 1 } })),
                    status("fresh", json!({ "waiting": { "reason": "ContainerCreating" } }), json!({})),
                    status("sidecar", json!({ "running": {} }), json!({}))
                ]
            }
        }));
        assert_eq!(logs_to_read(&p), vec![("token-check".to_string(), false), ("app".to_string(), true), ("sidecar".to_string(), false)]);
    }

    #[test]
    fn a_binding_grants_the_account_directly_or_through_its_groups() {
        use k8s_openapi::api::rbac::v1::Subject;
        let sa = |ns: Option<&str>| Subject { kind: "ServiceAccount".into(), name: "web".into(), namespace: ns.map(str::to_string), api_group: None };
        let group = |g: &str| Subject { kind: "Group".into(), name: g.into(), namespace: None, api_group: Some("rbac.authorization.k8s.io".into()) };
        assert_eq!(binds(&[sa(Some("app"))], "", "app", "web"), Some(None));
        assert_eq!(binds(&[sa(None)], "app", "app", "web"), Some(None), "a subject without a namespace is in the binding's");
        assert_eq!(binds(&[sa(Some("other"))], "", "app", "web"), None);
        assert_eq!(binds(&[group("system:serviceaccounts:app")], "", "app", "web"), Some(Some("system:serviceaccounts:app".into())));
        assert_eq!(binds(&[group("system:serviceaccounts:other")], "", "app", "web"), None);
    }

    #[test]
    fn a_log_line_is_kept_from_the_error_without_its_trace_ids() {
        let line = "2026-11-23T10:00:00Z ERR failed to get token: WorkloadIdentityCredential authentication failed: AADSTS70021: No matching federated identity record found for presented assertion. Assertion Issuer: 'https://oidc.example/abc/'. Assertion Subject: 'system:serviceaccount:app:web'. Trace ID: 1234 Correlation ID: 5678 Timestamp: 2026-11-23 10:00:00Z";
        assert_eq!(
            log_excerpt(line, "app", "web").as_deref(),
            Some("WorkloadIdentityCredential authentication failed: AADSTS70021: No matching federated identity record found for presented assertion. Assertion Issuer: 'https://oidc.example/abc/'. Assertion Subject: 'system:serviceaccount:app:web'.")
        );
        let rbac = r#"E1123 10:00:00 reflector.go:1] pods is forbidden: User "system:serviceaccount:app:web" cannot list resource "pods" in API group "" in the namespace "app""#;
        assert_eq!(log_excerpt(rbac, "app", "web").as_deref(), Some(r#"User "system:serviceaccount:app:web" cannot list resource "pods" in API group "" in the namespace "app""#));
        assert_eq!(log_excerpt(r#"pods is forbidden: User "system:serviceaccount:app:other" cannot list"#, "app", "web"), None, "another account's refusal");
        // The same refusal from a JSON logger.
        let json = r#"{"level":"error","msg":"list failed","error":"pods is forbidden: User \"system:serviceaccount:app:web\" cannot list resource \"pods\" in API group \"\" in the namespace \"app\"","ts":1}"#;
        assert_eq!(log_excerpt(json, "app", "web").as_deref(), Some(r#"User "system:serviceaccount:app:web" cannot list resource "pods" in API group "" in the namespace "app""#));
        assert_eq!(log_excerpt(&json.replace("app:web", "app:other"), "app", "web"), None);
        assert_eq!(log_excerpt("GET /healthz 200", "app", "web"), None);
        let long = format!("AADSTS50000: {}", "x".repeat(1000));
        assert!(log_excerpt(&long, "app", "web").unwrap().ends_with(" …"));
    }

    /// Builds the diagnosis of a sample of accounts, the Workload Identity
    /// ones first, printing counts only:
    /// SA_DIAG_TEST_CONTEXT=<context> cargo test --lib
    /// service_accounts::tests::service_account_diagnosis_against_a_live_cluster -- --ignored --exact --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set SA_DIAG_TEST_CONTEXT to run"]
    async fn service_account_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("SA_DIAG_TEST_CONTEXT") else { return };
        let mut all = crate::resources::get_service_accounts(&ctx).await.expect("list");
        all.sort_by_key(|s| s.workload_identity_client_id.is_empty());
        println!("accounts={} with a client ID={}", all.len(), all.iter().filter(|s| !s.workload_identity_client_id.is_empty()).count());
        for s in all.iter().take(6) {
            let d = get_service_account_diagnostics(&ctx, &s.namespace, &s.name).await.expect("diagnostics");
            let p = crate::claude::build_service_account_diagnosis_payload(&ctx, &s.namespace, &s.name).await.expect("payload");
            let pods = d.pods.as_ref().expect("pods");
            println!(
                "wi={} pods={} (ready {}, labelled {}, injected {}, stale client id {}) templates={:?} pull secrets={} bindings={:?} webhook={:?} issuer={} log excerpts={:?} tokens={} unavailable={}",
                !s.workload_identity_client_id.is_empty(),
                pods.len(),
                pods.iter().filter(|p| p.ready).count(),
                pods.iter().filter(|p| p.use_label.as_deref() == Some("true")).count(),
                pods.iter().filter(|p| !p.injected.is_empty()).count(),
                pods.iter().filter(|p| p.client_id_current == Some(false)).count(),
                d.templates.as_ref().map(Vec::len),
                d.pull_secrets.len(),
                d.bindings.as_ref().map(Vec::len),
                d.webhook.as_ref().map(|w| w.as_ref().map(Vec::len)),
                d.issuer.is_ok(),
                d.log_excerpts.as_ref().map(|(n, l)| (*n, l.len())),
                p.approx_tokens,
                p.prompt.matches("unavailable").count(),
            );
            if !s.workload_identity_client_id.is_empty() {
                assert!(matches!(d.webhook, Some(Ok(ref w)) if !w.is_empty()), "a cluster using Workload Identity has its webhook");
            }
        }
    }
}
