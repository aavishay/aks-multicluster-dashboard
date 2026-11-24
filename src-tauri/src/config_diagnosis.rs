//! A ConfigMap's or Secret's diagnosis: who uses it, how, and whether they
//! see what it holds now.
//!
//! How something uses one decides when a change reaches it. An environment
//! variable (`env` or `envFrom`) is read once, when the container starts, so
//! a pod started before the change keeps the old value until it restarts. A
//! mounted volume is refreshed by the kubelet within about a minute — but a
//! `subPath` mount never is, and the application still has to re-read the
//! file. So the diagnosis reads the last write to the object's data, as its
//! managedFields record it — an upper bound, as the same manager writing a
//! label moves it too — and when each consumer container's current instance
//! started.
//!
//! No value is read into the payload: a ConfigMap's and a Secret's keys are
//! named with their sizes, a TLS certificate by its public fields.

use crate::k8s::{self, event_to_info, Chrono};
use crate::kubeconfig::client_for_context;
use crate::models::EventInfo;
use chrono::{DateTime, Utc};
use k8s_openapi::api::core::v1::{ConfigMap, LocalObjectReference, PersistentVolume, Pod, PodSpec, Secret, SecretReference, Volume};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use kube::api::{Api, ListParams};
use kube::Client;
use serde_json::Value;

/// How a pod spec uses the object.
#[derive(Clone, PartialEq, Debug)]
pub enum Use {
    /// One key as an environment variable.
    EnvKey { container: String, key: String, optional: bool },
    /// Every key as environment variables.
    EnvFrom { container: String, optional: bool },
    /// Mounted as a volume, or as one source of a projected volume: the keys
    /// it picks (empty for all), and where each container mounts it, with
    /// whether through `subPath` or `subPathExpr`.
    Volume { volume: String, keys: Vec<String>, mounts: Vec<(String, String, bool)>, optional: bool },
    /// A Secret as an image pull secret.
    PullSecret,
    /// A Secret as the credentials a volume plugin reads when it mounts an
    /// inline volume: an azureFile share's account key, a CSI driver's
    /// node-publish secret.
    VolumeCredentials { volume: String, source: &'static str },
}

impl Use {
    /// Whether a change reaches it only when the container restarts.
    pub fn needs_restart(&self) -> bool {
        !self.restart_containers().is_empty()
    }

    /// The containers that read it only when they start: through env vars,
    /// or a `subPath` mount, which is never refreshed.
    pub fn restart_containers(&self) -> Vec<&str> {
        match self {
            Use::EnvKey { container, .. } | Use::EnvFrom { container, .. } => vec![container.as_str()],
            Use::Volume { mounts, .. } => mounts.iter().filter(|(_, _, sub_path)| *sub_path).map(|(c, _, _)| c.as_str()).collect(),
            Use::PullSecret | Use::VolumeCredentials { .. } => Vec::new(),
        }
    }

    /// Whether it is a volume mount the kubelet refreshes.
    pub fn refreshed(&self) -> bool {
        matches!(self, Use::Volume { mounts, .. } if mounts.iter().any(|(_, _, sub_path)| !*sub_path))
    }
}

/// A pod that uses it.
pub struct ConsumerPod {
    pub name: String,
    pub ready: bool,
    pub phase: String,
    /// `container: Reason` for each container waiting or last terminated.
    pub waiting: Vec<String>,
    /// How this pod itself uses it, which for a pod of an older revision is
    /// not how its workload's template does now.
    pub uses: Vec<Use>,
    /// When each container's current instance started; `None` for one
    /// waiting to start, whose next start reads the contents as they are then.
    pub container_started: Vec<(String, Option<DateTime<Utc>>)>,
}

impl ConsumerPod {
    /// Whether a container that reads it only at start began before `changed`
    /// and so may hold older contents: `None` when such a container's start is
    /// not known.
    pub fn may_be_stale(&self, changed: DateTime<Utc>) -> Option<bool> {
        let mut unknown = false;
        for container in self.uses.iter().flat_map(Use::restart_containers) {
            match self.container_started.iter().find(|(c, _)| c == container) {
                Some((_, Some(started))) if *started < changed => return Some(true),
                Some(_) => {}
                None => unknown = true,
            }
        }
        if unknown {
            None
        } else {
            Some(false)
        }
    }

    /// Whether a container that reads it only at start has yet to start: it
    /// will read the contents as they are then.
    pub fn yet_to_start(&self) -> bool {
        self.uses.iter().flat_map(Use::restart_containers).any(|c| self.container_started.iter().any(|(name, started)| name == c && started.is_none()))
    }
}

/// A workload, or for pods no listed workload accounts for their controller,
/// that uses the object.
pub struct Consumer {
    pub kind: String,
    pub name: String,
    /// How its template uses it; for a consumer found only from its pods,
    /// how the first of them does.
    pub uses: Vec<Use>,
    /// Whether `uses` is the template's, against which a pod that differs is
    /// of an older revision. Pods alone carry no order of revisions.
    pub from_template: bool,
    /// For a consumer found only from its pods: its workload's template was
    /// read and does not use it, so its pods are of an older revision.
    pub template_unused: bool,
    pub pods: Vec<ConsumerPod>,
}

/// Everything a ConfigMap or Secret diagnosis reads. Only the object is
/// required.
pub struct ConfigDiagnostics {
    pub namespace: String,
    pub name: String,
    /// Each key and its size in bytes.
    pub keys: Vec<(String, usize)>,
    pub immutable: bool,
    /// The latest its contents can have changed: the newest write by a
    /// manager that owns its data. That manager's write to another field (a
    /// label) moves it too, so a change then is possible, not certain.
    pub last_change: Option<DateTime<Utc>>,
    /// A Secret's type and what writes it; `None` for a ConfigMap.
    pub secret: Option<crate::models::SecretOverview>,
    /// A TLS Secret, by its keys and certificate.
    pub tls: Option<k8s::IngressTlsSecret>,
    /// What writes a ConfigMap: its owners and managed-by label.
    pub writers: Vec<String>,
    /// What uses it, from whatever could be read.
    pub consumers: Vec<Consumer>,
    /// The reads behind `consumers` that failed: the pods, or a workload kind.
    pub consumer_errors: Vec<String>,
    /// Whether its namespace's pods could be listed.
    pub pods_known: bool,
    /// For a Secret: the Ingresses whose TLS names it, with their hosts.
    pub ingresses: Result<Vec<(String, Vec<String>)>, String>,
    /// For a Secret: the Gateway listeners whose certificate it is, each
    /// with the hostname it serves (empty for any); a note in parentheses
    /// when some Gateway API kinds could not be listed.
    pub gateways: Result<Vec<(String, String)>, String>,
    /// For a Secret: the ServiceAccounts that list it.
    pub service_accounts: Result<Vec<String>, String>,
    /// For a Secret: the PersistentVolumes and StorageClasses that name it as
    /// a volume plugin's credentials, by the field; a note in parentheses for
    /// a kind that could not be listed.
    pub volumes: Result<Vec<String>, String>,
    pub manifest: String,
    pub events: Result<Vec<EventInfo>, String>,
    /// The Warning events of consumer pods that are not ready, by pod.
    pub pod_events: Vec<(String, Result<Vec<EventInfo>, String>)>,
}

/// The service account token volume every pod mounts projects
/// `kube-root-ca.crt` too: counting it would make every pod a consumer.
fn is_api_access_volume(name: &str) -> bool {
    name.starts_with("kube-api-access-")
}

/// Every way a pod spec uses the named ConfigMap or Secret, init containers
/// included.
pub(crate) fn uses_in(spec: &PodSpec, kind: &str, name: &str) -> Vec<Use> {
    let secret = kind == "Secret";
    let mut out = Vec::new();
    for c in spec.init_containers.iter().flatten().chain(spec.containers.iter()) {
        for e in c.env.iter().flatten() {
            let from = e.value_from.as_ref();
            let key_ref = if secret {
                from.and_then(|f| f.secret_key_ref.as_ref()).map(|r| (r.name.as_str(), r.key.as_str(), r.optional))
            } else {
                from.and_then(|f| f.config_map_key_ref.as_ref()).map(|r| (r.name.as_str(), r.key.as_str(), r.optional))
            };
            if let Some((n, key, optional)) = key_ref {
                if n == name {
                    out.push(Use::EnvKey { container: c.name.clone(), key: key.to_string(), optional: optional.unwrap_or(false) });
                }
            }
        }
        for e in c.env_from.iter().flatten() {
            let from = if secret { e.secret_ref.as_ref().map(|r| (r.name.as_str(), r.optional)) } else { e.config_map_ref.as_ref().map(|r| (r.name.as_str(), r.optional)) };
            if let Some((n, optional)) = from {
                if n == name {
                    out.push(Use::EnvFrom { container: c.name.clone(), optional: optional.unwrap_or(false) });
                }
            }
        }
    }
    for v in spec.volumes.iter().flatten() {
        if is_api_access_volume(&v.name) {
            continue;
        }
        let mut sources: Vec<(Vec<String>, bool)> = Vec::new();
        if secret {
            if let Some(s) = v.secret.as_ref().filter(|s| s.secret_name.as_deref() == Some(name)) {
                sources.push((s.items.iter().flatten().map(|i| i.key.clone()).collect(), s.optional.unwrap_or(false)));
            }
        } else if let Some(c) = v.config_map.as_ref().filter(|c| c.name == name) {
            sources.push((c.items.iter().flatten().map(|i| i.key.clone()).collect(), c.optional.unwrap_or(false)));
        }
        for p in v.projected.iter().flat_map(|p| p.sources.iter().flatten()) {
            if secret {
                if let Some(s) = p.secret.as_ref().filter(|s| s.name == name) {
                    sources.push((s.items.iter().flatten().map(|i| i.key.clone()).collect(), s.optional.unwrap_or(false)));
                }
            } else if let Some(c) = p.config_map.as_ref().filter(|c| c.name == name) {
                sources.push((c.items.iter().flatten().map(|i| i.key.clone()).collect(), c.optional.unwrap_or(false)));
            }
        }
        for (keys, optional) in sources {
            let mounts = spec
                .init_containers
                .iter()
                .flatten()
                .chain(spec.containers.iter())
                .flat_map(|c| {
                    c.volume_mounts.iter().flatten().filter(|m| m.name == v.name).map(|m| {
                        // subPathExpr is a subPath expanded from env vars, and as
                        // little refreshed.
                        let sub_path = [&m.sub_path, &m.sub_path_expr].iter().any(|p| p.as_deref().is_some_and(|s| !s.is_empty()));
                        (c.name.clone(), m.mount_path.clone(), sub_path)
                    })
                })
                .collect();
            out.push(Use::Volume { volume: v.name.clone(), keys, mounts, optional });
        }
        if let Some(source) = secret.then(|| volume_credentials(v, name)).flatten() {
            out.push(Use::VolumeCredentials { volume: v.name.clone(), source });
        }
    }
    if secret && spec.image_pull_secrets.iter().flatten().any(|r| r.name == name) {
        out.push(Use::PullSecret);
    }
    out
}

/// The plugin of an inline volume that reads the named Secret for its
/// credentials when it mounts the volume.
fn volume_credentials(v: &Volume, name: &str) -> Option<&'static str> {
    let names = |r: Option<&LocalObjectReference>| r.is_some_and(|r| r.name == name);
    if v.azure_file.as_ref().is_some_and(|a| a.secret_name == name) {
        Some("azureFile")
    } else if v.csi.as_ref().is_some_and(|c| names(c.node_publish_secret_ref.as_ref())) {
        Some("CSI")
    } else if v.cephfs.as_ref().is_some_and(|c| names(c.secret_ref.as_ref())) {
        Some("cephfs")
    } else if v.rbd.as_ref().is_some_and(|r| names(r.secret_ref.as_ref())) {
        Some("rbd")
    } else if v.iscsi.as_ref().is_some_and(|i| names(i.secret_ref.as_ref())) {
        Some("iscsi")
    } else if v.flex_volume.as_ref().is_some_and(|f| names(f.secret_ref.as_ref())) {
        Some("flexVolume")
    } else {
        None
    }
}

/// The fields of a PersistentVolume that name the Secret as its plugin's
/// credentials. A reference that names no namespace means its claim's.
pub(crate) fn pv_secret_fields(pv: &PersistentVolume, namespace: &str, name: &str) -> Vec<&'static str> {
    let Some(spec) = pv.spec.as_ref() else { return Vec::new() };
    let claim_namespace = spec.claim_ref.as_ref().and_then(|r| r.namespace.as_deref());
    let here = |ns: Option<&str>| ns.or(claim_namespace) == Some(namespace);
    let names = |r: Option<&SecretReference>| r.is_some_and(|r| r.name.as_deref() == Some(name) && here(r.namespace.as_deref()));
    let mut out = Vec::new();
    if let Some(c) = &spec.csi {
        for (field, r) in [
            ("spec.csi.nodeStageSecretRef", &c.node_stage_secret_ref),
            ("spec.csi.nodePublishSecretRef", &c.node_publish_secret_ref),
            ("spec.csi.controllerPublishSecretRef", &c.controller_publish_secret_ref),
            ("spec.csi.controllerExpandSecretRef", &c.controller_expand_secret_ref),
            ("spec.csi.nodeExpandSecretRef", &c.node_expand_secret_ref),
        ] {
            if names(r.as_ref()) {
                out.push(field);
            }
        }
    }
    if spec.azure_file.as_ref().is_some_and(|a| a.secret_name == name && here(a.secret_namespace.as_deref())) {
        out.push("spec.azureFile.secretName");
    }
    for (field, r) in [
        ("spec.cephfs.secretRef", spec.cephfs.as_ref().and_then(|c| c.secret_ref.as_ref())),
        ("spec.rbd.secretRef", spec.rbd.as_ref().and_then(|c| c.secret_ref.as_ref())),
        ("spec.iscsi.secretRef", spec.iscsi.as_ref().and_then(|c| c.secret_ref.as_ref())),
        ("spec.flexVolume.secretRef", spec.flex_volume.as_ref().and_then(|c| c.secret_ref.as_ref())),
    ] {
        if names(r) {
            out.push(field);
        }
    }
    out
}

/// The parameters of a StorageClass that name the Secret: a CSI driver's
/// secrets, and the azurefile driver's `secretName`. A namespace left out,
/// or `${pvc.namespace}`, is each claim's.
pub(crate) fn storage_class_secret_parameters(parameters: &std::collections::BTreeMap<String, String>, namespace: &str, name: &str) -> Vec<String> {
    let here = |ns: Option<&String>| ns.is_none_or(|ns| ns == namespace || ns == "${pvc.namespace}");
    let mut out = Vec::new();
    for prefix in ["provisioner", "controller-publish", "node-stage", "node-publish", "controller-expand", "node-expand"] {
        let key = format!("csi.storage.k8s.io/{prefix}-secret-name");
        if parameters.get(&key).is_some_and(|n| n == name) && here(parameters.get(&format!("csi.storage.k8s.io/{prefix}-secret-namespace"))) {
            out.push(key);
        }
    }
    if parameters.get("secretName").is_some_and(|n| n == name) && here(parameters.get("secretNamespace")) {
        out.push("secretName".to_string());
    }
    out
}

/// The latest its contents can have changed: the newest managedFields entry
/// that owns its data, else the newest entry. `None` when no entry records a
/// time: its creation is the earliest its contents could have changed, not
/// the latest, and says nothing of a later edit.
pub(crate) fn last_change(meta: &ObjectMeta) -> Option<DateTime<Utc>> {
    let entries = meta.managed_fields.iter().flatten();
    let touches_data = |f: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry| {
        f.fields_v1.as_ref().is_some_and(|v| v.0.get("f:data").is_some() || v.0.get("f:binaryData").is_some() || v.0.get("f:stringData").is_some())
    };
    entries
        .clone()
        .filter(|f| touches_data(f))
        .filter_map(|f| f.time.as_ref().map(|t| t.0.utc()))
        .max()
        .or_else(|| entries.filter_map(|f| f.time.as_ref().map(|t| t.0.utc())).max())
}

fn consumer_pod(p: &Pod, uses: Vec<Use>) -> ConsumerPod {
    let status = p.status.clone().unwrap_or_default();
    let container_started = status
        .init_container_statuses
        .iter()
        .flatten()
        .chain(status.container_statuses.iter().flatten())
        .map(|c| {
            let state = c.state.as_ref();
            let started = state
                .and_then(|s| s.running.as_ref())
                .and_then(|r| r.started_at.as_ref())
                .or_else(|| state.and_then(|s| s.terminated.as_ref()).and_then(|t| t.started_at.as_ref()))
                .map(|t| t.0.utc());
            (c.name.clone(), started)
        })
        .collect();
    ConsumerPod {
        name: p.metadata.name.clone().unwrap_or_default(),
        uses,
        container_started,
        ready: status.conditions.iter().flatten().any(|c| c.type_ == "Ready" && c.status == "True"),
        phase: status.phase.clone().unwrap_or_default(),
        waiting: status
            .init_container_statuses
            .iter()
            .flatten()
            .chain(status.container_statuses.iter().flatten())
            .filter_map(|c| {
                let reason = c
                    .state
                    .as_ref()
                    .and_then(|s| s.waiting.as_ref())
                    .and_then(|w| w.reason.clone())
                    .or_else(|| (!c.ready).then(|| c.last_state.as_ref().and_then(|l| l.terminated.as_ref()).and_then(|t| t.reason.clone())).flatten())?;
                Some(format!("{}: {reason}", c.name))
            })
            .collect(),
    }
}

/// A pod's controller, as `Kind/name`, with a ReplicaSet's taken back to its
/// Deployment by the pod-template-hash it is named with.
fn controller_of(p: &Pod) -> (String, String) {
    let Some(o) = p.metadata.owner_references.iter().flatten().find(|o| o.controller == Some(true)) else {
        return ("Pod".to_string(), p.metadata.name.clone().unwrap_or_default());
    };
    if o.kind == "ReplicaSet" {
        if let Some(hash) = p.metadata.labels.as_ref().and_then(|l| l.get("pod-template-hash")) {
            if let Some(deployment) = o.name.strip_suffix(&format!("-{hash}")) {
                return ("Deployment".to_string(), deployment.to_string());
            }
        }
    }
    (o.kind.clone(), o.name.clone())
}

/// The workloads whose pod template uses it, with their pods; then the pods
/// no such workload accounts for, grouped by their controller.
pub(crate) fn consumers(templates: Vec<(String, String, Option<LabelSelector>, PodSpec)>, pods: &[Pod], kind: &str, name: &str) -> Vec<Consumer> {
    let mut out: Vec<Consumer> = Vec::new();
    let mut claimed = std::collections::HashSet::new();
    let read: Vec<(String, String)> = templates.iter().map(|(k, n, _, _)| (k.clone(), n.clone())).collect();
    // A CronJob's pods belong to its Jobs, named after it.
    let job_of = |cronjob: &str, job: &str| job.strip_prefix(&format!("{cronjob}-")).is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()));
    let pod_uses: Vec<(usize, Vec<Use>)> =
        pods.iter().enumerate().filter_map(|(i, p)| p.spec.as_ref().map(|s| (i, uses_in(s, kind, name))).filter(|(_, u)| !u.is_empty())).collect();
    for (wkind, wname, selector, spec) in templates {
        let uses = uses_in(&spec, kind, name);
        if uses.is_empty() {
            continue;
        }
        let mine: Vec<ConsumerPod> = pod_uses
            .iter()
            .filter(|(i, _)| {
                let p = &pods[*i];
                match &selector {
                    Some(sel) => k8s::label_selector_matches(sel, p.metadata.labels.as_ref()),
                    None => job_of(&wname, &controller_of(p).1),
                }
            })
            .map(|(i, uses)| {
                claimed.insert(*i);
                consumer_pod(&pods[*i], uses.clone())
            })
            .collect();
        out.push(Consumer { kind: wkind, name: wname, uses, from_template: true, template_unused: false, pods: mine });
    }
    for (i, uses) in &pod_uses {
        if claimed.contains(i) {
            continue;
        }
        let (ckind, cname) = controller_of(&pods[*i]);
        match out.iter_mut().find(|c| c.kind == ckind && c.name == cname) {
            Some(c) => c.pods.push(consumer_pod(&pods[*i], uses.clone())),
            None => {
                let template_unused = read.iter().any(|(k, n)| (*k == ckind && *n == cname) || (k == "CronJob" && ckind == "Job" && job_of(n, &cname)));
                out.push(Consumer { kind: ckind, name: cname, uses: uses.clone(), from_template: false, template_unused, pods: vec![consumer_pod(&pods[*i], uses.clone())] })
            }
        }
    }
    out
}

/// Annotations that may hold a copy of the object, values and all: kubectl's
/// last-applied, and any other tool's that keeps one (kapp's
/// `kapp.k14s.io/original`) — known by being structured or long, as no list
/// of tools can be complete. Replaced by their size.
pub(crate) fn mask_copying_annotations(manifest: &mut Value) {
    let Some(a) = manifest.pointer_mut("/metadata/annotations").and_then(Value::as_object_mut) else { return };
    for (key, value) in a.iter_mut() {
        let Some(text) = value.as_str() else { continue };
        let trimmed = text.trim_start();
        if key == k8s::LAST_APPLIED_ANNOTATION || trimmed.starts_with('{') || trimmed.starts_with('[') || text.len() > 256 {
            *value = Value::String(format!("<not sent: {} bytes>", text.len()));
        }
    }
}

/// A ConfigMap's manifest with each value replaced by its size: one can hold
/// whole configuration files, and credentials in them.
fn configmap_manifest(cm: &ConfigMap) -> Result<String, String> {
    let mut v = serde_json::to_value(cm).map_err(|e| format!("Failed to render the ConfigMap: {e}"))?;
    for field in ["data", "binaryData"] {
        if let Some(map) = v.get_mut(field).and_then(Value::as_object_mut) {
            for value in map.values_mut() {
                let bytes = value.as_str().map_or(0, str::len);
                *value = Value::String(format!("<not sent: {bytes} bytes>"));
            }
        }
    }
    if let Some(meta) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.remove("managedFields");
    }
    mask_copying_annotations(&mut v);
    serde_yaml::to_string(&v).map_err(|e| format!("Failed to render YAML: {e}"))
}

/// A Secret's manifest as the Secret panel redacts it, its values replaced
/// by their sizes, and any annotation that may copy them masked too.
fn secret_manifest(s: &Secret) -> Result<String, String> {
    let yaml = crate::secrets::redacted_manifest(s)?.yaml_without_managed_fields;
    let mut v: Value = serde_yaml::from_str(&yaml).map_err(|e| format!("Failed to read the redacted Secret: {e}"))?;
    mask_copying_annotations(&mut v);
    serde_yaml::to_string(&v).map_err(|e| format!("Failed to render YAML: {e}"))
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

/// The pod templates of the namespace's workloads, and the kinds that could
/// not be listed: one forbidden kind leaves the others.
async fn read_templates(client: &Client, namespace: &str) -> (Vec<(String, String, Option<LabelSelector>, PodSpec)>, Vec<String>) {
    use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
    use k8s_openapi::api::batch::v1::CronJob;
    let params = ListParams::default();
    let (deployment_api, statefulset_api) = (Api::<Deployment>::namespaced(client.clone(), namespace), Api::<StatefulSet>::namespaced(client.clone(), namespace));
    let (daemonset_api, cronjob_api) = (Api::<DaemonSet>::namespaced(client.clone(), namespace), Api::<CronJob>::namespaced(client.clone(), namespace));
    let (deployments, statefulsets, daemonsets, cronjobs) =
        tokio::join!(deployment_api.list(&params), statefulset_api.list(&params), daemonset_api.list(&params), cronjob_api.list(&params));
    fn items<K: Clone>(errors: &mut Vec<String>, what: &str, r: Result<kube::api::ObjectList<K>, kube::Error>) -> Vec<K> {
        r.map(|l| l.items).unwrap_or_else(|e| {
            errors.push(format!("Failed to list {what}: {e}"));
            Vec::new()
        })
    }
    let mut errors = Vec::new();
    let (deployments, statefulsets) = (items(&mut errors, "Deployments", deployments), items(&mut errors, "StatefulSets", statefulsets));
    let (daemonsets, cronjobs) = (items(&mut errors, "DaemonSets", daemonsets), items(&mut errors, "CronJobs", cronjobs));
    let mut out = Vec::new();
    for d in deployments {
        if let Some(spec) = d.spec.template.spec {
            out.push(("Deployment".to_string(), d.metadata.name.unwrap_or_default(), Some(d.spec.selector), spec));
        }
    }
    for s in statefulsets {
        if let Some(spec) = s.spec.template.spec {
            out.push(("StatefulSet".to_string(), s.metadata.name.unwrap_or_default(), Some(s.spec.selector), spec));
        }
    }
    for d in daemonsets {
        if let Some(spec) = d.spec.template.spec {
            out.push(("DaemonSet".to_string(), d.metadata.name.unwrap_or_default(), Some(d.spec.selector), spec));
        }
    }
    for c in cronjobs {
        if let Some(spec) = c.spec.job_template.spec.and_then(|s| s.template.spec) {
            out.push(("CronJob".to_string(), c.metadata.name.unwrap_or_default(), None, spec));
        }
    }
    (out, errors)
}

/// The Ingresses in the namespace whose TLS names the Secret, with the hosts
/// each serves with it.
async fn read_ingresses(client: &Client, namespace: &str, name: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    use k8s_openapi::api::networking::v1::Ingress;
    let list = Api::<Ingress>::namespaced(client.clone(), namespace).list(&ListParams::default()).await.map_err(|e| format!("Failed to list Ingresses: {e}"))?;
    Ok(list
        .items
        .iter()
        .filter_map(|i| {
            let hosts: Vec<String> =
                i.spec.iter().flat_map(|s| s.tls.iter().flatten()).filter(|t| t.secret_name.as_deref() == Some(name)).flat_map(|t| t.hosts.clone().unwrap_or_default()).collect();
            let names_it = i.spec.iter().flat_map(|s| s.tls.iter().flatten()).any(|t| t.secret_name.as_deref() == Some(name));
            names_it.then(|| (i.metadata.name.clone().unwrap_or_default(), hosts))
        })
        .collect())
}

/// The Gateway listeners whose certificate is the Secret, as
/// `namespace/gateway listener (hostname)`, each with its hostname.
async fn read_gateways(context_name: &str, namespace: &str, name: &str) -> Result<Vec<(String, String)>, String> {
    let api = crate::gateway_api::get_gateway_api(context_name).await?;
    let mut out = Vec::new();
    for g in &api.gateways {
        for l in &g.listeners {
            let names_it = l.certificates.iter().any(|c| (g.namespace == namespace && c == name) || *c == format!("{namespace}/{name}"));
            if names_it {
                let label = format!("{}/{} listener {}{}", g.namespace, g.name, l.name, if l.hostname.is_empty() { String::new() } else { format!(" ({})", l.hostname) });
                out.push((label, l.hostname.clone()));
            }
        }
    }
    if let Some(e) = api.error {
        out.push((format!("(some Gateway API kinds could not be listed: {e})"), String::new()));
    }
    Ok(out)
}

/// The PersistentVolumes and StorageClasses that name the Secret as their
/// plugin's credentials. One kind that cannot be listed leaves the other.
async fn read_volumes(client: &Client, namespace: &str, name: &str) -> Result<Vec<String>, String> {
    use k8s_openapi::api::storage::v1::StorageClass;
    let all = ListParams::default();
    let (pv_api, class_api) = (Api::<PersistentVolume>::all(client.clone()), Api::<StorageClass>::all(client.clone()));
    let (pvs, classes) = tokio::join!(pv_api.list(&all), class_api.list(&all));
    let mut out = Vec::new();
    let mut errors = Vec::new();
    match pvs {
        Ok(l) => out.extend(l.items.iter().filter_map(|pv| {
            let fields = pv_secret_fields(pv, namespace, name);
            (!fields.is_empty()).then(|| format!("PersistentVolume {}: {}", pv.metadata.name.as_deref().unwrap_or_default(), fields.join(", ")))
        })),
        Err(e) => errors.push(format!("Failed to list PersistentVolumes: {e}")),
    }
    match classes {
        Ok(l) => out.extend(l.items.iter().filter_map(|c| {
            let keys = storage_class_secret_parameters(c.parameters.as_ref()?, namespace, name);
            (!keys.is_empty()).then(|| format!("StorageClass {}: parameter {}", c.metadata.name.as_deref().unwrap_or_default(), keys.join(", ")))
        })),
        Err(e) => errors.push(format!("Failed to list StorageClasses: {e}")),
    }
    if errors.len() == 2 {
        return Err(errors.join("; "));
    }
    out.extend(errors.into_iter().map(|e| format!("({e})")));
    Ok(out)
}

async fn read_service_accounts(client: &Client, namespace: &str, name: &str) -> Result<Vec<String>, String> {
    use k8s_openapi::api::core::v1::ServiceAccount;
    let list = Api::<ServiceAccount>::namespaced(client.clone(), namespace).list(&ListParams::default()).await.map_err(|e| format!("Failed to list ServiceAccounts: {e}"))?;
    Ok(list
        .items
        .iter()
        .filter_map(|sa| {
            let pull = sa.image_pull_secrets.iter().flatten().any(|r| r.name == name);
            let listed = sa.secrets.iter().flatten().any(|r| r.name.as_deref() == Some(name));
            let how = match (pull, listed) {
                (true, _) => "as an image pull secret, so every pod running as it gets it",
                (false, true) => "among its token Secrets",
                (false, false) => return None,
            };
            Some(format!("{} {how}", sa.metadata.name.clone().unwrap_or_default()))
        })
        .collect())
}

pub async fn get_config_diagnostics(context_name: &str, kind: &str, namespace: &str, name: &str) -> Result<ConfigDiagnostics, String> {
    let client = client_for_context(context_name).await?;
    let (keys, immutable, meta, secret, tls, writers, manifest) = match kind {
        "ConfigMap" => {
            let cm = Api::<ConfigMap>::namespaced(client.clone(), namespace).get(name).await.map_err(|e| k8s::get_error("ConfigMap", name, e))?;
            let mut keys: Vec<(String, usize)> = cm.data.iter().flatten().map(|(k, v)| (k.clone(), v.len())).collect();
            keys.extend(cm.binary_data.iter().flatten().map(|(k, v)| (k.clone(), v.0.len())));
            keys.sort();
            let mut writers: Vec<String> = cm.metadata.owner_references.iter().flatten().map(|o| format!("owned by {} {}", o.kind, o.name)).collect();
            if let Some(m) = cm.metadata.labels.as_ref().and_then(|l| l.get("app.kubernetes.io/managed-by")) {
                writers.push(format!("app.kubernetes.io/managed-by: {m}"));
            }
            if let Some(r) = cm.metadata.annotations.as_ref().and_then(|a| a.get("meta.helm.sh/release-name")) {
                writers.push(format!("Helm release {r}"));
            }
            let manifest = configmap_manifest(&cm)?;
            (keys, cm.immutable.unwrap_or(false), cm.metadata, None, None, writers, manifest)
        }
        "Secret" => {
            let s = Api::<Secret>::namespaced(client.clone(), namespace).get(name).await.map_err(|e| k8s::get_error("Secret", name, e))?;
            // Sizes only: the values are dropped here.
            let keys: Vec<(String, usize)> = s.data.iter().flatten().map(|(k, v)| (k.clone(), v.0.len())).collect();
            let overview = crate::secrets::overview_of(&s);
            let tls = (overview.secret_type == "kubernetes.io/tls" || s.data.as_ref().is_some_and(|d| d.contains_key("tls.crt"))).then(|| k8s::tls_secret_of(&s));
            let manifest = secret_manifest(&s)?;
            (keys, s.immutable.unwrap_or(false), s.metadata, Some(overview), tls, Vec::new(), manifest)
        }
        other => return Err(format!("{other} is not a ConfigMap or a Secret")),
    };
    let last_change = last_change(&meta);
    let is_secret = kind == "Secret";
    let tls_secret = tls.is_some();

    let pods_fut = async { Api::<Pod>::namespaced(client.clone(), namespace).list(&ListParams::default()).await.map(|l| l.items).map_err(|e| format!("Failed to list pods: {e}")) };
    let ingresses_fut = async { if is_secret { read_ingresses(&client, namespace, name).await } else { Ok(Vec::new()) } };
    let gateways_fut = async { if tls_secret { read_gateways(context_name, namespace, name).await } else { Ok(Vec::new()) } };
    let accounts_fut = async { if is_secret { read_service_accounts(&client, namespace, name).await } else { Ok(Vec::new()) } };
    let volumes_fut = async { if is_secret { read_volumes(&client, namespace, name).await } else { Ok(Vec::new()) } };
    let (pods, templates, ingresses, gateways, service_accounts, volumes, events) = tokio::join!(
        pods_fut,
        read_templates(&client, namespace),
        ingresses_fut,
        gateways_fut,
        accounts_fut,
        volumes_fut,
        events_of(&client, kind, namespace, name, false),
    );

    let (templates, mut consumer_errors) = templates;
    let pods_known = pods.is_ok();
    let pods = pods.unwrap_or_else(|e| {
        consumer_errors.push(e);
        Vec::new()
    });
    let consumers = consumers(templates, &pods, kind, name);
    let unready: Vec<String> = consumers.iter().flat_map(|c| &c.pods).filter(|p| !p.ready && p.phase != "Succeeded").map(|p| p.name.clone()).take(3).collect();
    let pod_events = futures::future::join_all(unready.into_iter().map(|pod| {
        let client = client.clone();
        async move {
            let events = events_of(&client, "Pod", namespace, &pod, true).await;
            (pod, events)
        }
    }))
    .await;

    Ok(ConfigDiagnostics {
        namespace: namespace.to_string(),
        name: name.to_string(),
        keys,
        immutable,
        last_change,
        secret,
        tls,
        writers,
        consumers,
        consumer_errors,
        pods_known,
        ingresses,
        gateways,
        service_accounts,
        volumes,
        manifest,
        events,
        pod_events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(v: serde_json::Value) -> PodSpec {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn every_way_a_pod_uses_a_config_map_is_found() {
        let s = spec(json!({
            "initContainers": [{ "name": "init", "envFrom": [{ "configMapRef": { "name": "app" } }] }],
            "containers": [{
                "name": "web",
                "env": [{ "name": "MODE", "valueFrom": { "configMapKeyRef": { "name": "app", "key": "mode", "optional": true } } },
                        { "name": "OTHER", "valueFrom": { "configMapKeyRef": { "name": "other", "key": "x" } } }],
                "volumeMounts": [{ "name": "conf", "mountPath": "/etc/app" }, { "name": "one", "mountPath": "/etc/app.yaml", "subPath": "app.yaml" },
                                 { "name": "per-pod", "mountPath": "/etc/pod.yaml", "subPathExpr": "$(POD_NAME).yaml" },
                                 { "name": "kube-api-access-abcde", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount" }]
            }],
            "volumes": [
                { "name": "conf", "configMap": { "name": "app" } },
                { "name": "one", "projected": { "sources": [{ "configMap": { "name": "app", "items": [{ "key": "app.yaml", "path": "app.yaml" }] } }] } },
                { "name": "per-pod", "configMap": { "name": "app" } },
                { "name": "kube-api-access-abcde", "projected": { "sources": [{ "configMap": { "name": "app" } }] } }
            ]
        }));
        let uses = uses_in(&s, "ConfigMap", "app");
        assert_eq!(uses, vec![
            Use::EnvFrom { container: "init".into(), optional: false },
            Use::EnvKey { container: "web".into(), key: "mode".into(), optional: true },
            Use::Volume { volume: "conf".into(), keys: vec![], mounts: vec![("web".into(), "/etc/app".into(), false)], optional: false },
            Use::Volume { volume: "one".into(), keys: vec!["app.yaml".into()], mounts: vec![("web".into(), "/etc/app.yaml".into(), true)], optional: false },
            Use::Volume { volume: "per-pod".into(), keys: vec![], mounts: vec![("web".into(), "/etc/pod.yaml".into(), true)], optional: false },
        ]);
        assert_eq!(uses.iter().map(Use::needs_restart).collect::<Vec<_>>(), vec![true, true, false, true, true], "subPathExpr is as unrefreshed as subPath");
        assert!(uses_in(&s, "Secret", "app").is_empty(), "a Secret of the same name is another object");
    }

    #[test]
    fn a_secret_is_also_used_as_a_pull_secret() {
        let s = spec(json!({
            "imagePullSecrets": [{ "name": "acr" }],
            "containers": [{ "name": "web", "env": [{ "name": "PW", "valueFrom": { "secretKeyRef": { "name": "acr", "key": "password" } } }] }],
            "volumes": [{ "name": "certs", "secret": { "secretName": "acr", "optional": true } }]
        }));
        assert_eq!(uses_in(&s, "Secret", "acr"), vec![
            Use::EnvKey { container: "web".into(), key: "password".into(), optional: false },
            Use::Volume { volume: "certs".into(), keys: vec![], mounts: vec![], optional: true },
            Use::PullSecret,
        ]);
    }

    #[test]
    fn a_secret_is_found_as_a_volume_plugins_credentials() {
        let s = spec(json!({
            "containers": [{ "name": "web" }],
            "volumes": [
                { "name": "share", "azureFile": { "secretName": "storage", "shareName": "data" } },
                { "name": "vault", "csi": { "driver": "secrets-store.csi.k8s.io", "nodePublishSecretRef": { "name": "storage" } } },
                { "name": "other", "csi": { "driver": "file.csi.azure.com", "nodePublishSecretRef": { "name": "elsewhere" } } }
            ]
        }));
        assert_eq!(uses_in(&s, "Secret", "storage"), vec![
            Use::VolumeCredentials { volume: "share".into(), source: "azureFile" },
            Use::VolumeCredentials { volume: "vault".into(), source: "CSI" },
        ]);
        assert!(uses_in(&s, "ConfigMap", "storage").is_empty(), "only a Secret holds a volume's credentials");
        assert!(!Use::VolumeCredentials { volume: "share".into(), source: "azureFile" }.needs_restart());

        let pv: PersistentVolume = serde_json::from_value(json!({
            "metadata": { "name": "pv-files" },
            "spec": {
                "claimRef": { "namespace": "app", "name": "files" },
                "csi": { "driver": "file.csi.azure.com", "volumeHandle": "h",
                    "nodeStageSecretRef": { "name": "storage", "namespace": "app" },
                    "nodePublishSecretRef": { "name": "storage", "namespace": "other" } },
                "azureFile": { "secretName": "storage", "shareName": "data" }
            }
        }))
        .unwrap();
        // A reference that names no namespace means its claim's.
        assert_eq!(pv_secret_fields(&pv, "app", "storage"), vec!["spec.csi.nodeStageSecretRef", "spec.azureFile.secretName"]);
        assert_eq!(pv_secret_fields(&pv, "other", "storage"), vec!["spec.csi.nodePublishSecretRef"]);
        assert!(pv_secret_fields(&pv, "app", "elsewhere").is_empty());

        let parameters: std::collections::BTreeMap<String, String> = [
            ("csi.storage.k8s.io/node-stage-secret-name", "storage"),
            ("csi.storage.k8s.io/node-stage-secret-namespace", "${pvc.namespace}"),
            ("csi.storage.k8s.io/provisioner-secret-name", "storage"),
            ("csi.storage.k8s.io/provisioner-secret-namespace", "kube-system"),
            ("secretName", "storage"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(storage_class_secret_parameters(&parameters, "app", "storage"), vec!["csi.storage.k8s.io/node-stage-secret-name", "secretName"]);
        assert_eq!(storage_class_secret_parameters(&parameters, "kube-system", "storage").len(), 3);
    }

    #[test]
    fn the_last_change_is_the_newest_write_to_the_data() {
        let meta: ObjectMeta = serde_json::from_value(json!({
            "name": "app", "creationTimestamp": "2026-01-01T00:00:00Z",
            "managedFields": [
                { "manager": "kubectl", "operation": "Update", "time": "2026-11-20T10:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": { "f:data": { "f:mode": {} } } },
                { "manager": "argocd", "operation": "Update", "time": "2026-11-22T10:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": { "f:metadata": { "f:labels": {} } } }
            ]
        })).unwrap();
        assert_eq!(last_change(&meta).map(|t| t.to_rfc3339()).as_deref(), Some("2026-11-20T10:00:00+00:00"), "a label change is not a change of contents");
        // The data's owner writing only a label moves its time too: the last
        // change is at most this, not certainly this.
        let relabelled: ObjectMeta = serde_json::from_value(json!({
            "name": "app",
            "managedFields": [{ "manager": "kubectl", "operation": "Update", "time": "2026-11-23T10:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": { "f:data": { "f:mode": {} }, "f:metadata": { "f:labels": {} } } }]
        })).unwrap();
        assert_eq!(last_change(&relabelled).map(|t| t.to_rfc3339()).as_deref(), Some("2026-11-23T10:00:00+00:00"));
        // Without managedFields only its creation is known, the earliest its
        // contents could have changed, not the latest.
        let bare: ObjectMeta = serde_json::from_value(json!({ "name": "app", "creationTimestamp": "2026-01-01T00:00:00Z" })).unwrap();
        assert_eq!(last_change(&bare), None);
    }

    #[test]
    fn a_pod_may_be_stale_only_by_the_start_of_a_container_that_reads_it_at_start() {
        let at = |t: &str| chrono::DateTime::parse_from_rfc3339(t).unwrap().with_timezone(&Utc);
        let changed = at("2026-11-24T10:00:00Z");
        let pod = |uses: Vec<Use>, started: Vec<(&str, Option<&str>)>| ConsumerPod {
            name: "p".into(), ready: true, phase: "Running".into(), waiting: vec![], uses,
            container_started: started.into_iter().map(|(c, t)| (c.to_string(), t.map(at))).collect(),
        };
        let env = || vec![Use::EnvFrom { container: "app".into(), optional: false }];
        // The pod is old, but its container restarted after the change.
        assert_eq!(pod(env(), vec![("app", Some("2026-11-24T11:00:00Z")), ("sidecar", Some("2026-11-01T00:00:00Z"))]).may_be_stale(changed), Some(false));
        assert_eq!(pod(env(), vec![("app", Some("2026-11-24T09:00:00Z"))]).may_be_stale(changed), Some(true));
        assert_eq!(pod(env(), vec![("app", None)]).may_be_stale(changed), Some(false), "waiting to start: its next start reads what is there then");
        assert!(pod(env(), vec![("app", None)]).yet_to_start());
        assert!(!pod(env(), vec![("app", Some("2026-11-24T11:00:00Z")), ("sidecar", None)]).yet_to_start(), "only a container that reads it counts");
        assert_eq!(pod(env(), vec![]).may_be_stale(changed), None, "no status for the container: unknown");
        // A whole-volume mount is refreshed whatever the container's age.
        let volume = vec![Use::Volume { volume: "conf".into(), keys: vec![], mounts: vec![("app".into(), "/etc/app".into(), false)], optional: false }];
        assert_eq!(pod(volume, vec![("app", Some("2026-11-01T00:00:00Z"))]).may_be_stale(changed), Some(false));
    }

    #[test]
    fn a_containers_current_instance_start_is_read_from_its_state() {
        let p: Pod = serde_json::from_value(json!({
            "metadata": { "name": "web-1" }, "spec": { "containers": [] },
            "status": { "phase": "Running", "containerStatuses": [
                { "name": "app", "ready": true, "restartCount": 0, "image": "i", "imageID": "", "state": { "running": { "startedAt": "2026-11-24T09:00:00Z" } } },
                { "name": "done", "ready": false, "restartCount": 0, "image": "i", "imageID": "", "state": { "terminated": { "exitCode": 0, "startedAt": "2026-11-24T08:00:00Z" } } },
                { "name": "crashing", "ready": false, "restartCount": 4, "image": "i", "imageID": "", "state": { "waiting": { "reason": "CrashLoopBackOff" } } }
            ] }
        })).unwrap();
        let at = |t: &str| Some(chrono::DateTime::parse_from_rfc3339(t).unwrap().with_timezone(&Utc));
        assert_eq!(consumer_pod(&p, vec![]).container_started, vec![("app".to_string(), at("2026-11-24T09:00:00Z")), ("done".to_string(), at("2026-11-24T08:00:00Z")), ("crashing".to_string(), None)]);
    }

    #[test]
    fn annotations_that_may_copy_the_object_are_masked() {
        let mut v = json!({ "metadata": { "annotations": {
            "kubectl.kubernetes.io/last-applied-configuration": "{\"data\":{\"password\":\"hunter2\"}}",
            "kapp.k14s.io/original": "{\"data\":{\"tls.key\":\"LS0tLS1CRUdJTi\"}}",
            "long": "x".repeat(300),
            "meta.helm.sh/release-name": "web"
        } } });
        mask_copying_annotations(&mut v);
        let text = v.to_string();
        assert!(!text.contains("hunter2") && !text.contains("LS0tLS1CRUdJTi") && !text.contains("xxxx"), "{text}");
        assert!(text.contains("\"meta.helm.sh/release-name\":\"web\""), "short plain annotations stay: {text}");
    }

    #[test]
    fn consumers_are_grouped_by_workload_with_their_pods() {
        let template = spec(json!({ "containers": [{ "name": "web", "envFrom": [{ "configMapRef": { "name": "app" } }] }] }));
        let selector: LabelSelector = serde_json::from_value(json!({ "matchLabels": { "app": "web" } })).unwrap();
        let pod = |name: &str, labels: serde_json::Value, owner: serde_json::Value, uses: bool| -> Pod {
            let containers = if uses { json!([{ "name": "web", "envFrom": [{ "configMapRef": { "name": "app" } }] }]) } else { json!([{ "name": "web" }]) };
            serde_json::from_value(json!({
                "metadata": { "name": name, "labels": labels, "ownerReferences": [owner] },
                "spec": { "containers": containers },
                "status": { "phase": "Running", "startTime": "2026-11-21T10:00:00Z", "conditions": [{ "type": "Ready", "status": "True" }] }
            }))
            .unwrap()
        };
        let rs = |name: &str| json!({ "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": name, "uid": "u", "controller": true });
        let pods = vec![
            pod("web-5d8f-a", json!({ "app": "web", "pod-template-hash": "5d8f" }), rs("web-5d8f"), true),
            pod("web-5d8f-b", json!({ "app": "web", "pod-template-hash": "5d8f" }), rs("web-5d8f"), true),
            pod("api-77c4-a", json!({ "app": "api", "pod-template-hash": "77c4" }), rs("api-77c4"), true),
            pod("other-1", json!({ "app": "other" }), rs("other-1"), false),
            pod("nightly-29123456-x", json!({}), json!({ "apiVersion": "batch/v1", "kind": "Job", "name": "nightly-29123456", "uid": "j", "controller": true }), true),
            // Workloads whose templates were read and no longer use it.
            pod("old-6b9c-a", json!({ "app": "old", "pod-template-hash": "6b9c" }), rs("old-6b9c"), true),
            pod("weekly-29123456-x", json!({}), json!({ "apiVersion": "batch/v1", "kind": "Job", "name": "weekly-29123456", "uid": "w", "controller": true }), true),
        ];
        let cron = spec(json!({ "containers": [{ "name": "job", "envFrom": [{ "configMapRef": { "name": "app" } }] }] }));
        let unused = spec(json!({ "containers": [{ "name": "web" }] }));
        let old_selector: LabelSelector = serde_json::from_value(json!({ "matchLabels": { "app": "old" } })).unwrap();
        let found = consumers(
            vec![
                ("Deployment".into(), "web".into(), Some(selector), template),
                ("CronJob".into(), "nightly".into(), None, cron),
                ("Deployment".into(), "old".into(), Some(old_selector), unused.clone()),
                ("CronJob".into(), "weekly".into(), None, unused),
            ],
            &pods,
            "ConfigMap",
            "app",
        );
        let summary: Vec<(String, String, Vec<String>)> = found.iter().map(|c| (c.kind.clone(), c.name.clone(), c.pods.iter().map(|p| p.name.clone()).collect())).collect();
        assert_eq!(summary, vec![
            ("Deployment".to_string(), "web".to_string(), vec!["web-5d8f-a".to_string(), "web-5d8f-b".to_string()]),
            ("CronJob".to_string(), "nightly".to_string(), vec!["nightly-29123456-x".to_string()]),
            // Its template was not listed (another namespace's view, say): found from the pod and taken back to its Deployment.
            ("Deployment".to_string(), "api".to_string(), vec!["api-77c4-a".to_string()]),
            ("Deployment".to_string(), "old".to_string(), vec!["old-6b9c-a".to_string()]),
            ("Job".to_string(), "weekly-29123456".to_string(), vec!["weekly-29123456-x".to_string()]),
        ]);
        let unused_templates: Vec<(&str, bool)> = found.iter().map(|c| (c.name.as_str(), c.template_unused)).collect();
        assert_eq!(unused_templates, vec![("web", false), ("nightly", false), ("api", false), ("old", true), ("weekly-29123456", true)]);
    }

    /// Diagnoses a sample of ConfigMaps and Secrets, the most used first,
    /// printing counts only:
    /// CONFIG_DIAG_TEST_CONTEXT=<context> cargo test --lib
    /// config_diagnosis::tests::config_diagnosis_against_a_live_cluster -- --ignored --exact --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set CONFIG_DIAG_TEST_CONTEXT to run"]
    async fn config_diagnosis_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("CONFIG_DIAG_TEST_CONTEXT") else { return };
        let namespace = std::env::var("CONFIG_DIAG_TEST_NAMESPACE").ok();
        let client = client_for_context(&ctx).await.unwrap();
        let pods: Vec<Pod> = Api::<Pod>::all(client.clone()).list(&ListParams::default()).await.unwrap().items;
        // The objects the most pods use, by kind, outside kube-system.
        let mut counts: std::collections::BTreeMap<(String, String, String), usize> = std::collections::BTreeMap::new();
        for p in pods.iter().filter(|p| p.metadata.namespace.as_deref() != Some("kube-system")) {
            let ns = p.metadata.namespace.clone().unwrap_or_default();
            if namespace.as_ref().is_some_and(|n| *n != ns) {
                continue;
            }
            let Some(spec) = &p.spec else { continue };
            for c in spec.containers.iter().chain(spec.init_containers.iter().flatten()) {
                for e in c.env_from.iter().flatten() {
                    if let Some(r) = &e.config_map_ref {
                        *counts.entry(("ConfigMap".into(), ns.clone(), r.name.clone())).or_default() += 1;
                    }
                    if let Some(r) = &e.secret_ref {
                        *counts.entry(("Secret".into(), ns.clone(), r.name.clone())).or_default() += 1;
                    }
                }
            }
            for v in spec.volumes.iter().flatten().filter(|v| !is_api_access_volume(&v.name)) {
                if let Some(c) = &v.config_map {
                    *counts.entry(("ConfigMap".into(), ns.clone(), c.name.clone())).or_default() += 1;
                }
                if let Some(s) = v.secret.as_ref().and_then(|s| s.secret_name.clone()) {
                    *counts.entry(("Secret".into(), ns.clone(), s)).or_default() += 1;
                }
            }
        }
        let mut ranked: Vec<_> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        let mut sample: Vec<(String, String, String)> = Vec::new();
        for kind in ["ConfigMap", "Secret"] {
            sample.extend(ranked.iter().filter(|((k, _, _), _)| k == kind).take(3).map(|(key, _)| key.clone()));
        }
        println!("objects used by pods (outside kube-system)={} sampled={}", ranked.len(), sample.len());
        for (kind, ns, name) in &sample {
            let d = get_config_diagnostics(&ctx, kind, ns, name).await.expect("diagnostics");
            let p = crate::claude::build_config_diagnosis_payload(&ctx, kind, ns, name).await.expect("payload");
            assert!(d.consumer_errors.is_empty(), "{:?}", d.consumer_errors);
            let consumers = &d.consumers;
            let restart: usize = consumers.iter().filter(|c| c.uses.iter().any(Use::needs_restart)).count();
            println!(
                "{kind}: keys={} last change known={} consumers={} (needing a restart for a change {restart}) pods={} ingresses={:?} gateways={:?} accounts={:?} volumes={:?} tls={} tokens={} unavailable={}",
                d.keys.len(),
                d.last_change.is_some(),
                consumers.len(),
                consumers.iter().map(|c| c.pods.len()).sum::<usize>(),
                d.ingresses.as_ref().map(Vec::len),
                d.gateways.as_ref().map(Vec::len),
                d.service_accounts.as_ref().map(Vec::len),
                d.volumes.as_ref().map(Vec::len),
                d.tls.is_some(),
                p.approx_tokens,
                p.prompt.matches("unavailable").count(),
            );
            assert!(!consumers.is_empty(), "an object the pods use has consumers");
        }
        // A Secret a PersistentVolume reads its credentials from is found
        // through that volume.
        let pvs = Api::<PersistentVolume>::all(client.clone()).list(&ListParams::default()).await.unwrap().items;
        let referenced = pvs.iter().find_map(|pv| {
            let spec = pv.spec.as_ref()?;
            let claim_namespace = spec.claim_ref.as_ref().and_then(|r| r.namespace.clone());
            let csi = spec.csi.as_ref().and_then(|c| c.node_stage_secret_ref.clone().or_else(|| c.node_publish_secret_ref.clone()));
            csi.and_then(|r| Some((r.namespace.or_else(|| claim_namespace.clone())?, r.name?)))
                .or_else(|| spec.azure_file.as_ref().and_then(|a| Some((a.secret_namespace.clone().or_else(|| claim_namespace.clone())?, a.secret_name.clone()))))
        });
        println!("a Secret a PersistentVolume reads found={}", referenced.is_some());
        if let Some((ns, name)) = referenced {
            match get_config_diagnostics(&ctx, "Secret", &ns, &name).await {
                Ok(d) => {
                    let named = d.volumes.as_ref().map(|v| v.iter().filter(|l| l.starts_with("PersistentVolume ")).count());
                    println!("that Secret: PersistentVolumes naming it={named:?}");
                    assert!(named.is_ok_and(|n| n > 0), "the volume that reads it names it");
                }
                Err(_) => println!("that Secret does not exist"),
            }
        }
    }
}
