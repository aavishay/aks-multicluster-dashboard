//! The core object kinds behind the Namespaces, Services, Ingress, PVC, PV and
//! ConfigMaps tabs: one list per kind, and a single manifest/events pair shared
//! by all six detail panels.
//!
//! Lists go through the typed k8s-openapi structs, so the mapping into each
//! row is ordinary field access and can be unit-tested on hand-built objects.
//! The manifest and events go through `DynamicObject` and the involved-object
//! match instead, the same way the CRD-backed panels do, so all five kinds
//! share one implementation rather than five near-copies.

use crate::k8s::{age_days, age_seconds, created_at, event_to_info, list_events_sorted, object_manifest};
use crate::kubeconfig::client_for_context;
use crate::models::{
    ConfigMapEntry, ConfigMapInfo, ConfigMapKeyInfo, EventInfo, IngressInfo, IngressRuleInfo, NamespaceInfo, ObjectManifest, PvInfo,
    PvcInfo, ServiceInfo,
};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, PersistentVolume, PersistentVolumeClaim, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressBackend};
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use kube::Client;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The kinds these tabs cover, and the only ones the shared manifest and
/// events commands accept. A closed list rather than any kind the caller
/// names: an unexpected kind is a caller bug, and failing on it beats an empty
/// "No events found" that hides it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Namespace,
    Service,
    Ingress,
    PersistentVolumeClaim,
    PersistentVolume,
    ConfigMap,
}

impl Kind {
    fn parse(kind: &str) -> Result<Self, String> {
        match kind {
            "Namespace" => Ok(Self::Namespace),
            "Service" => Ok(Self::Service),
            "Ingress" => Ok(Self::Ingress),
            "PersistentVolumeClaim" => Ok(Self::PersistentVolumeClaim),
            "PersistentVolume" => Ok(Self::PersistentVolume),
            "ConfigMap" => Ok(Self::ConfigMap),
            other => Err(format!("Unknown resource kind '{other}'")),
        }
    }

    fn api_resource(self) -> ApiResource {
        match self {
            Self::Namespace => ApiResource::erase::<Namespace>(&()),
            Self::Service => ApiResource::erase::<Service>(&()),
            Self::Ingress => ApiResource::erase::<Ingress>(&()),
            Self::PersistentVolumeClaim => ApiResource::erase::<PersistentVolumeClaim>(&()),
            Self::PersistentVolume => ApiResource::erase::<PersistentVolume>(&()),
            Self::ConfigMap => ApiResource::erase::<ConfigMap>(&()),
        }
    }

    fn namespaced(self) -> bool {
        matches!(self, Self::Service | Self::Ingress | Self::PersistentVolumeClaim | Self::ConfigMap)
    }
}

/// `key=value` pairs, in the map's (sorted) order.
fn pairs(map: Option<&BTreeMap<String, String>>) -> Vec<String> {
    map.map(|m| m.iter().map(|(k, v)| format!("{k}={v}")).collect()).unwrap_or_default()
}

/// kubectl's ACCESS MODES abbreviations.
fn access_modes(modes: Option<&Vec<String>>) -> Vec<String> {
    modes
        .map(|ms| {
            ms.iter()
                .map(|m| match m.as_str() {
                    "ReadWriteOnce" => "RWO".to_string(),
                    "ReadOnlyMany" => "ROX".to_string(),
                    "ReadWriteMany" => "RWX".to_string(),
                    "ReadWriteOncePod" => "RWOP".to_string(),
                    other => other.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn namespace_info(ns: Namespace) -> NamespaceInfo {
    NamespaceInfo {
        name: ns.metadata.name.clone().unwrap_or_default(),
        status: ns.status.as_ref().and_then(|s| s.phase.clone()).unwrap_or_default(),
        labels: pairs(ns.metadata.labels.as_ref()),
        age_days: age_days(ns.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(ns.metadata.creation_timestamp.clone()),
        created_at: created_at(&ns.metadata.creation_timestamp),
    }
}

/// Ready and total endpoints per Service, keyed by (namespace, name). A
/// Service's endpoints can span several slices, which are summed. An
/// endpoint's `ready` left unset means ready, per the EndpointSlice API.
pub(crate) fn endpoint_counts(slices: &[EndpointSlice]) -> HashMap<(String, String), (i64, i64)> {
    let mut out: HashMap<(String, String), (i64, i64)> = HashMap::new();
    for slice in slices {
        let Some(service) = slice.metadata.labels.as_ref().and_then(|l| l.get("kubernetes.io/service-name")) else {
            continue;
        };
        let ns = slice.metadata.namespace.clone().unwrap_or_default();
        let entry = out.entry((ns, service.clone())).or_default();
        for ep in &slice.endpoints {
            entry.1 += 1;
            if ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true) {
                entry.0 += 1;
            }
        }
    }
    out
}

/// `endpoints` is `None` when EndpointSlices could not be listed, which leaves
/// every count unknown rather than wrongly zero.
pub(crate) fn service_info(svc: Service, endpoints: Option<&HashMap<(String, String), (i64, i64)>>) -> ServiceInfo {
    let namespace = svc.metadata.namespace.clone().unwrap_or_default();
    let name = svc.metadata.name.clone().unwrap_or_default();
    let spec = svc.spec.as_ref();
    let service_type = spec.and_then(|s| s.type_.clone()).unwrap_or_else(|| "ClusterIP".to_string());
    let cluster_ip = spec.and_then(|s| s.cluster_ip.clone()).unwrap_or_default();

    let lb_addresses: Vec<String> = svc
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .map(|ing| ing.iter().filter_map(|i| i.ip.clone().or_else(|| i.hostname.clone())).collect())
        .unwrap_or_default();
    let mut external = lb_addresses.clone();
    external.extend(spec.and_then(|s| s.external_ips.clone()).unwrap_or_default());
    if service_type == "ExternalName" {
        external.extend(spec.and_then(|s| s.external_name.clone()));
    }

    let ports = spec
        .and_then(|s| s.ports.as_ref())
        .map(|ps| {
            ps.iter()
                .map(|p| {
                    let proto = p.protocol.clone().unwrap_or_else(|| "TCP".to_string());
                    match p.node_port {
                        Some(np) => format!("{}:{np}/{proto}", p.port),
                        None => format!("{}/{proto}", p.port),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let selector = pairs(spec.and_then(|s| s.selector.as_ref()));
    // Nothing to count against without a selector: its endpoints are managed
    // by hand, or it is an alias to a name outside the cluster.
    let countable = !selector.is_empty() && service_type != "ExternalName";
    let counts = if countable {
        endpoints.map(|m| m.get(&(namespace.clone(), name.clone())).copied().unwrap_or((0, 0)))
    } else {
        None
    };

    ServiceInfo {
        pending_load_balancer: service_type == "LoadBalancer" && lb_addresses.is_empty(),
        endpoints_ready: counts.map(|c| c.0),
        endpoints_total: counts.map(|c| c.1),
        age_days: age_days(svc.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(svc.metadata.creation_timestamp.clone()),
        created_at: created_at(&svc.metadata.creation_timestamp),
        namespace,
        name,
        service_type,
        cluster_ip,
        external,
        ports,
        selector,
    }
}

fn backend_text(b: &IngressBackend) -> String {
    if let Some(svc) = &b.service {
        let port = svc
            .port
            .as_ref()
            .and_then(|p| p.number.map(|n| n.to_string()).or_else(|| p.name.clone()))
            .unwrap_or_default();
        return if port.is_empty() { svc.name.clone() } else { format!("{}:{port}", svc.name) };
    }
    if let Some(r) = &b.resource {
        return format!("{}/{}", r.kind, r.name);
    }
    String::new()
}

pub(crate) fn ingress_info(ing: Ingress) -> IngressInfo {
    let spec = ing.spec.as_ref();
    let class = spec
        .and_then(|s| s.ingress_class_name.clone())
        .or_else(|| ing.metadata.annotations.as_ref().and_then(|a| a.get("kubernetes.io/ingress.class").cloned()))
        .unwrap_or_default();

    let mut rules = Vec::new();
    let mut hosts = BTreeSet::new();
    for rule in spec.and_then(|s| s.rules.as_ref()).into_iter().flatten() {
        let host = rule.host.clone().filter(|h| !h.is_empty()).unwrap_or_else(|| "*".to_string());
        hosts.insert(host.clone());
        for path in rule.http.as_ref().map(|h| h.paths.as_slice()).unwrap_or_default() {
            rules.push(IngressRuleInfo {
                host: host.clone(),
                path: path.path.clone().unwrap_or_else(|| "/".to_string()),
                backend: backend_text(&path.backend),
            });
        }
    }

    let address = ing
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .map(|ing| ing.iter().filter_map(|i| i.ip.clone().or_else(|| i.hostname.clone())).collect())
        .unwrap_or_default();

    IngressInfo {
        namespace: ing.metadata.namespace.clone().unwrap_or_default(),
        name: ing.metadata.name.clone().unwrap_or_default(),
        class,
        hosts: hosts.into_iter().collect(),
        address,
        tls: spec.and_then(|s| s.tls.as_ref()).is_some_and(|t| !t.is_empty()),
        rules,
        default_backend: spec.and_then(|s| s.default_backend.as_ref()).map(backend_text),
        age_days: age_days(ing.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(ing.metadata.creation_timestamp.clone()),
        created_at: created_at(&ing.metadata.creation_timestamp),
    }
}

pub(crate) fn pvc_info(pvc: PersistentVolumeClaim) -> PvcInfo {
    let spec = pvc.spec.as_ref();
    let status = pvc.status.as_ref();
    PvcInfo {
        namespace: pvc.metadata.namespace.clone().unwrap_or_default(),
        name: pvc.metadata.name.clone().unwrap_or_default(),
        status: status.and_then(|s| s.phase.clone()).unwrap_or_default(),
        volume: spec.and_then(|s| s.volume_name.clone()).unwrap_or_default(),
        capacity: status
            .and_then(|s| s.capacity.as_ref())
            .and_then(|c| c.get("storage"))
            .map(|q| q.0.clone())
            .unwrap_or_default(),
        requested: spec
            .and_then(|s| s.resources.as_ref())
            .and_then(|r| r.requests.as_ref())
            .and_then(|r| r.get("storage"))
            .map(|q| q.0.clone())
            .unwrap_or_default(),
        access_modes: access_modes(spec.and_then(|s| s.access_modes.as_ref())),
        storage_class: spec.and_then(|s| s.storage_class_name.clone()).unwrap_or_default(),
        volume_mode: spec.and_then(|s| s.volume_mode.clone()).unwrap_or_default(),
        age_days: age_days(pvc.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(pvc.metadata.creation_timestamp.clone()),
        created_at: created_at(&pvc.metadata.creation_timestamp),
    }
}

/// What backs a volume: the CSI driver when there is one — on AKS nearly
/// always — or the in-tree volume type for one provisioned before the CSI
/// migration, named as the API spells the field. FlexVolume names its driver,
/// which says more than "flexVolume". Every source this k8s-openapi version
/// knows is listed, so a known type never shows as blank.
fn pv_source(s: &k8s_openapi::api::core::v1::PersistentVolumeSpec) -> String {
    if let Some(csi) = &s.csi {
        return csi.driver.clone();
    }
    if let Some(flex) = &s.flex_volume {
        return format!("flexVolume ({})", flex.driver);
    }
    let in_tree = [
        (s.aws_elastic_block_store.is_some(), "awsElasticBlockStore"),
        (s.azure_disk.is_some(), "azureDisk"),
        (s.azure_file.is_some(), "azureFile"),
        (s.cephfs.is_some(), "cephfs"),
        (s.cinder.is_some(), "cinder"),
        (s.fc.is_some(), "fc"),
        (s.flocker.is_some(), "flocker"),
        (s.gce_persistent_disk.is_some(), "gcePersistentDisk"),
        (s.glusterfs.is_some(), "glusterfs"),
        (s.host_path.is_some(), "hostPath"),
        (s.iscsi.is_some(), "iscsi"),
        (s.local.is_some(), "local"),
        (s.nfs.is_some(), "nfs"),
        (s.photon_persistent_disk.is_some(), "photonPersistentDisk"),
        (s.portworx_volume.is_some(), "portworxVolume"),
        (s.quobyte.is_some(), "quobyte"),
        (s.rbd.is_some(), "rbd"),
        (s.scale_io.is_some(), "scaleIO"),
        (s.storageos.is_some(), "storageos"),
        (s.vsphere_volume.is_some(), "vsphereVolume"),
    ];
    in_tree.iter().find(|(set, _)| *set).map(|(_, name)| name.to_string()).unwrap_or_default()
}

pub(crate) fn pv_info(pv: PersistentVolume) -> PvInfo {
    let spec = pv.spec.as_ref();
    let status = pv.status.as_ref();
    let claim = spec.and_then(|s| s.claim_ref.as_ref());
    let source = spec.map(pv_source).unwrap_or_default();
    PvInfo {
        name: pv.metadata.name.clone().unwrap_or_default(),
        capacity: spec
            .and_then(|s| s.capacity.as_ref())
            .and_then(|c| c.get("storage"))
            .map(|q| q.0.clone())
            .unwrap_or_default(),
        access_modes: access_modes(spec.and_then(|s| s.access_modes.as_ref())),
        reclaim_policy: spec.and_then(|s| s.persistent_volume_reclaim_policy.clone()).unwrap_or_default(),
        status: status.and_then(|s| s.phase.clone()).unwrap_or_default(),
        claim_namespace: claim.and_then(|c| c.namespace.clone()).unwrap_or_default(),
        claim_name: claim.and_then(|c| c.name.clone()).unwrap_or_default(),
        storage_class: spec.and_then(|s| s.storage_class_name.clone()).unwrap_or_default(),
        source,
        reason: status.and_then(|s| s.reason.clone()).unwrap_or_default(),
        age_days: age_days(pv.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(pv.metadata.creation_timestamp.clone()),
        created_at: created_at(&pv.metadata.creation_timestamp),
    }
}

/// Keys from `data` then `binaryData`, each in key order — the order kubectl
/// and the YAML show them in.
pub(crate) fn configmap_entries(cm: &ConfigMap) -> Vec<ConfigMapEntry> {
    let mut out: Vec<ConfigMapEntry> = cm
        .data
        .iter()
        .flatten()
        .map(|(k, v)| ConfigMapEntry { key: k.clone(), bytes: v.len(), value: v.clone(), binary: false })
        .collect();
    out.extend(
        cm.binary_data
            .iter()
            .flatten()
            .map(|(k, v)| ConfigMapEntry { key: k.clone(), bytes: v.0.len(), value: String::new(), binary: true }),
    );
    out
}

pub(crate) fn configmap_info(cm: ConfigMap) -> ConfigMapInfo {
    let keys: Vec<ConfigMapKeyInfo> = configmap_entries(&cm)
        .into_iter()
        .map(|e| ConfigMapKeyInfo { name: e.key, bytes: e.bytes, binary: e.binary })
        .collect();
    ConfigMapInfo {
        namespace: cm.metadata.namespace.clone().unwrap_or_default(),
        name: cm.metadata.name.clone().unwrap_or_default(),
        total_bytes: keys.iter().map(|k| k.bytes).sum(),
        keys,
        immutable: cm.immutable.unwrap_or(false),
        age_days: age_days(cm.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(cm.metadata.creation_timestamp.clone()),
        created_at: created_at(&cm.metadata.creation_timestamp),
    }
}

async fn list_all<K>(client: &Client, what: &str) -> Result<Vec<K>, String>
where
    K: kube::Resource<DynamicType = ()> + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let api: Api<K> = Api::all(client.clone());
    api.list(&ListParams::default())
        .await
        .map(|l| l.items)
        .map_err(|e| format!("Failed to list {what}: {e}"))
}

pub async fn get_namespaces(context_name: &str) -> Result<Vec<NamespaceInfo>, String> {
    let client = client_for_context(context_name).await?;
    Ok(list_all::<Namespace>(&client, "namespaces").await?.into_iter().map(namespace_info).collect())
}

pub async fn get_services(context_name: &str) -> Result<Vec<ServiceInfo>, String> {
    let client = client_for_context(context_name).await?;
    // Listed together. The slices are best-effort: a reader who may list
    // Services but not EndpointSlices still gets the tab, with the endpoint
    // column unknown rather than the whole tab failing.
    let (services, slices) = tokio::join!(
        list_all::<Service>(&client, "services"),
        list_all::<EndpointSlice>(&client, "endpointslices"),
    );
    let counts = slices.ok().map(|s| endpoint_counts(&s));
    Ok(services?.into_iter().map(|s| service_info(s, counts.as_ref())).collect())
}

pub async fn get_ingresses(context_name: &str) -> Result<Vec<IngressInfo>, String> {
    let client = client_for_context(context_name).await?;
    Ok(list_all::<Ingress>(&client, "ingresses").await?.into_iter().map(ingress_info).collect())
}

pub async fn get_pvcs(context_name: &str) -> Result<Vec<PvcInfo>, String> {
    let client = client_for_context(context_name).await?;
    Ok(list_all::<PersistentVolumeClaim>(&client, "persistentvolumeclaims").await?.into_iter().map(pvc_info).collect())
}

pub async fn get_pvs(context_name: &str) -> Result<Vec<PvInfo>, String> {
    let client = client_for_context(context_name).await?;
    Ok(list_all::<PersistentVolume>(&client, "persistentvolumes").await?.into_iter().map(pv_info).collect())
}

pub async fn get_configmaps(context_name: &str) -> Result<Vec<ConfigMapInfo>, String> {
    let client = client_for_context(context_name).await?;
    Ok(list_all::<ConfigMap>(&client, "configmaps").await?.into_iter().map(configmap_info).collect())
}

/// One ConfigMap's keys with their values, for the panel's Data view — fetched
/// when it opens rather than carried by every row of the table.
pub async fn get_configmap_data(context_name: &str, namespace: &str, name: &str) -> Result<Vec<ConfigMapEntry>, String> {
    let client = client_for_context(context_name).await?;
    let api: Api<ConfigMap> = Api::namespaced(client, namespace);
    let cm = api.get(name).await.map_err(|e| format!("Failed to get ConfigMap '{name}': {e}"))?;
    Ok(configmap_entries(&cm))
}

/// The YAML for any of the six kinds. `namespace` is ignored for the two
/// cluster-scoped ones.
pub async fn get_resource_manifest(context_name: &str, kind: &str, namespace: &str, name: &str) -> Result<ObjectManifest, String> {
    let k = Kind::parse(kind)?;
    let client = client_for_context(context_name).await?;
    let ar = k.api_resource();
    let api: Api<DynamicObject> = if k.namespaced() {
        Api::namespaced_with(client, namespace, &ar)
    } else {
        Api::all_with(client, &ar)
    };
    let obj = api.get(name).await.map_err(|e| format!("Failed to get {kind} '{name}': {e}"))?;
    object_manifest(obj)
}

/// Events about one object, filtered by involved object before the cluster-wide
/// cap, as the other panels' events are. The namespace is matched only for the
/// namespaced kinds: events about a Namespace or a PersistentVolume are
/// recorded wherever the reporting component put them.
pub async fn get_resource_events(context_name: &str, kind: &str, namespace: &str, name: &str) -> Result<Vec<EventInfo>, String> {
    let k = Kind::parse(kind)?;
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;
    Ok(items
        .into_iter()
        .filter(|e| {
            e.involved_object.kind.as_deref() == Some(kind)
                && e.involved_object.name.as_deref() == Some(name)
                && (!k.namespaced() || e.metadata.namespace.as_deref() == Some(namespace))
        })
        .map(event_to_info)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        LoadBalancerIngress, LoadBalancerStatus, ObjectReference, PersistentVolumeClaimSpec, PersistentVolumeClaimStatus,
        PersistentVolumeSpec, PersistentVolumeStatus, ServicePort, ServiceSpec, ServiceStatus, VolumeResourceRequirements,
        CSIPersistentVolumeSource,
    };
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions};
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, IngressRule, IngressServiceBackend, IngressSpec, IngressTLS, ServiceBackendPort,
    };
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn meta(ns: Option<&str>, name: &str) -> ObjectMeta {
        ObjectMeta { namespace: ns.map(String::from), name: Some(name.into()), ..Default::default() }
    }

    fn slice(ns: &str, service: &str, ready: &[Option<bool>]) -> EndpointSlice {
        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                labels: Some(BTreeMap::from([("kubernetes.io/service-name".to_string(), service.to_string())])),
                ..Default::default()
            },
            endpoints: ready
                .iter()
                .map(|r| Endpoint { conditions: Some(EndpointConditions { ready: *r, ..Default::default() }), ..Default::default() })
                .collect(),
            ..Default::default()
        }
    }

    fn svc(spec: ServiceSpec, status: Option<ServiceStatus>) -> Service {
        Service { metadata: meta(Some("apps"), "web"), spec: Some(spec), status }
    }

    #[test]
    fn endpoints_sum_across_slices_and_unset_ready_counts_as_ready() {
        let counts = endpoint_counts(&[slice("apps", "web", &[Some(true), Some(false)]), slice("apps", "web", &[None])]);
        assert_eq!(counts.get(&("apps".into(), "web".into())), Some(&(2, 3)));
    }

    #[test]
    fn service_ports_selector_and_endpoints() {
        let counts = endpoint_counts(&[slice("apps", "web", &[Some(false)])]);
        let info = service_info(
            svc(
                ServiceSpec {
                    type_: Some("NodePort".into()),
                    cluster_ip: Some("10.0.0.7".into()),
                    ports: Some(vec![
                        ServicePort { port: 80, node_port: Some(30080), protocol: Some("TCP".into()), ..Default::default() },
                        ServicePort { port: 53, protocol: Some("UDP".into()), ..Default::default() },
                    ]),
                    selector: Some(BTreeMap::from([("tier".into(), "web".into()), ("app".into(), "shop".into())])),
                    ..Default::default()
                },
                None,
            ),
            Some(&counts),
        );
        assert_eq!(info.ports, vec!["80:30080/TCP", "53/UDP"]);
        assert_eq!(info.selector, vec!["app=shop", "tier=web"]);
        assert_eq!((info.endpoints_ready, info.endpoints_total), (Some(0), Some(1)));
        assert!(!info.pending_load_balancer);
    }

    #[test]
    fn a_selector_with_no_slices_is_zero_endpoints_but_unknown_when_slices_failed() {
        let spec = ServiceSpec { selector: Some(BTreeMap::from([("app".into(), "x".into())])), ..Default::default() };
        let empty = HashMap::new();
        assert_eq!(service_info(svc(spec.clone(), None), Some(&empty)).endpoints_ready, Some(0));
        assert_eq!(service_info(svc(spec, None), None).endpoints_ready, None);
    }

    #[test]
    fn selectorless_and_external_name_services_have_nothing_to_count() {
        let empty = HashMap::new();
        let bare = service_info(svc(ServiceSpec::default(), None), Some(&empty));
        assert_eq!(bare.endpoints_ready, None);
        assert_eq!(bare.service_type, "ClusterIP");
        let alias = service_info(
            svc(
                ServiceSpec {
                    type_: Some("ExternalName".into()),
                    external_name: Some("db.example.com".into()),
                    selector: Some(BTreeMap::from([("app".into(), "x".into())])),
                    ..Default::default()
                },
                None,
            ),
            Some(&empty),
        );
        assert_eq!(alias.endpoints_ready, None);
        assert_eq!(alias.external, vec!["db.example.com"]);
    }

    #[test]
    fn a_load_balancer_is_pending_until_it_has_an_address() {
        let spec = ServiceSpec { type_: Some("LoadBalancer".into()), ..Default::default() };
        assert!(service_info(svc(spec.clone(), None), None).pending_load_balancer);
        let assigned = service_info(
            svc(
                spec,
                Some(ServiceStatus {
                    load_balancer: Some(LoadBalancerStatus {
                        ingress: Some(vec![LoadBalancerIngress { ip: Some("20.1.2.3".into()), ..Default::default() }]),
                    }),
                    ..Default::default()
                }),
            ),
            None,
        );
        assert!(!assigned.pending_load_balancer);
        assert_eq!(assigned.external, vec!["20.1.2.3"]);
    }

    #[test]
    fn ingress_rules_hosts_class_and_tls() {
        let backend = |name: &str, port: i32| IngressBackend {
            service: Some(IngressServiceBackend {
                name: name.into(),
                port: Some(ServiceBackendPort { number: Some(port), ..Default::default() }),
            }),
            ..Default::default()
        };
        let ing = Ingress {
            metadata: ObjectMeta {
                annotations: Some(BTreeMap::from([("kubernetes.io/ingress.class".to_string(), "nginx".to_string())])),
                ..meta(Some("apps"), "shop")
            },
            spec: Some(IngressSpec {
                rules: Some(vec![
                    IngressRule {
                        host: Some("shop.example.com".into()),
                        http: Some(HTTPIngressRuleValue {
                            paths: vec![HTTPIngressPath { path: Some("/api".into()), path_type: "Prefix".into(), backend: backend("api", 8080) }],
                        }),
                    },
                    IngressRule {
                        host: None,
                        http: Some(HTTPIngressRuleValue {
                            paths: vec![HTTPIngressPath { path: None, path_type: "Prefix".into(), backend: backend("web", 80) }],
                        }),
                    },
                ]),
                tls: Some(vec![IngressTLS { hosts: Some(vec!["shop.example.com".into()]), ..Default::default() }]),
                ..Default::default()
            }),
            status: None,
        };
        let info = ingress_info(ing);
        assert_eq!(info.class, "nginx");
        assert_eq!(info.hosts, vec!["*", "shop.example.com"]);
        assert!(info.tls);
        assert!(info.address.is_empty());
        assert_eq!(
            info.rules,
            vec![
                IngressRuleInfo { host: "shop.example.com".into(), path: "/api".into(), backend: "api:8080".into() },
                IngressRuleInfo { host: "*".into(), path: "/".into(), backend: "web:80".into() },
            ]
        );
    }

    #[test]
    fn pvc_reads_requested_and_bound_capacity() {
        let info = pvc_info(PersistentVolumeClaim {
            metadata: meta(Some("apps"), "data"),
            spec: Some(PersistentVolumeClaimSpec {
                access_modes: Some(vec!["ReadWriteOnce".into(), "ReadWriteOncePod".into()]),
                resources: Some(VolumeResourceRequirements {
                    requests: Some(BTreeMap::from([("storage".to_string(), Quantity("10Gi".into()))])),
                    ..Default::default()
                }),
                storage_class_name: Some("managed-csi".into()),
                volume_name: Some("pvc-123".into()),
                ..Default::default()
            }),
            status: Some(PersistentVolumeClaimStatus {
                phase: Some("Bound".into()),
                capacity: Some(BTreeMap::from([("storage".to_string(), Quantity("16Gi".into()))])),
                ..Default::default()
            }),
        });
        assert_eq!((info.requested.as_str(), info.capacity.as_str()), ("10Gi", "16Gi"));
        assert_eq!(info.access_modes, vec!["RWO", "RWOP"]);
        assert_eq!((info.status.as_str(), info.volume.as_str()), ("Bound", "pvc-123"));
    }

    #[test]
    fn pv_reads_claim_and_csi_source() {
        let info = pv_info(PersistentVolume {
            metadata: meta(None, "pvc-123"),
            spec: Some(PersistentVolumeSpec {
                capacity: Some(BTreeMap::from([("storage".to_string(), Quantity("16Gi".into()))])),
                claim_ref: Some(ObjectReference { namespace: Some("apps".into()), name: Some("data".into()), ..Default::default() }),
                csi: Some(CSIPersistentVolumeSource { driver: "disk.csi.azure.com".into(), volume_handle: "h".into(), ..Default::default() }),
                persistent_volume_reclaim_policy: Some("Delete".into()),
                ..Default::default()
            }),
            status: Some(PersistentVolumeStatus { phase: Some("Released".into()), ..Default::default() }),
        });
        assert_eq!((info.claim_namespace.as_str(), info.claim_name.as_str()), ("apps", "data"));
        assert_eq!(info.source, "disk.csi.azure.com");
        assert_eq!((info.status.as_str(), info.reclaim_policy.as_str()), ("Released", "Delete"));
    }

    /// Lists all five kinds from a real cluster and fetches one manifest and
    /// its events per kind. Prints counts only — never names or values.
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set RESOURCES_TEST_CONTEXT to run"]
    async fn resources_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("RESOURCES_TEST_CONTEXT") else { return };
        let ns = get_namespaces(&ctx).await.expect("namespaces");
        let svcs = get_services(&ctx).await.expect("services");
        let ings = get_ingresses(&ctx).await.expect("ingresses");
        let pvcs = get_pvcs(&ctx).await.expect("pvcs");
        let pvs = get_pvs(&ctx).await.expect("pvs");
        let counted = svcs.iter().filter(|s| s.endpoints_ready.is_some()).count();
        let no_ready = svcs.iter().filter(|s| s.endpoints_ready == Some(0)).count();
        println!(
            "namespaces={} services={} (with endpoint counts {counted}, none ready {no_ready}, LB pending {}) ingresses={} (no address {}) pvcs={} (not bound {}) pvs={}",
            ns.len(),
            svcs.len(),
            svcs.iter().filter(|s| s.pending_load_balancer).count(),
            ings.len(),
            ings.iter().filter(|i| i.address.is_empty()).count(),
            pvcs.len(),
            pvcs.iter().filter(|p| p.status != "Bound").count(),
            pvs.len(),
        );
        if let Some(s) = svcs.first() {
            let m = get_resource_manifest(&ctx, "Service", &s.namespace, &s.name).await.expect("service manifest");
            assert!(m.yaml_without_managed_fields.contains("kind: Service"));
            get_resource_events(&ctx, "Service", &s.namespace, &s.name).await.expect("service events");
        }
        if let Some(n) = ns.first() {
            let m = get_resource_manifest(&ctx, "Namespace", "", &n.name).await.expect("namespace manifest");
            assert!(m.yaml_without_managed_fields.contains("kind: Namespace"));
        }
        if let Some(p) = pvs.first() {
            let m = get_resource_manifest(&ctx, "PersistentVolume", "", &p.name).await.expect("pv manifest");
            assert!(m.yaml_without_managed_fields.contains("kind: PersistentVolume"));
        }
        if let Some(i) = ings.first() {
            let m = get_resource_manifest(&ctx, "Ingress", &i.namespace, &i.name).await.expect("ingress manifest");
            assert!(m.yaml_without_managed_fields.contains("apiVersion: networking.k8s.io/v1"));
        }
        if let Some(c) = pvcs.first() {
            get_resource_manifest(&ctx, "PersistentVolumeClaim", &c.namespace, &c.name).await.expect("pvc manifest");
        }
        let cms = get_configmaps(&ctx).await.expect("configmaps");
        let biggest = cms.iter().map(|c| c.total_bytes).max().unwrap_or(0);
        let binary = cms.iter().filter(|c| c.keys.iter().any(|k| k.binary)).count();
        println!("configmaps={} (largest {biggest} bytes, with binary keys {binary})", cms.len());
        if let Some(c) = cms.iter().find(|c| !c.keys.is_empty()) {
            let entries = get_configmap_data(&ctx, &c.namespace, &c.name).await.expect("configmap data");
            assert_eq!(entries.len(), c.keys.len());
            assert_eq!(entries.iter().map(|e| e.bytes).sum::<usize>(), c.total_bytes);
            get_resource_manifest(&ctx, "ConfigMap", &c.namespace, &c.name).await.expect("configmap manifest");
        }
    }

    #[test]
    fn configmap_lists_text_then_binary_keys_with_sizes() {
        use k8s_openapi::ByteString;
        let cm = ConfigMap {
            metadata: meta(Some("apps"), "cfg"),
            data: Some(BTreeMap::from([("b.conf".to_string(), "x=1\n".to_string()), ("a.json".to_string(), "{}".to_string())])),
            binary_data: Some(BTreeMap::from([("logo.png".to_string(), ByteString(vec![0u8; 300]))])),
            immutable: Some(true),
        };
        let entries = configmap_entries(&cm);
        assert_eq!(entries.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(), vec!["a.json", "b.conf", "logo.png"]);
        assert_eq!(entries[2], ConfigMapEntry { key: "logo.png".into(), value: String::new(), binary: true, bytes: 300 });
        let info = configmap_info(cm);
        assert_eq!(info.total_bytes, 2 + 4 + 300);
        assert!(info.immutable);
        assert!(info.keys.iter().all(|k| k.name != "a.json" || k.bytes == 2));
    }

    #[test]
    fn pv_source_names_in_tree_types_and_flex_drivers() {
        use k8s_openapi::api::core::v1::{FlexPersistentVolumeSource, GCEPersistentDiskVolumeSource, ISCSIPersistentVolumeSource};
        let gce = PersistentVolumeSpec {
            gce_persistent_disk: Some(GCEPersistentDiskVolumeSource { pd_name: "disk-1".into(), ..Default::default() }),
            ..Default::default()
        };
        assert_eq!(pv_source(&gce), "gcePersistentDisk");
        let iscsi = PersistentVolumeSpec {
            iscsi: Some(ISCSIPersistentVolumeSource { iqn: "iqn".into(), target_portal: "10.0.0.1:3260".into(), ..Default::default() }),
            ..Default::default()
        };
        assert_eq!(pv_source(&iscsi), "iscsi");
        let flex = PersistentVolumeSpec {
            flex_volume: Some(FlexPersistentVolumeSource { driver: "example/lvm".into(), ..Default::default() }),
            ..Default::default()
        };
        assert_eq!(pv_source(&flex), "flexVolume (example/lvm)");
        assert_eq!(pv_source(&PersistentVolumeSpec::default()), "");
    }

    #[test]
    fn only_the_six_kinds_are_accepted() {
        assert!(Kind::parse("Secret").is_err());
        assert!(Kind::parse("ConfigMap").unwrap().namespaced());
        assert!(Kind::parse("PersistentVolume").is_ok());
        assert!(!Kind::parse("Namespace").unwrap().namespaced());
        assert!(Kind::parse("Ingress").unwrap().namespaced());
    }
}
