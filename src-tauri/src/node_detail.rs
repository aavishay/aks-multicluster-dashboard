//! The Node panel's Overview: why a node is not Ready, what is pressuring it,
//! what keeps pods off it, and what it has to give — read from the same object
//! the YAML view renders, so it costs no extra request.

use crate::k8s::created_at;
use crate::models::{NodeDetail, PodConditionInfo};
use k8s_openapi::api::core::v1::Node;
use std::collections::BTreeMap;

fn quantities(map: Option<&BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>>) -> BTreeMap<String, String> {
    map.map(|m| m.iter().map(|(k, v)| (k.clone(), v.0.clone())).collect()).unwrap_or_default()
}

pub(crate) fn node_detail(node: &Node) -> NodeDetail {
    let spec = node.spec.as_ref();
    let status = node.status.as_ref();
    let info = status.and_then(|s| s.node_info.as_ref());
    let address = |kind: &str| {
        status
            .and_then(|s| s.addresses.as_ref())
            .and_then(|a| a.iter().find(|a| a.type_ == kind))
            .map(|a| a.address.clone())
            .unwrap_or_default()
    };
    let identity = crate::k8s::node_identity(node);
    let mut conditions: Vec<PodConditionInfo> = status
            .and_then(|s| s.conditions.as_ref())
            .map(|cs| {
                cs.iter()
                    .map(|c| PodConditionInfo {
                        condition_type: c.type_.clone(),
                        status: c.status.clone(),
                        reason: c.reason.clone().unwrap_or_default(),
                        message: c.message.clone().unwrap_or_default(),
                        last_transition: created_at(&c.last_transition_time),
                    })
                    .collect()
            })
            .unwrap_or_default();
    // A node that has not published a Ready condition yet — one just joining —
    // is Unknown, which the Nodes table already treats as not ready. Said
    // outright here rather than left as a missing row.
    if !conditions.iter().any(|c| c.condition_type == "Ready") {
        conditions.push(PodConditionInfo {
            condition_type: "Ready".into(),
            status: "Unknown".into(),
            reason: "NotReported".into(),
            message: "The node has not reported a Ready condition yet.".into(),
            last_transition: None,
        });
    }
    NodeDetail {
        unschedulable: spec.and_then(|s| s.unschedulable).unwrap_or(false),
        roles: identity.roles,
        instance_type: identity.instance_type.unwrap_or_default(),
        zone: identity.zone.unwrap_or_default(),
        nap_pool: identity.node_pool.unwrap_or_default(),
        agent_pool: node.metadata.labels.as_ref().and_then(|l| l.get("agentpool")).cloned().unwrap_or_default(),
        kubelet_version: info.map(|i| i.kubelet_version.clone()).unwrap_or_default(),
        os_image: info.map(|i| i.os_image.clone()).unwrap_or_default(),
        created_at: created_at(&node.metadata.creation_timestamp),
        conditions,
        taints: spec
            .and_then(|s| s.taints.as_ref())
            .map(|ts| {
                ts.iter()
                    .map(|t| match t.value.as_deref().filter(|v| !v.is_empty()) {
                        Some(v) => format!("{}={v}:{}", t.key, t.effect),
                        None => format!("{}:{}", t.key, t.effect),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        labels: node
            .metadata
            .labels
            .as_ref()
            .map(|l| l.iter().map(|(k, v)| format!("{k}={v}")).collect())
            .unwrap_or_default(),
        kernel_version: info.map(|i| i.kernel_version.clone()).unwrap_or_default(),
        container_runtime: info.map(|i| i.container_runtime_version.clone()).unwrap_or_default(),
        architecture: info.map(|i| i.architecture.clone()).unwrap_or_default(),
        operating_system: info.map(|i| i.operating_system.clone()).unwrap_or_default(),
        internal_ip: address("InternalIP"),
        external_ip: address("ExternalIP"),
        pod_cidrs: spec
            .and_then(|s| s.pod_cidrs.clone().or_else(|| s.pod_cidr.clone().map(|c| vec![c])))
            .unwrap_or_default(),
        provider_id: spec.and_then(|s| s.provider_id.clone()).unwrap_or_default(),
        capacity: quantities(status.and_then(|s| s.capacity.as_ref())),
        allocatable: quantities(status.and_then(|s| s.allocatable.as_ref())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{NodeAddress, NodeCondition, NodeSpec, NodeStatus, NodeSystemInfo, Taint};
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    #[test]
    fn a_pressured_cordoned_node() {
        let node = Node {
            metadata: ObjectMeta {
                labels: Some(BTreeMap::from([("agentpool".to_string(), "general".to_string())])),
                ..Default::default()
            },
            spec: Some(NodeSpec {
                unschedulable: Some(true),
                taints: Some(vec![
                    Taint { key: "node.kubernetes.io/unschedulable".into(), effect: "NoSchedule".into(), ..Default::default() },
                    Taint { key: "sku".into(), value: Some("gpu".into()), effect: "NoSchedule".into(), ..Default::default() },
                ]),
                pod_cidr: Some("10.244.3.0/24".into()),
                provider_id: Some("azure:///subscriptions/x/vmss/aks-general/virtualMachines/3".into()),
                ..Default::default()
            }),
            status: Some(NodeStatus {
                conditions: Some(vec![
                    NodeCondition { type_: "MemoryPressure".into(), status: "True".into(), reason: Some("KubeletHasInsufficientMemory".into()), ..Default::default() },
                    NodeCondition { type_: "Ready".into(), status: "True".into(), ..Default::default() },
                ]),
                addresses: Some(vec![NodeAddress { type_: "InternalIP".into(), address: "10.224.0.9".into() }]),
                capacity: Some(BTreeMap::from([("cpu".to_string(), Quantity("4".into())), ("nvidia.com/gpu".to_string(), Quantity("1".into()))])),
                allocatable: Some(BTreeMap::from([("cpu".to_string(), Quantity("3860m".into()))])),
                node_info: Some(NodeSystemInfo { kernel_version: "5.15.0".into(), container_runtime_version: "containerd://1.7.15".into(), ..Default::default() }),
                ..Default::default()
            }),
        };
        let d = node_detail(&node);
        assert!(d.unschedulable);
        assert_eq!((d.agent_pool.as_str(), d.nap_pool.as_str()), ("general", ""));
        assert_eq!(d.roles, vec!["worker"]);
        assert_eq!(d.taints, vec!["node.kubernetes.io/unschedulable:NoSchedule", "sku=gpu:NoSchedule"]);
        assert_eq!(d.conditions[0].reason, "KubeletHasInsufficientMemory");
        assert_eq!(d.pod_cidrs, vec!["10.244.3.0/24"]);
        assert_eq!(d.internal_ip, "10.224.0.9");
        assert_eq!(d.capacity.get("nvidia.com/gpu").map(String::as_str), Some("1"));
        assert_eq!(d.allocatable.get("cpu").map(String::as_str), Some("3860m"));
        assert_eq!(d.container_runtime, "containerd://1.7.15");
        assert_eq!(d.labels, vec!["agentpool=general"]);
    }

    #[test]
    fn a_node_with_no_ready_condition_reads_as_unknown() {
        let d = node_detail(&Node { status: Some(NodeStatus::default()), ..Default::default() });
        let ready = d.conditions.iter().find(|c| c.condition_type == "Ready").expect("synthesised");
        assert_eq!((ready.status.as_str(), ready.reason.as_str()), ("Unknown", "NotReported"));
    }

    /// Maps every node of a real cluster. Prints counts only — no names.
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set NODE_DETAIL_TEST_CONTEXT to run"]
    async fn node_detail_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("NODE_DETAIL_TEST_CONTEXT") else { return };
        let client = crate::kubeconfig::client_for_context(&ctx).await.expect("client");
        let nodes = kube::Api::<Node>::all(client).list(&Default::default()).await.expect("nodes").items;
        let details: Vec<NodeDetail> = nodes.iter().map(node_detail).collect();
        let tainted = details.iter().filter(|d| !d.taints.is_empty()).count();
        let pressured = details
            .iter()
            .filter(|d| d.conditions.iter().any(|c| c.condition_type != "Ready" && c.status == "True"))
            .count();
        let extended: std::collections::BTreeSet<&String> =
            details.iter().flat_map(|d| d.capacity.keys()).filter(|k| !["cpu", "memory", "pods", "ephemeral-storage"].contains(&k.as_str()) && !k.starts_with("hugepages-")).collect();
        println!(
            "nodes={} tainted={tainted} pressured={pressured} with_internal_ip={} extended_resources={extended:?}",
            details.len(),
            details.iter().filter(|d| !d.internal_ip.is_empty()).count()
        );
        assert!(details.iter().all(|d| d.allocatable.contains_key("cpu") && d.allocatable.contains_key("memory")));
    }
}
