//! The NAP panel's Overview: whether a Karpenter NodePool is ready and if not
//! why, how close it is to its limits, what nodes it may create, and when
//! Karpenter may take them away again — read from the same NodePool the YAML
//! view renders.
//!
//! NodePools have no typed Rust struct here, so this reads the JSON, applying
//! Karpenter's documented defaults where a field is unset so the Overview says
//! what will happen rather than leaving a blank.

use crate::k8s::{json_str, parse_cpu_millicores, parse_memory_ki};
use crate::models::{NapBudget, NapDetail, NapRequirement, NapResourceUse, PodConditionInfo};
use kube::api::DynamicObject;
use serde_json::Value;

/// Karpenter's defaults for what a NodePool leaves unset.
const DEFAULT_EXPIRE_AFTER: &str = "720h";
const DEFAULT_CONSOLIDATION_POLICY: &str = "WhenEmptyOrUnderutilized";
const DEFAULT_CONSOLIDATE_AFTER: &str = "0s";
/// v1beta1's: its policy was named differently, and it had no delay to
/// default — `consolidateAfter` could not even be set with WhenUnderutilized.
const V1BETA1_DEFAULT_CONSOLIDATION_POLICY: &str = "WhenUnderutilized";
const DEFAULT_BUDGET_NODES: &str = "10%";

/// Shown first, in this order; anything else only when it is limited or in use.
const LEADING_RESOURCES: [&str; 5] = ["cpu", "memory", "nvidia.com/gpu", "nodes", "pods"];

fn array<'a>(v: Option<&'a Value>, key: &str) -> &'a [Value] {
    v.and_then(|v| v.get(key)).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default()
}

fn strings(v: Option<&Value>, key: &str) -> Vec<String> {
    array(v, key).iter().filter_map(Value::as_str).map(str::to_string).collect()
}

/// A duration field, which Karpenter also allows to be the string `Never`.
fn duration(v: Option<&Value>, key: &str) -> Option<String> {
    match v.and_then(|v| v.get(key))? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn taint(t: &Value) -> String {
    let (key, value, effect) = (json_str(Some(t), "key"), json_str(Some(t), "value"), json_str(Some(t), "effect"));
    format!("{key}{}{}", if value.is_empty() { String::new() } else { format!("={value}") }, if effect.is_empty() { String::new() } else { format!(":{effect}") })
}

/// A resource quantity in the unit its kind is counted in.
fn measure(name: &str, q: &str) -> (&'static str, i64) {
    match name {
        "cpu" => ("millicores", parse_cpu_millicores(q)),
        "memory" | "ephemeral-storage" => ("ki", parse_memory_ki(q)),
        n if n.starts_with("hugepages-") => ("ki", parse_memory_ki(q)),
        _ => ("count", q.parse::<f64>().map(|f| f.round() as i64).unwrap_or(0)),
    }
}

fn resources(limits: Option<&Value>, used: Option<&Value>) -> Vec<NapResourceUse> {
    let quantity = |v: Option<&Value>, k: &str| v.and_then(|v| v.get(k)).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let mut names: Vec<String> = LEADING_RESOURCES.iter().map(|s| s.to_string()).collect();
    let mut rest: Vec<String> = [limits, used]
        .into_iter()
        .flat_map(|v| v.and_then(Value::as_object).into_iter().flat_map(|o| o.keys().cloned()))
        .filter(|k| !LEADING_RESOURCES.contains(&k.as_str()))
        .collect();
    rest.sort();
    rest.dedup();
    names.extend(rest);
    names
        .into_iter()
        .filter_map(|name| {
            let limit = quantity(limits, &name);
            let used_q = quantity(used, &name);
            let (unit, used) = measure(&name, used_q.as_deref().unwrap_or("0"));
            let limit = limit.map(|l| measure(&name, &l).1);
            // CPU and memory always; the rest only when they say something.
            (name == "cpu" || name == "memory" || limit.is_some() || used > 0).then(|| NapResourceUse { name, unit: unit.to_string(), used, limit })
        })
        .collect()
}

pub(crate) fn nap_detail(obj: &DynamicObject) -> NapDetail {
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");
    let template = spec.and_then(|s| s.get("template"));
    let template_spec = template.and_then(|t| t.get("spec"));
    let node_class = template_spec.and_then(|t| t.get("nodeClassRef"));
    let disruption = spec.and_then(|s| s.get("disruption"));
    let budgets: Vec<NapBudget> = array(disruption, "budgets")
        .iter()
        .map(|b| NapBudget {
            nodes: match json_str(Some(b), "nodes") {
                "" => DEFAULT_BUDGET_NODES.to_string(),
                n => n.to_string(),
            },
            reasons: strings(Some(b), "reasons"),
            schedule: json_str(Some(b), "schedule").to_string(),
            duration: json_str(Some(b), "duration").to_string(),
        })
        .collect();
    let budgets_default = budgets.is_empty();
    let v1beta1 = obj.types.as_ref().is_some_and(|t| t.api_version.ends_with("/v1beta1"));

    NapDetail {
        node_class_kind: json_str(node_class, "kind").to_string(),
        node_class_name: json_str(node_class, "name").to_string(),
        weight: spec.and_then(|s| s.get("weight")).and_then(Value::as_i64),
        requirements: array(template_spec, "requirements")
            .iter()
            .map(|r| NapRequirement {
                key: json_str(Some(r), "key").to_string(),
                operator: json_str(Some(r), "operator").to_string(),
                values: strings(Some(r), "values"),
                min_values: r.get("minValues").and_then(Value::as_i64),
            })
            .collect(),
        taints: array(template_spec, "taints").iter().map(taint).collect(),
        startup_taints: array(template_spec, "startupTaints").iter().map(taint).collect(),
        labels: template
            .and_then(|t| t.get("metadata"))
            .and_then(|m| m.get("labels"))
            .and_then(Value::as_object)
            .map(|o| o.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default())).collect())
            .unwrap_or_default(),
        // Karpenter v1 moved expireAfter into the template; v1beta1 kept it
        // under disruption, and this fleet has clusters on both.
        expire_after: duration(template_spec, "expireAfter")
            .or_else(|| duration(disruption, "expireAfter"))
            .unwrap_or_else(|| DEFAULT_EXPIRE_AFTER.to_string()),
        termination_grace_period: duration(template_spec, "terminationGracePeriod").unwrap_or_default(),
        consolidation_policy: match json_str(disruption, "consolidationPolicy") {
            "" if v1beta1 => V1BETA1_DEFAULT_CONSOLIDATION_POLICY.to_string(),
            "" => DEFAULT_CONSOLIDATION_POLICY.to_string(),
            p => p.to_string(),
        },
        // Empty for a v1beta1 pool that sets none: no delay at all.
        consolidate_after: duration(disruption, "consolidateAfter").unwrap_or_else(|| if v1beta1 { String::new() } else { DEFAULT_CONSOLIDATE_AFTER.to_string() }),
        budgets: if budgets_default {
            vec![NapBudget { nodes: DEFAULT_BUDGET_NODES.to_string(), ..Default::default() }]
        } else {
            budgets
        },
        budgets_default,
        resources: resources(spec.and_then(|s| s.get("limits")), status.and_then(|s| s.get("resources"))),
        conditions: array(status, "conditions")
            .iter()
            .map(|c| PodConditionInfo {
                condition_type: json_str(Some(c), "type").to_string(),
                status: json_str(Some(c), "status").to_string(),
                reason: json_str(Some(c), "reason").to_string(),
                message: json_str(Some(c), "message").to_string(),
                last_transition: Some(json_str(Some(c), "lastTransitionTime").to_string()).filter(|s| !s.is_empty()),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::{ObjectMeta, TypeMeta};
    use serde_json::json;

    fn pool(data: Value) -> DynamicObject {
        DynamicObject { types: None, metadata: ObjectMeta::default(), data }
    }

    #[test]
    fn a_pool_at_its_cpu_limit() {
        let d = nap_detail(&pool(json!({
            "spec": {
                "weight": 10,
                "template": {
                    "metadata": { "labels": { "role": "gpu" } },
                    "spec": {
                        "nodeClassRef": { "group": "karpenter.azure.com", "kind": "AKSNodeClass", "name": "gpu" },
                        "requirements": [
                            { "key": "karpenter.sh/capacity-type", "operator": "In", "values": ["spot", "on-demand"] },
                            { "key": "karpenter.azure.com/sku-family", "operator": "In", "values": ["N"], "minValues": 2 }
                        ],
                        "taints": [{ "key": "nvidia.com/gpu", "effect": "NoSchedule" }, { "key": "role", "value": "gpu", "effect": "NoExecute" }],
                        "expireAfter": "Never",
                        "terminationGracePeriod": "48h"
                    }
                },
                "limits": { "cpu": "64", "memory": "256Gi" },
                "disruption": {
                    "consolidationPolicy": "WhenEmpty",
                    "consolidateAfter": "5m",
                    "budgets": [{ "nodes": "0", "reasons": ["Drifted"] }, { "nodes": "20%", "schedule": "0 9 * * mon-fri", "duration": "8h" }]
                }
            },
            "status": {
                "resources": { "cpu": "64", "memory": "268435456Ki", "nodes": "4", "pods": "120", "nvidia.com/gpu": "4", "hugepages-1Gi": "0", "ephemeral-storage": "512Gi" },
                "conditions": [{ "type": "Ready", "status": "True", "lastTransitionTime": "2026-10-07T08:00:00Z" }, { "type": "NodeRegistrationHealthy", "status": "Unknown" }]
            }
        })));
        assert_eq!((d.node_class_kind.as_str(), d.node_class_name.as_str()), ("AKSNodeClass", "gpu"));
        assert_eq!(d.weight, Some(10));
        assert_eq!(d.requirements[1].min_values, Some(2));
        assert_eq!(d.taints, vec!["nvidia.com/gpu:NoSchedule", "role=gpu:NoExecute"]);
        assert_eq!(d.labels, vec!["role=gpu"]);
        assert_eq!((d.expire_after.as_str(), d.termination_grace_period.as_str()), ("Never", "48h"));
        assert_eq!((d.consolidation_policy.as_str(), d.consolidate_after.as_str()), ("WhenEmpty", "5m"));
        assert!(!d.budgets_default);
        assert_eq!(d.budgets[0], NapBudget { nodes: "0".into(), reasons: vec!["Drifted".into()], ..Default::default() });
        assert_eq!(d.budgets[1].schedule, "0 9 * * mon-fri");
        // In order, with the zero hugepages left out and the storage in use kept.
        assert_eq!(d.resources.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["cpu", "memory", "nvidia.com/gpu", "nodes", "pods", "ephemeral-storage"]);
        assert_eq!((d.resources[0].used, d.resources[0].limit), (64_000, Some(64_000)));
        assert_eq!((d.resources[1].unit.as_str(), d.resources[1].used, d.resources[1].limit), ("ki", 268_435_456, Some(268_435_456)));
        assert_eq!((d.resources[3].unit.as_str(), d.resources[3].used, d.resources[3].limit), ("count", 4, None));
        assert_eq!(d.conditions[0].last_transition.as_deref(), Some("2026-10-07T08:00:00Z"));
    }

    #[test]
    fn an_empty_pool_gets_karpenters_defaults() {
        let d = nap_detail(&pool(json!({ "spec": { "template": { "spec": {} } } })));
        assert_eq!(d.weight, None);
        assert_eq!(d.expire_after, "720h");
        assert_eq!((d.consolidation_policy.as_str(), d.consolidate_after.as_str()), ("WhenEmptyOrUnderutilized", "0s"));
        assert!(d.budgets_default);
        assert_eq!(d.budgets, vec![NapBudget { nodes: "10%".into(), ..Default::default() }]);
        // CPU and memory are always shown, unlimited and unused.
        assert_eq!(d.resources.len(), 2);
        assert!(d.resources.iter().all(|r| r.used == 0 && r.limit.is_none()));
    }

    #[test]
    fn a_v1beta1_pool_keeps_expire_after_under_disruption_and_its_own_defaults() {
        let mut obj = pool(json!({ "spec": { "disruption": { "expireAfter": "168h" } } }));
        obj.types = Some(TypeMeta { api_version: "karpenter.sh/v1beta1".into(), kind: "NodePool".into() });
        let d = nap_detail(&obj);
        assert_eq!(d.expire_after, "168h");
        assert_eq!((d.consolidation_policy.as_str(), d.consolidate_after.as_str()), ("WhenUnderutilized", ""));
    }

    /// Fetches every NodePool's manifest through the real command path.
    /// Prints counts only — no names or values.
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set NAP_DETAIL_TEST_CONTEXT to run"]
    async fn nap_detail_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("NAP_DETAIL_TEST_CONTEXT") else { return };
        let list = crate::k8s::get_nap_node_pools(&ctx).await.expect("pools");
        let (mut requirements, mut taints, mut budgets, mut default_budgets, mut limited, mut at_limit, mut conditions) = (0, 0, 0, 0, 0, 0, 0);
        for p in &list.node_pools {
            let d = crate::k8s::get_nap_node_pool_manifest(&ctx, &p.name).await.expect("manifest + detail").detail;
            requirements += d.requirements.len();
            taints += d.taints.len();
            budgets += d.budgets.len();
            default_budgets += usize::from(d.budgets_default);
            limited += d.resources.iter().filter(|r| r.limit.is_some()).count();
            at_limit += d.resources.iter().filter(|r| r.limit.is_some_and(|l| r.used >= l)).count();
            conditions += d.conditions.len();
            // The row and the detail read the same rollup.
            let cpu = d.resources.iter().find(|r| r.name == "cpu").expect("cpu");
            assert_eq!((cpu.used, cpu.limit), (p.cpu_used_millicores, p.cpu_limit_millicores));
            let nodes = d.resources.iter().find(|r| r.name == "nodes").map_or(0, |r| r.used);
            assert_eq!(nodes, p.nodes);
        }
        println!(
            "installed={} pools={} requirements={requirements} taints={taints} budgets={budgets} default_budgets={default_budgets} limited={limited} at_limit={at_limit} conditions={conditions}",
            list.installed,
            list.node_pools.len()
        );
    }
}
