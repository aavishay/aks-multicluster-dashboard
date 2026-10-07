//! The Workload panel's Overview: how a Deployment, StatefulSet or DaemonSet
//! rolls out, what it selects, whether its controller has caught up, and what
//! its pods are built from — read from the same object the YAML view renders.
//!
//! The pod template goes through the Pod panel's own helpers, so a template's
//! containers and references read exactly like a running pod's, minus the
//! status a template does not have.

use crate::k8s::created_at;
use crate::models::{PodConditionInfo, WorkloadDetail};
use crate::pod_detail::{container_detail, references};
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use k8s_openapi::api::core::v1::PodTemplateSpec;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use std::collections::BTreeMap;

fn pairs(map: Option<&BTreeMap<String, String>>) -> Vec<String> {
    map.map(|m| m.iter().map(|(k, v)| format!("{k}={v}")).collect()).unwrap_or_default()
}

fn int_or_string(v: &IntOrString) -> String {
    match v {
        IntOrString::Int(i) => i.to_string(),
        IntOrString::String(s) => s.clone(),
    }
}

/// matchLabels as `key=value`, then each expression as kubectl describes it.
fn selector(sel: &LabelSelector) -> Vec<String> {
    let mut out = pairs(sel.match_labels.as_ref());
    for e in sel.match_expressions.iter().flatten() {
        let values = e.values.as_ref().map(|v| v.join(", ")).unwrap_or_default();
        out.push(match e.operator.as_str() {
            "Exists" | "DoesNotExist" => format!("{} {}", e.key, e.operator),
            op => format!("{} {op} ({values})", e.key),
        });
    }
    out
}

/// The pod-template half every kind shares.
fn with_template(mut d: WorkloadDetail, template: &PodTemplateSpec) -> WorkloadDetail {
    d.template_labels = pairs(template.metadata.as_ref().and_then(|m| m.labels.as_ref()));
    if let Some(spec) = &template.spec {
        d.containers = spec.containers.iter().map(|c| container_detail(c, None)).collect();
        d.init_containers = spec.init_containers.iter().flatten().map(|c| container_detail(c, None)).collect();
        d.references = references(spec);
        if d.node_selector.is_empty() {
            d.node_selector = pairs(spec.node_selector.as_ref());
        }
    }
    d
}

fn rolling(max_surge: Option<&IntOrString>, max_unavailable: Option<&IntOrString>, partition: Option<i32>) -> String {
    let mut parts = Vec::new();
    if let Some(s) = max_surge {
        parts.push(format!("max surge {}", int_or_string(s)));
    }
    if let Some(u) = max_unavailable {
        parts.push(format!("max unavailable {}", int_or_string(u)));
    }
    if let Some(p) = partition.filter(|p| *p > 0) {
        parts.push(format!("partition {p}"));
    }
    if parts.is_empty() {
        "RollingUpdate".to_string()
    } else {
        format!("RollingUpdate ({})", parts.join(", "))
    }
}

fn conditions<C>(list: Option<&Vec<C>>, read: impl Fn(&C) -> PodConditionInfo) -> Vec<PodConditionInfo> {
    list.map(|cs| cs.iter().map(read).collect()).unwrap_or_default()
}

pub(crate) fn deployment_detail(d: &Deployment) -> WorkloadDetail {
    let spec = d.spec.as_ref();
    let status = d.status.as_ref();
    let strategy = spec.and_then(|s| s.strategy.as_ref());
    let detail = WorkloadDetail {
        strategy: match strategy.and_then(|s| s.type_.as_deref()) {
            Some("Recreate") => "Recreate".to_string(),
            _ => {
                let ru = strategy.and_then(|s| s.rolling_update.as_ref());
                rolling(ru.and_then(|r| r.max_surge.as_ref()), ru.and_then(|r| r.max_unavailable.as_ref()), None)
            }
        },
        selector: spec.map(|s| selector(&s.selector)).unwrap_or_default(),
        revision: d
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("deployment.kubernetes.io/revision"))
            .cloned()
            .unwrap_or_default(),
        generation: d.metadata.generation.unwrap_or_default(),
        observed_generation: status.and_then(|s| s.observed_generation).unwrap_or_default(),
        paused: spec.and_then(|s| s.paused).unwrap_or(false),
        conditions: conditions(status.and_then(|s| s.conditions.as_ref()), |c| PodConditionInfo {
            condition_type: c.type_.clone(),
            status: c.status.clone(),
            reason: c.reason.clone().unwrap_or_default(),
            message: c.message.clone().unwrap_or_default(),
            last_transition: created_at(&c.last_transition_time),
        }),
        ..Default::default()
    };
    match spec {
        Some(s) => with_template(detail, &s.template),
        None => detail,
    }
}

pub(crate) fn statefulset_detail(s: &StatefulSet) -> WorkloadDetail {
    let spec = s.spec.as_ref();
    let status = s.status.as_ref();
    let strategy = spec.and_then(|sp| sp.update_strategy.as_ref());
    let current = status.and_then(|st| st.current_revision.clone()).unwrap_or_default();
    let update = status.and_then(|st| st.update_revision.clone()).unwrap_or_default();
    let detail = WorkloadDetail {
        strategy: match strategy.and_then(|st| st.type_.as_deref()) {
            Some("OnDelete") => "OnDelete".to_string(),
            _ => {
                let ru = strategy.and_then(|st| st.rolling_update.as_ref());
                rolling(None, ru.and_then(|r| r.max_unavailable.as_ref()), ru.and_then(|r| r.partition))
            }
        },
        selector: spec.map(|sp| selector(&sp.selector)).unwrap_or_default(),
        // Only worth a second value while the two differ: a rollout in progress.
        update_revision: if update != current { update } else { String::new() },
        revision: current,
        generation: s.metadata.generation.unwrap_or_default(),
        observed_generation: status.and_then(|st| st.observed_generation).unwrap_or_default(),
        service_name: spec.map(|sp| sp.service_name.clone()).unwrap_or_default(),
        pod_management_policy: spec.and_then(|sp| sp.pod_management_policy.clone()).unwrap_or_else(|| "OrderedReady".to_string()),
        volume_claim_templates: spec
            .and_then(|sp| sp.volume_claim_templates.as_ref())
            .map(|ts| ts.iter().filter_map(|t| t.metadata.name.clone()).collect())
            .unwrap_or_default(),
        conditions: conditions(status.and_then(|st| st.conditions.as_ref()), |c| PodConditionInfo {
            condition_type: c.type_.clone(),
            status: c.status.clone(),
            reason: c.reason.clone().unwrap_or_default(),
            message: c.message.clone().unwrap_or_default(),
            last_transition: created_at(&c.last_transition_time),
        }),
        ..Default::default()
    };
    match spec {
        Some(sp) => with_template(detail, &sp.template),
        None => detail,
    }
}

pub(crate) fn daemonset_detail(ds: &DaemonSet) -> WorkloadDetail {
    let spec = ds.spec.as_ref();
    let status = ds.status.as_ref();
    let strategy = spec.and_then(|s| s.update_strategy.as_ref());
    let detail = WorkloadDetail {
        strategy: match strategy.and_then(|s| s.type_.as_deref()) {
            Some("OnDelete") => "OnDelete".to_string(),
            _ => {
                let ru = strategy.and_then(|s| s.rolling_update.as_ref());
                rolling(ru.and_then(|r| r.max_surge.as_ref()), ru.and_then(|r| r.max_unavailable.as_ref()), None)
            }
        },
        selector: spec.map(|s| selector(&s.selector)).unwrap_or_default(),
        generation: ds.metadata.generation.unwrap_or_default(),
        observed_generation: status.and_then(|s| s.observed_generation).unwrap_or_default(),
        misscheduled: status.map(|s| s.number_misscheduled).unwrap_or_default(),
        conditions: conditions(status.and_then(|s| s.conditions.as_ref()), |c| PodConditionInfo {
            condition_type: c.type_.clone(),
            status: c.status.clone(),
            reason: c.reason.clone().unwrap_or_default(),
            message: c.message.clone().unwrap_or_default(),
            last_transition: created_at(&c.last_transition_time),
        }),
        ..Default::default()
    };
    match spec {
        Some(s) => with_template(detail, &s.template),
        None => detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::apps::v1::{
        DaemonSetSpec, DaemonSetStatus, DeploymentCondition, DeploymentSpec, DeploymentStatus, DeploymentStrategy,
        RollingUpdateDeployment, RollingUpdateStatefulSetStrategy, StatefulSetSpec, StatefulSetStatus,
        StatefulSetUpdateStrategy,
    };
    use k8s_openapi::api::core::v1::{ConfigMapVolumeSource, Container, PersistentVolumeClaim, PodSpec, Volume};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelectorRequirement, ObjectMeta};

    fn template(labels: &[(&str, &str)]) -> PodTemplateSpec {
        PodTemplateSpec {
            metadata: Some(ObjectMeta {
                labels: Some(labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()),
                ..Default::default()
            }),
            spec: Some(PodSpec {
                containers: vec![Container { name: "app".into(), image: Some("app:2".into()), ..Default::default() }],
                volumes: Some(vec![Volume {
                    name: "cfg".into(),
                    config_map: Some(ConfigMapVolumeSource { name: "app-config".into(), ..Default::default() }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn deployment_strategy_selector_revision_and_template() {
        let d = Deployment {
            metadata: ObjectMeta {
                generation: Some(7),
                annotations: Some(BTreeMap::from([("deployment.kubernetes.io/revision".to_string(), "12".to_string())])),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                selector: LabelSelector {
                    match_labels: Some(BTreeMap::from([("app".to_string(), "api".to_string())])),
                    match_expressions: Some(vec![LabelSelectorRequirement {
                        key: "tier".into(),
                        operator: "In".into(),
                        values: Some(vec!["web".into(), "edge".into()]),
                    }]),
                },
                strategy: Some(DeploymentStrategy {
                    type_: Some("RollingUpdate".into()),
                    rolling_update: Some(RollingUpdateDeployment {
                        max_surge: Some(IntOrString::String("25%".into())),
                        max_unavailable: Some(IntOrString::Int(0)),
                    }),
                }),
                template: template(&[("app", "api"), ("tier", "web")]),
                ..Default::default()
            }),
            status: Some(DeploymentStatus {
                observed_generation: Some(6),
                conditions: Some(vec![DeploymentCondition {
                    type_: "Progressing".into(),
                    status: "False".into(),
                    reason: Some("ProgressDeadlineExceeded".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };
        let w = deployment_detail(&d);
        assert_eq!(w.strategy, "RollingUpdate (max surge 25%, max unavailable 0)");
        assert_eq!(w.selector, vec!["app=api", "tier In (web, edge)"]);
        assert_eq!(w.template_labels, vec!["app=api", "tier=web"]);
        assert_eq!((w.revision.as_str(), w.generation, w.observed_generation), ("12", 7, 6));
        assert_eq!(w.conditions[0].reason, "ProgressDeadlineExceeded");
        assert_eq!(w.containers[0].image, "app:2");
        assert_eq!(w.references[0].name, "app-config");
    }

    #[test]
    fn statefulset_revisions_claim_templates_and_partition() {
        let s = StatefulSet {
            metadata: ObjectMeta::default(),
            spec: Some(StatefulSetSpec {
                service_name: "db-headless".into(),
                update_strategy: Some(StatefulSetUpdateStrategy {
                    type_: Some("RollingUpdate".into()),
                    rolling_update: Some(RollingUpdateStatefulSetStrategy { partition: Some(2), ..Default::default() }),
                }),
                volume_claim_templates: Some(vec![PersistentVolumeClaim {
                    metadata: ObjectMeta { name: Some("data".into()), ..Default::default() },
                    ..Default::default()
                }]),
                template: template(&[("app", "db")]),
                ..Default::default()
            }),
            status: Some(StatefulSetStatus {
                current_revision: Some("db-5d".into()),
                update_revision: Some("db-6f".into()),
                ..Default::default()
            }),
        };
        let w = statefulset_detail(&s);
        assert_eq!(w.strategy, "RollingUpdate (partition 2)");
        assert_eq!((w.revision.as_str(), w.update_revision.as_str()), ("db-5d", "db-6f"));
        assert_eq!(w.volume_claim_templates, vec!["data"]);
        assert_eq!((w.service_name.as_str(), w.pod_management_policy.as_str()), ("db-headless", "OrderedReady"));
    }

    #[test]
    fn daemonset_on_delete_and_misscheduled() {
        let ds = DaemonSet {
            metadata: ObjectMeta::default(),
            spec: Some(DaemonSetSpec {
                update_strategy: Some(k8s_openapi::api::apps::v1::DaemonSetUpdateStrategy { type_: Some("OnDelete".into()), ..Default::default() }),
                template: template(&[("app", "agent")]),
                ..Default::default()
            }),
            status: Some(DaemonSetStatus { number_misscheduled: 1, ..Default::default() }),
        };
        let w = daemonset_detail(&ds);
        assert_eq!((w.strategy.as_str(), w.misscheduled), ("OnDelete", 1));
        assert_eq!(w.template_labels, vec!["app=agent"]);
    }

    /// Maps every workload of a real cluster. Prints counts only — no names.
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set WORKLOAD_DETAIL_TEST_CONTEXT to run"]
    async fn workload_detail_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("WORKLOAD_DETAIL_TEST_CONTEXT") else { return };
        let client = crate::kubeconfig::client_for_context(&ctx).await.expect("client");
        let lp = kube::api::ListParams::default();
        let deps = kube::Api::<Deployment>::all(client.clone()).list(&lp).await.expect("deployments").items;
        let sts = kube::Api::<StatefulSet>::all(client.clone()).list(&lp).await.expect("statefulsets").items;
        let dss = kube::Api::<DaemonSet>::all(client).list(&lp).await.expect("daemonsets").items;
        let all: Vec<WorkloadDetail> = deps
            .iter()
            .map(deployment_detail)
            .chain(sts.iter().map(statefulset_detail))
            .chain(dss.iter().map(daemonset_detail))
            .collect();
        let behind = all.iter().filter(|w| w.observed_generation < w.generation).count();
        let failing_progress = all
            .iter()
            .filter(|w| w.conditions.iter().any(|c| c.condition_type == "Progressing" && c.status == "False"))
            .count();
        let mid_rollout = all.iter().filter(|w| !w.update_revision.is_empty()).count();
        let no_template_labels = all.iter().filter(|w| w.template_labels.is_empty()).count();
        let refs: usize = all.iter().map(|w| w.references.len()).sum();
        let claim_templates: usize = all.iter().map(|w| w.volume_claim_templates.len()).sum();
        println!(
            "deployments={} statefulsets={} daemonsets={} generation_behind={behind} progress_failed={failing_progress} sts_mid_rollout={mid_rollout} no_template_labels={no_template_labels} references={refs} claim_templates={claim_templates}",
            deps.len(),
            sts.len(),
            dss.len()
        );
        assert!(all.iter().all(|w| !w.strategy.is_empty() && !w.containers.is_empty()));
    }
}
