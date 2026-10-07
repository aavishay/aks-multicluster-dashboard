//! The HPA panel's Overview: what it measures against what it targets, how it
//! scales up and down, why it cannot when it cannot, and who owns it — read
//! from the same object the YAML view renders.

use crate::k8s::{created_at, hpa_metric_rows};
use crate::models::{HpaDetail, PodConditionInfo};
use k8s_openapi::api::autoscaling::v2::{HPAScalingRules, HorizontalPodAutoscaler};

/// One direction's rules in words: the stabilization window, each policy, and
/// how several policies combine.
fn rules(r: &HPAScalingRules, default_window: i32) -> Vec<String> {
    let mut out = vec![format!("Stabilization window {}s", r.stabilization_window_seconds.unwrap_or(default_window))];
    for p in r.policies.iter().flatten() {
        let amount = match p.type_.as_str() {
            "Percent" => format!("{}%", p.value),
            "Pods" => format!("{} pod{}", p.value, if p.value == 1 { "" } else { "s" }),
            other => format!("{} {other}", p.value),
        };
        out.push(format!("At most {amount} per {}s", p.period_seconds));
    }
    match r.select_policy.as_deref() {
        Some("Disabled") => out.push("Disabled — it never scales this way".to_string()),
        Some("Min") if r.policies.as_ref().is_some_and(|p| p.len() > 1) => out.push("Whichever policy allows the least".to_string()),
        Some("Max") | None if r.policies.as_ref().is_some_and(|p| p.len() > 1) => out.push("Whichever policy allows the most".to_string()),
        _ => {}
    }
    out
}

pub(crate) fn hpa_detail(hpa: &HorizontalPodAutoscaler) -> HpaDetail {
    let spec = hpa.spec.as_ref();
    let status = hpa.status.as_ref();
    let behavior = spec.and_then(|s| s.behavior.as_ref());
    // Kubernetes' documented defaults when `behavior` (or one direction of it)
    // is unset: scale up at once, by 100% or 4 pods per 15s, whichever is more;
    // scale down after a 300s window, by up to 100% per 15s.
    let (scale_up, scale_down) = (
        behavior.and_then(|b| b.scale_up.as_ref()).map(|r| rules(r, 0)).unwrap_or_else(|| {
            vec![
                "Stabilization window 0s".to_string(),
                "At most 100% or 4 pods per 15s, whichever is more".to_string(),
            ]
        }),
        behavior.and_then(|b| b.scale_down.as_ref()).map(|r| rules(r, 300)).unwrap_or_else(|| {
            vec!["Stabilization window 300s".to_string(), "At most 100% per 15s".to_string()]
        }),
    );
    let owner = hpa.metadata.owner_references.iter().flatten().find(|o| o.controller == Some(true));
    HpaDetail {
        target_kind: spec.map(|s| s.scale_target_ref.kind.clone()).unwrap_or_default(),
        target_name: spec.map(|s| s.scale_target_ref.name.clone()).unwrap_or_default(),
        // The API server defaults an unset minReplicas to 1, as hpa_to_info says.
        min_replicas: spec.and_then(|s| s.min_replicas).unwrap_or(1) as i64,
        max_replicas: spec.map(|s| s.max_replicas).unwrap_or_default() as i64,
        current_replicas: status.and_then(|s| s.current_replicas).unwrap_or(0) as i64,
        desired_replicas: status.map(|s| s.desired_replicas).unwrap_or_default() as i64,
        last_scale_at: status.and_then(|s| created_at(&s.last_scale_time)),
        metrics: hpa_metric_rows(
            spec.and_then(|s| s.metrics.as_deref()).unwrap_or_default(),
            status.and_then(|s| s.current_metrics.as_deref()).unwrap_or_default(),
        ),
        scale_up,
        scale_down,
        behavior_is_default: behavior.is_none(),
        conditions: status
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
            .unwrap_or_default(),
        owner_kind: owner.map(|o| o.kind.clone()).unwrap_or_default(),
        owner_name: owner.map(|o| o.name.clone()).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::autoscaling::v2::{
        CrossVersionObjectReference, HPAScalingPolicy, HorizontalPodAutoscalerBehavior, HorizontalPodAutoscalerSpec,
        HorizontalPodAutoscalerStatus, MetricSpec, MetricStatus, MetricTarget, MetricValueStatus, ResourceMetricSource,
        ResourceMetricStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};

    fn hpa(behavior: Option<HorizontalPodAutoscalerBehavior>) -> HorizontalPodAutoscaler {
        HorizontalPodAutoscaler {
            metadata: ObjectMeta {
                owner_references: Some(vec![OwnerReference {
                    kind: "ScaledObject".into(),
                    name: "api".into(),
                    controller: Some(true),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            spec: Some(HorizontalPodAutoscalerSpec {
                scale_target_ref: CrossVersionObjectReference { kind: "Deployment".into(), name: "api".into(), ..Default::default() },
                max_replicas: 10,
                metrics: Some(vec![
                    MetricSpec {
                        type_: "Resource".into(),
                        resource: Some(ResourceMetricSource {
                            name: "cpu".into(),
                            target: MetricTarget { type_: "Utilization".into(), average_utilization: Some(70), ..Default::default() },
                        }),
                        ..Default::default()
                    },
                    MetricSpec {
                        type_: "Resource".into(),
                        resource: Some(ResourceMetricSource {
                            name: "memory".into(),
                            target: MetricTarget { type_: "Utilization".into(), average_utilization: Some(80), ..Default::default() },
                        }),
                        ..Default::default()
                    },
                ]),
                behavior,
                ..Default::default()
            }),
            status: Some(HorizontalPodAutoscalerStatus {
                current_metrics: Some(vec![MetricStatus {
                    type_: "Resource".into(),
                    resource: Some(ResourceMetricStatus {
                        name: "cpu".into(),
                        current: MetricValueStatus { average_utilization: Some(41), ..Default::default() },
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn metrics_pair_and_a_missing_reading_is_unknown() {
        let d = hpa_detail(&hpa(None));
        assert_eq!(d.metrics.len(), 2);
        assert_eq!((d.metrics[0].name.as_str(), d.metrics[0].current.as_str(), d.metrics[0].target.as_str()), ("cpu", "41%", "70%"));
        assert_eq!(d.metrics[1].current, "<unknown>");
        assert_eq!((d.owner_kind.as_str(), d.owner_name.as_str()), ("ScaledObject", "api"));
        assert_eq!((d.target_kind.as_str(), d.target_name.as_str(), d.min_replicas, d.max_replicas), ("Deployment", "api", 1, 10));
    }

    #[test]
    fn unset_behavior_states_the_kubernetes_defaults() {
        let d = hpa_detail(&hpa(None));
        assert!(d.behavior_is_default);
        assert_eq!(d.scale_down[0], "Stabilization window 300s");
        assert_eq!(d.scale_up[0], "Stabilization window 0s");
    }

    #[test]
    fn explicit_behavior_is_described_rule_by_rule() {
        let d = hpa_detail(&hpa(Some(HorizontalPodAutoscalerBehavior {
            scale_down: Some(HPAScalingRules {
                stabilization_window_seconds: Some(600),
                policies: Some(vec![
                    HPAScalingPolicy { type_: "Pods".into(), value: 1, period_seconds: 60 },
                    HPAScalingPolicy { type_: "Percent".into(), value: 10, period_seconds: 60 },
                ]),
                select_policy: Some("Min".into()),
                ..Default::default()
            }),
            scale_up: Some(HPAScalingRules { select_policy: Some("Disabled".into()), ..Default::default() }),
        })));
        assert!(!d.behavior_is_default);
        assert_eq!(
            d.scale_down,
            vec!["Stabilization window 600s", "At most 1 pod per 60s", "At most 10% per 60s", "Whichever policy allows the least"]
        );
        assert_eq!(d.scale_up, vec!["Stabilization window 0s", "Disabled — it never scales this way"]);
    }

    /// Fetches every HPA's manifest through the real command path, so the
    /// DynamicObject -> typed conversion is exercised on live objects. Prints
    /// counts only — no names.
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set HPA_DETAIL_TEST_CONTEXT to run"]
    async fn hpa_detail_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("HPA_DETAIL_TEST_CONTEXT") else { return };
        let client = crate::kubeconfig::client_for_context(&ctx).await.expect("client");
        let list = kube::Api::<HorizontalPodAutoscaler>::all(client).list(&Default::default()).await.expect("hpas").items;
        let (mut metrics, mut unknown, mut keda, mut custom_behavior, mut not_active) = (0, 0, 0, 0, 0);
        for h in &list {
            let (ns, name) = (h.metadata.namespace.clone().unwrap_or_default(), h.metadata.name.clone().unwrap_or_default());
            let m = crate::k8s::get_hpa_manifest(&ctx, &ns, &name).await.expect("manifest + typed detail");
            let d = m.detail;
            metrics += d.metrics.len();
            unknown += d.metrics.iter().filter(|r| r.current == "<unknown>").count();
            keda += usize::from(d.owner_kind == "ScaledObject");
            custom_behavior += usize::from(!d.behavior_is_default);
            not_active += usize::from(d.conditions.iter().any(|c| c.condition_type == "ScalingActive" && c.status != "True"));
            assert!(!d.scale_up.is_empty() && !d.scale_down.is_empty());
        }
        println!("hpas={} metrics={metrics} unknown_readings={unknown} keda_owned={keda} custom_behavior={custom_behavior} scaling_inactive={not_active}", list.len());
    }
}
