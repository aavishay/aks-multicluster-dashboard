//! The KEDA panel's Overview: what a ScaledObject or ScaledJob scales, between
//! which bounds and how often it looks, each trigger and whether KEDA can read
//! it, and what it falls back to when it cannot — read from the same object the
//! YAML view renders.
//!
//! KEDA's resources have no typed Rust struct here, so this reads the JSON,
//! applying KEDA's documented defaults where a field is unset so the Overview
//! says what will happen rather than leaving a blank.

use crate::k8s::json_str;
use crate::models::{KedaDetail, KedaTriggerInfo, PodConditionInfo};
use kube::api::DynamicObject;
use serde_json::Value;

fn i64_at(v: Option<&Value>, key: &str) -> Option<i64> {
    v.and_then(|v| v.get(key)).and_then(Value::as_i64)
}

fn triggers(spec: Option<&Value>, status: Option<&Value>) -> Vec<KedaTriggerInfo> {
    let health = status.and_then(|s| s.get("health")).and_then(Value::as_object);
    spec.and_then(|s| s.get("triggers"))
        .and_then(Value::as_array)
        .map(|ts| {
            ts.iter()
                .enumerate()
                .map(|(i, t)| {
                    let auth = t.get("authenticationRef");
                    let auth_ref = match json_str(auth, "name") {
                        "" => String::new(),
                        name => format!(
                            "{}/{name}",
                            match json_str(auth, "kind") {
                                "" => "TriggerAuthentication",
                                k => k,
                            }
                        ),
                    };
                    // KEDA names each trigger's metric `s<index>-<scaler>-…`,
                    // and keys `status.health` by that name.
                    let reported = health.and_then(|h| h.iter().find(|(k, _)| k.starts_with(&format!("s{i}-"))).map(|(_, v)| v));
                    KedaTriggerInfo {
                        trigger_type: json_str(Some(t), "type").to_string(),
                        name: json_str(Some(t), "name").to_string(),
                        metadata: t
                            .get("metadata")
                            .and_then(Value::as_object)
                            .map(|m| {
                                let mut kv: Vec<String> = m
                                    .iter()
                                    .map(|(k, v)| format!("{k}={}", v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                                    .collect();
                                kv.sort();
                                kv
                            })
                            .unwrap_or_default(),
                        auth_ref,
                        metric_type: json_str(Some(t), "metricType").to_string(),
                        health: json_str(reported, "status").to_string(),
                        failures: i64_at(reported, "numberOfFailures"),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// KEDA's reading of a pause annotation: Go's `strconv.ParseBool` (`1`, `t`,
/// `T`, `TRUE`, `true`, `True` and their false counterparts), with a value that
/// does not parse counting as paused — KEDA errs towards not scaling.
fn pause_flag(value: &str) -> bool {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => true,
        "0" | "f" | "F" | "FALSE" | "false" | "False" => false,
        _ => true,
    }
}

/// The fallback rule in words, including `fallback.behavior` (KEDA 2.15+):
/// `static` (the default) holds the fallback count; the `currentReplicas`
/// variants keep the current count, or the higher or lower of the two.
fn fallback_text(fallback: Option<&Value>) -> String {
    let (Some(n), Some(r)) = (i64_at(fallback, "failureThreshold"), i64_at(fallback, "replicas")) else {
        return String::new();
    };
    let after = format!("After {n} failure{} in a row", if n == 1 { "" } else { "s" });
    let plural = |r: i64| if r == 1 { "" } else { "s" };
    match json_str(fallback, "behavior") {
        "currentReplicas" => format!("{after}, keep the current replica count"),
        "currentReplicasIfHigher" => format!("{after}, keep the current count if it is above {r}, else {r} replica{}", plural(r)),
        "currentReplicasIfLower" => format!("{after}, keep the current count if it is below {r}, else {r} replica{}", plural(r)),
        _ => format!("{after}, hold {r} replica{}", plural(r)),
    }
}

pub(crate) fn keda_detail(obj: &DynamicObject, kind: &str) -> KedaDetail {
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");
    let is_job = kind == "ScaledJob";
    let target = spec.and_then(|s| s.get("scaleTargetRef"));
    let annotations = obj.metadata.annotations.as_ref();
    // paused-replicas is a ScaledObject annotation; a ScaledJob ignores it.
    let paused_replicas = if is_job { None } else { annotations.and_then(|a| a.get("autoscaling.keda.sh/paused-replicas")).cloned() };
    let paused = paused_replicas.is_some() || annotations.and_then(|a| a.get("autoscaling.keda.sh/paused")).is_some_and(|v| pause_flag(v));
    let fallback = spec.and_then(|s| s.get("fallback"));

    KedaDetail {
        target_kind: if is_job {
            "Job".to_string()
        } else {
            match json_str(target, "kind") {
                "" => "Deployment".to_string(), // KEDA's documented default
                k => k.to_string(),
            }
        },
        target_name: if is_job { String::new() } else { json_str(target, "name").to_string() },
        // Both kinds take a minimum, defaulting to 0, as the list mapper reads it.
        min_replicas: i64_at(spec, "minReplicaCount").unwrap_or(0),
        max_replicas: i64_at(spec, "maxReplicaCount").unwrap_or(100),
        idle_replicas: i64_at(spec, "idleReplicaCount"),
        polling_interval: i64_at(spec, "pollingInterval").unwrap_or(30),
        cooldown_period: if is_job { None } else { Some(i64_at(spec, "cooldownPeriod").unwrap_or(300)) },
        fallback: fallback_text(fallback),
        paused,
        paused_replicas,
        hpa_name: json_str(status, "hpaName").to_string(),
        last_active: status.and_then(|s| s.get("lastActiveTime")).and_then(Value::as_str).map(str::to_string),
        scaling_strategy: if is_job {
            match json_str(spec.and_then(|s| s.get("scalingStrategy")), "strategy") {
                "" => "default".to_string(),
                s => s.to_string(),
            }
        } else {
            String::new()
        },
        triggers: triggers(spec, status),
        conditions: status
            .and_then(|s| s.get("conditions"))
            .and_then(Value::as_array)
            .map(|cs| {
                cs.iter()
                    .map(|c| PodConditionInfo {
                        condition_type: json_str(Some(c), "type").to_string(),
                        status: json_str(Some(c), "status").to_string(),
                        reason: json_str(Some(c), "reason").to_string(),
                        message: json_str(Some(c), "message").to_string(),
                        last_transition: c.get("lastTransitionTime").and_then(Value::as_str).map(str::to_string),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use serde_json::json;

    fn obj(annotations: Option<(&str, &str)>, data: Value) -> DynamicObject {
        DynamicObject {
            types: None,
            metadata: ObjectMeta {
                annotations: annotations.map(|(k, v)| [(k.to_string(), v.to_string())].into_iter().collect()),
                ..Default::default()
            },
            data,
        }
    }

    #[test]
    fn scaled_object_defaults_triggers_health_and_fallback() {
        let d = keda_detail(
            &obj(
                None,
                json!({
                    "spec": {
                        "scaleTargetRef": { "name": "worker" },
                        "maxReplicaCount": 20,
                        "fallback": { "failureThreshold": 3, "replicas": 2 },
                        "triggers": [
                            { "type": "azure-servicebus", "metadata": { "queueName": "orders", "messageCount": "5" },
                              "authenticationRef": { "name": "sb-auth" } },
                            { "type": "cpu", "metricType": "Utilization", "metadata": { "value": "70" } }
                        ]
                    },
                    "status": {
                        "hpaName": "keda-hpa-worker",
                        "health": { "s0-azure-servicebus-orders": { "numberOfFailures": 4, "status": "Failing" } },
                        "conditions": [{ "type": "Ready", "status": "False", "reason": "ScaledObjectCheckFailed", "message": "failed to ensure HPA" }]
                    }
                }),
            ),
            "ScaledObject",
        );
        assert_eq!((d.target_kind.as_str(), d.target_name.as_str()), ("Deployment", "worker"));
        assert_eq!((d.min_replicas, d.max_replicas, d.polling_interval, d.cooldown_period), (0, 20, 30, Some(300)));
        assert_eq!(d.fallback, "After 3 failures in a row, hold 2 replicas");
        assert_eq!(d.hpa_name, "keda-hpa-worker");
        let t = &d.triggers[0];
        assert_eq!(t.metadata, vec!["messageCount=5", "queueName=orders"]);
        assert_eq!((t.auth_ref.as_str(), t.health.as_str(), t.failures), ("TriggerAuthentication/sb-auth", "Failing", Some(4)));
        // The second trigger's s1- metric is not in status.health: unreported, not healthy.
        assert_eq!((d.triggers[1].health.as_str(), d.triggers[1].failures), ("", None));
        assert_eq!(d.conditions[0].reason, "ScaledObjectCheckFailed");
    }

    #[test]
    fn fallback_behavior_is_described() {
        let f = |behavior: &str| fallback_text(Some(&json!({ "failureThreshold": 3, "replicas": 2, "behavior": behavior })));
        assert_eq!(f("static"), "After 3 failures in a row, hold 2 replicas");
        assert_eq!(f("currentReplicas"), "After 3 failures in a row, keep the current replica count");
        assert_eq!(f("currentReplicasIfHigher"), "After 3 failures in a row, keep the current count if it is above 2, else 2 replicas");
        assert_eq!(f("currentReplicasIfLower"), "After 3 failures in a row, keep the current count if it is below 2, else 2 replicas");
        assert_eq!(fallback_text(Some(&json!({ "failureThreshold": 3, "replicas": 2 }))), "After 3 failures in a row, hold 2 replicas");
        assert_eq!(fallback_text(None), "");
    }

    #[test]
    fn scaled_job_and_paused_annotations() {
        let job = keda_detail(
            &obj(None, json!({ "spec": { "jobTargetRef": {}, "minReplicaCount": 3, "maxReplicaCount": 10, "scalingStrategy": { "strategy": "accurate" }, "triggers": [] } })),
            "ScaledJob",
        );
        assert_eq!((job.target_kind.as_str(), job.min_replicas, job.max_replicas, job.cooldown_period), ("Job", 3, 10, None));
        assert_eq!(job.scaling_strategy, "accurate");

        let paused = keda_detail(&obj(Some(("autoscaling.keda.sh/paused-replicas", "0")), json!({ "spec": {} })), "ScaledObject");
        assert!(paused.paused);
        assert_eq!(paused.paused_replicas.as_deref(), Some("0"));
        // A ScaledJob ignores paused-replicas.
        let job_with_replicas = keda_detail(&obj(Some(("autoscaling.keda.sh/paused-replicas", "0")), json!({ "spec": {} })), "ScaledJob");
        assert!(!job_with_replicas.paused && job_with_replicas.paused_replicas.is_none());
        // ParseBool's spellings, and an unparseable value errs towards paused.
        for (v, want) in [("true", true), ("True", true), ("1", true), ("false", false), ("0", false), ("yes", true)] {
            let d = keda_detail(&obj(Some(("autoscaling.keda.sh/paused", v)), json!({ "spec": {} })), "ScaledObject");
            assert_eq!(d.paused, want, "paused={v}");
            assert!(d.paused_replicas.is_none());
        }
    }

    /// Fetches every ScaledObject and ScaledJob through the real command path.
    /// Prints counts only — no names, no trigger metadata.
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set KEDA_DETAIL_TEST_CONTEXT to run"]
    async fn keda_detail_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("KEDA_DETAIL_TEST_CONTEXT") else { return };
        let list = crate::k8s::get_keda_scaled_objects(&ctx).await.expect("list");
        let (mut triggers, mut unhealthy, mut unreported, mut with_hpa, mut with_fallback, mut not_ready) = (0, 0, 0, 0, 0, 0);
        for o in &list.scaled_objects {
            let m = crate::k8s::get_keda_manifest(&ctx, &o.namespace, &o.kind, &o.name).await.expect("manifest + detail");
            let d = m.detail;
            triggers += d.triggers.len();
            unhealthy += d.triggers.iter().filter(|t| t.health == "Failing").count();
            unreported += d.triggers.iter().filter(|t| t.health.is_empty()).count();
            with_hpa += usize::from(!d.hpa_name.is_empty());
            with_fallback += usize::from(!d.fallback.is_empty());
            not_ready += usize::from(d.conditions.iter().any(|c| c.condition_type == "Ready" && c.status != "True"));
            assert_eq!(d.target_kind == "Job", o.kind == "ScaledJob");
        }
        println!(
            "installed={} objects={} triggers={triggers} failing_triggers={unhealthy} unreported_triggers={unreported} with_hpa={with_hpa} with_fallback={with_fallback} not_ready={not_ready}",
            list.installed,
            list.scaled_objects.len()
        );
    }
}
