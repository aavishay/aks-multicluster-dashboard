//! The Pod panel's Overview: the facts a pod's YAML buries, pulled out of the
//! same object the YAML view renders, so it costs no extra request.
//!
//! Spec and status are merged per container — the spec says what it should be
//! (image, resources, ports), the status what it is doing (state, restarts,
//! why it last stopped) — because a reader asking "why is this pod failing"
//! needs both side by side, which the YAML keeps two screens apart.

use crate::k8s::created_at;
use crate::models::{ContainerDetail, PodConditionInfo, PodDetail, PodReference};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Pod, PodSpec};
use std::collections::BTreeMap;

fn quantity(map: Option<&BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>>, key: &str) -> String {
    map.and_then(|m| m.get(key)).map(|q| q.0.clone()).unwrap_or_default()
}

/// Also used for a workload's pod template, with no status: the spec half only.
pub(crate) fn container_detail(c: &Container, status: Option<&ContainerStatus>) -> ContainerDetail {
    let resources = c.resources.as_ref();
    let mut d = ContainerDetail {
        name: c.name.clone(),
        image: c.image.clone().unwrap_or_default(),
        cpu_request: quantity(resources.and_then(|r| r.requests.as_ref()), "cpu"),
        cpu_limit: quantity(resources.and_then(|r| r.limits.as_ref()), "cpu"),
        memory_request: quantity(resources.and_then(|r| r.requests.as_ref()), "memory"),
        memory_limit: quantity(resources.and_then(|r| r.limits.as_ref()), "memory"),
        ports: c
            .ports
            .iter()
            .flatten()
            .map(|p| {
                let proto = p.protocol.clone().unwrap_or_else(|| "TCP".to_string());
                match &p.name {
                    Some(n) => format!("{n} {}/{proto}", p.container_port),
                    None => format!("{}/{proto}", p.container_port),
                }
            })
            .collect(),
        ..Default::default()
    };
    let Some(s) = status else { return d };
    d.ready = s.ready;
    d.restart_count = s.restart_count;
    // The status's image is what is actually running, which can differ from
    // the spec while a rollout or an image pull is in progress.
    if !s.image.is_empty() {
        d.image = s.image.clone();
    }
    if let Some(state) = &s.state {
        if let Some(r) = &state.running {
            d.state = "running".into();
            d.state_since = created_at(&r.started_at);
        } else if let Some(w) = &state.waiting {
            d.state = "waiting".into();
            d.state_reason = w.reason.clone().unwrap_or_default();
            d.state_message = w.message.clone().unwrap_or_default();
        } else if let Some(t) = &state.terminated {
            d.state = "terminated".into();
            d.state_reason = t.reason.clone().unwrap_or_default();
            d.state_message = t.message.clone().unwrap_or_default();
            d.state_since = created_at(&t.finished_at);
            d.exit_code = Some(t.exit_code);
        }
    }
    if let Some(t) = s.last_state.as_ref().and_then(|l| l.terminated.as_ref()) {
        d.last_reason = t.reason.clone().unwrap_or_default();
        d.last_exit_code = Some(t.exit_code);
        d.last_finished = created_at(&t.finished_at);
        d.last_message = t.message.clone().unwrap_or_default();
    }
    d
}

/// Adds `via` to the reference for (kind, name), creating it on first sight.
fn note(refs: &mut Vec<PodReference>, kind: &str, name: &str, via: &str) {
    if name.is_empty() {
        return;
    }
    match refs.iter_mut().find(|r| r.kind == kind && r.name == name) {
        Some(r) => {
            if !r.via.iter().any(|v| v == via) {
                r.via.push(via.to_string());
            }
        }
        None => refs.push(PodReference { kind: kind.to_string(), name: name.to_string(), via: vec![via.to_string()] }),
    }
}

/// Every ConfigMap, Secret and PVC the pod reads: volumes (projected ones
/// included), `envFrom`, single `env` values and image-pull secrets.
///
/// `kube-root-ca.crt` is left out. Kubernetes projects it into every pod's
/// service-account volume on its own, so listing it on every pod would bury
/// the references someone actually wrote.
///
/// Takes the spec rather than the pod, so a workload's pod template answers
/// the same question for every pod it will create.
pub(crate) fn references(spec: &PodSpec) -> Vec<PodReference> {
    let mut refs = Vec::new();
    for v in spec.volumes.iter().flatten() {
        if let Some(c) = &v.config_map {
            note(&mut refs, "ConfigMap", &c.name, "volume");
        }
        if let Some(s) = &v.secret {
            note(&mut refs, "Secret", s.secret_name.as_deref().unwrap_or_default(), "volume");
        }
        if let Some(p) = &v.persistent_volume_claim {
            note(&mut refs, "PersistentVolumeClaim", &p.claim_name, "volume");
        }
        for src in v.projected.iter().flat_map(|p| p.sources.iter().flatten()) {
            if let Some(c) = &src.config_map {
                if c.name != "kube-root-ca.crt" {
                    note(&mut refs, "ConfigMap", &c.name, "volume");
                }
            }
            if let Some(s) = &src.secret {
                note(&mut refs, "Secret", &s.name, "volume");
            }
        }
    }
    // Ephemeral containers too: one added by `kubectl debug` reads its own
    // env, and "every" reference should not miss it. Their type differs from
    // Container's, so the two env fields are gathered into one shape first.
    let envs = spec
        .init_containers
        .iter()
        .flatten()
        .chain(spec.containers.iter())
        .map(|c| (c.env_from.as_ref(), c.env.as_ref()))
        .chain(spec.ephemeral_containers.iter().flatten().map(|c| (c.env_from.as_ref(), c.env.as_ref())));
    for (env_from, env) in envs {
        for from in env_from.into_iter().flatten() {
            if let Some(r) = &from.config_map_ref {
                note(&mut refs, "ConfigMap", &r.name, "envFrom");
            }
            if let Some(r) = &from.secret_ref {
                note(&mut refs, "Secret", &r.name, "envFrom");
            }
        }
        for e in env.into_iter().flatten() {
            let Some(src) = &e.value_from else { continue };
            if let Some(r) = &src.config_map_key_ref {
                note(&mut refs, "ConfigMap", &r.name, "env");
            }
            if let Some(r) = &src.secret_key_ref {
                note(&mut refs, "Secret", &r.name, "env");
            }
        }
    }
    for s in spec.image_pull_secrets.iter().flatten() {
        note(&mut refs, "Secret", &s.name, "imagePull");
    }
    refs
}

pub(crate) fn pod_detail(pod: &Pod) -> PodDetail {
    let spec = pod.spec.as_ref();
    let status = pod.status.as_ref();
    let statuses = |list: Option<&Vec<ContainerStatus>>, name: &str| -> Option<ContainerStatus> {
        list.and_then(|l| l.iter().find(|s| s.name == name)).cloned()
    };
    let controller = pod
        .metadata
        .owner_references
        .iter()
        .flatten()
        .find(|o| o.controller == Some(true));
    PodDetail {
        phase: status.and_then(|s| s.phase.clone()).unwrap_or_default(),
        reason: status.and_then(|s| s.reason.clone()).unwrap_or_default(),
        message: status.and_then(|s| s.message.clone()).unwrap_or_default(),
        node: spec.and_then(|s| s.node_name.clone()).unwrap_or_default(),
        pod_ip: status.and_then(|s| s.pod_ip.clone()).unwrap_or_default(),
        host_ip: status.and_then(|s| s.host_ip.clone()).unwrap_or_default(),
        qos_class: status.and_then(|s| s.qos_class.clone()).unwrap_or_default(),
        service_account: spec.and_then(|s| s.service_account_name.clone()).unwrap_or_default(),
        priority_class: spec.and_then(|s| s.priority_class_name.clone()).unwrap_or_default(),
        restart_policy: spec.and_then(|s| s.restart_policy.clone()).unwrap_or_default(),
        start_time: status.map(|s| created_at(&s.start_time)).unwrap_or_default(),
        controller_kind: controller.map(|o| o.kind.clone()).unwrap_or_default(),
        controller_name: controller.map(|o| o.name.clone()).unwrap_or_default(),
        init_containers: spec
            .map(|s| {
                s.init_containers
                    .iter()
                    .flatten()
                    .map(|c| container_detail(c, statuses(status.and_then(|st| st.init_container_statuses.as_ref()), &c.name).as_ref()))
                    .collect()
            })
            .unwrap_or_default(),
        containers: spec
            .map(|s| {
                s.containers
                    .iter()
                    .map(|c| container_detail(c, statuses(status.and_then(|st| st.container_statuses.as_ref()), &c.name).as_ref()))
                    .collect()
            })
            .unwrap_or_default(),
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
        references: spec.map(references).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        ConfigMapEnvSource, ConfigMapProjection, ConfigMapVolumeSource, ContainerPort, ContainerState, ContainerStateRunning,
        ContainerStateTerminated, ContainerStateWaiting, EnvFromSource, EnvVar, EnvVarSource, LocalObjectReference,
        PersistentVolumeClaimVolumeSource, PodSpec, PodStatus, ProjectedVolumeSource, ResourceRequirements, SecretKeySelector,
        SecretVolumeSource, Volume, VolumeProjection,
    };
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference, Time};

    fn t(s: &str) -> Time {
        Time(chrono::DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&chrono::Utc))
    }

    #[test]
    fn a_crashlooping_container_shows_its_wait_and_why_it_last_died() {
        let pod = Pod {
            metadata: ObjectMeta {
                owner_references: Some(vec![OwnerReference {
                    kind: "ReplicaSet".into(),
                    name: "api-7c9".into(),
                    controller: Some(true),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            spec: Some(PodSpec {
                node_name: Some("aks-general-1".into()),
                containers: vec![Container {
                    name: "api".into(),
                    image: Some("api:1".into()),
                    ports: Some(vec![ContainerPort { container_port: 8080, name: Some("http".into()), ..Default::default() }]),
                    resources: Some(ResourceRequirements {
                        requests: Some(BTreeMap::from([("memory".to_string(), Quantity("256Mi".into()))])),
                        limits: Some(BTreeMap::from([("memory".to_string(), Quantity("512Mi".into()))])),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            status: Some(PodStatus {
                phase: Some("Running".into()),
                container_statuses: Some(vec![ContainerStatus {
                    name: "api".into(),
                    image: "api:1".into(),
                    ready: false,
                    restart_count: 41,
                    state: Some(ContainerState {
                        waiting: Some(ContainerStateWaiting { reason: Some("CrashLoopBackOff".into()), message: Some("back-off 5m0s".into()) }),
                        ..Default::default()
                    }),
                    last_state: Some(ContainerState {
                        terminated: Some(ContainerStateTerminated {
                            exit_code: 137,
                            reason: Some("OOMKilled".into()),
                            finished_at: Some(t("2026-10-06T08:00:00Z")),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };
        let d = pod_detail(&pod);
        let c = &d.containers[0];
        assert_eq!((c.state.as_str(), c.state_reason.as_str(), c.restart_count), ("waiting", "CrashLoopBackOff", 41));
        assert_eq!((c.last_reason.as_str(), c.last_exit_code), ("OOMKilled", Some(137)));
        assert_eq!(c.last_finished.as_deref(), Some("2026-10-06T08:00:00Z"));
        assert_eq!((c.memory_request.as_str(), c.memory_limit.as_str()), ("256Mi", "512Mi"));
        assert_eq!(c.ports, vec!["http 8080/TCP"]);
        assert_eq!((d.controller_kind.as_str(), d.controller_name.as_str()), ("ReplicaSet", "api-7c9"));
        assert_eq!(d.node, "aks-general-1");
    }

    #[test]
    fn a_running_container_reports_when_it_started() {
        let pod = Pod {
            spec: Some(PodSpec { containers: vec![Container { name: "web".into(), ..Default::default() }], ..Default::default() }),
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    name: "web".into(),
                    ready: true,
                    state: Some(ContainerState {
                        running: Some(ContainerStateRunning { started_at: Some(t("2026-10-06T07:00:00Z")) }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let c = &pod_detail(&pod).containers[0];
        assert_eq!((c.state.as_str(), c.ready), ("running", true));
        assert_eq!(c.state_since.as_deref(), Some("2026-10-06T07:00:00Z"));
    }

    #[test]
    fn references_cover_volumes_env_and_pull_secrets_without_the_root_ca() {
        let pod = Pod {
            spec: Some(PodSpec {
                volumes: Some(vec![
                    Volume { name: "cfg".into(), config_map: Some(ConfigMapVolumeSource { name: "app-config".into(), ..Default::default() }), ..Default::default() },
                    Volume { name: "tls".into(), secret: Some(SecretVolumeSource { secret_name: Some("app-tls".into()), ..Default::default() }), ..Default::default() },
                    Volume {
                        name: "data".into(),
                        persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource { claim_name: "data-0".into(), ..Default::default() }),
                        ..Default::default()
                    },
                    Volume {
                        name: "kube-api-access".into(),
                        projected: Some(ProjectedVolumeSource {
                            sources: Some(vec![VolumeProjection {
                                config_map: Some(ConfigMapProjection { name: "kube-root-ca.crt".into(), ..Default::default() }),
                                ..Default::default()
                            }]),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ]),
                containers: vec![Container {
                    name: "app".into(),
                    env_from: Some(vec![EnvFromSource { config_map_ref: Some(ConfigMapEnvSource { name: "app-config".into(), ..Default::default() }), ..Default::default() }]),
                    env: Some(vec![EnvVar {
                        name: "DB_PASSWORD".into(),
                        value_from: Some(EnvVarSource {
                            secret_key_ref: Some(SecretKeySelector { name: "db".into(), key: "password".into(), ..Default::default() }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                image_pull_secrets: Some(vec![LocalObjectReference { name: "acr".into() }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let refs = pod_detail(&pod).references;
        let as_tuples: Vec<(&str, &str, String)> = refs.iter().map(|r| (r.kind.as_str(), r.name.as_str(), r.via.join(","))).collect();
        assert_eq!(
            as_tuples,
            vec![
                ("ConfigMap", "app-config", "volume,envFrom".to_string()),
                ("Secret", "app-tls", "volume".to_string()),
                ("PersistentVolumeClaim", "data-0", "volume".to_string()),
                ("Secret", "db", "env".to_string()),
                ("Secret", "acr", "imagePull".to_string()),
            ]
        );
    }

    #[test]
    fn an_ephemeral_containers_env_counts_as_a_reference() {
        use k8s_openapi::api::core::v1::{EphemeralContainer, SecretEnvSource};
        let pod = Pod {
            spec: Some(PodSpec {
                containers: vec![Container { name: "app".into(), ..Default::default() }],
                ephemeral_containers: Some(vec![EphemeralContainer {
                    name: "debugger".into(),
                    env_from: Some(vec![EnvFromSource { secret_ref: Some(SecretEnvSource { name: "debug-creds".into(), ..Default::default() }), ..Default::default() }]),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let refs = pod_detail(&pod).references;
        assert_eq!(refs, vec![PodReference { kind: "Secret".into(), name: "debug-creds".into(), via: vec!["envFrom".into()] }]);
    }

    /// Maps every pod of a real cluster. Prints counts only — no names.
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set POD_DETAIL_TEST_CONTEXT to run"]
    async fn pod_detail_against_a_live_cluster() {
        let Ok(ctx) = std::env::var("POD_DETAIL_TEST_CONTEXT") else { return };
        let client = crate::kubeconfig::client_for_context(&ctx).await.expect("client");
        let pods: kube::Api<Pod> = kube::Api::all(client);
        let list = pods.list(&Default::default()).await.expect("pods").items;
        let details: Vec<PodDetail> = list.iter().map(pod_detail).collect();
        let containers: Vec<&ContainerDetail> = details.iter().flat_map(|d| d.containers.iter()).collect();
        let waiting = containers.iter().filter(|c| c.state == "waiting").count();
        let crashloop = containers.iter().filter(|c| c.state_reason == "CrashLoopBackOff").count();
        let with_last = containers.iter().filter(|c| !c.last_reason.is_empty()).count();
        let oom = containers.iter().filter(|c| c.last_reason == "OOMKilled").count();
        let refs: usize = details.iter().map(|d| d.references.len()).sum();
        let pvcs = details.iter().flat_map(|d| d.references.iter()).filter(|r| r.kind == "PersistentVolumeClaim").count();
        let no_node = details.iter().filter(|d| d.node.is_empty()).count();
        println!(
            "pods={} containers={} waiting={waiting} crashloop={crashloop} with_last_termination={with_last} oomkilled={oom} references={refs} pvc_refs={pvcs} unscheduled={no_node}",
            details.len(),
            containers.len()
        );
        let mut no_conditions: std::collections::BTreeMap<String, usize> = Default::default();
        for d in details.iter().filter(|d| d.conditions.is_empty()) {
            *no_conditions.entry(format!("{}/{}", d.phase, d.reason)).or_default() += 1;
        }
        println!("pods without conditions, by phase/reason: {no_conditions:?}");
        // Every container the spec declares gets a row, status or not.
        assert_eq!(containers.len(), list.iter().map(|p| p.spec.as_ref().map_or(0, |s| s.containers.len())).sum::<usize>());
    }
}
