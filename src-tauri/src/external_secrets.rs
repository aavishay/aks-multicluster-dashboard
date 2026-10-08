//! External Secrets Operator: `ExternalSecret` objects — which store each
//! Secret is synced from, into which Secret, and whether that sync works.
//!
//! An ExternalSecret carries references, not values: a store, a remote key
//! and a property. So unlike `secrets.rs` there is nothing to redact, and its
//! YAML and its mappings are shown as they are.

use crate::k8s::{age_days, age_seconds, created_at, event_to_info, json_str, list_events_sorted, object_manifest};
use crate::kubeconfig::client_for_context;
use crate::models::{EventInfo, ExternalSecretDetail, ExternalSecretInfo, ExternalSecretMapping, ExternalSecretsResult, SecretStoreInfo, SecretStoresResult};
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams};
use kube::Client;
use serde_json::Value;

pub(crate) const GROUP: &str = "external-secrets.io";

/// ESO promoted `ExternalSecret` to `v1` in 0.17 and still serves `v1beta1`
/// beside it, while older installs serve only `v1beta1`. Tried newest-first,
/// falling back on 404, so an older cluster is not reported as having no ESO.
pub(crate) const VERSIONS: &[&str] = &["v1", "v1beta1"];

fn resource(version: &str) -> ApiResource {
    ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk(GROUP, version, "ExternalSecret"), "externalsecrets")
}

/// The `Ready` condition: whether it is True, and its reason and message.
///
/// Its own reader rather than `k8s::json_condition`, which drops the message —
/// and for ESO the message is the point: it is the provider's own account of
/// why a sync failed ("could not get secret data from provider: …").
fn ready_condition(status: Option<&Value>) -> (bool, String, String) {
    let found = status
        .and_then(|s| s.get("conditions"))
        .and_then(Value::as_array)
        .and_then(|arr| arr.iter().find(|c| json_str(Some(c), "type") == "Ready"));
    match found {
        Some(c) => (
            json_str(Some(c), "status") == "True",
            json_str(Some(c), "reason").to_string(),
            json_str(Some(c), "message").to_string(),
        ),
        None => (false, String::new(), String::new()),
    }
}

fn to_info(obj: &DynamicObject) -> ExternalSecretInfo {
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");
    let store = spec.and_then(|s| s.get("secretStoreRef"));
    let target = spec.and_then(|s| s.get("target"));
    let name = obj.metadata.name.clone().unwrap_or_default();
    let count = |field: &str| spec.and_then(|s| s.get(field)).and_then(Value::as_array).map_or(0, Vec::len);
    let (ready, reason, message) = ready_condition(status);

    ExternalSecretInfo {
        namespace: obj.metadata.namespace.clone().unwrap_or_default(),
        store_kind: match json_str(store, "kind") {
            "" => "SecretStore".to_string(), // ESO's documented default
            k => k.to_string(),
        },
        store_name: json_str(store, "name").to_string(),
        target_name: match json_str(target, "name") {
            "" => name.clone(), // defaults to the ExternalSecret's own name
            n => n.to_string(),
        },
        target_type: match json_str(target.and_then(|t| t.get("template")), "type") {
            "" => "Opaque".to_string(),
            t => t.to_string(),
        },
        refresh_interval: json_str(spec, "refreshInterval").to_string(),
        data_count: count("data"),
        data_from_count: count("dataFrom"),
        ready,
        reason,
        message,
        last_refresh: Some(json_str(status, "refreshTime")).filter(|t| !t.is_empty()).map(str::to_string),
        age_days: age_days(obj.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(obj.metadata.creation_timestamp.clone()),
        created_at: created_at(&obj.metadata.creation_timestamp),
        name,
    }
}

pub async fn get_external_secrets(context_name: &str) -> Result<ExternalSecretsResult, String> {
    let client = client_for_context(context_name).await?;
    for version in VERSIONS {
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &resource(version));
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                return Ok(ExternalSecretsResult {
                    installed: true,
                    error: None,
                    external_secrets: list.items.iter().map(to_info).collect(),
                })
            }
            Err(kube::Error::Api(resp)) if resp.code == 404 => continue,
            Err(e) => return Err(format!("Failed to list ExternalSecrets: {e}")),
        }
    }
    Ok(ExternalSecretsResult { installed: false, error: None, external_secrets: Vec::new() })
}

/// A store's provider, read generically: ESO has some thirty providers, each
/// with its own fields, so this names the common ones and falls back to the
/// provider's name alone.
fn store_info(obj: &DynamicObject, kind: &str) -> SecretStoreInfo {
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");
    let (provider, conf) = spec
        .and_then(|s| s.get("provider"))
        .and_then(Value::as_object)
        .and_then(|p| p.iter().next())
        .map(|(k, v)| (k.clone(), Some(v)))
        .unwrap_or_default();
    let first = |keys: &[&str]| keys.iter().map(|k| json_str(conf, k)).find(|v| !v.is_empty()).unwrap_or_default().to_string();
    let auth_obj = conf.and_then(|c| c.get("auth"));
    // Azure names its method; the others are known by which auth block is set.
    let auth = match json_str(conf, "authType") {
        "" => auth_obj.and_then(Value::as_object).and_then(|a| a.keys().next().cloned()).unwrap_or_default(),
        t => t.to_string(),
    };
    // Azure names the identity beside its method; the others put a service
    // account under the chosen auth method — `auth.kubernetes` for Vault,
    // `auth.jwt` for AWS, `auth.workloadIdentity` for GCP.
    fn sa_ref(v: Option<&Value>) -> &str {
        json_str(v.and_then(|v| v.get("serviceAccountRef")), "name")
    }
    let method = auth_obj.and_then(Value::as_object).and_then(|a| a.values().next());
    let identity = [json_str(conf, "identityId"), sa_ref(conf), sa_ref(method)]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .to_string();
    let (ready, reason, message) = ready_condition(status);
    SecretStoreInfo {
        kind: kind.to_string(),
        namespace: obj.metadata.namespace.clone().unwrap_or_default(),
        name: obj.metadata.name.clone().unwrap_or_default(),
        provider,
        target: first(&["vaultUrl", "server", "region", "projectID", "remoteNamespace", "url"]),
        auth,
        identity,
        ready,
        reason,
        message,
        capabilities: json_str(status, "capabilities").to_string(),
        age_days: age_days(obj.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(obj.metadata.creation_timestamp.clone()),
        created_at: created_at(&obj.metadata.creation_timestamp),
    }
}

/// Every SecretStore and ClusterSecretStore, newest API version first.
///
/// The two are listed separately and either may fail alone: a reader allowed
/// namespaced stores but not cluster-wide ones still gets the first, with the
/// second's failure reported rather than the whole tab failing.
pub async fn get_secret_stores(context_name: &str) -> Result<SecretStoresResult, String> {
    let client = client_for_context(context_name).await?;
    let list = |kind: &'static str, plural: &'static str| {
        let client = client.clone();
        async move {
            for version in VERSIONS {
                let ar = ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk(GROUP, version, kind), plural);
                let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
                match api.list(&ListParams::default()).await {
                    Ok(list) => return Ok(Some(list.items.iter().map(|o| store_info(o, kind)).collect::<Vec<_>>())),
                    Err(kube::Error::Api(resp)) if resp.code == 404 => continue,
                    Err(e) => return Err(format!("Failed to list {kind}s: {e}")),
                }
            }
            Ok(None)
        }
    };
    let (namespaced, cluster) = tokio::join!(list("SecretStore", "secretstores"), list("ClusterSecretStore", "clustersecretstores"));
    let mut stores = Vec::new();
    let mut errors = Vec::new();
    let mut installed = false;
    for result in [namespaced, cluster] {
        match result {
            Ok(Some(s)) => {
                installed = true;
                stores.extend(s);
            }
            Ok(None) => {}
            Err(e) => errors.push(e),
        }
    }
    // Both failing is the tab failing, not a partial answer.
    if !installed && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(SecretStoresResult { installed, error: (!errors.is_empty()).then(|| errors.join("; ")), stores })
}

async fn get_one(client: &Client, namespace: &str, name: &str) -> Result<DynamicObject, String> {
    let mut tried = Vec::new();
    for version in VERSIONS {
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &resource(version));
        match api.get(name).await {
            Ok(obj) => return Ok(obj),
            Err(kube::Error::Api(resp)) if resp.code == 404 => tried.push(*version),
            Err(e) => return Err(format!("Failed to get ExternalSecret '{name}': {e}")),
        }
    }
    Err(format!("ExternalSecret '{name}' not found (tried {})", tried.join(", ")))
}

fn mappings(spec: Option<&Value>) -> Vec<ExternalSecretMapping> {
    spec.and_then(|s| s.get("data"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|e| {
                    let remote = e.get("remoteRef");
                    ExternalSecretMapping {
                        secret_key: json_str(Some(e), "secretKey").to_string(),
                        remote_key: json_str(remote, "key").to_string(),
                        property: json_str(remote, "property").to_string(),
                        version: json_str(remote, "version").to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// One `spec.dataFrom` entry as a line a reader can take in at a glance.
/// Each can yield any number of keys, so there is no key list to show — only
/// what it pulls.
fn describe_data_from(entry: &Value) -> String {
    if let Some(extract) = entry.get("extract") {
        let key = json_str(Some(extract), "key");
        return match json_str(Some(extract), "property") {
            "" => format!("Extract every property of {key}"),
            p => format!("Extract every property of {key}, property {p}"),
        };
    }
    if let Some(find) = entry.get("find") {
        let mut parts = Vec::new();
        if let Some(re) = find.pointer("/name/regexp").and_then(Value::as_str) {
            parts.push(format!("named /{re}/"));
        }
        if let Some(tags) = find.get("tags").and_then(Value::as_object).filter(|t| !t.is_empty()) {
            let tags: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default())).collect();
            parts.push(format!("tagged {}", tags.join(", ")));
        }
        if let Some(path) = find.get("path").and_then(Value::as_str) {
            parts.push(format!("under {path}"));
        }
        return if parts.is_empty() { "Find every secret in the store".to_string() } else { format!("Find secrets {}", parts.join(", ")) };
    }
    if let Some(generator) = entry.pointer("/sourceRef/generatorRef") {
        return format!("Generated by {} {}", json_str(Some(generator), "kind"), json_str(Some(generator), "name"));
    }
    "An entry this panel does not recognise — see the YAML".to_string()
}

pub async fn get_external_secret_detail(context_name: &str, namespace: &str, name: &str) -> Result<ExternalSecretDetail, String> {
    let client = client_for_context(context_name).await?;
    let obj = get_one(&client, namespace, name).await?;
    let spec = obj.data.get("spec");
    let mappings = mappings(spec);
    let data_from = spec
        .and_then(|s| s.get("dataFrom"))
        .and_then(Value::as_array)
        .map(|entries| entries.iter().map(describe_data_from).collect())
        .unwrap_or_default();
    Ok(ExternalSecretDetail { mappings, data_from, manifest: object_manifest(obj)? })
}

/// ESO reports a failing sync as a Warning event on the ExternalSecret as well
/// as in its condition — and the event history shows whether it has been
/// failing for a minute or a week, which the condition alone cannot.
pub async fn get_external_secret_events(context_name: &str, namespace: &str, name: &str) -> Result<Vec<EventInfo>, String> {
    let client = client_for_context(context_name).await?;
    let items = list_events_sorted(&client).await?;
    Ok(items
        .into_iter()
        .filter(|e| {
            e.involved_object.kind.as_deref() == Some("ExternalSecret")
                && e.involved_object.name.as_deref() == Some(name)
                && e.metadata.namespace.as_deref() == Some(namespace)
        })
        .map(event_to_info)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> DynamicObject {
        serde_json::from_value(v).unwrap()
    }

    fn synced() -> DynamicObject {
        obj(json!({
            "apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
            "metadata": { "name": "amlv-service-secret", "namespace": "amlv-service" },
            "spec": {
                "refreshInterval": "1h",
                "secretStoreRef": { "kind": "ClusterSecretStore", "name": "azure-kv" },
                "target": { "name": "amlv-env", "template": { "type": "kubernetes.io/dockerconfigjson" } },
                "data": [
                    { "secretKey": "DB_PASSWORD", "remoteRef": { "key": "amlv-db", "property": "password" } },
                    { "secretKey": "API_TOKEN", "remoteRef": { "key": "amlv-api-token", "version": "3" } }
                ],
                "dataFrom": [ { "extract": { "key": "amlv-shared" } } ]
            },
            "status": {
                "refreshTime": "2026-09-28T10:00:00Z",
                "conditions": [ { "type": "Ready", "status": "True", "reason": "SecretSynced", "message": "Secret was synced" } ]
            }
        }))
    }

    #[test]
    fn a_synced_external_secret_reads_its_store_target_and_counts() {
        let i = to_info(&synced());
        assert!(i.ready);
        assert_eq!((i.store_kind.as_str(), i.store_name.as_str()), ("ClusterSecretStore", "azure-kv"));
        assert_eq!((i.target_name.as_str(), i.target_type.as_str()), ("amlv-env", "kubernetes.io/dockerconfigjson"));
        assert_eq!((i.data_count, i.data_from_count), (2, 1));
        assert_eq!(i.last_refresh.as_deref(), Some("2026-09-28T10:00:00Z"));
    }

    #[test]
    fn a_failing_sync_keeps_the_providers_message() {
        let mut o = synced();
        o.data["status"]["conditions"] = json!([{
            "type": "Ready", "status": "False", "reason": "SecretSyncedError",
            "message": "could not get secret data from provider: Secret amlv-db not found"
        }]);
        let i = to_info(&o);
        assert!(!i.ready);
        assert_eq!(i.reason, "SecretSyncedError");
        assert!(i.message.contains("amlv-db not found"), "the message is the useful part");
    }

    #[test]
    fn defaults_follow_eso_when_fields_are_omitted() {
        let i = to_info(&obj(json!({
            "apiVersion": "external-secrets.io/v1beta1", "kind": "ExternalSecret",
            "metadata": { "name": "bare", "namespace": "ns" },
            "spec": { "secretStoreRef": { "name": "vault" } }
        })));
        assert_eq!(i.store_kind, "SecretStore");
        assert_eq!(i.target_name, "bare", "target defaults to the ExternalSecret's own name");
        assert_eq!(i.target_type, "Opaque");
        // No status yet: not ready, and no reason to claim — not an error.
        assert!(!i.ready);
        assert_eq!((i.reason.as_str(), i.message.as_str(), i.last_refresh.clone()), ("", "", None));
    }

    #[test]
    fn mappings_carry_remote_key_property_and_version() {
        let m = mappings(synced().data.get("spec"));
        assert_eq!(
            m,
            vec![
                ExternalSecretMapping { secret_key: "DB_PASSWORD".into(), remote_key: "amlv-db".into(), property: "password".into(), version: "".into() },
                ExternalSecretMapping { secret_key: "API_TOKEN".into(), remote_key: "amlv-api-token".into(), property: "".into(), version: "3".into() },
            ]
        );
    }

    #[test]
    fn each_kind_of_data_from_entry_reads_as_a_sentence() {
        assert_eq!(describe_data_from(&json!({ "extract": { "key": "shared" } })), "Extract every property of shared");
        assert_eq!(
            describe_data_from(&json!({ "find": { "name": { "regexp": "^amlv-" }, "tags": { "env": "prod" } } })),
            "Find secrets named /^amlv-/, tagged env=prod"
        );
        assert_eq!(
            describe_data_from(&json!({ "sourceRef": { "generatorRef": { "kind": "Password", "name": "db-pass" } } })),
            "Generated by Password db-pass"
        );
        assert_eq!(describe_data_from(&json!({ "somethingNew": {} })), "An entry this panel does not recognise — see the YAML");
    }

    #[test]
    fn an_azure_key_vault_store_names_its_vault_and_identity() {
        let s = store_info(
            &obj(json!({
                "apiVersion": "external-secrets.io/v1", "kind": "SecretStore",
                "metadata": { "name": "kv", "namespace": "prod" },
                "spec": { "provider": { "azurekv": { "authType": "ManagedIdentity", "identityId": "abc", "vaultUrl": "https://kv.vault.azure.net", "tenantId": "t" } } },
                "status": { "capabilities": "ReadWrite", "conditions": [{ "type": "Ready", "status": "True", "reason": "Valid", "message": "store validated" }] }
            })),
            "SecretStore",
        );
        assert_eq!((s.provider.as_str(), s.target.as_str()), ("azurekv", "https://kv.vault.azure.net"));
        assert_eq!((s.auth.as_str(), s.identity.as_str()), ("ManagedIdentity", "abc"));
        assert!(s.ready);
        assert_eq!(s.capabilities, "ReadWrite");
    }

    #[test]
    fn another_provider_is_known_by_its_auth_block() {
        let s = store_info(
            &obj(json!({
                "apiVersion": "external-secrets.io/v1", "kind": "ClusterSecretStore",
                "metadata": { "name": "vault" },
                "spec": { "provider": { "vault": { "server": "https://vault:8200", "auth": { "kubernetes": { "role": "eso", "serviceAccountRef": { "name": "eso-vault" } } } } } },
                "status": { "conditions": [{ "type": "Ready", "status": "False", "reason": "InvalidProviderConfig", "message": "permission denied" }] }
            })),
            "ClusterSecretStore",
        );
        assert_eq!((s.namespace.as_str(), s.provider.as_str(), s.target.as_str(), s.auth.as_str()), ("", "vault", "https://vault:8200", "kubernetes"));
        // Nested under the chosen auth method, not beside it.
        assert_eq!(s.identity, "eso-vault");
        assert!(!s.ready);
        assert_eq!(s.message, "permission denied");
    }
}
