//! Kubernetes Secrets, listed and inspected without their values.
//!
//! Values stay out of the webview until someone asks for one. The list and the
//! detail panel carry key names and decoded sizes only, the YAML is redacted
//! before it is serialised, and `get_secret_value` returns exactly one key.
//!
//! The list does fetch full objects from the API server — Kubernetes will not
//! return a Secret's key names without its data — but the values are dropped
//! here, in Rust, as each item is mapped, and never cross IPC.
//!
//! Helm release Secrets are the exception, and are listed metadata-only. Helm
//! keeps one per release *revision*, each holding the full rendered manifest,
//! so they dominate a cluster's Secret bytes: `helm.rs` records one cluster at
//! 26.5 MB across 151 of them for 24 releases. The Helm tab already reads them
//! metadata-only for that reason, and listing them in full here would
//! re-download all of it on every refresh.

use crate::k8s::{age_days, age_seconds};
use crate::kubeconfig::client_for_context;
use crate::models::{ObjectManifest, SecretDetail, SecretInfo, SecretKeyInfo, SecretValue};
use base64::Engine;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams};
use kube::core::PartialObjectMeta;
use serde_json::Value;

const HELM_RELEASE_TYPE: &str = "helm.sh/release.v1";

/// `kubectl apply` stores the whole object it applied here, as JSON, for its
/// three-way merge — values included, in plain text for `stringData`. So this
/// annotation is as sensitive as `data` itself and is redacted with it.
const LAST_APPLIED: &str = "kubectl.kubernetes.io/last-applied-configuration";

fn keys_of(s: &Secret) -> Vec<SecretKeyInfo> {
    // A BTreeMap, so the keys arrive already sorted.
    s.data
        .iter()
        .flatten()
        .map(|(k, v)| SecretKeyInfo { name: k.clone(), bytes: v.0.len() })
        .collect()
}

fn secret_to_info(s: &Secret) -> SecretInfo {
    SecretInfo {
        namespace: s.metadata.namespace.clone().unwrap_or_default(),
        name: s.metadata.name.clone().unwrap_or_default(),
        secret_type: s.type_.clone().unwrap_or_else(|| "Opaque".to_string()),
        keys: Some(keys_of(s)),
        immutable: s.immutable.unwrap_or(false),
        age_days: age_days(s.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(s.metadata.creation_timestamp.clone()),
    }
}

/// The type comes from the field selector that fetched it, not from the item:
/// a metadata-only list carries no `type`.
fn helm_meta_to_info(m: &PartialObjectMeta<Secret>) -> SecretInfo {
    SecretInfo {
        namespace: m.metadata.namespace.clone().unwrap_or_default(),
        name: m.metadata.name.clone().unwrap_or_default(),
        secret_type: HELM_RELEASE_TYPE.to_string(),
        keys: None,
        immutable: false,
        age_days: age_days(m.metadata.creation_timestamp.clone()),
        age_seconds: age_seconds(m.metadata.creation_timestamp.clone()),
    }
}

pub async fn get_secrets(context_name: &str) -> Result<Vec<SecretInfo>, String> {
    let client = client_for_context(context_name).await?;
    let api: Api<Secret> = Api::all(client);

    // Two requests, split on the field selector Secrets support for `type`, so
    // the expensive half is never downloaded. Concurrent, so a slow cluster
    // costs one round trip rather than two.
    let ordinary = ListParams::default().fields(&format!("type!={HELM_RELEASE_TYPE}"));
    let helm = ListParams::default().fields(&format!("type={HELM_RELEASE_TYPE}"));
    let (ordinary, helm) = tokio::join!(api.list(&ordinary), api.list_metadata(&helm));

    // Both are required. Showing the ordinary half alone would silently present
    // a partial list as the whole one.
    let ordinary = ordinary.map_err(|e| list_error("secrets", e))?;
    let helm = helm.map_err(|e| list_error("Helm release secrets", e))?;

    let mut out: Vec<SecretInfo> = ordinary.items.iter().map(secret_to_info).collect();
    out.extend(helm.items.iter().map(helm_meta_to_info));
    Ok(out)
}

/// A 403 is the expected failure here rather than an exotic one: the built-in
/// `view` ClusterRole and AKS's `RBAC Reader` both leave Secrets out on
/// purpose, so a reader set up the usual way hits it on every cluster. Say so,
/// or "forbidden" reads like a fault in the app.
fn list_error(what: &str, e: kube::Error) -> String {
    match &e {
        kube::Error::Api(resp) if resp.code == 403 => format!(
            "Not allowed to list {what} on this cluster. The built-in `view` role and AKS RBAC Reader exclude Secrets by design; reading them needs `list` and `get` on `secrets`. ({e})"
        ),
        _ => format!("Failed to list {what}: {e}"),
    }
}

fn placeholder(bytes: usize) -> String {
    format!("<redacted: {bytes} bytes>")
}

/// The Secret as YAML, with every value replaced by its size.
///
/// Redacted on a JSON copy rather than on the typed object: `data` is a map of
/// raw bytes, so writing a placeholder back into it would serialise as the
/// placeholder's base64 — "PHJlZGFjdGVkPg==" — which reads like a real value.
fn redacted_manifest(secret: &Secret) -> Result<ObjectManifest, String> {
    let mut v = serde_json::to_value(secret).map_err(|e| format!("Failed to render the Secret: {e}"))?;

    if let Some(data) = v.get_mut("data").and_then(Value::as_object_mut) {
        for (key, value) in data.iter_mut() {
            let bytes = secret.data.as_ref().and_then(|d| d.get(key)).map_or(0, |b| b.0.len());
            *value = Value::String(placeholder(bytes));
        }
    }
    // Write-only in the API, so the server does not return it — but redacted
    // anyway rather than trusting that to stay true of every server.
    if let Some(string_data) = v.get_mut("stringData").and_then(Value::as_object_mut) {
        for value in string_data.values_mut() {
            let bytes = value.as_str().map_or(0, str::len);
            *value = Value::String(placeholder(bytes));
        }
    }
    if let Some(applied) = v.pointer_mut(&format!("/metadata/annotations/{}", LAST_APPLIED.replace('/', "~1"))) {
        *applied = Value::String("<redacted: this annotation holds a full copy of the Secret, values included>".to_string());
    }

    let yaml_full = serde_yaml::to_string(&v).map_err(|e| format!("Failed to render YAML: {e}"))?;
    if let Some(meta) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.remove("managedFields");
    }
    let yaml_without_managed_fields = serde_yaml::to_string(&v).map_err(|e| format!("Failed to render YAML: {e}"))?;

    Ok(ObjectManifest { yaml_full, yaml_without_managed_fields })
}

async fn get_secret(context_name: &str, namespace: &str, name: &str) -> Result<Secret, String> {
    let client = client_for_context(context_name).await?;
    let api: Api<Secret> = Api::namespaced(client, namespace);
    api.get(name).await.map_err(|e| format!("Failed to get Secret '{name}': {e}"))
}

pub async fn get_secret_detail(context_name: &str, namespace: &str, name: &str) -> Result<SecretDetail, String> {
    let secret = get_secret(context_name, namespace, name).await?;
    Ok(SecretDetail { keys: keys_of(&secret), manifest: redacted_manifest(&secret)? })
}

fn value_of(raw: &[u8]) -> SecretValue {
    match std::str::from_utf8(raw) {
        Ok(text) => SecretValue { bytes: raw.len(), text: Some(text.to_string()), base64: None },
        Err(_) => SecretValue {
            bytes: raw.len(),
            text: None,
            base64: Some(base64::engine::general_purpose::STANDARD.encode(raw)),
        },
    }
}

/// One key's decoded value — the only path by which a value leaves this module.
///
/// Fetched fresh rather than kept from the detail call, which never held
/// values: the panel can have been open long enough for the Secret to rotate.
pub async fn get_secret_value(context_name: &str, namespace: &str, name: &str, key: &str) -> Result<SecretValue, String> {
    let secret = get_secret(context_name, namespace, name).await?;
    let raw = secret
        .data
        .as_ref()
        .and_then(|d| d.get(key))
        .ok_or_else(|| format!("Secret '{name}' no longer has a key '{key}' — it may have changed since the panel opened."))?;
    Ok(value_of(&raw.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::ByteString;
    use std::collections::BTreeMap;

    const PASSWORD: &str = "hunter2-super-secret";
    const TOKEN: &str = "tok_live_ABCDEF123456";

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn sample() -> Secret {
        let mut data = BTreeMap::new();
        data.insert("password".to_string(), ByteString(PASSWORD.as_bytes().to_vec()));
        data.insert("api-token".to_string(), ByteString(TOKEN.as_bytes().to_vec()));
        let mut annotations = BTreeMap::new();
        annotations.insert(
            LAST_APPLIED.to_string(),
            format!(r#"{{"apiVersion":"v1","kind":"Secret","stringData":{{"password":"{PASSWORD}"}}}}"#),
        );
        annotations.insert("team".to_string(), "payments".to_string());
        Secret {
            metadata: ObjectMeta {
                name: Some("db-creds".into()),
                namespace: Some("payments".into()),
                annotations: Some(annotations),
                managed_fields: Some(vec![Default::default()]),
                ..Default::default()
            },
            type_: Some("Opaque".into()),
            data: Some(data),
            ..Default::default()
        }
    }

    /// Every spelling a leaked value could take in serialised output.
    fn assert_no_value_in(text: &str) {
        for secret in [PASSWORD, TOKEN] {
            assert!(!text.contains(secret), "plain value leaked: {secret}");
            assert!(!text.contains(&b64(secret)), "base64 value leaked: {secret}");
        }
    }

    #[test]
    fn the_list_carries_key_names_and_sizes_but_no_values() {
        let info = secret_to_info(&sample());
        assert_eq!(
            info.keys,
            Some(vec![
                SecretKeyInfo { name: "api-token".into(), bytes: TOKEN.len() },
                SecretKeyInfo { name: "password".into(), bytes: PASSWORD.len() },
            ])
        );
        // What actually crosses IPC is the serialised struct.
        assert_no_value_in(&serde_json::to_string(&info).unwrap());
    }

    #[test]
    fn the_yaml_is_redacted_in_both_views() {
        let m = redacted_manifest(&sample()).unwrap();
        for yaml in [&m.yaml_full, &m.yaml_without_managed_fields] {
            assert_no_value_in(yaml);
            assert!(yaml.contains(&placeholder(PASSWORD.len())), "value replaced by its size");
            // Everything that is not a value survives.
            assert!(yaml.contains("apiVersion: v1") && yaml.contains("kind: Secret"));
            assert!(yaml.contains("team: payments"));
        }
        assert!(m.yaml_full.contains("managedFields"));
        assert!(!m.yaml_without_managed_fields.contains("managedFields"));
    }

    #[test]
    fn the_last_applied_annotation_is_redacted_too() {
        // The case a `data`-only redaction misses: `kubectl apply` leaves a
        // plain-text copy of the values in this annotation.
        let yaml = redacted_manifest(&sample()).unwrap().yaml_without_managed_fields;
        assert!(yaml.contains(LAST_APPLIED));
        assert!(yaml.contains("holds a full copy of the Secret"));
        assert_no_value_in(&yaml);
    }

    #[test]
    fn string_data_is_redacted_if_a_server_ever_returns_it() {
        let mut s = sample();
        s.string_data = Some(BTreeMap::from([("password".to_string(), PASSWORD.to_string())]));
        assert_no_value_in(&redacted_manifest(&s).unwrap().yaml_full);
    }

    #[test]
    fn a_helm_release_secret_is_listed_without_claiming_it_has_no_keys() {
        let m = PartialObjectMeta::<Secret> {
            metadata: ObjectMeta { name: Some("sh.helm.release.v1.apisix.v7".into()), namespace: Some("apisix".into()), ..Default::default() },
            ..Default::default()
        };
        let info = helm_meta_to_info(&m);
        assert_eq!(info.secret_type, HELM_RELEASE_TYPE);
        assert_eq!(info.keys, None, "unknown, not zero");
    }

    #[test]
    fn a_revealed_value_is_text_when_it_can_be_and_base64_when_it_cannot() {
        assert_eq!(value_of(PASSWORD.as_bytes()), SecretValue { bytes: PASSWORD.len(), text: Some(PASSWORD.into()), base64: None });
        let binary = [0xff, 0xfe, 0x00, 0x10];
        assert_eq!(
            value_of(&binary),
            SecretValue { bytes: 4, text: None, base64: Some(base64::engine::general_purpose::STANDARD.encode(binary)) }
        );
    }
}
