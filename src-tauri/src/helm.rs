//! Reads Helm's release state directly out of its storage backend.
//!
//! Helm keeps one Secret per release *revision*, of type
//! `helm.sh/release.v1` and named `sh.helm.release.v1.<release>.v<revision>`,
//! whose single `release` key holds `base64(gzip(json))` of the release
//! object. There's no Helm API server to ask, so `helm list` itself works the
//! same way — this reproduces it against the same data rather than shelling
//! out to the `helm` binary, which may not be installed and would need its
//! own kubeconfig/auth round trip per cluster.
//!
//! Cost matters here: on a private-link cluster each round trip runs into
//! tens of seconds, and a fleet's release Secrets are large — one real
//! cluster measured 26.5 MB across 151 revision Secrets for only 24 distinct
//! releases, since every superseded revision keeps its full rendered
//! manifest. So the list path fetches *metadata only* (labels carry the
//! release name, status and revision), works out the newest revision per
//! release, and then fetches just those payloads, concurrently.

use crate::kubeconfig::client_for_context;
use crate::models::{HelmReleaseDetail, HelmReleaseInfo};
use base64::Engine;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams};
use std::collections::HashMap;
use std::io::Read;

/// Helm's storage-backend Secret type, and the label it stamps on them.
const HELM_SECRET_TYPE: &str = "helm.sh/release.v1";
const HELM_OWNER_LABEL: &str = "owner=helm";

/// Guards against a pathological release blowing out memory: Helm's payload
/// is a gzipped rendered manifest, so a legitimate one is well under this
/// even for a large chart (the biggest seen on a real cluster decoded to
/// ~100 KB).
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

/// The label-derived facts about one revision Secret, available without
/// fetching its payload.
struct RevisionRef {
    namespace: String,
    secret_name: String,
    release_name: String,
    revision: i64,
    status: String,
}

fn parse_revision_metadata(meta: &kube::core::PartialObjectMeta<Secret>) -> Option<RevisionRef> {
    let labels = meta.metadata.labels.as_ref()?;
    Some(RevisionRef {
        namespace: meta.metadata.namespace.clone()?,
        secret_name: meta.metadata.name.clone()?,
        release_name: labels.get("name")?.clone(),
        // Helm writes the revision as a decimal string; a Secret without a
        // usable one isn't a release revision we can order, so skip it.
        revision: labels.get("version")?.parse().ok()?,
        status: labels.get("status").cloned().unwrap_or_else(|| "unknown".to_string()),
    })
}

/// `base64(gzip(json))` -> the release JSON. The outer base64 layer that
/// Kubernetes applies to Secret values is already undone by the time this
/// sees `data` (k8s-openapi hands back a `ByteString` of raw bytes), so what
/// arrives here is Helm's own base64 text.
fn decode_release_payload(raw: &[u8]) -> Result<serde_json::Value, String> {
    let gzipped = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| format!("Release payload is not valid base64: {e}"))?;

    let mut json = Vec::new();
    GzDecoder::new(gzipped.as_slice())
        .take(MAX_DECOMPRESSED_BYTES)
        .read_to_end(&mut json)
        .map_err(|e| format!("Failed to gunzip release payload: {e}"))?;

    serde_json::from_slice(&json).map_err(|e| format!("Release payload is not valid JSON: {e}"))
}

fn str_at<'a>(value: &'a serde_json::Value, path: &[&str]) -> &'a str {
    let mut cursor = value;
    for key in path {
        match cursor.get(key) {
            Some(next) => cursor = next,
            None => return "",
        }
    }
    cursor.as_str().unwrap_or_default()
}

/// Helm timestamps are RFC 3339 with an offset (e.g.
/// `2026-04-29T16:37:04.6162361+03:00`). Normalised to UTC so the frontend
/// gets the same shape every other tab's timestamps use, and so the age
/// columns can be computed here.
fn parse_helm_time(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw).ok().map(|t| t.with_timezone(&Utc))
}

fn release_info_from_payload(r: &RevisionRef, revision_count: i64, payload: &serde_json::Value) -> HelmReleaseInfo {
    let last_deployed = parse_helm_time(str_at(payload, &["info", "last_deployed"]));
    let (age_days, age_seconds) = match last_deployed {
        Some(t) => {
            let elapsed = Utc::now() - t;
            (elapsed.num_days().max(0), elapsed.num_seconds().max(0))
        }
        None => (0, 0),
    };

    HelmReleaseInfo {
        namespace: r.namespace.clone(),
        name: r.release_name.clone(),
        revision: r.revision,
        // The payload's status is authoritative; the label is a mirror of it,
        // used only as a fallback if the payload couldn't be decoded.
        status: match str_at(payload, &["info", "status"]) {
            "" => r.status.clone(),
            s => s.to_string(),
        },
        chart_name: str_at(payload, &["chart", "metadata", "name"]).to_string(),
        chart_version: str_at(payload, &["chart", "metadata", "version"]).to_string(),
        app_version: str_at(payload, &["chart", "metadata", "appVersion"]).to_string(),
        description: str_at(payload, &["info", "description"]).to_string(),
        last_deployed: last_deployed.map(|t| t.to_rfc3339()),
        first_deployed: parse_helm_time(str_at(payload, &["info", "first_deployed"])).map(|t| t.to_rfc3339()),
        revision_count,
        age_days,
        age_seconds,
    }
}

/// A release whose payload wouldn't decode still gets a row, built from the
/// labels alone — better than dropping it silently, since a release that
/// can't be read is exactly the sort of thing worth seeing.
fn release_info_from_labels_only(r: &RevisionRef, revision_count: i64, error: &str) -> HelmReleaseInfo {
    HelmReleaseInfo {
        namespace: r.namespace.clone(),
        name: r.release_name.clone(),
        revision: r.revision,
        status: r.status.clone(),
        chart_name: String::new(),
        chart_version: String::new(),
        app_version: String::new(),
        description: format!("[could not read release payload: {error}]"),
        last_deployed: None,
        first_deployed: None,
        revision_count,
        age_days: 0,
        age_seconds: 0,
    }
}

pub async fn get_helm_releases(context_name: &str) -> Result<Vec<HelmReleaseInfo>, String> {
    let client = client_for_context(context_name).await?;
    let all_secrets: Api<Secret> = Api::all(client.clone());

    // Metadata-only: the payloads are the expensive part and most belong to
    // superseded revisions we'll never show.
    let lp = ListParams::default()
        .labels(HELM_OWNER_LABEL)
        .fields(&format!("type={HELM_SECRET_TYPE}"));
    let metas = all_secrets
        .list_metadata(&lp)
        .await
        .map_err(|e| format!("Failed to list Helm release secrets: {e}"))?
        .items;

    // Keep the highest revision per (namespace, release), counting how many
    // revisions Helm is retaining for it.
    let mut latest: HashMap<(String, String), (RevisionRef, i64)> = HashMap::new();
    for meta in &metas {
        let Some(rev) = parse_revision_metadata(meta) else { continue };
        let key = (rev.namespace.clone(), rev.release_name.clone());
        match latest.get_mut(&key) {
            Some((existing, count)) => {
                *count += 1;
                if rev.revision > existing.revision {
                    *existing = rev;
                }
            }
            None => {
                latest.insert(key, (rev, 1));
            }
        }
    }

    // Only now fetch payloads, and only for the surviving revisions — issued
    // concurrently so a slow cluster costs roughly one round trip rather than
    // one per release.
    //
    // Each get must be namespaced. The list above is deliberately `Api::all`
    // (one cross-namespace LIST), but that same handle's `get` would build a
    // cluster-scoped `/api/v1/secrets/{name}` path, which doesn't exist for a
    // namespaced resource and 404s for every release.
    let fetches = latest.into_values().map(|(rev, count)| {
        let client = client.clone();
        async move {
            let api: Api<Secret> = Api::namespaced(client, &rev.namespace);
            let payload = match api.get(&rev.secret_name).await {
                Ok(secret) => secret
                    .data
                    .as_ref()
                    .and_then(|d| d.get("release"))
                    .ok_or_else(|| "secret has no 'release' key".to_string())
                    .and_then(|bytes| decode_release_payload(&bytes.0)),
                Err(e) => Err(e.to_string()),
            };
            match payload {
                Ok(p) => release_info_from_payload(&rev, count, &p),
                Err(e) => release_info_from_labels_only(&rev, count, &e),
            }
        }
    });

    let mut out: Vec<HelmReleaseInfo> = futures::future::join_all(fetches).await;
    // Unhealthy first (same convention as the Workloads tab), then by name.
    out.sort_by(|a, b| {
        let healthy = |s: &str| s == "deployed";
        healthy(&a.status)
            .cmp(&healthy(&b.status))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.namespace.cmp(&b.namespace))
    });
    Ok(out)
}

/// Renders a JSON value as YAML, or the empty string for a null/absent one —
/// Helm stores "no user-supplied values" as an empty object or null, and
/// showing `{}`/`null` reads worse than showing nothing.
fn json_to_yaml_or_empty(value: Option<&serde_json::Value>) -> String {
    match value {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::Object(map)) if map.is_empty() => String::new(),
        Some(v) => serde_yaml::to_string(v).unwrap_or_default(),
    }
}

pub async fn get_helm_release_detail(
    context_name: &str,
    namespace: &str,
    name: &str,
    revision: i64,
) -> Result<HelmReleaseDetail, String> {
    let client = client_for_context(context_name).await?;
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let secret_name = format!("sh.helm.release.v1.{name}.v{revision}");
    let secret = secrets
        .get(&secret_name)
        .await
        .map_err(|e| format!("Failed to get Helm release secret '{secret_name}': {e}"))?;

    let raw = secret
        .data
        .as_ref()
        .and_then(|d| d.get("release"))
        .ok_or_else(|| format!("Secret '{secret_name}' has no 'release' key"))?;
    let payload = decode_release_payload(&raw.0)?;

    Ok(HelmReleaseDetail {
        values_yaml: json_to_yaml_or_empty(payload.get("config")),
        default_values_yaml: json_to_yaml_or_empty(payload.pointer("/chart/values")),
        manifest: payload.get("manifest").and_then(|m| m.as_str()).unwrap_or_default().to_string(),
        notes: str_at(&payload, &["info", "notes"]).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// Builds the exact `base64(gzip(json))` shape Helm stores, so the decoder
    /// is exercised against the real encoding rather than a stand-in.
    fn encode_like_helm(json: &str) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(json.as_bytes()).unwrap();
        let gzipped = encoder.finish().unwrap();
        base64::engine::general_purpose::STANDARD.encode(gzipped).into_bytes()
    }

    #[test]
    fn decodes_the_base64_gzip_json_helm_stores() {
        let raw = encode_like_helm(r#"{"name":"apisix","version":17}"#);
        let decoded = decode_release_payload(&raw).expect("should decode");
        assert_eq!(decoded["name"], "apisix");
        assert_eq!(decoded["version"], 17);
    }

    #[test]
    fn decode_reports_each_layer_failing_distinctly() {
        let not_base64 = decode_release_payload(b"!!!not base64!!!").unwrap_err();
        assert!(not_base64.contains("base64"), "got: {not_base64}");

        let base64_but_not_gzip = base64::engine::general_purpose::STANDARD.encode("plain text").into_bytes();
        let not_gzip = decode_release_payload(&base64_but_not_gzip).unwrap_err();
        assert!(not_gzip.contains("gunzip"), "got: {not_gzip}");

        let gzip_but_not_json = encode_like_helm("this is not json");
        let not_json = decode_release_payload(&gzip_but_not_json).unwrap_err();
        assert!(not_json.contains("JSON"), "got: {not_json}");
    }

    /// Field shapes taken from a real `sh.helm.release.v1.*` payload.
    fn sample_payload() -> serde_json::Value {
        serde_json::json!({
            "name": "apisix",
            "version": 17,
            "namespace": "apisix",
            "info": {
                "status": "failed",
                "first_deployed": "2026-04-29T00:46:42.9045066+03:00",
                "last_deployed": "2026-04-29T16:37:04.6162361+03:00",
                "description": "Upgrade \"apisix\" failed",
                "notes": "APISIX is installed."
            },
            "chart": {
                "metadata": { "name": "apisix", "version": "2.14.0", "appVersion": "3.16.0" },
                "values": { "replicaCount": 1 }
            },
            "config": { "replicaCount": 3 },
            "manifest": "apiVersion: v1\nkind: Service\n"
        })
    }

    fn sample_ref() -> RevisionRef {
        RevisionRef {
            namespace: "apisix".to_string(),
            secret_name: "sh.helm.release.v1.apisix.v17".to_string(),
            release_name: "apisix".to_string(),
            revision: 17,
            status: "failed".to_string(),
        }
    }

    #[test]
    fn maps_payload_fields_onto_the_release_row() {
        let info = release_info_from_payload(&sample_ref(), 3, &sample_payload());
        assert_eq!(info.name, "apisix");
        assert_eq!(info.revision, 17);
        assert_eq!(info.revision_count, 3);
        assert_eq!(info.status, "failed");
        assert_eq!(info.chart_name, "apisix");
        assert_eq!(info.chart_version, "2.14.0");
        assert_eq!(info.app_version, "3.16.0");
        assert_eq!(info.description, "Upgrade \"apisix\" failed");
        // Normalised to UTC: 16:37:04+03:00 -> 13:37:04Z
        assert!(info.last_deployed.as_deref().unwrap().starts_with("2026-04-29T13:37:04"));
        assert!(info.first_deployed.is_some());
    }

    #[test]
    fn missing_payload_fields_do_not_panic() {
        let info = release_info_from_payload(&sample_ref(), 1, &serde_json::json!({}));
        // Falls back to the label-derived status rather than blanking it.
        assert_eq!(info.status, "failed");
        assert_eq!(info.chart_version, "");
        assert_eq!(info.last_deployed, None);
        assert_eq!(info.age_seconds, 0);
    }

    #[test]
    fn an_undecodable_release_still_produces_a_row() {
        let info = release_info_from_labels_only(&sample_ref(), 2, "bad gzip");
        assert_eq!(info.name, "apisix");
        assert_eq!(info.revision, 17);
        assert_eq!(info.status, "failed");
        assert!(info.description.contains("bad gzip"));
    }

    #[test]
    fn empty_values_render_as_blank_rather_than_braces() {
        assert_eq!(json_to_yaml_or_empty(None), "");
        assert_eq!(json_to_yaml_or_empty(Some(&serde_json::Value::Null)), "");
        assert_eq!(json_to_yaml_or_empty(Some(&serde_json::json!({}))), "");
        assert_eq!(
            json_to_yaml_or_empty(Some(&serde_json::json!({"replicaCount": 3}))).trim(),
            "replicaCount: 3"
        );
    }

    #[test]
    fn parses_helm_offset_timestamps_and_rejects_junk() {
        let t = parse_helm_time("2026-04-29T16:37:04.6162361+03:00").expect("should parse");
        assert_eq!(t.to_rfc3339(), "2026-04-29T13:37:04.616236100+00:00");
        assert!(parse_helm_time("").is_none());
        assert!(parse_helm_time("not a time").is_none());
    }
}
