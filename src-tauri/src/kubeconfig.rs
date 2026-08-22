//! Helpers for discovering kubeconfig contexts and building a `kube::Client`
//! for a chosen context. AKS clusters get here the normal way: the user runs
//! `az aks get-credentials --resource-group <rg> --name <cluster> --merge`
//! for each cluster (see README.md), which appends a context to
//! `~/.kube/config`. We never talk to the Azure control plane directly; we
//! just read whatever kubeconfig contexts are already on disk, exactly like
//! kubectl/Lens/Headlamp do.

use crate::models::ClusterEntry;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Transport-level timeouts. These are deliberately looser than the
/// per-operation ceiling enforced in `commands.rs` (which is what actually
/// bounds how long the UI can wait) — they exist only so a connection that
/// has genuinely gone away can't be held forever, while still leaving room
/// for a slow VPN and for large list responses on big clusters.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

/// Resolve the kubeconfig path: respects `KUBECONFIG` env var (first entry if
/// multiple are colon-separated) and otherwise falls back to `~/.kube/config`.
pub fn kubeconfig_path() -> Option<PathBuf> {
    if let Ok(val) = std::env::var("KUBECONFIG") {
        if let Some(first) = val.split(':').next() {
            if !first.is_empty() {
                return Some(PathBuf::from(first));
            }
        }
    }
    dirs::home_dir().map(|h| h.join(".kube").join("config"))
}

fn looks_like_aks(server: &str, context_name: &str, cluster_name: &str) -> bool {
    server.contains("azmk8s.io")
        || server.contains(".azure.")
        || context_name.to_lowercase().contains("aks")
        || cluster_name.to_lowercase().contains("aks")
}

/// List every context found in the kubeconfig, flagged with a best-effort
/// guess at whether it's an AKS cluster (so the UI can badge/filter them).
pub fn list_contexts() -> Result<Vec<ClusterEntry>, String> {
    let path = kubeconfig_path().ok_or_else(|| "Could not determine home directory to locate ~/.kube/config".to_string())?;
    if !path.exists() {
        return Err(format!(
            "No kubeconfig found at {}. Run `az aks get-credentials --merge` for each AKS cluster first (see README).",
            path.display()
        ));
    }

    let raw = Kubeconfig::read_from(&path)
        .map_err(|e| format!("Failed to parse kubeconfig at {}: {e}", path.display()))?;

    let mut entries = Vec::new();
    for ctx in &raw.contexts {
        let context_name = ctx.name.clone();
        let cluster_name = ctx
            .context
            .as_ref()
            .map(|c| c.cluster.clone())
            .unwrap_or_default();
        let namespace = ctx.context.as_ref().and_then(|c| c.namespace.clone());

        let server = raw
            .clusters
            .iter()
            .find(|c| c.name == cluster_name)
            .and_then(|c| c.cluster.as_ref())
            .and_then(|c| c.server.clone())
            .unwrap_or_default();

        let is_aks = looks_like_aks(&server, &context_name, &cluster_name);

        entries.push(ClusterEntry {
            context_name,
            cluster_name,
            server,
            namespace,
            is_aks,
        });
    }

    // AKS clusters first, then alphabetical, so a mixed kubeconfig (e.g. a
    // local kind cluster alongside real AKS clusters) still surfaces the
    // relevant ones at the top.
    entries.sort_by(|a, b| {
        b.is_aks
            .cmp(&a.is_aks)
            .then_with(|| a.context_name.cmp(&b.context_name))
    });

    Ok(entries)
}

/// Clients are cached per context, because building one is far from free: each
/// `kube::Client` carries its own TLS connector and its own hyper connection
/// pool, and for AKS's `kubelogin` exec auth, constructing the config also
/// spawns a subprocess (with its pipes) to mint a token.
///
/// Rebuilding per call was the direct cause of `Too many open files (os error
/// 24)` across every cluster at once. Auto-refresh re-fetches the active tab
/// *and* every selected cluster's sidebar badge on each tick, so a 16-cluster
/// selection on a 15s interval meant ~32 brand-new clients and ~32 `kubelogin`
/// spawns every 15 seconds — and a connection to a cluster that accepts TCP
/// but never answers (a private-link cluster reached from outside its VNet)
/// stays open until its read timeout expires, so descriptors accumulated far
/// faster than they were reclaimed.
///
/// Sharing one client per context is also the correct thing for auth: kube's
/// auth layer refreshes an expired exec token in place behind the shared
/// client, so the plugin runs when the token actually expires rather than on
/// every single request.
///
/// The cache is invalidated wholesale when the kubeconfig's mtime changes, so
/// running `az aks get-credentials` while the app is open is picked up without
/// a restart.
struct ClientCache {
    kubeconfig_stamp: Option<SystemTime>,
    clients: HashMap<String, Client>,
}

static CLIENT_CACHE: Mutex<Option<ClientCache>> = Mutex::new(None);

fn kubeconfig_stamp(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Return a `kube::Client` scoped to the named context, reusing a previously
/// built one when possible. See [`ClientCache`] for why reuse matters.
pub async fn client_for_context(context_name: &str) -> Result<Client, String> {
    let path = kubeconfig_path().ok_or_else(|| "Could not determine home directory".to_string())?;
    let stamp = kubeconfig_stamp(&path);

    {
        let mut guard = CLIENT_CACHE.lock().unwrap();
        match guard.as_mut() {
            Some(cache) if cache.kubeconfig_stamp == stamp => {
                if let Some(client) = cache.clients.get(context_name) {
                    return Ok(client.clone());
                }
            }
            // No cache yet, or the kubeconfig changed on disk — start clean so
            // a stale server address or credential can't linger.
            _ => *guard = Some(ClientCache { kubeconfig_stamp: stamp, clients: HashMap::new() }),
        }
    }

    let client = build_client(&path, context_name).await?;

    // The lock is never held across the await above, so two concurrent callers
    // for the same context can both build one; last writer wins and the loser's
    // client is simply dropped. That's cheaper than serialising every caller
    // behind a build, and harmless since clients are interchangeable.
    let mut guard = CLIENT_CACHE.lock().unwrap();
    if let Some(cache) = guard.as_mut() {
        if cache.kubeconfig_stamp == stamp {
            cache.clients.insert(context_name.to_string(), client.clone());
        }
    }

    Ok(client)
}

async fn build_client(path: &Path, context_name: &str) -> Result<Client, String> {
    let raw = Kubeconfig::read_from(path).map_err(|e| format!("Failed to read kubeconfig: {e}"))?;

    let options = KubeConfigOptions {
        context: Some(context_name.to_string()),
        cluster: None,
        user: None,
    };

    let mut config = Config::from_custom_kubeconfig(raw, &options)
        .await
        .map_err(|e| format!("Failed to build config for context '{context_name}': {e}"))?;

    config.connect_timeout = Some(CONNECT_TIMEOUT);
    config.read_timeout = Some(READ_TIMEOUT);
    config.write_timeout = Some(WRITE_TIMEOUT);

    Client::try_from(config).map_err(|e| format!("Failed to build client for context '{context_name}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A kubeconfig shaped like what `az aks get-credentials --merge` actually
    /// produces: two AKS clusters (Azure AD / kubelogin exec auth, azmk8s.io
    /// server hostnames) plus one unrelated local cluster, to make sure AKS
    /// detection and sorting work against realistic input rather than a
    /// hand-simplified fixture.
    const SAMPLE_KUBECONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: aks-prod-euwe
clusters:
  - name: aks-prod-euwe
    cluster:
      server: https://example-prod-euwe-12345678.hcp.westeurope.azmk8s.io:443
      certificate-authority-data: ZmFrZQ==
  - name: aks-staging-eastus
    cluster:
      server: https://example-staging-eastus-87654321.hcp.eastus.azmk8s.io:443
      certificate-authority-data: ZmFrZQ==
  - name: kind-local
    cluster:
      server: https://127.0.0.1:6443
      certificate-authority-data: ZmFrZQ==
contexts:
  - name: aks-prod-euwe
    context:
      cluster: aks-prod-euwe
      user: clusterUser_prod-rg_aks-prod-euwe
      namespace: default
  - name: aks-staging-eastus
    context:
      cluster: aks-staging-eastus
      user: clusterUser_staging-rg_aks-staging-eastus
  - name: kind-local
    context:
      cluster: kind-local
      user: kind-local
users:
  - name: clusterUser_prod-rg_aks-prod-euwe
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: kubelogin
        args: ["get-token", "--login", "devicecode", "--server-id", "fake"]
  - name: clusterUser_staging-rg_aks-staging-eastus
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: kubelogin
        args: ["get-token", "--login", "devicecode", "--server-id", "fake"]
  - name: kind-local
    user:
      token: faketoken
"#;

    /// Points `KUBECONFIG` at a freshly-written temp file for the duration of
    /// the closure, restoring (or clearing) the previous value afterwards.
    /// Tests in this module run serially via `cargo test -- --test-threads=1`
    /// implied by the shared env var, but we guard with a mutex to be safe if
    /// that assumption ever changes.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_sample_kubeconfig<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut path = std::env::temp_dir();
        path.push(format!("aks-dashboard-test-kubeconfig-{}", std::process::id()));
        let mut file = std::fs::File::create(&path).expect("write temp kubeconfig");
        file.write_all(SAMPLE_KUBECONFIG.as_bytes()).expect("write contents");
        drop(file);

        let previous = std::env::var("KUBECONFIG").ok();
        std::env::set_var("KUBECONFIG", &path);
        let result = f();
        match previous {
            Some(v) => std::env::set_var("KUBECONFIG", v),
            None => std::env::remove_var("KUBECONFIG"),
        }
        std::fs::remove_file(&path).ok();
        result
    }

    #[test]
    fn kubeconfig_path_honors_kubeconfig_env_var() {
        with_sample_kubeconfig(|| {
            let path = kubeconfig_path().expect("path");
            assert!(path.to_string_lossy().contains("aks-dashboard-test-kubeconfig"));
        });
    }

    #[test]
    fn list_contexts_flags_aks_clusters_and_sorts_them_first() {
        with_sample_kubeconfig(|| {
            let entries = list_contexts().expect("list_contexts should succeed against a valid kubeconfig");
            assert_eq!(entries.len(), 3);

            let aks_entries: Vec<&ClusterEntry> = entries.iter().filter(|e| e.is_aks).collect();
            assert_eq!(aks_entries.len(), 2, "both azmk8s.io clusters should be flagged as AKS");

            // AKS entries sort before the non-AKS one.
            assert!(entries[0].is_aks && entries[1].is_aks && !entries[2].is_aks);

            // Within the AKS group, alphabetical by context name.
            assert_eq!(entries[0].context_name, "aks-prod-euwe");
            assert_eq!(entries[1].context_name, "aks-staging-eastus");

            let kind_entry = entries.iter().find(|e| e.context_name == "kind-local").unwrap();
            assert!(!kind_entry.is_aks);
            assert_eq!(kind_entry.namespace, None);

            let prod = entries.iter().find(|e| e.context_name == "aks-prod-euwe").unwrap();
            assert_eq!(prod.namespace, Some("default".to_string()));
            assert!(prod.server.contains("azmk8s.io"));
        });
    }

    #[test]
    fn list_contexts_errors_clearly_when_kubeconfig_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous = std::env::var("KUBECONFIG").ok();
        std::env::set_var("KUBECONFIG", "/nonexistent/path/kubeconfig-does-not-exist");
        let result = list_contexts();
        match previous {
            Some(v) => std::env::set_var("KUBECONFIG", v),
            None => std::env::remove_var("KUBECONFIG"),
        }
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("az aks get-credentials"));
    }
}
