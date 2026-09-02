mod claude;
mod commands;
mod helm;
mod k8s;
mod kubeconfig;
mod metrics_backend;
mod models;
mod redact;
mod retry;

/// A macOS app launched via Finder/Dock/Launchpad is spawned by launchd with
/// a minimal `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`) rather than the user's
/// shell profile — so kube's exec-based auth plugins (`kubelogin`, `az`,
/// etc.) fail with "No such file or directory" even though they resolve
/// fine in a terminal. Recover the real PATH by asking the user's login
/// shell for it (the same trick Lens/VS Code use); fall back to appending
/// common install locations if that fails for any reason (no `$SHELL`, a
/// shell that errors out, etc.) so we still cover the common case.
#[cfg(target_os = "macos")]
fn ensure_usable_path() {
    const START: &str = "__aks_dashboard_path_start__";
    const END: &str = "__aks_dashboard_path_end__";

    let recovered = std::env::var("SHELL").ok().and_then(|shell| {
        let output = std::process::Command::new(shell)
            .args(["-ilc", &format!("echo -n {START}$PATH{END}")])
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        let start = text.find(START)? + START.len();
        let end = text.find(END)?;
        let path = text.get(start..end)?;
        (!path.is_empty()).then(|| path.to_string())
    });

    match recovered {
        Some(path) => std::env::set_var("PATH", path),
        None => {
            let home = std::env::var("HOME").unwrap_or_default();
            let fallback_dirs = [
                "/opt/homebrew/bin".to_string(),
                "/opt/homebrew/sbin".to_string(),
                "/usr/local/bin".to_string(),
                "/usr/local/sbin".to_string(),
                format!("{home}/.local/bin"),
            ];
            let current = std::env::var("PATH").unwrap_or_default();
            let mut parts: Vec<String> = current.split(':').filter(|s| !s.is_empty()).map(String::from).collect();
            for dir in fallback_dirs {
                if std::path::Path::new(&dir).is_dir() && !parts.iter().any(|p| p == &dir) {
                    parts.push(dir);
                }
            }
            std::env::set_var("PATH", parts.join(":"));
        }
    }
}

/// launchd hands GUI processes (anything started from Finder/Dock/Launchpad
/// rather than a shell) a `RLIMIT_NOFILE` soft limit of 256 on macOS, where an
/// interactive shell typically has orders of magnitude more. Talking to a whole
/// fleet at once — a connection pool per cluster, each with its own TLS
/// connections, plus `kubelogin` subprocesses and their pipes — can run through
/// 256 descriptors, which surfaces as `Too many open files (os error 24)` on
/// every cluster simultaneously. Raise the soft limit toward the hard limit,
/// which is exactly what `ulimit -n` does for a shell.
#[cfg(unix)]
fn raise_open_file_limit() {
    /// Comfortably above what a full fleet refresh needs, and still far below
    /// macOS's `kern.maxfilesperproc`.
    const DESIRED: libc::rlim_t = 8192;

    // SAFETY: both calls take a valid, fully-initialised `rlimit` we own, and
    // we only apply `setrlimit` after `getrlimit` reported success.
    unsafe {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return;
        }
        // Raising the *soft* limit needs no privileges as long as it stays
        // within the hard limit; lowering it is never what we want.
        let target = if limit.rlim_max == libc::RLIM_INFINITY {
            DESIRED
        } else {
            DESIRED.min(limit.rlim_max)
        };
        if target > limit.rlim_cur {
            limit.rlim_cur = target;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "macos")]
    ensure_usable_path();

    #[cfg(unix)]
    raise_open_file_limit();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::list_clusters,
            commands::get_cluster_overview,
            commands::get_nodes,
            commands::get_node_manifest,
            commands::get_node_events,
            commands::get_pods,
            commands::stream_pods,
            commands::get_workloads,
            commands::get_workload_manifest,
            commands::get_workload_events,
            commands::get_workload_revisions,
            commands::get_events,
            commands::get_resource_usage,
            commands::get_metrics_over_time,
            commands::get_pod_manifest,
            commands::get_pod_logs,
            commands::start_pod_log_stream,
            commands::stop_pod_log_stream,
            commands::get_workload_logs,
            commands::start_workload_log_stream,
            commands::get_pod_metrics_over_time,
            commands::get_node_metrics_over_time,
            commands::get_workload_metrics_over_time,
            commands::get_helm_releases,
            commands::get_helm_release_detail,
            commands::get_nap_node_pools,
            commands::get_keda_scaled_objects,
            commands::get_keda_manifest,
            commands::get_keda_events,
            commands::get_nap_node_pool_manifest,
            commands::get_nap_node_pool_events,
            commands::get_nap_node_pool_metrics_over_time,
            commands::get_gitops_apps,
            commands::get_gitops_manifest,
            commands::get_gitops_events,
            commands::list_metrics_backends,
            commands::test_metrics_backend,
            commands::claude_auth_status,
            commands::claude_set_api_key,
            commands::claude_clear_api_key,
            commands::claude_build_diagnosis,
            commands::claude_diagnose,
            commands::claude_explain_error,
            commands::kubeconfig_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
