# AKS Fleet Dashboard

A native desktop, multi-cluster Kubernetes dashboard for Azure AKS
fleets — Rust (Tauri) backend talking directly to the Kubernetes API via
[`kube-rs`](https://kube.rs), Tailwind-styled frontend. Think a small,
purpose-built slice of Lens/Headlamp/Aptakube: a cluster switcher in the
sidebar, and per-cluster views for health, nodes, workloads, pods, resource
usage, and events.

It does **not** talk to Azure's control plane itself — it reads whatever
contexts are already in your kubeconfig, exactly like `kubectl` does. That's
deliberate: kubeconfig + `kubelogin`/Azure AD auth is what Lens, Headlamp,
Aptakube, and `kubectl` itself all build on, and it means this app doesn't
need to embed any Azure credentials or auth flows of its own.


## Install

```bash
brew install --cask aavishay/aks-fleet-dashboard/aks-fleet-dashboard
```

Universal build — native on both Apple Silicon and Intel Macs.

The app is ad-hoc signed rather than signed with an Apple Developer ID, so
macOS quarantines it on first launch ("cannot be opened because the developer
cannot be verified"). Clear the flag once after installing:

```bash
xattr -dr com.apple.quarantine "/Applications/AKS Fleet Dashboard.app"
```

Prefer not to use Homebrew? Grab the `.dmg` from
[Releases](https://github.com/aavishay/aks-multicluster-dashboard/releases).

### Prerequisites

A working `kubectl` context per cluster — the app reads your existing
`~/.kube/config` and never stores credentials of its own:

```bash
az aks get-credentials --resource-group <rg> --name <cluster> --merge
```

## Why this is source you build, not a binary we hand you

This was built and validated (`cargo check`, `cargo test`, `cargo clippy`,
`cargo build`, `tsc`, `vite build` — all green) inside a Linux cloud sandbox.
Tauri apps are native per-platform: a Linux build here doesn't produce a
macOS `.app`. To get an app you can double-click on your Mac (M-series), the
`npm run tauri build` step needs to run **on your Mac**, once, with its own
Xcode toolchain. Everything up to that point (all the Rust and TypeScript
logic) is already written and tested — this is a five-minute local build,
not a from-scratch project.

## 1. One-time prerequisites (on your Mac)

```bash
xcode-select --install                     # Xcode command line tools
brew install node rustup-init azure-cli kubelogin
rustup-init -y && source "$HOME/.cargo/env"
```

`kubelogin` is what lets `kubectl`/this app complete the Azure AD login for
each AKS cluster's API server; `az aks get-credentials` wires it in
automatically for AAD-integrated clusters.

## 2. Point kubeconfig at your AKS clusters

```bash
az login --use-device-code
# repeat for every cluster you want in the dashboard:
az aks get-credentials \
  --resource-group <resource-group> \
  --name <cluster-name> \
  --merge
```

Each `--merge` appends a context to `~/.kube/config` rather than overwriting
it, so all your clusters end up side by side — that's the list the app's
sidebar reads. Verify with `kubectl config get-contexts` before opening the
app.

If you use a non-default kubeconfig location, set `KUBECONFIG` in your shell
before launching the app (`export KUBECONFIG=/path/to/config`); the app
respects it the same way `kubectl` does.

RBAC needed per cluster: read access to `nodes`, `namespaces`, `pods`,
`events`, `deployments`/`statefulsets`/`daemonsets`, and (optional, for the
Resource Usage tab) `metrics.k8s.io` — e.g. bind your Azure AD user/group to
the built-in `view` ClusterRole, or `Azure Kubernetes Service RBAC Reader`
at the Azure role-assignment level.

## 3. Install dependencies and run

```bash
cd aks-multicluster-dashboard
npm install
npm run tauri dev      # dev mode, hot reload
```

## 4. Build the installable app

```bash
npm run tauri build
```

Output lands under `src-tauri/target/release/bundle/` — a `.app` plus a
`.dmg` you can drag into `Applications` or hand to a teammate.

## What each tab shows

Overview gives per-cluster health at a glance: Kubernetes version, nodes
ready, namespace count, pod health, warning event count. Nodes lists every
node with CPU/memory (capacity, allocatable, and — if `metrics-server` is
running — live usage), zone, instance type, and cordon status. Workloads
covers Deployments/StatefulSets/DaemonSets with desired-vs-ready replica
counts. Pods is a live pod table with restarts and per-pod CPU/memory. Resource
Usage rolls the fleet's CPU/memory usage-vs-allocatable into two bars.
Events surfaces recent cluster events, defaulting to warnings only. The
sidebar auto-refreshes cluster health badges, and there's a refresh interval
selector (15s/30s/60s/5m/off) for the active tab.

## What's intentionally not built yet

**Cost.** There's a stub tab explaining why: Kubernetes' own API has no
concept of Azure billing, so this needs the Azure Cost Management REST API
(or an in-cluster tool like OpenCost/Kubecost) rather than kubeconfig access.
A reasonable v2: add `src-tauri/src/cost.rs` with a Rust command that calls
Cost Management's `query` API scoped to each cluster's resource group
(needs an app registration with `Cost Management Reader` on the relevant
subscription(s)), and render it in the existing Cost tab in `src/main.ts`.

**Cluster comparison view.** Right now you switch between clusters one at a
time in the sidebar. A side-by-side or grid view across all clusters for a
single metric (e.g. "pods not ready across the fleet") would be a natural
next step if the single-cluster view proves too narrow day to day.

**Live push updates.** Data refreshes by polling on an interval, not via
Kubernetes watch streams — simpler and fine at this scale, but means events
between polls can be missed. `kube-rs` supports watch streams
(`kube::runtime::watcher`) if this becomes a real gap.

## Project layout

```
src-tauri/src/
  kubeconfig.rs   kubeconfig discovery + per-context kube::Client construction
  k8s.rs          all Kubernetes API calls (nodes, pods, workloads, events, metrics)
  models.rs       data structs shared with the frontend (keep in sync with src/types.ts)
  commands.rs     #[tauri::command] wrappers exposed to the frontend
  lib.rs          Tauri app wiring
src/
  api.ts          typed wrappers around Tauri's invoke()
  types.ts        TypeScript mirror of models.rs
  format.ts       cpu/memory/age/time formatting helpers
  main.ts         all UI state + rendering (single-file, no framework)
  styles.css      Tailwind v4 import + design tokens (dark theme)
```

## Troubleshooting

"No AKS clusters found" on launch means the app couldn't find (or parse)
`~/.kube/config` — check `kubectl config get-contexts` works first. A
cluster showing "unreachable" in the sidebar usually means its Azure AD
token expired; run `kubectl get nodes --context <name>` once to trigger a
fresh `kubelogin` device-code prompt, then reopen the app.

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE)
(`AGPL-3.0-only`).

Copyright (C) 2026 Avishay Ashkenazi

AGPL is strong copyleft: anyone who distributes this — or, under section 13,
runs a modified version as a network service others interact with — must make
the corresponding source available under the same terms.
