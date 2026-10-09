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

On macOS and Linux, through Homebrew (below). On Windows, through Scoop — see
[Windows (x64)](#windows-x64) for the steps.

```bash
brew trust --tap aavishay/aks-fleet-dashboard
brew tap aavishay/aks-fleet-dashboard
brew install --cask aks-fleet-dashboard
```

Both first steps are one-offs. The order matters and is not the intuitive one:
as of Homebrew 7.0, `brew tap` verifies the tap by loading everything in it,
and loading a cask from an untrusted third-party tap is refused — so tapping
first fails with `invalid syntax in tap!` and deletes the clone it just made.
Trusting first works because `brew trust --tap` only records the name, and
accepts a tap that is not installed yet. Once tapped, the cask goes by its
short name.

To upgrade an existing install to the latest release:

```bash
brew upgrade --cask aks-fleet-dashboard
```

The same commands work on macOS and on Linux amd64 — the cask picks the right
artifact for the platform it is running on. See [macOS](#macos) and
[Linux (amd64)](#linux-amd64) for what differs.

### macOS

Universal build — native on both Apple Silicon and Intel Macs.

The app is ad-hoc signed rather than signed with an Apple Developer ID, so
macOS quarantines it on first launch ("cannot be opened because the developer
cannot be verified"). Clear the flag once after installing:

```bash
xattr -dr com.apple.quarantine "/Applications/AKS Fleet Dashboard.app"
```

### Linux (amd64)

Homebrew installs the AppImage into `~/Applications` and marks it executable.
x86-64 only — there is no arm64 Linux build yet. Two things differ from macOS:

- **API keys need a Secret Service.** Keys for the AI providers go to the
  system credential store, which on Linux means a running D-Bus secret
  service — `gnome-keyring` or `kwallet` on a normal desktop session. Without
  one, saving a key fails; everything else works, and the provider env vars
  (`ANTHROPIC_API_KEY` and friends) are honoured either way.
- **Ctrl replaces Cmd.** Every shortcut that is `⌘` on macOS is `Ctrl` on
  Linux. Press `?` in the app for the list, which labels itself per platform.

The AppImage is built on `ubuntu-22.04`, the oldest runner image GitHub still
offers, so it links against an older glibc than a 24.04 build would and
should reach correspondingly more distros. It needs a normal X11 or Wayland
session.

It is packaged with `linuxdeploy`, which pulls the app's library dependencies
into the image, so a host WebKitGTK install should not be required — but that
has not been confirmed on real hardware, and neither has first launch. If it
fails to start, installing your distribution's `webkit2gtk-4.1` runtime is
the first thing to try, and please open an issue.

### Windows (x64)

Through [Scoop](https://scoop.sh), which plays the part Homebrew does on the
other two platforms. Everything below runs in PowerShell, as your own user —
none of it needs an administrator prompt.

**1. Install Scoop**, if you don't have it yet, and `git`, which Scoop needs
to add a bucket:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
scoop install git
```

**2. Install the app:**

```powershell
scoop bucket add aks-fleet-dashboard https://github.com/aavishay/scoop-aks-fleet-dashboard
scoop install aks-fleet-dashboard
```

**3. Install the Azure CLI, `kubectl` and Azure's `kubelogin`**, which AKS
sign-in runs through:

```powershell
scoop install azure-cli kubectl azure-kubelogin
```

Take `azure-kubelogin`, not `kubelogin`: in Scoop that name belongs to an
unrelated OIDC plugin in the Extras bucket, and AKS sign-in fails with it.
If you'd rather not take `kubectl` and `kubelogin` from Scoop, install just
`azure-cli` here and then run `az aks install-cli`, which downloads those two —
it needs `az` already installed, so it cannot replace it.

**4. Add your clusters to kubeconfig:**

```powershell
az login
az aks get-credentials --resource-group <resource-group> --name <cluster-name>
```

Repeat the second line for every cluster you want in the dashboard. Each run
adds a context to `%USERPROFILE%\.kube\config` — merging into it is the
command's default, and there is no `--merge` flag; check them with
`kubectl config get-contexts`. The app reads that file, or the first one in
`KUBECONFIG` if you set it.

**5. Sign in once from the terminal**, so `kubelogin` has a token before the
app asks for one. Its sign-in prompt goes to a terminal, which the app does not
have:

```powershell
kubectl get nodes --context <cluster-name>
```

**6. Open the app** from the Start menu: **AKS Fleet Dashboard**. If a cluster
later shows "unreachable" because the token expired, run the same `kubectl`
command again and reopen the app.

To upgrade to the latest release:

```powershell
scoop update aks-fleet-dashboard
```

What differs from macOS:

- **Ctrl replaces Cmd**, as on Linux. Press `?` in the app for the list.
- **It renders in WebView2**, the Edge engine Windows 11 and an up-to-date
  Windows 10 already carry. If the window comes up blank, install the
  [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/).
- **The installer is not code-signed.** Scoop unpacks it rather than running
  it, so installing through Scoop should not prompt. Running the
  `x64-setup.exe` from the release by hand may bring up SmartScreen's
  "Windows protected your PC": choose **More info → Run anyway**.

### Without Homebrew

Releases carry the artifacts directly:
[Releases](https://github.com/aavishay/aks-multicluster-dashboard/releases).
Take the `.dmg`, or the `.app.zip` if you would rather not mount a disk image.
Every release from 0.7.2 onward also carries an `x86_64.AppImage` for Linux —
`chmod +x` it and run it — and from 0.7.40 an `x64-setup.exe` for Windows,
which installs for your user alone and needs no admin rights.

### Optional: AI diagnosis

Any node, workload, pod, Argo CD application or Helm release can be diagnosed
by an AI model: open it and click **Diagnose** in its panel, or press `⌘D` on
a focused row. The app gathers the status, events and manifest behind it —
plus recent logs for a pod — and shows you exactly what will be sent, with a
summary of what was redacted. Nothing leaves the machine until you confirm.

It works with Claude, Gemini, or a local Ollama. Click the AI button in the
top bar to choose one and, for Claude or Gemini, paste an API key (from
[console.anthropic.com](https://console.anthropic.com) or
[aistudio.google.com](https://aistudio.google.com)). The key is stored in your
operating system's credential store — Keychain on macOS, the D-Bus secret
service on Linux, Credential Manager on Windows — never in the app or in a file
it owns.

An exported `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` takes precedence if you'd
rather not store one.

### Prerequisites

A working `kubectl` context per cluster — the app reads your existing
`~/.kube/config` and never stores credentials of its own:

```bash
az aks get-credentials --resource-group <rg> --name <cluster>
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
  --name <cluster-name>
```

Each run merges a context into `~/.kube/config` rather than overwriting it —
that is the command's default, and there is no `--merge` flag — so all your
clusters end up side by side — that's the list the app's
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

The PV tab needs cluster-scoped read on `persistentvolumes`, which `view`
does not include, so with it alone that tab shows a permission error while the
others work. The Services tab also reads `endpointslices` to count ready
endpoints; without that, the Endpoints column shows "—" rather than failing.

The Secrets tab needs more than that: both of those roles leave Secrets out
on purpose, so with either one the tab shows a permission error for every
cluster. It needs `list` and `get` on `secrets` — for example
`Azure Kubernetes Service RBAC Writer`, or a role of your own that adds just
those two verbs.

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

The tabs sit in eight groups — Overview, Cluster, Workloads, Network,
Storage, Config, Delivery and Insights — with the active group's tabs on a
second row. A group's badge adds up the problems in its tabs, ⌘1–⌘8 switch
groups (each remembers the tab you last used in it), and ⌘K jumps straight
to any tab.

Overview gives per-cluster health at a glance: Kubernetes version, nodes
ready, namespace count, pod health, warning event count. Nodes lists every
node with CPU/memory (capacity, allocatable, and — if `metrics-server` is
running — live usage), zone, instance type, and cordon status; a node's panel
opens on an Overview — why it is not Ready, any memory, disk or PID pressure,
whether it is cordoned, its taints, capacity against allocatable and use
(GPUs included), and the pods on it, the failing ones first. Workloads
covers Deployments/StatefulSets/DaemonSets with desired-vs-ready replica
counts; a workload's panel opens on an Overview — why a rollout is stuck, the
replica counts, strategy and revision, the HPA or KEDA object scaling it, its
pods and the Services that select it, its conditions, and what its pod
template runs and reads. Pods is a live pod table with restarts and per-pod CPU/memory; a pod's
panel opens on an Overview — each container's state, restarts, why it last
exited (OOMKilled, exit code), image and resources, the pod's conditions, its
node and owner, and every ConfigMap, Secret and PVC it uses, each a link.
Resource
Usage rolls the fleet's CPU/memory usage-vs-allocatable into two bars.
Namespaces lists each namespace with its status, flagging any stuck
Terminating. Services shows type, cluster IP, external address, ports and
ready endpoints, flagging a LoadBalancer still waiting for an address and a
selector that matches no ready pod. Ingress shows class, hosts, the address
its controller published, TLS and backends, flagging one no controller has
picked up. PVC and PV list claims and volumes with status, capacity, access
modes and storage class, each linking to the other; a claim not Bound and a
volume Failed or Pending are flagged. ConfigMaps lists each ConfigMap's keys,
total size and whether it is immutable; its values are fetched only when you
open one, where a Data view shows each key's value with a filter over names
and values. Those six share one panel: an Overview of what the row means, the
YAML, and the object's events.
Events surfaces recent cluster events, defaulting to warnings only; an
event's object opens its own panel when the app has one for that kind (Jobs,
CronJobs, policies and the like stay plain text), a ReplicaSet's opens the
Deployment its name belongs to when the Workloads list has it, and the funnel
beside it narrows the table to that object. HPA lists
each autoscaler with its replicas and metrics; its panel opens on an Overview —
why it is not scaling when it is not, each metric against its target, the
scale-up and scale-down behavior (Kubernetes' defaults said as such), and the
KEDA ScaledObject that owns it, if one does. KEDA lists ScaledObjects and
ScaledJobs; their panel opens on an Overview — why one is not ready, whether
it is paused or in fallback, what it scales between which bounds and how often
it looks (KEDA's defaults applied where unset), each trigger with its
authentication and whether KEDA can read it, and the HPA it drives. NAP
lists Node Auto Provisioning's Karpenter NodePools with their node counts and
how much of their CPU and memory limits they have provisioned; a pool's panel
opens on an Overview — why it is not ready, whether it has hit a limit, what
nodes it may create (node class, weight, capacity type, requirements, taints
and labels), when Karpenter consolidates or replaces them (its defaults said
as such), and the nodes it has. GitOps
lists Argo CD Applications with their sync and health; an app's panel opens on
an Overview — why it is degraded or out of sync, what the last sync did and
each resource it failed to apply, its sources and destination, how it syncs,
the resources that need attention (each a link when the app deploys to the
cluster it runs in), its images and recent deployments — with a Diff of each
drifted resource beside it. Helm lists every release with its chart, status
and revision count, read straight from Helm's release Secrets; a release's
panel opens on an Overview — why it failed or is stuck pending, which chart
and app version it runs, which values it overrides, what it rendered (its
workloads with whether they are ready, each a link), its hooks and subcharts,
and every stored revision — beside its values, manifest and notes. Secrets
lists every Secret with its type and key count; its panel opens on an
Overview — what the type holds, who writes it (an ExternalSecret, a Helm
release, cert-manager, a ServiceAccount's token), a pull secret's registries,
and every certificate it holds with its names, issuer and expiry, flagged once
expired or within 30 days. Certificates are read in the backend and only their
public fields reach the window. The Keys view shows each key's name and size,
keeps values masked until you reveal one, and forgets them when it closes. Helm's own release Secrets are listed without their contents,
which the Helm tab already shows. ServiceAccounts shows each account's Azure
workload identity (its client ID), image pull secrets and whether it mounts a
token. ExternalSecrets lists External Secrets Operator's syncs with their
store, target Secret and whether they are synced; one's panel opens on an
Overview — why a sync fails beside its store's own health, the target Secret
and whether it exists, how often it refreshes, and its creation, deletion and
template behaviour (ESO's defaults said as such). SecretStores lists External Secrets Operator's SecretStores and
ClusterSecretStores with their provider, vault, sign-in method and whether ESO
can reach them; a store's panel lists the ExternalSecrets reading from it. PDB
lists PodDisruptionBudgets with what each allows right now, flagging one that
blocks every eviction — the one a drain or node upgrade will wait on. The
sidebar auto-refreshes cluster health badges, and there's a refresh interval
selector (15s/30s/60s/5m/off) for the active tab, defaulting to 15s.

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
