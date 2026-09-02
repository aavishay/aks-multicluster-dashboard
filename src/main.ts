import "./styles.css";
import { api } from "./api";
import { formatAgeDetailed, formatKi, formatMillicores, formatPct, relativeTime } from "./format";
import type {
  ClaudeAuthState,
  ClaudeDiagnosisPayload,
  ClusterEntry,
  ClusterOverview,
  EventInfo,
  GitOpsAppInfo,
  GitOpsAppManifest,
  GitOpsResult,
  KedaResult,
  KedaScaledObjectInfo,
  HelmReleaseDetail,
  MetricsBackendInfo,
  MetricsBackendTestResult,
  HelmReleaseInfo,
  MetricSample,
  MetricsOverTimeResult,
  NapNodePoolInfo,
  NapNodePoolManifest,
  NapResult,
  NodeInfo,
  NodeManifest,
  PodInfo,
  PodManifest,
  ResourceUsageSummary,
  TabId,
  WorkloadInfo,
  WorkloadManifest,
  WorkloadRevisionInfo,
} from "./types";

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

type Theme = "light" | "dark";

const THEME_STORAGE_KEY = "aks-dashboard-theme";

function getInitialTheme(): Theme {
  const stored = localStorage.getItem(THEME_STORAGE_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem(THEME_STORAGE_KEY, theme);
}

// Set before the first render() so the window never flashes the wrong theme.
const initialTheme = getInitialTheme();
applyTheme(initialTheme);

function toggleTheme() {
  state.theme = state.theme === "light" ? "dark" : "light";
  applyTheme(state.theme);
  render();
}

// ---------------------------------------------------------------------------
// UI scale (zoom)
//
// All of the app's Tailwind text/spacing utilities are rem-based, so setting
// the root element's font-size scales the whole UI proportionally — text,
// padding, gaps and borders together — rather than just growing text into
// unchanged spacing.
//
// Deliberately *not* CSS `zoom`/`transform: scale()`: several places here
// position fixed-position overlays (the enum-filter dropdown panel, the chart
// hover tooltip) from a trigger's `getBoundingClientRect()`, and a zoomed or
// scaled root makes those rects disagree with the viewport coordinates a
// `position: fixed` element is laid out in — so the panel lands away from its
// button. Scaling the rem basis keeps one coordinate space, and stays crisp
// at every step instead of resampling the rendered output.
//
// One numeric ladder backs both entry points: the topbar "A" button cycles
// through it, and Cmd+Plus/Cmd+Minus step along it (Cmd+0 returns to 100%).
// ---------------------------------------------------------------------------

/** Percentages of the browser's default root font-size, ascending. 100 must be present — it's the reset target and the default. */
const UI_SCALE_STEPS = [75, 87.5, 100, 112.5, 125, 150, 175] as const;
const DEFAULT_UI_SCALE = 100;

const UI_SCALE_STORAGE_KEY = "aks-dashboard-ui-scale";
/** Superseded by `UI_SCALE_STORAGE_KEY`; still read once so an existing small/normal/large preference carries over instead of silently resetting. */
const LEGACY_FONT_SIZE_STORAGE_KEY = "aks-dashboard-font-size";

function getInitialUiScale(): number {
  const stored = Number(localStorage.getItem(UI_SCALE_STORAGE_KEY));
  if (UI_SCALE_STEPS.includes(stored as (typeof UI_SCALE_STEPS)[number])) return stored;

  switch (localStorage.getItem(LEGACY_FONT_SIZE_STORAGE_KEY)) {
    case "small":
      return 87.5;
    case "large":
      return 125;
    default:
      return DEFAULT_UI_SCALE;
  }
}

function applyUiScale(scale: number) {
  // Inline style rather than a `data-` attribute plus a stylesheet rule per
  // step, so the ladder can grow by editing one array.
  document.documentElement.style.fontSize = `${scale}%`;
  localStorage.setItem(UI_SCALE_STORAGE_KEY, String(scale));
}

// Set before the first render() so the window never flashes the wrong size.
const initialUiScale = getInitialUiScale();
applyUiScale(initialUiScale);

function setUiScale(scale: number) {
  if (scale === state.uiScale) return;
  state.uiScale = scale;
  applyUiScale(scale);
  render();
}

/** Nearest ladder index to the current scale, so a value from an older build (or a hand-edited localStorage entry) still steps sensibly. */
function currentUiScaleIndex(): number {
  let nearest = 0;
  UI_SCALE_STEPS.forEach((step, i) => {
    if (Math.abs(step - state.uiScale) < Math.abs(UI_SCALE_STEPS[nearest] - state.uiScale)) nearest = i;
  });
  return nearest;
}

/** Cmd+Plus / Cmd+Minus: one step along the ladder, stopping at either end. */
function stepUiScale(delta: number) {
  const next = currentUiScaleIndex() + delta;
  if (next < 0 || next >= UI_SCALE_STEPS.length) return;
  setUiScale(UI_SCALE_STEPS[next]);
}

/** Cmd+0. */
function resetUiScale() {
  setUiScale(DEFAULT_UI_SCALE);
}

/** The "A" button: wraps around, so the whole ladder stays reachable by clicking alone. */
function cycleUiScale() {
  setUiScale(UI_SCALE_STEPS[(currentUiScaleIndex() + 1) % UI_SCALE_STEPS.length]);
}

// ---------------------------------------------------------------------------
// Time-series datasource override
//
// The backend auto-discovers a Prometheus/VictoriaMetrics Service per cluster
// by scoring Service names, which is a heuristic and can pick wrong — on a
// VictoriaMetrics k8s-stack cluster several scrape-target Services match the
// same name substrings as the real query endpoint. An override here wins
// outright and skips discovery entirely, so it also works on a cluster where
// discovery finds nothing at all.
//
// Keyed by kubeconfig context, since each cluster has its own backend.
// ---------------------------------------------------------------------------

const METRICS_BACKEND_STORAGE_KEY = "aks-dashboard-metrics-backends";

function loadMetricsBackendOverrides(): Map<string, MetricsBackendInfo> {
  try {
    const raw = localStorage.getItem(METRICS_BACKEND_STORAGE_KEY);
    if (!raw) return new Map();
    const parsed = JSON.parse(raw) as Record<string, MetricsBackendInfo>;
    return new Map(Object.entries(parsed));
  } catch {
    // A malformed entry (hand-edited, or written by an older build) shouldn't
    // stop the app from starting — fall back to pure auto-discovery.
    return new Map();
  }
}

function saveMetricsBackendOverrides() {
  localStorage.setItem(
    METRICS_BACKEND_STORAGE_KEY,
    JSON.stringify(Object.fromEntries(state.metricsBackendOverrides)),
  );
}

/** The override for a context, or null to let the backend auto-discover. */
function metricsBackendFor(ctx: string): MetricsBackendInfo | null {
  return state.metricsBackendOverrides.get(ctx) ?? null;
}

// ---------------------------------------------------------------------------
// Sidebar collapse
// ---------------------------------------------------------------------------

const SIDEBAR_COLLAPSED_STORAGE_KEY = "aks-dashboard-sidebar-collapsed";

function getInitialSidebarCollapsed(): boolean {
  return localStorage.getItem(SIDEBAR_COLLAPSED_STORAGE_KEY) === "true";
}

function toggleSidebar() {
  state.sidebarCollapsed = !state.sidebarCollapsed;
  localStorage.setItem(SIDEBAR_COLLAPSED_STORAGE_KEY, String(state.sidebarCollapsed));
  render();
}

// ---------------------------------------------------------------------------
// Table pagination
//
// Display-only, deliberately: `recordTableSnapshot` keeps recording the whole
// filtered set, so "select all" and "Copy to clipboard" still cover every
// matching row and not just the visible page. Paging that too would quietly
// cap an export at the page size, which is the opposite of what the tables
// are for.
// ---------------------------------------------------------------------------

const PAGE_SIZE_STORAGE_KEY = "aks-dashboard-page-size";
const PAGE_SIZE_OPTIONS = [50, 100, 200];
/** Derived rather than assuming `PAGE_SIZE_OPTIONS[0]`, so reordering the options for display can't silently move the visibility threshold. */
const MIN_PAGE_SIZE = Math.min(...PAGE_SIZE_OPTIONS);
const DEFAULT_PAGE_SIZE = 100;

function getInitialPageSize(): number {
  const stored = Number(localStorage.getItem(PAGE_SIZE_STORAGE_KEY));
  // Anything unrecognised (an older build's value, a hand-edited entry) falls
  // back rather than leaving a table stuck on a size the picker can't show.
  return PAGE_SIZE_OPTIONS.includes(stored) ? stored : DEFAULT_PAGE_SIZE;
}

function setPageSize(size: number) {
  if (!PAGE_SIZE_OPTIONS.includes(size)) return;
  state.pageSize = size;
  localStorage.setItem(PAGE_SIZE_STORAGE_KEY, String(size));
  // Page 3 of 50 and page 3 of 200 point at completely different rows, so
  // every table restarts rather than jumping somewhere arbitrary.
  state.tablePage = {};
  render();
}

/**
 * Total pages for `total` rows at the current page size.
 *
 * Floored at 1 so an empty table can't report 0 pages, which would clamp
 * `currentPage` to 0 and hand `pageSlice` a negative start offset. Nothing
 * renders it at that size — the control hides at or below `MIN_PAGE_SIZE` —
 * but the arithmetic still has to hold for callers that slice regardless.
 */
function pageCount(total: number): number {
  return Math.max(1, Math.ceil(total / state.pageSize));
}

/** The stored page clamped into range for `total` rows — a filter that shrinks the table can leave it past the end. Pure: never writes state mid-render. */
function currentPage(tab: TabId, total: number): number {
  return Math.min(Math.max(1, state.tablePage[tab] ?? 1), pageCount(total));
}

function setTablePage(tab: TabId, page: number) {
  state.tablePage[tab] = Math.max(1, page);
  render();
}

/** Back to page 1, for when the row set changes under the reader (a filter edit, say) and holding the old page would land them somewhere unrelated. */
function resetTablePage(tab: TabId) {
  delete state.tablePage[tab];
}

/** The slice of `rows` belonging to this tab's current page. */
function pageSlice<T>(tab: TabId, rows: T[]): T[] {
  const start = (currentPage(tab, rows.length) - 1) * state.pageSize;
  return rows.slice(start, start + state.pageSize);
}

/**
 * The page-size picker plus range readout and prev/next.
 *
 * Hidden entirely below the smallest page size: a table of 12 nodes can't be
 * paginated at any available setting, so the control would be dead chrome.
 */
function renderPagination(tab: TabId, total: number): string {
  if (total <= MIN_PAGE_SIZE) return "";
  const pages = pageCount(total);
  const page = currentPage(tab, total);
  const first = total === 0 ? 0 : (page - 1) * state.pageSize + 1;
  const last = Math.min(total, page * state.pageSize);

  const options = PAGE_SIZE_OPTIONS.map(
    (n) => `<option value="${n}" ${state.pageSize === n ? "selected" : ""}>${n} per page</option>`,
  ).join("");

  const step = (label: string, target: number, disabled: boolean, title: string) =>
    `<button type="button" title="${esc(title)}" ${disabled ? "disabled" : ""}
       onclick="window.__app.setTablePage(${jsArg(tab)}, ${target})"
       class="rounded border border-gridline px-2 py-1 ${
         disabled ? "cursor-default text-ink-muted opacity-40" : "text-ink-secondary hover:bg-surface-3 hover:text-ink-primary"
       }">${label}</button>`;

  return `
    <div class="mt-2 flex items-center justify-between text-xs text-ink-muted">
      <span class="tabular">${first}–${last} of ${total}</span>
      <span class="flex items-center gap-2">
        ${
          pages > 1
            ? `${step("‹", page - 1, page <= 1, "Previous page")}
               <span class="tabular">Page ${page} of ${pages}</span>
               ${step("›", page + 1, page >= pages, "Next page")}`
            : ""
        }
        <select onchange="window.__app.setPageSize(Number(this.value))"
                class="rounded border border-gridline bg-surface-2 px-1.5 py-1 text-xs text-ink-primary outline-none focus:border-series-blue">
          ${options}
        </select>
      </span>
    </div>`;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/**
 * The Graph tab's state, identical across the Pod, Node and Workload detail
 * panels — each of those interfaces extends this, which is what lets a single
 * `renderMetricsGraphView` serve all three.
 */
interface MetricsViewState {
  metrics: MetricsOverTimeResult | null;
  metricsLoading: boolean;
  metricsError: string | null;
  metricsRangeMinutes: number;
}

/** Every detail panel opens its Graph tab on this window. */
const DEFAULT_METRICS_RANGE_MINUTES = 60;

const EMPTY_METRICS_VIEW_STATE: MetricsViewState = {
  metrics: null,
  metricsLoading: false,
  metricsError: null,
  metricsRangeMinutes: DEFAULT_METRICS_RANGE_MINUTES,
};

interface PodDetailState extends MetricsViewState {
  ctx: string;
  namespace: string;
  name: string;
  view: "yaml" | "logs" | "graph";
  containers: string[];
  activeContainer: string;
  manifest: PodManifest | null;
  manifestError: string | null;
  showManagedFields: boolean;
  yamlSearch: string;
  /** Which match (0-based, in document order) is the "current" one — scrolled to and highlighted distinctly. */
  yamlSearchIndex: number;
  logMode: "head" | "tail";
  logLines: number;
  logText: string;
  logWrap: boolean;
  logSearch: string;
  logSearchIndex: number;
  logLoading: boolean;
  logError: string | null;
  following: boolean;
  /** Set once `start_pod_log_stream` resolves; `stop_pod_log_stream` needs it to cancel the right background task. */
  logStreamId: number | null;
}

interface NodeDetailState extends MetricsViewState {
  ctx: string;
  name: string;
  view: "yaml" | "events" | "graph";
  manifest: NodeManifest | null;
  manifestError: string | null;
  showManagedFields: boolean;
  yamlSearch: string;
  yamlSearchIndex: number;
  events: EventInfo[] | null;
  eventsError: string | null;
  eventsLoading: boolean;
}

interface WorkloadDetailState extends MetricsViewState {
  ctx: string;
  kind: string;
  namespace: string;
  name: string;
  view: "yaml" | "logs" | "events" | "graph" | "revisions";
  manifest: WorkloadManifest | null;
  manifestError: string | null;
  showManagedFields: boolean;
  yamlSearch: string;
  yamlSearchIndex: number;
  events: EventInfo[] | null;
  eventsError: string | null;
  eventsLoading: boolean;
  revisions: WorkloadRevisionInfo[] | null;
  revisionsError: string | null;
  revisionsLoading: boolean;
  /** Revision numbers picked for comparison, oldest selection first, at most two. */
  revisionCompare: number[];
  /** Pods owned by this workload, for the pod picker in the Logs tab — fetched lazily, once, the first time that tab is opened. */
  pods: string[] | null;
  podsError: string | null;
  podsLoading: boolean;
  activePod: string;
  /** From `manifest.containers` — same for every pod this workload owns, so there's no per-pod container fetch. */
  activeContainer: string;
  logMode: "head" | "tail";
  logLines: number;
  logText: string;
  logWrap: boolean;
  logSearch: string;
  logSearchIndex: number;
  logLoading: boolean;
  logError: string | null;
  following: boolean;
  logStreamId: number | null;
}

interface GitOpsDetailState {
  ctx: string;
  namespace: string;
  name: string;
  view: "yaml" | "events";
  manifest: GitOpsAppManifest | null;
  manifestError: string | null;
  showManagedFields: boolean;
  yamlSearch: string;
  yamlSearchIndex: number;
  events: EventInfo[] | null;
  eventsError: string | null;
  eventsLoading: boolean;
}

interface NapDetailState extends MetricsViewState {
  ctx: string;
  name: string;
  view: "yaml" | "events" | "graph";
  manifest: NapNodePoolManifest | null;
  manifestError: string | null;
  showManagedFields: boolean;
  yamlSearch: string;
  yamlSearchIndex: number;
  events: EventInfo[] | null;
  eventsError: string | null;
  eventsLoading: boolean;
}

interface HelmDetailState {
  ctx: string;
  namespace: string;
  name: string;
  revision: number;
  view: "values" | "manifest" | "notes";
  detail: HelmReleaseDetail | null;
  detailError: string | null;
  /** Values tab only: show the chart's defaults instead of the user's overrides. */
  showDefaultValues: boolean;
  search: string;
  searchIndex: number;
}

/** The "explain this error" panel: one error in, streamed prose out. */
interface ClaudeExplainState {
  /** The error text sent to Claude — shown verbatim so it's clear what left the machine. */
  errorText: string;
  /** Short label for the panel header, e.g. "apisix (Helm release)". */
  subject: string;
  /** Accumulated text deltas. */
  answer: string;
  streaming: boolean;
  error: string | null;
}

/**
 * Pod diagnosis. Unlike explain-error this sends logs, so it is a two-step
 * flow: assemble + preview the redacted payload, then send only on an explicit
 * confirmation.
 */
interface ClaudeDiagnoseState {
  ctx: string;
  namespace: string;
  podName: string;
  container: string;
  /** Assembled payload, or null while still being built. */
  payload: ClaudeDiagnosisPayload | null;
  /** True once the user has approved sending. */
  sent: boolean;
  /** Whether the assembled payload is expanded for review. */
  showPayload: boolean;
  answer: string;
  streaming: boolean;
  error: string | null;
}

interface AppState {
  theme: Theme;
  /** Root font-size as a percentage — scales the whole rem-based UI. One of `UI_SCALE_STEPS`. */
  uiScale: number;
  sidebarCollapsed: boolean;
  loadingClusters: boolean;
  clusterListError: string | null;
  kubeconfigPath: string | null;
  clusters: ClusterEntry[];
  /** Substring filter over the sidebar's cluster list (context/cluster name); purely a display filter, doesn't affect selection. */
  clusterFilter: string;
  selectedContexts: Set<string>;
  /** Contexts currently retrying a failed connection via the sidebar's Reconnect button. */
  reconnecting: Set<string>;
  /** Cmd+K cluster quick-switcher; null when closed. Toggling a cluster doesn't close it, so several can be picked in one go. */
  clusterPalette: { query: string; highlightedIndex: number } | null;
  activeTab: TabId;
  overviews: Map<string, ClusterOverview>;
  nodes: Map<string, NodeInfo[]>;
  pods: Map<string, PodInfo[]>;
  /**
   * Contexts where every page of a pods fetch has actually landed — NOT the
   * same as `pods.has(ctx)`, which goes true after just the first page of a
   * first load. Governs whether the next pods fetch for a context is
   * treated as a first load (progressive render, roll back on error) or a
   * refresh (silent accumulate, preserve stale data on error): a first load
   * interrupted after page one must still count as incomplete, or a later
   * failed refresh would silently and permanently freeze that partial page
   * as if it were the whole cluster.
   */
  podsLoadedComplete: Set<string>;
  workloads: Map<string, WorkloadInfo[]>;
  events: Map<string, EventInfo[]>;
  eventsWarningsOnly: boolean;
  nap: Map<string, NapResult>;
  keda: Map<string, KedaResult>;
  gitops: Map<string, GitOpsResult>;
  helm: Map<string, HelmReleaseInfo[]>;
  resourceUsage: Map<string, ResourceUsageSummary>;
  metricsOverTime: Map<string, MetricsOverTimeResult>;
  metricsRangeMinutes: number;
  /** Per-context datasource override; absent means auto-discover. */
  metricsBackendOverrides: Map<string, MetricsBackendInfo>;
  /** Context whose datasource editor is open, or null. */
  metricsBackendEditor: string | null;
  /** Candidates discovered for the editor's context, and the probe verdict. */
  metricsBackendCandidates: MetricsBackendInfo[] | null;
  metricsBackendDraft: MetricsBackendInfo | null;
  metricsBackendTest: MetricsBackendTestResult | null;
  metricsBackendTesting: boolean;
  claudeAuth: ClaudeAuthState | null;
  claudePanelOpen: boolean;
  claudeExplain: ClaudeExplainState | null;
  claudeDiagnose: ClaudeDiagnoseState | null;
  sortState: Partial<Record<TabId, SortSpec>>;
  filterState: Partial<Record<TabId, Partial<Record<string, ColumnFilterState>>>>;
  /** filterKey (`${tab}:${col.key}`) of the currently open enum-filter dropdown, or null. */
  openEnumFilter: string | null;
  /** User-resized column widths (px), per tab per column key. Unset columns fall back to `defaultColumnWidth`. */
  columnWidths: Partial<Record<TabId, Record<string, number>>>;
  /** Row keys checked for clipboard copy, per tab. */
  selectedRows: Partial<Record<TabId, Set<string>>>;
  /** How many rows each table shows at once. One global preference rather than per-tab, persisted across launches. */
  pageSize: number;
  /**
   * Current page per table, 1-based. Not persisted: a page number is only
   * meaningful against a particular row set, and both the data and the
   * filters are gone by the next launch. Absent means page 1, and readers
   * clamp it into range rather than writing back during a render.
   */
  tablePage: Partial<Record<TabId, number>>;
  /**
   * Keyboard row cursor per table, as an index into the rows currently
   * RENDERED in that table's `<tbody>` — not into the full filtered set.
   *
   * Indexing what's actually on screen keeps this free of any pagination
   * knowledge: six of the ten tables paginate and four don't, so an index
   * into the filtered set would need to know which is which and offset
   * accordingly — one more parallel list to forget to update. Undefined
   * until the reader first presses Up/Down, so no cursor is drawn before
   * then.
   */
  focusedRow: Partial<Record<TabId, number>>;
  /** When true for a tab, only unhealthy rows (the red status dot) are shown — nodes/pods/workloads. */
  unhealthyOnly: Partial<Record<TabId, boolean>>;
  /** Transient "Copied N rows" / "Copy failed" message, cleared after a couple seconds. */
  copyToast: string | null;
  tabError: string | null;
  /**
   * Source of truth behind `tabError`, one entry per context that failed the
   * current active tab's last fetch attempt. Reconnecting a single cluster
   * needs to update just that context's line without disturbing any other
   * selected cluster's still-valid error — a plain joined string can't do
   * that once it's been concatenated, so this stays structured and
   * `recomputeTabError` derives the display string from it.
   */
  tabErrorsByContext: Map<string, string>;
  tabLoading: boolean;
  /** Which of the selected clusters' fetches haven't settled yet for the tab currently loading, shrinking as each one resolves. */
  tabLoadProgress: { total: number; pending: Set<string> } | null;
  /** `Date.now()` when the current tab load started, so the loading view can show elapsed time. */
  tabLoadStartedAt: number | null;
  lastUpdated: Date | null;
  autoRefreshSeconds: number;
  podDetail: PodDetailState | null;
  nodeDetail: NodeDetailState | null;
  workloadDetail: WorkloadDetailState | null;
  gitOpsDetail: GitOpsDetailState | null;
  napDetail: NapDetailState | null;
  helmDetail: HelmDetailState | null;
}

const state: AppState = {
  theme: initialTheme,
  uiScale: initialUiScale,
  sidebarCollapsed: getInitialSidebarCollapsed(),
  loadingClusters: true,
  clusterListError: null,
  kubeconfigPath: null,
  clusters: [],
  clusterFilter: "",
  selectedContexts: new Set(),
  reconnecting: new Set(),
  clusterPalette: null,
  activeTab: "overview",
  overviews: new Map(),
  nodes: new Map(),
  pods: new Map(),
  podsLoadedComplete: new Set(),
  workloads: new Map(),
  events: new Map(),
  eventsWarningsOnly: true,
  nap: new Map(),
  keda: new Map(),
  gitops: new Map(),
  helm: new Map(),
  resourceUsage: new Map(),
  metricsOverTime: new Map(),
  metricsRangeMinutes: 60,
  metricsBackendOverrides: loadMetricsBackendOverrides(),
  metricsBackendEditor: null,
  metricsBackendCandidates: null,
  metricsBackendDraft: null,
  metricsBackendTest: null,
  metricsBackendTesting: false,
  claudeAuth: null,
  claudePanelOpen: false,
  claudeExplain: null,
  claudeDiagnose: null,
  sortState: {},
  filterState: {},
  openEnumFilter: null,
  columnWidths: {},
  selectedRows: {},
  pageSize: getInitialPageSize(),
  tablePage: {},
  focusedRow: {},
  unhealthyOnly: {},
  copyToast: null,
  tabError: null,
  tabErrorsByContext: new Map(),
  tabLoading: false,
  tabLoadProgress: null,
  tabLoadStartedAt: null,
  lastUpdated: null,
  autoRefreshSeconds: 30,
  podDetail: null,
  nodeDetail: null,
  workloadDetail: null,
  gitOpsDetail: null,
  napDetail: null,
  helmDetail: null,
};

let refreshTimer: number | undefined;
let requestGeneration = 0;
/** Bumped whenever the cluster selection changes, so a background prefetch loop targeting the old selection stops advancing (see `prefetchOtherTabsInBackground`). */
let backgroundPrefetchGeneration = 0;
/** Bumped on every open/close/switch of the pod detail panel, so a stale async fetch from a since-abandoned pod can't clobber the next one's state. */
let podDetailToken = 0;
/** Same idea as `podDetailToken`, for the node detail panel. */
let nodeDetailToken = 0;
/** Same idea as `podDetailToken`, for the workload detail panel. */
let workloadDetailToken = 0;
/** Same idea as `podDetailToken`, for the GitOps app detail panel. */
let gitOpsDetailToken = 0;
let napDetailToken = 0;
/** Same idea as `podDetailToken`, for the Helm release detail panel. */
let helmDetailToken = 0;
/** Bumped per explain request, so a stale stream can't append to a newer one. */
let claudeExplainToken = 0;
/** Same guard for the diagnosis stream. */
let claudeDiagnoseToken = 0;
/** rAF-batches streamed token appends, same as the log-follow path. */
let claudeRenderScheduled = false;
let logRenderScheduled = false;
/** rAF-batches the cluster palette's hover-driven re-renders, same idea as the log-follow path — a fast mouse sweep across several rows shouldn't force a full render() per row. */
let clusterPaletteHoverRenderScheduled = false;
/** Same idea for streamed pod pages: one repaint per frame, not one per arriving page. */
let podsStreamRenderScheduled = false;
/**
 * Set only by an explicit search action (typing a query, next/prev), so the
 * post-render scroll-to-current-match doesn't also fire on an unrelated
 * re-render (e.g. the auto-refresh timer) and yank the reader's scroll
 * position around — the same class of bug the YAML/log scroll-reset fixes
 * elsewhere in this file exist to avoid.
 */
let pendingSearchScroll = false;
/** Same idea as `pendingSearchScroll`, for the cluster palette's arrow-key navigation scrolling its highlighted row into view. */
let pendingClusterPaletteScroll = false;
/** Set when the row cursor moves, so the post-render pass scrolls it into view — but only then, never on an ordinary auto-refresh re-render. */
let pendingRowFocusScroll = false;
/**
 * `data-scroll-id` -> edge to snap a log view to on the next render, set
 * whenever fresh Head/Tail content just loaded: "bottom" for Tail, so the
 * most recent output is visible without scrolling down manually (the way a
 * terminal naturally ends up at the last line printed); "top" for Head, so
 * the earliest lines — the whole point of asking for the head — are what's
 * visible without scrolling up first. Consumed in `render()`, and only
 * removed once actually applied to a found element: the panel can open on
 * the YAML tab while logs prefetch silently in the background, so the log
 * `<pre>` may not exist in the DOM yet when its content first arrives, and
 * the pending scroll needs to survive until the Logs tab is actually shown.
 * Follow mode already pins to bottom on every render regardless, so this
 * only matters for a one-shot Head/Tail load.
 */
const pendingLogScroll = new Map<string, "top" | "bottom">();

// Re-renders once a second while a tab is loading, purely so the elapsed-time
// readout in the loading view ticks up — no state besides the clock changes.
// Only actually worth a render while that readout is the thing on screen
// (`renderLoadingState` only shows it pre-first-load, via the same
// `hasAnyDataForTab` check below); a background auto-refresh of an
// already-loaded tab leaves the existing table on screen untouched instead,
// so ticking on every one of its seconds would just be redrawing everything
// else in the app — including any open pod detail panel — for nothing.
let loadingTicker: number | undefined;

function startLoadingTicker() {
  if (loadingTicker !== undefined) return;
  loadingTicker = window.setInterval(() => {
    if (!state.tabLoading) {
      stopLoadingTicker();
    } else if (!hasAnyDataForTab()) {
      render();
    }
  }, 1000);
}

function stopLoadingTicker() {
  if (loadingTicker === undefined) return;
  window.clearInterval(loadingTicker);
  loadingTicker = undefined;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function esc(s: string | null | undefined): string {
  if (s === null || s === undefined) return "";
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/**
 * A value safe to splice into an inline event-handler attribute as a JS
 * string-literal argument, e.g. `onclick="fn(${jsArg(x)})"`.
 *
 * `esc()` alone is not enough here even though it escapes quotes: HTML
 * entities are decoded back to literal characters *before* the browser parses
 * the attribute text as JS, so an `esc()`-escaped quote reappears as a real
 * `'` in the JS source and can terminate the string literal early — a classic
 * mixed-context escaping bug, not a hypothetical one. `JSON.stringify`
 * produces a complete JS string literal (quotes, backslashes and control
 * characters all escaped); `esc()` on top of that only neutralizes the outer
 * HTML attribute delimiter, and round-trips cleanly since JSON's escapes are
 * plain backslash sequences that HTML has no reason to alter.
 */
function jsArg(value: string): string {
  return esc(JSON.stringify(value));
}

// ---------------------------------------------------------------------------
// Column sorting
//
// Each table defines its columns as a `value(row)` accessor returning either
// a number or a string. Numeric and enum-like columns (health, phase, kind)
// return a number — a raw metric or a rank in a defined order — so they
// compare numerically; free-text columns return a string and compare via
// localeCompare. The comparator picks based on the runtime type, so callers
// never have to declare a column "type" separately from its accessor.
// ---------------------------------------------------------------------------

type SortDirection = "asc" | "desc";

interface SortSpec {
  column: string;
  direction: SortDirection;
}

/// How a column's values compare (sorting) and how the user narrows them
/// down (filtering): "number" gets a numeric min/max range, "enum" gets a
/// single-select dropdown built from the values actually present, "string"
/// gets a substring search box.
type ColumnFilterType = "string" | "number" | "enum";

interface ColumnDef<T> {
  key: string;
  label: string;
  value: (row: T) => string | number;
  /** Omit for columns not worth filtering (e.g. a derived timestamp). */
  filter?: ColumnFilterType;
  /**
   * Text used when copying rows to the clipboard, if it differs from
   * `value` — e.g. a column whose cell pairs two formatted numbers
   * ("1.20 cores / 3.80 cores") while `value` returns just the raw usage
   * for sorting. Defaults to `String(value(row))`.
   */
  copyText?: (row: T) => string;
  /**
   * Sort key, if it needs finer granularity than `value` — e.g. pod age is
   * filtered in whole days (`value`) but sorted by exact seconds so that
   * two pods both under a day old don't tie. Defaults to `value`.
   */
  sortValue?: (row: T) => string | number;
}

interface ColumnFilterState {
  text?: string;
  min?: number;
  max?: number;
  enumValues?: Set<string>;
}

function setSort(tab: TabId, column: string) {
  const current = state.sortState[tab];
  state.sortState[tab] =
    current && current.column === column
      ? { column, direction: current.direction === "asc" ? "desc" : "asc" }
      : { column, direction: "asc" };
  render();
}

function sortRows<T>(tab: TabId, rows: T[], columns: ColumnDef<T>[]): T[] {
  const spec = state.sortState[tab];
  if (!spec) return rows;
  const column = columns.find((c) => c.key === spec.column);
  if (!column) return rows;
  const sorted = [...rows];
  sorted.sort((a, b) => {
    const va = (column.sortValue ?? column.value)(a);
    const vb = (column.sortValue ?? column.value)(b);
    const cmp = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
    return spec.direction === "asc" ? cmp : -cmp;
  });
  return sorted;
}

function sortableHeaderRow<T>(tab: TabId, columns: ColumnDef<T>[]): string {
  const spec = state.sortState[tab];
  return columns
    .map((c) => {
      const indicator = spec && spec.column === c.key ? (spec.direction === "asc" ? " ▲" : " ▼") : "";
      return `
        <th class="relative cursor-pointer select-none hover:text-ink-secondary" onclick="window.__app.setSort(${jsArg(tab)},${jsArg(c.key)})">
          <span class="block truncate pr-2">${esc(c.label)}${indicator}</span>
          <span
            onmousedown="event.stopPropagation(); window.__app.startColumnResize(event,${jsArg(tab)},${jsArg(c.key)})"
            onclick="event.stopPropagation()"
            title="Drag to resize"
            class="absolute right-0 top-0 h-full w-2 cursor-col-resize select-none hover:bg-series-blue/50"
          ></span>
        </th>`;
    })
    .join("");
}

// ---------------------------------------------------------------------------
// Column widths
//
// Tables use `table-layout: fixed` with an explicit `<colgroup>` so a
// column's width holds steady across the header/filter/body rows and is
// user-resizable regardless of cell content. Columns without a stored width
// fall back to a per-kind default; the drag itself (`startColumnResize`)
// mutates the live `<col>` elements directly rather than going through
// state+render() on every mousemove, since a full re-render per pixel of
// drag would be visibly janky.
// ---------------------------------------------------------------------------

const MIN_COLUMN_WIDTH = 60;

function defaultColumnWidth<T>(col: ColumnDef<T>): number {
  if (col.key === "message") return 320;
  if (col.key === "name" || col.key === "object" || col.key === "cluster") return 200;
  // A number filter is two side-by-side inputs (min/max), each with a native
  // spinner control eating into its content box. This width (matching the
  // general fallback below) was previously overridden to a narrower value
  // for number-filter columns specifically, which clipped the "min"/"max"
  // placeholder text down to an unreadable sliver — confirmed by rendering
  // the actual filter-cell markup against the app's compiled CSS and
  // measuring it, not just eyeballed. See PR #5 for the numbers.
  return 150;
}

function columnWidth<T>(tab: TabId, col: ColumnDef<T>): number {
  return state.columnWidths[tab]?.[col.key] ?? defaultColumnWidth(col);
}

/** `leadingWidths` covers any unlabeled columns before `columns` (e.g. the status-dot column). */
function renderColGroup<T>(tab: TabId, columns: ColumnDef<T>[], leadingWidths: number[] = []): string {
  const leading = leadingWidths.map((w) => `<col style="width:${w}px">`).join("");
  const cols = columns
    .map((c) => `<col data-col-width="${tab}:${esc(c.key)}" style="width:${columnWidth(tab, c)}px">`)
    .join("");
  return `<colgroup>${leading}${cols}</colgroup>`;
}

interface ColumnResizeDrag {
  tab: TabId;
  key: string;
  startX: number;
  startWidth: number;
  width: number;
}

let columnResizeDrag: ColumnResizeDrag | null = null;

function startColumnResize(e: MouseEvent, tab: TabId, key: string) {
  e.preventDefault();
  const th = (e.target as HTMLElement).closest("th");
  if (!th) return;
  columnResizeDrag = { tab, key, startX: e.clientX, startWidth: th.getBoundingClientRect().width, width: th.getBoundingClientRect().width };
  document.body.style.cursor = "col-resize";
  document.body.style.userSelect = "none";
}

document.addEventListener("mousemove", (e) => {
  if (!columnResizeDrag) return;
  const drag = columnResizeDrag;
  drag.width = Math.max(MIN_COLUMN_WIDTH, Math.round(drag.startWidth + (e.clientX - drag.startX)));
  document.querySelectorAll<HTMLElement>(`col[data-col-width="${drag.tab}:${drag.key}"]`).forEach((col) => {
    col.style.width = `${drag.width}px`;
  });
});

document.addEventListener("mouseup", () => {
  if (!columnResizeDrag) return;
  const { tab, key, width } = columnResizeDrag;
  (state.columnWidths[tab] ??= {})[key] = width;
  columnResizeDrag = null;
  document.body.style.cursor = "";
  document.body.style.userSelect = "";
  render();
});

// ---------------------------------------------------------------------------
// Row selection & clipboard copy
//
// Each table's render pass calls `recordTableSnapshot` with the exact
// filtered+sorted rows it's about to display and a per-row key, so
// `copySelectedRows` can build clipboard text (tab-separated, so it pastes
// cleanly into a spreadsheet) purely from that snapshot — it never needs to
// recompute a table's columns/rows/filters itself.
// ---------------------------------------------------------------------------

interface TableSnapshot {
  headers: string[];
  rows: [key: string, cells: string[]][];
}

const tableSnapshots: Partial<Record<TabId, TableSnapshot>> = {};

/** `leading` covers a synthetic first column with no `ColumnDef` of its own (e.g. the status-dot column's text equivalent, "Ready"/"Not ready"). */
function recordTableSnapshot<T>(
  tab: TabId,
  columns: ColumnDef<T>[],
  rows: T[],
  keyOf: (row: T) => string,
  leading?: { header: string; text: (row: T) => string },
) {
  const headers = [...(leading ? [leading.header] : []), ...columns.map((c) => c.label)];
  const rows_: [string, string[]][] = rows.map((row) => [
    keyOf(row),
    [
      ...(leading ? [leading.text(row)] : []),
      ...columns.map((c) => (c.copyText ? c.copyText(row) : String(c.value(row)))),
    ],
  ]);
  tableSnapshots[tab] = { headers, rows: rows_ };
}

function rowSelection(tab: TabId): Set<string> {
  return state.selectedRows[tab] ?? (state.selectedRows[tab] = new Set());
}

function toggleRowSelected(tab: TabId, key: string, checked: boolean) {
  const sel = rowSelection(tab);
  if (checked) sel.add(key);
  else sel.delete(key);
  render();
}

function toggleAllRowsSelected(tab: TabId, checked: boolean) {
  const sel = rowSelection(tab);
  if (checked) {
    for (const [key] of tableSnapshots[tab]?.rows ?? []) sel.add(key);
  } else {
    sel.clear();
  }
  render();
}

function clearRowSelection(tab: TabId) {
  rowSelection(tab).clear();
  render();
}

function showCopyToast(message: string) {
  state.copyToast = message;
  render();
  window.setTimeout(() => {
    if (state.copyToast === message) {
      state.copyToast = null;
      render();
    }
  }, 1800);
}

/**
 * A plain, inline-styled `<table>` — rich-text editors (MS Teams, Outlook,
 * Word, Excel) render this as a real table on paste, since they read the
 * clipboard's `text/html` entry rather than its `text/plain` one. Styles are
 * inlined (no CSS classes/vars) because the pasted markup is copied out of
 * this document entirely, into a target that has no idea what `--gridline`
 * or `.data-table` mean.
 */
function buildClipboardHtmlTable(headers: string[], rows: string[][]): string {
  const cellStyle = "border:1px solid #999999;padding:4px 8px;text-align:left;";
  const thead = `<tr>${headers.map((h) => `<th style="${cellStyle}background:#f2f2f2;font-weight:600;">${esc(h)}</th>`).join("")}</tr>`;
  const tbody = rows
    .map((cells) => `<tr>${cells.map((c) => `<td style="${cellStyle}">${esc(c)}</td>`).join("")}</tr>`)
    .join("");
  return `<table style="border-collapse:collapse;">${`<thead>${thead}</thead><tbody>${tbody}</tbody>`}</table>`;
}

/** Tab-separated plain text, for targets that only read `text/plain` (still pastes fine into a spreadsheet). */
function buildClipboardPlainText(headers: string[], rows: string[][]): string {
  return [headers.join("\t"), ...rows.map((r) => r.join("\t"))].join("\n");
}

/** Plain-text-only clipboard write, with a hidden-textarea fallback for webview contexts that don't grant the async Clipboard API by default. */
async function copyPlainTextToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      const ok = document.execCommand("copy");
      textarea.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

async function copyTableToClipboard(headers: string[], rows: string[][]): Promise<boolean> {
  const text = buildClipboardPlainText(headers, rows);

  if (typeof ClipboardItem !== "undefined" && navigator.clipboard?.write) {
    try {
      const html = buildClipboardHtmlTable(headers, rows);
      await navigator.clipboard.write([
        new ClipboardItem({
          "text/plain": new Blob([text], { type: "text/plain" }),
          "text/html": new Blob([html], { type: "text/html" }),
        }),
      ]);
      return true;
    } catch {
      // Fall through to the plain-text path below — e.g. Safari/WKWebView
      // versions that support `clipboard.writeText` but not multi-type
      // `clipboard.write`, or a webview that denies it outright.
    }
  }

  return copyPlainTextToClipboard(text);
}

/** Copies the current text of a YAML/Log `<pre>`, identified by its (already-unique) `data-scroll-id`, to the clipboard. Reads live DOM text rather than re-deriving it, so it always matches exactly what's on screen — highlighting spans and all, stripped back down to plain text. */
async function copyPreToClipboard(scrollId: string) {
  const el = document.querySelector(`[data-scroll-id="${scrollId}"]`);
  const text = el instanceof HTMLElement ? (el.textContent ?? "") : "";
  const ok = await copyPlainTextToClipboard(text);
  showCopyToast(ok ? "Copied to clipboard" : "Copy failed");
}

/** Small "Copy" button shared by every YAML/Log view, wired to the `<pre>` with a matching `data-scroll-id`. */
function renderCopyButton(scrollId: string): string {
  return `
    <button
      type="button"
      title="Copy to clipboard"
      onclick="window.__app.copyPreToClipboard(${jsArg(scrollId)})"
      class="rounded px-2 py-1 text-xs text-ink-secondary hover:bg-surface-3 hover:text-ink-primary"
    >Copy</button>`;
}

async function copySelectedRows(tab: TabId) {
  const snap = tableSnapshots[tab];
  const sel = rowSelection(tab);
  if (!snap || sel.size === 0) return;
  const chosen = snap.rows.filter(([key]) => sel.has(key));
  const ok = await copyTableToClipboard(snap.headers, chosen.map(([, cells]) => cells));
  showCopyToast(ok ? `Copied ${chosen.length} row${chosen.length === 1 ? "" : "s"} to clipboard` : "Copy failed");
}

function toggleUnhealthyOnly(tab: TabId) {
  state.unhealthyOnly[tab] = !state.unhealthyOnly[tab];
  resetTablePage(tab);
  render();
}

/** A "red dot" toggle for the tables whose health is derived client-side (nodes/pods/workloads) rather than fetched separately like `eventsWarningsOnly`. */
function unhealthyOnlyToggle(tab: TabId): string {
  const checked = !!state.unhealthyOnly[tab];
  return `
    <label class="flex items-center gap-2 text-xs text-ink-secondary">
      <input type="checkbox" ${checked ? "checked" : ""} onchange="window.__app.toggleUnhealthyOnly(${jsArg(tab)})" />
      <span class="flex items-center gap-1.5">${statusDot(false)} Unhealthy only</span>
    </label>`;
}

function selectionToolbar(tab: TabId): string {
  const count = rowSelection(tab).size;
  if (count === 0) return "";
  return `
    <div class="mb-2 flex items-center justify-between rounded-md border border-gridline bg-surface-2 px-3 py-1.5 text-xs text-ink-secondary">
      <span>${count} row${count === 1 ? "" : "s"} selected</span>
      <span class="flex items-center gap-3">
        <button onclick="window.__app.copySelectedRows(${jsArg(tab)})" class="font-medium text-ink-primary hover:underline">Copy to clipboard</button>
        <button onclick="window.__app.clearRowSelection(${jsArg(tab)})" class="hover:text-ink-primary hover:underline">Clear</button>
      </span>
    </div>`;
}

function selectAllCheckboxHeader<T>(tab: TabId, rows: T[], keyOf: (row: T) => string): string {
  const sel = rowSelection(tab);
  const allSelected = rows.length > 0 && rows.every((r) => sel.has(keyOf(r)));
  return `
    <th>
      <input type="checkbox" class="accent-series-blue" title="Select all" ${allSelected ? "checked" : ""}
             onchange="window.__app.toggleAllRowsSelected(${jsArg(tab)}, this.checked)" />
    </th>`;
}

function rowCheckboxCell(tab: TabId, key: string): string {
  const checked = rowSelection(tab).has(key);
  // `data-row-key` is what the keyboard selection shortcuts read to identify a
  // row. Living on this one shared helper means all ten tables get it without
  // ten separate edits — and without the shortcuts having to map a cursor's
  // on-screen index back through pagination to a row identity.
  return `
    <td>
      <input type="checkbox" class="accent-series-blue" data-row-key="${esc(key)}" ${checked ? "checked" : ""}
             onchange="window.__app.toggleRowSelected(${jsArg(tab)},${jsArg(key)}, this.checked)" />
    </td>`;
}

function copyToastBanner(): string {
  if (!state.copyToast) return "";
  return `<div class="fixed bottom-5 right-5 z-30 rounded-md border border-gridline bg-surface-3 px-3 py-2 text-xs text-ink-primary shadow-lg">${esc(state.copyToast)}</div>`;
}

function tabFilters(tab: TabId): Partial<Record<string, ColumnFilterState>> {
  return state.filterState[tab] ?? (state.filterState[tab] = {});
}

function hasActiveFilters(tab: TabId): boolean {
  return Object.values(state.filterState[tab] ?? {}).some(
    (f) => f && (f.text || f.min !== undefined || f.max !== undefined || (f.enumValues && f.enumValues.size > 0)),
  );
}

function setStringFilter(tab: TabId, key: string, text: string) {
  tabFilters(tab)[key] = { ...tabFilters(tab)[key], text: text || undefined };
  resetTablePage(tab);
  render();
}

function setNumberFilter(tab: TabId, key: string, bound: "min" | "max", raw: string) {
  const parsed = Number(raw);
  // An in-progress value like "-" or "" parses to NaN/is empty; treat both as
  // "no bound yet" rather than storing NaN, which would otherwise round-trip
  // back into the input's rendered value as the literal text "NaN".
  const value = raw !== "" && Number.isFinite(parsed) ? parsed : undefined;
  tabFilters(tab)[key] = { ...tabFilters(tab)[key], [bound]: value };
  resetTablePage(tab);
  render();
}

function setEnumFilter(tab: TabId, key: string, values: string[]) {
  tabFilters(tab)[key] = { ...tabFilters(tab)[key], enumValues: values.length > 0 ? new Set(values) : undefined };
  resetTablePage(tab);
  render();
}

function toggleEnumFilterValue(tab: TabId, key: string, value: string, checked: boolean) {
  const next = new Set(tabFilters(tab)[key]?.enumValues ?? []);
  if (checked) next.add(value);
  else next.delete(value);
  setEnumFilter(tab, key, Array.from(next));
}

function toggleEnumDropdown(filterKey: string) {
  state.openEnumFilter = state.openEnumFilter === filterKey ? null : filterKey;
  render();
}

function closeEnumDropdown() {
  if (state.openEnumFilter === null) return;
  state.openEnumFilter = null;
  render();
}

function clearFilters(tab: TabId) {
  state.filterState[tab] = {};
  resetTablePage(tab);
  render();
}

function applyFilters<T>(tab: TabId, rows: T[], columns: ColumnDef<T>[]): T[] {
  const filters = state.filterState[tab];
  if (!filters) return rows;
  return rows.filter((row) =>
    columns.every((col) => {
      const f = filters[col.key];
      if (!f) return true;
      const v = col.value(row);
      switch (col.filter) {
        case "number": {
          const num = typeof v === "number" ? v : Number(v);
          if (f.min !== undefined && !(num >= f.min)) return false;
          if (f.max !== undefined && !(num <= f.max)) return false;
          return true;
        }
        case "enum":
          return !f.enumValues || f.enumValues.size === 0 || f.enumValues.has(String(v));
        case "string":
        default:
          return !f.text || String(v).toLowerCase().includes(f.text.toLowerCase());
      }
    }),
  );
}

const FILTER_INPUT_CLASS =
  "w-full min-w-0 rounded border border-gridline bg-surface-2 px-1.5 py-1 text-xs normal-case text-ink-primary outline-none focus:border-series-blue";

function filterRowCells<T>(tab: TabId, columns: ColumnDef<T>[], allRows: T[]): string {
  return columns
    .map((col) => {
      const current = tabFilters(tab)[col.key];
      const filterKey = `${tab}:${col.key}`;

      if (!col.filter) {
        return `<th></th>`;
      }

      if (col.filter === "number") {
        return `
          <th>
            <div class="flex gap-1">
              <input type="number" placeholder="min" value="${current?.min ?? ""}" data-filter-key="${filterKey}:min"
                     oninput="window.__app.setNumberFilter(${jsArg(tab)},${jsArg(col.key)},'min',this.value)" class="${FILTER_INPUT_CLASS}" />
              <input type="number" placeholder="max" value="${current?.max ?? ""}" data-filter-key="${filterKey}:max"
                     oninput="window.__app.setNumberFilter(${jsArg(tab)},${jsArg(col.key)},'max',this.value)" class="${FILTER_INPUT_CLASS}" />
            </div>
          </th>`;
      }

      if (col.filter === "enum") {
        const distinct = Array.from(new Set(allRows.map((r) => String(col.value(r))))).sort((a, b) =>
          a.localeCompare(b),
        );
        const selected = current?.enumValues;
        const isOpen = state.openEnumFilter === filterKey;
        const summary =
          !selected || selected.size === 0
            ? "All"
            : selected.size === 1
              ? Array.from(selected)[0] || "(none)"
              : `${selected.size} selected`;
        return `
          <th>
            <div class="relative" data-enum-dropdown="${filterKey}">
              <button
                type="button"
                data-filter-key="${filterKey}"
                title="Filter by ${esc(col.label)}; empty selection shows all"
                onclick="window.__app.toggleEnumDropdown(${jsArg(filterKey)})"
                class="${FILTER_INPUT_CLASS} flex items-center justify-between gap-1 text-left"
              >
                <span class="truncate">${esc(summary)}</span>
                <svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="currentColor" stroke-width="2" class="shrink-0"><polyline points="6 9 12 15 18 9"/></svg>
              </button>
              ${
                isOpen
                  ? `
                <div class="fixed z-20 max-h-56 w-48 overflow-auto rounded-md border border-gridline bg-surface-2 py-1 shadow-lg" data-scroll-id="enum-dropdown:${filterKey}" data-enum-dropdown-panel="${filterKey}">
                  <div class="flex items-center justify-end border-b border-gridline px-2 pb-1.5 mb-0.5 text-[11px] normal-case">
                    <button type="button" onclick="window.__app.setEnumFilter(${jsArg(tab)},${jsArg(col.key)}, [])" class="text-ink-secondary hover:text-ink-primary hover:underline">Clear</button>
                  </div>
                  ${distinct
                    .map(
                      (v) => `
                    <label class="flex cursor-pointer items-center gap-2 px-2 py-1 text-xs normal-case text-ink-primary hover:bg-surface-3">
                      <input
                        type="checkbox"
                        value="${esc(v)}"
                        class="accent-series-blue"
                        ${selected?.has(v) ? "checked" : ""}
                        onchange="window.__app.toggleEnumFilterValue(${jsArg(tab)},${jsArg(col.key)}, this.value, this.checked)"
                      />
                      <span class="truncate">${esc(v) || "(none)"}</span>
                    </label>`,
                    )
                    .join("")}
                </div>`
                  : ""
              }
            </div>
          </th>`;
      }

      return `
        <th>
          <input type="text" placeholder="Filter…" value="${esc(current?.text ?? "")}" data-filter-key="${filterKey}"
                 oninput="window.__app.setStringFilter(${jsArg(tab)},${jsArg(col.key)}, this.value)" class="${FILTER_INPUT_CLASS}" />
        </th>`;
    })
    .join("");
}

function filterSummary(tab: TabId, totalCount: number, filteredCount: number): string {
  if (!hasActiveFilters(tab)) return "";
  return `
    <div class="mb-2 flex items-center justify-between text-xs text-ink-muted">
      <span>Showing ${filteredCount} of ${totalCount}</span>
      <button onclick="window.__app.clearFilters(${jsArg(tab)})" class="text-ink-secondary hover:text-ink-primary hover:underline">Clear filters</button>
    </div>`;
}

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "nodes", label: "Nodes" },
  { id: "workloads", label: "Workloads" },
  { id: "pods", label: "Pods" },
  { id: "resources", label: "Resource Usage" },
  { id: "metrics", label: "Metrics" },
  { id: "events", label: "Events" },
  { id: "nap", label: "NAP" },
  { id: "keda", label: "KEDA" },
  { id: "gitops", label: "GitOps" },
  { id: "helm", label: "Helm" },
  { id: "cost", label: "Cost" },
];

function statusDot(healthy: boolean | undefined, unknown = false): string {
  const color = unknown ? "bg-ink-muted" : healthy ? "bg-status-good" : "bg-status-critical";
  return `<span class="inline-block h-2 w-2 rounded-full ${color}"></span>`;
}

function selectedContextsList(): string[] {
  return state.clusters.filter((c) => state.selectedContexts.has(c.context_name)).map((c) => c.context_name);
}

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

async function init() {
  render();
  try {
    state.kubeconfigPath = await api.kubeconfigPath();
    state.clusters = await api.listClusters();
    state.loadingClusters = false;
    if (state.clusters.length > 0) {
      state.selectedContexts.add(state.clusters[0].context_name);
      refreshSidebarBadges();
      loadTabData();
    }
  } catch (e) {
    state.loadingClusters = false;
    state.clusterListError = String(e);
  }
  render();
  scheduleAutoRefresh();
  // Probed once at startup so the Claude affordances know whether to offer
  // an explain button or a sign-in prompt.
  refreshClaudeAuth();
}

async function refreshSidebarBadges() {
  // The badges render straight out of `state.overviews`, which the overview
  // tab's own load already fills — and every caller here pairs this with
  // `loadTabData()`. Fetching again on that tab would just double the API
  // calls (and the connections behind them) per cluster per refresh tick.
  if (state.activeTab === "overview") return;

  for (const ctx of selectedContextsList()) {
    api
      .getOverview(ctx)
      .then((ov) => {
        state.overviews.set(ctx, ov);
        render();
      })
      .catch(() => {
        /* badge stays "unknown" */
      });
  }
}

/** Fetches one tab's data for one cluster and stores it in the matching cache Map — the one place that knows which API call backs which tab, shared by the foreground loader and the background prefetcher below. */
async function fetchTabDataForContext(tab: TabId, ctx: string): Promise<void> {
  switch (tab) {
    case "overview":
      state.overviews.set(ctx, await api.getOverview(ctx));
      break;
    case "nodes":
      state.nodes.set(ctx, await api.getNodes(ctx));
      break;
    case "workloads":
      state.workloads.set(ctx, await api.getWorkloads(ctx));
      break;
    case "pods": {
      // Paged rather than one getPods() await: on a thousand-plus-pod
      // cluster, replacing the whole table only once everything has arrived
      // means the first row takes as long to appear as the last one does.
      //
      // Only shown page-by-page on a genuinely first load, though. "First
      // load" is tracked by podsLoadedComplete, NOT by whether state.pods
      // already has an entry — a first load that gets interrupted after
      // page one still leaves state.pods non-empty, and on a slow/flaky
      // cluster (one real fetch here took 82s against this app's own 30s
      // auto-refresh interval, so overlapping attempts are the norm, not
      // the exception) every later refresh attempt can keep failing
      // without ever re-completing. If "first load" were keyed off
      // state.pods.has(ctx), that single page-one write would permanently
      // pass every future attempt through the refresh path below — which
      // preserves stale data on failure by design — freezing that one
      // partial page forever with nothing to ever mark it incomplete again.
      // On a genuine refresh of confirmed-complete data, there's already a
      // complete table on screen, very possibly filtered down to a handful
      // of rows; replacing it with just page one and growing from there
      // means matching rows visibly vanish and reappear as later pages
      // land, which reads as pods flickering in and out rather than a
      // smoother load — so refreshes still stay atomic: accumulate locally
      // and commit once.
      const isFirstLoad = !state.podsLoadedComplete.has(ctx);
      // Streamed pages drive the first-load preview only. What finally gets
      // committed is streamPods' RESOLVED VALUE, the backend's own complete
      // list — see api.streamPods for why summing the pages here instead
      // would deterministically drop the last one.
      const preview: PodInfo[] = [];
      let pods: PodInfo[] = [];
      try {
        pods = await api.streamPods(ctx, undefined, (page) => {
          // The preview exists only to get rows on screen during a first
          // load. A refresh already has a full table up and commits the
          // return value atomically at the end, so there's nothing to
          // accumulate for — bail before doing the work at all.
          if (!isFirstLoad) return;
          // Appended in place rather than `preview = preview.concat(page)`:
          // concat copies the whole accumulated array per page, which is
          // quadratic across a many-page cluster. Pushed element-wise rather
          // than spread, so this stays correct if POD_PAGE_SIZE is ever
          // raised past the argument-count ceiling a spread would hit.
          for (const pod of page) preview.push(pod);
          state.pods.set(ctx, preview);
          // rAF-batched: render() rebuilds the whole app's innerHTML, and
          // on a multi-thousand-pod cluster each rebuild is already the
          // most expensive thing on the main thread. Pages can land within
          // a few hundred ms of each other, so coalesce to at most one
          // repaint per frame rather than one per page.
          schedulePodsStreamRender();
        });
      } catch (e) {
        // A failure partway through a first load can leave state.pods
        // holding whichever pages already arrived — indistinguishable from a
        // genuinely complete list, so a later refresh would treat it as
        // done and never retry the rest. Roll back to "no data" (the same
        // state a first-load failure left before pagination existed) so the
        // next attempt is a real first load again, not a refresh of a
        // partial cache.
        //
        // Only if this attempt is still the last writer, though: auto-refresh
        // doesn't wait for a slow context's previous attempt to finish before
        // starting another, so an older first-load attempt can still be
        // failing after a newer, faster one already completed and marked
        // podsLoadedComplete. Deleting unconditionally would then wipe out
        // that newer, already-confirmed-complete result out from under it.
        // preview !== state.pods.get(ctx) means someone else has already
        // written over this attempt's own progress.
        if (isFirstLoad && state.pods.get(ctx) === preview) state.pods.delete(ctx);
        throw e;
      }
      // Committed unconditionally, first load or refresh: the preview written
      // during streaming is by definition missing at least the final page.
      state.pods.set(ctx, pods);
      // Only reached once every page has actually arrived without throwing
      // — this, not the presence of any data, is what "first load done"
      // means from here on.
      state.podsLoadedComplete.add(ctx);
      break;
    }
    case "resources":
      state.resourceUsage.set(ctx, await api.getResourceUsage(ctx));
      break;
    case "metrics":
      state.metricsOverTime.set(ctx, await api.getMetricsOverTime(ctx, state.metricsRangeMinutes, metricsBackendFor(ctx)));
      break;
    case "events":
      state.events.set(ctx, await api.getEvents(ctx, state.eventsWarningsOnly));
      break;
    case "nap":
      state.nap.set(ctx, await api.getNapNodePools(ctx));
      break;
    case "keda":
      state.keda.set(ctx, await api.getKedaScaledObjects(ctx));
      break;
    case "gitops":
      state.gitops.set(ctx, await api.getGitOpsApps(ctx));
      break;
    case "helm":
      state.helm.set(ctx, await api.getHelmReleases(ctx));
      break;
    case "cost":
      break;
  }
}

function tabHasDataForContext(tab: TabId, ctx: string): boolean {
  switch (tab) {
    case "overview":
      return state.overviews.has(ctx);
    case "nodes":
      return state.nodes.has(ctx);
    case "workloads":
      return state.workloads.has(ctx);
    case "pods":
      return state.pods.has(ctx);
    case "resources":
      return state.resourceUsage.has(ctx);
    case "metrics":
      return state.metricsOverTime.has(ctx);
    case "events":
      return state.events.has(ctx);
    case "nap":
      return state.nap.has(ctx);
    case "keda":
      return state.keda.has(ctx);
    case "gitops":
      return state.gitops.has(ctx);
    case "helm":
      return state.helm.has(ctx);
    case "cost":
      return true;
  }
}

/**
 * Rebuilds `state.tabError` (the string the error banner actually renders)
 * from `state.tabErrorsByContext`. A single failing cluster is shown bare
 * when it's the only one selected, since there's nothing to disambiguate;
 * with more than one selected, every line is prefixed with its context even
 * if only one of them currently has an error, so it's clear which cluster it
 * is without having to cross-reference the sidebar.
 */
function recomputeTabError() {
  if (state.tabErrorsByContext.size === 0) {
    state.tabError = null;
    return;
  }
  const multi = state.selectedContexts.size > 1;
  state.tabError = [...state.tabErrorsByContext.entries()].map(([ctx, msg]) => (multi ? `${ctx}: ${msg}` : msg)).join("\n");
}

/**
 * Retries one cluster's connection from the sidebar's Reconnect button,
 * without disturbing any other selected cluster's already-good data — unlike
 * `loadTabData()`, which re-fetches the whole current selection.
 *
 * Refreshes the overview (so the sidebar dot/badge updates) and, if some
 * other tab is active, that tab's data for this context too — reconnecting
 * should mean "this cluster's data comes back", not just "the dot turns
 * green while the table stays empty until the next auto-refresh".
 */
async function reconnectCluster(contextName: string) {
  if (state.reconnecting.has(contextName)) return;
  state.reconnecting.add(contextName);
  render();

  try {
    state.overviews.set(contextName, await api.getOverview(contextName));
  } catch {
    // get_cluster_overview reports a failure in-band (reachable: false)
    // rather than rejecting; a rejection here means the IPC call itself
    // failed, which leaves the previous overview in place — still better
    // than discarding a last-known-good status over a one-off glitch.
  }

  if (state.activeTab !== "overview") {
    try {
      await fetchTabDataForContext(state.activeTab, contextName);
      state.tabErrorsByContext.delete(contextName);
    } catch (e) {
      state.tabErrorsByContext.set(contextName, String(e));
    }
    recomputeTabError();
  }

  state.reconnecting.delete(contextName);
  render();
}

async function loadTabData() {
  const ctxs = selectedContextsList();
  const gen = ++requestGeneration;
  if (ctxs.length === 0) {
    state.tabLoading = false;
    state.tabLoadProgress = null;
    stopLoadingTicker();
    render();
    return;
  }
  state.tabLoading = true;
  state.tabErrorsByContext.clear();
  state.tabError = null;
  state.tabLoadProgress = { total: ctxs.length, pending: new Set(ctxs) };
  state.tabLoadStartedAt = Date.now();
  startLoadingTicker();
  render();

  const fetchOne = async (ctx: string) => {
    try {
      await fetchTabDataForContext(state.activeTab, ctx);
      state.tabErrorsByContext.delete(ctx);
    } catch (e) {
      state.tabErrorsByContext.set(ctx, String(e));
    } finally {
      // Reflects real per-cluster completion (not a simulated/animated
      // fill), so it stays honest even when one cluster is much slower
      // than the rest — a fast cluster's fetch settling before a slow
      // one's doesn't just wait around silently.
      if (gen === requestGeneration && state.tabLoadProgress) {
        state.tabLoadProgress.pending.delete(ctx);
        render();
      }
    }
  };

  await Promise.all(ctxs.map(fetchOne));

  if (gen !== requestGeneration) return;
  recomputeTabError();
  state.lastUpdated = new Date();
  state.tabLoading = false;
  state.tabLoadProgress = null;
  state.tabLoadStartedAt = null;
  stopLoadingTicker();
  render();

  // Quietly warm the other tabs' caches for the current selection so
  // switching to one of them later doesn't hit an empty cache and show a
  // loading spinner — see `prefetchOtherTabsInBackground` for how this stays
  // cheap once everything is warm and backs off when the selection changes.
  prefetchOtherTabsInBackground();
}

/**
 * Fetches every *other* tab's data for the current cluster selection, one
 * (tab, cluster) pair at a time, skipping anything already cached — so a
 * first visit to a tab (or a fresh cluster selection) doesn't have to wait on
 * a cold cache. Deliberately sequential rather than fanned out: this is
 * low-priority background work competing with whatever the user is actually
 * looking at, not another thing to race against a flaky cluster connection.
 *
 * Safe to call after every `loadTabData()` completion (not just the first):
 * once a tab is warm, `tabHasDataForContext` short-circuits the whole loop
 * with no network calls, so the steady-state cost is just a cheap scan.
 * `backgroundPrefetchGeneration` is bumped on cluster-selection changes so a
 * loop targeting an old selection stops advancing (already-issued requests
 * still complete and populate the cache — cheap to let finish, not worth
 * cancelling).
 */
async function prefetchOtherTabsInBackground() {
  const myGeneration = ++backgroundPrefetchGeneration;
  const ctxs = selectedContextsList();
  if (ctxs.length === 0) return;

  const otherTabs = TABS.map((t) => t.id).filter((id) => id !== "cost" && id !== state.activeTab);

  for (const tab of otherTabs) {
    for (const ctx of ctxs) {
      if (myGeneration !== backgroundPrefetchGeneration) return;
      if (tabHasDataForContext(tab, ctx)) continue;
      // A cluster already known unreachable would otherwise get hit with a
      // fresh ~60s-timeout attempt per tab, every auto-refresh tick, purely
      // in the background — skip it until its overview says otherwise.
      if (state.overviews.get(ctx)?.reachable === false) continue;
      try {
        await fetchTabDataForContext(tab, ctx);
      } catch {
        // Best-effort: the tab will just fetch normally (and show its own
        // error) if the user switches to it before this succeeds.
      }
      if (myGeneration === backgroundPrefetchGeneration) render();
    }
  }
}

function scheduleAutoRefresh() {
  if (refreshTimer) window.clearInterval(refreshTimer);
  if (state.autoRefreshSeconds <= 0) return;
  refreshTimer = window.setInterval(() => {
    loadTabData();
    refreshSidebarBadges();
  }, state.autoRefreshSeconds * 1000);
}

// ---------------------------------------------------------------------------
// Event handlers (exposed on window for simple delegated onclick handlers)
// ---------------------------------------------------------------------------

function setClusterFilter(text: string) {
  state.clusterFilter = text;
  render();
}

function toggleCluster(contextName: string) {
  backgroundPrefetchGeneration++; // stop any prefetch loop still targeting the old selection
  if (state.selectedContexts.has(contextName)) {
    state.selectedContexts.delete(contextName);
  } else {
    state.selectedContexts.add(contextName);
  }
  render();
  loadTabData();
  refreshSidebarBadges();
}

function selectAllClusters() {
  backgroundPrefetchGeneration++;
  for (const c of state.clusters) state.selectedContexts.add(c.context_name);
  render();
  loadTabData();
  refreshSidebarBadges();
}

function clearClusterSelection() {
  backgroundPrefetchGeneration++;
  state.selectedContexts.clear();
  render();
  loadTabData();
}

/** Clusters matching the palette's current query — shared by the render and the keyboard-nav bounds so they can't disagree on what's "visible". */
function clusterPaletteVisible(): ClusterEntry[] {
  const query = state.clusterPalette?.query.trim().toLowerCase();
  if (!query) return state.clusters;
  return state.clusters.filter((c) => c.context_name.toLowerCase().includes(query) || c.cluster_name.toLowerCase().includes(query));
}

function openClusterPalette() {
  state.clusterPalette = { query: "", highlightedIndex: 0 };
  render();
}

function closeClusterPalette() {
  state.clusterPalette = null;
  render();
}

function setClusterPaletteQuery(query: string) {
  if (!state.clusterPalette) return;
  state.clusterPalette.query = query;
  // The old index may no longer correspond to anything, or even be in range,
  // once the query narrows the list — simplest correct behavior is to reset
  // to the top match, same as most quick-switchers do on every keystroke.
  state.clusterPalette.highlightedIndex = 0;
  render();
}

function moveClusterPaletteHighlight(delta: number) {
  const palette = state.clusterPalette;
  if (!palette) return;
  const visible = clusterPaletteVisible();
  if (visible.length === 0) return;
  palette.highlightedIndex = Math.max(0, Math.min(visible.length - 1, palette.highlightedIndex + delta));
  pendingClusterPaletteScroll = true;
  render();
}

/** Mouse hover takes over the highlight rather than drawing its own separate hover state, so there's only ever one highlighted row, whether it got there by keyboard or mouse. */
function setClusterPaletteHighlight(index: number) {
  const palette = state.clusterPalette;
  if (!palette || palette.highlightedIndex === index) return;
  palette.highlightedIndex = index;
  // render() rebuilds the whole app's innerHTML, not just the palette; a
  // fast mouse sweep can fire mouseenter once per row in a handful of
  // milliseconds, so batch those into at most one render per frame instead
  // of one full-app rebuild per row crossed. highlightedIndex itself is
  // still updated synchronously above, so click/Enter always act on the
  // current row even before the next paint.
  if (clusterPaletteHoverRenderScheduled) return;
  clusterPaletteHoverRenderScheduled = true;
  requestAnimationFrame(() => {
    clusterPaletteHoverRenderScheduled = false;
    render();
  });
}

/** Toggles the highlighted cluster without closing the palette, so several can be picked in one session. */
function toggleClusterPaletteHighlighted() {
  const palette = state.clusterPalette;
  if (!palette) return;
  const c = clusterPaletteVisible()[palette.highlightedIndex];
  if (c) toggleCluster(c.context_name);
}

interface ViewSnapshot {
  tab: TabId;
  podsFilter: Partial<Record<string, ColumnFilterState>> | undefined;
  podsUnhealthyOnly: boolean | undefined;
}

/**
 * Browser-style paired navigation stacks. `back` is pushed by every
 * navigation (`pushViewHistory`); stepping back moves the current view onto
 * `forward` and vice versa, so Cmd+Left / Cmd+Right can walk the same trail
 * in both directions. A fresh navigation discards `forward`, matching what a
 * browser does when you follow a new link after going back.
 */
const viewHistory: { back: ViewSnapshot[]; forward: ViewSnapshot[] } = { back: [], forward: [] };

function cloneColumnFilterRecord(
  rec: Partial<Record<string, ColumnFilterState>> | undefined,
): Partial<Record<string, ColumnFilterState>> | undefined {
  if (!rec) return undefined;
  const clone: Partial<Record<string, ColumnFilterState>> = {};
  for (const [key, value] of Object.entries(rec)) {
    if (!value) continue;
    clone[key] = { ...value, enumValues: value.enumValues ? new Set(value.enumValues) : undefined };
  }
  return clone;
}

/**
 * The current tab plus whatever pods-tab filter/unhealthy state a drill-down
 * (`viewPodsForWorkload`/`viewPodsForNode`) is about to clobber — the only
 * state any navigation function in this file mutates besides `activeTab`. A
 * plain tab switch's pods fields just get written back unchanged, so this one
 * snapshot shape covers both cases.
 */
function currentViewSnapshot(): ViewSnapshot {
  return {
    tab: state.activeTab,
    podsFilter: cloneColumnFilterRecord(state.filterState.pods),
    podsUnhealthyOnly: state.unhealthyOnly.pods,
  };
}

function applyViewSnapshot(snapshot: ViewSnapshot) {
  state.activeTab = snapshot.tab;
  state.filterState.pods = snapshot.podsFilter;
  state.unhealthyOnly.pods = snapshot.podsUnhealthyOnly;
  render();
  loadTabData();
}

/** Called by every function that changes `state.activeTab`, right before it does so. */
function pushViewHistory() {
  viewHistory.back.push(currentViewSnapshot());
  // Navigating somewhere new abandons the forward trail, as in a browser.
  viewHistory.forward.length = 0;
}

/** Cmd+Left. No-op at the start of history. */
function goBackView() {
  const previous = viewHistory.back.pop();
  if (!previous) return;
  viewHistory.forward.push(currentViewSnapshot());
  applyViewSnapshot(previous);
}

/** Cmd+Right. No-op unless a `goBackView` has left something to return to. */
function goForwardView() {
  const next = viewHistory.forward.pop();
  if (!next) return;
  viewHistory.back.push(currentViewSnapshot());
  applyViewSnapshot(next);
}

function selectTab(tab: TabId) {
  if (state.activeTab === tab) return;
  pushViewHistory();
  state.activeTab = tab;
  render();
  loadTabData();
}

/** Drill down from a Workloads row into its pods, pre-filtered to just that workload. */
function viewPodsForWorkload(ctx: string, kind: string, namespace: string, name: string) {
  pushViewHistory();
  state.filterState.pods = {
    cluster: { enumValues: new Set([ctx]) },
    namespace: { enumValues: new Set([namespace]) },
    owner: { enumValues: new Set([`${kind}/${name}`]) },
  };
  state.unhealthyOnly.pods = false;
  state.activeTab = "pods";
  render();
  loadTabData();
}

/** Drill down from a Nodes row into its pods, pre-filtered to just that node. */
function viewPodsForNode(ctx: string, nodeName: string) {
  pushViewHistory();
  state.filterState.pods = {
    cluster: { enumValues: new Set([ctx]) },
    node: { enumValues: new Set([nodeName]) },
  };
  state.unhealthyOnly.pods = false;
  state.activeTab = "pods";
  render();
  loadTabData();
}

/** Drill down from a NAP row into the nodes it actually provisioned. */
function viewNodesForNodePool(ctx: string, poolName: string) {
  pushViewHistory();
  state.filterState.nodes = {
    cluster: { enumValues: new Set([ctx]) },
    node_pool: { enumValues: new Set([poolName]) },
  };
  state.unhealthyOnly.nodes = false;
  state.activeTab = "nodes";
  render();
  loadTabData();
}

// ---------------------------------------------------------------------------
// Node detail panel (YAML / Events)
// ---------------------------------------------------------------------------

function openNodeDetail(ctx: string, name: string) {
  closePodDetail();
  closeWorkloadDetail();
  closeGitOpsDetail();
  closeHelmDetail();
  closeNapDetail();
  const token = ++nodeDetailToken;
  state.nodeDetail = {
    ctx,
    name,
    view: "yaml",
    manifest: null,
    manifestError: null,
    showManagedFields: false,
    yamlSearch: "",
    yamlSearchIndex: 0,
    events: null,
    eventsError: null,
    eventsLoading: false,
    ...EMPTY_METRICS_VIEW_STATE,
  };
  render();

  api
    .getNodeManifest(ctx, name)
    .then((manifest) => {
      if (token !== nodeDetailToken || !state.nodeDetail) return;
      state.nodeDetail.manifest = manifest;
      render();
    })
    .catch((e) => {
      if (token !== nodeDetailToken || !state.nodeDetail) return;
      state.nodeDetail.manifestError = String(e);
      render();
    });
}

function closeNodeDetail() {
  nodeDetailToken += 1;
  state.nodeDetail = null;
  render();
}

function setNodeDetailView(view: NodeDetailState["view"]) {
  if (!state.nodeDetail) return;
  state.nodeDetail.view = view;
  render();
  if (view === "events" && !state.nodeDetail.events && !state.nodeDetail.eventsLoading) {
    fetchNodeEvents();
  }
  if (view === "graph" && !state.nodeDetail.metrics && !state.nodeDetail.metricsLoading) {
    fetchNodeMetrics();
  }
}

function setNodeMetricsRange(minutes: number) {
  if (!state.nodeDetail) return;
  state.nodeDetail.metricsRangeMinutes = minutes;
  render();
  fetchNodeMetrics();
}

async function fetchNodeMetrics() {
  const nd = state.nodeDetail;
  if (!nd) return;
  const token = nodeDetailToken;
  nd.metricsLoading = true;
  nd.metricsError = null;
  render();
  try {
    const result = await api.getNodeMetricsOverTime(nd.ctx, nd.name, nd.metricsRangeMinutes, metricsBackendFor(nd.ctx));
    if (token !== nodeDetailToken || !state.nodeDetail) return;
    state.nodeDetail.metrics = result;
  } catch (e) {
    if (token !== nodeDetailToken || !state.nodeDetail) return;
    state.nodeDetail.metricsError = String(e);
  } finally {
    if (token === nodeDetailToken && state.nodeDetail) state.nodeDetail.metricsLoading = false;
    render();
  }
}

function toggleNodeManagedFields() {
  if (!state.nodeDetail) return;
  state.nodeDetail.showManagedFields = !state.nodeDetail.showManagedFields;
  render();
}

async function fetchNodeEvents() {
  const nd = state.nodeDetail;
  if (!nd) return;
  const token = nodeDetailToken;
  nd.eventsLoading = true;
  nd.eventsError = null;
  render();
  try {
    const events = await api.getNodeEvents(nd.ctx, nd.name);
    if (token !== nodeDetailToken || !state.nodeDetail) return;
    state.nodeDetail.events = events;
  } catch (e) {
    if (token !== nodeDetailToken || !state.nodeDetail) return;
    state.nodeDetail.eventsError = String(e);
  } finally {
    if (token === nodeDetailToken && state.nodeDetail) state.nodeDetail.eventsLoading = false;
    render();
  }
}

/** The YAML text currently on screen — whichever of the two cached variants the toggle selects. */
function currentNodeYamlText(nd: NodeDetailState): string {
  if (!nd.manifest) return "";
  return nd.showManagedFields ? nd.manifest.yaml_full : nd.manifest.yaml_without_managed_fields;
}

function setNodeSearch(_view: string, query: string) {
  if (!state.nodeDetail) return;
  state.nodeDetail.yamlSearch = query;
  state.nodeDetail.yamlSearchIndex = 0;
  pendingSearchScroll = true;
  render();
}

function moveNodeSearch(_view: string, delta: number) {
  const nd = state.nodeDetail;
  if (!nd || !nd.yamlSearch) return;
  const count = countSearchMatches(currentNodeYamlText(nd), nd.yamlSearch);
  if (count === 0) return;
  nd.yamlSearchIndex = (((nd.yamlSearchIndex + delta) % count) + count) % count;
  pendingSearchScroll = true;
  render();
}

// ---------------------------------------------------------------------------
// Helm release detail panel (Values / Manifest / Notes)
// ---------------------------------------------------------------------------

function openHelmDetail(ctx: string, namespace: string, name: string, revision: number) {
  closePodDetail();
  closeNodeDetail();
  closeWorkloadDetail();
  closeGitOpsDetail();
  closeNapDetail();
  const token = ++helmDetailToken;
  state.helmDetail = {
    ctx,
    namespace,
    name,
    revision,
    view: "values",
    detail: null,
    detailError: null,
    showDefaultValues: false,
    search: "",
    searchIndex: 0,
  };
  render();

  // One fetch covers all three tabs: they're separate fields of the same
  // decoded release payload, so splitting them would mean re-fetching and
  // re-gunzipping the same Secret per tab.
  api
    .getHelmReleaseDetail(ctx, namespace, name, revision)
    .then((detail) => {
      if (token !== helmDetailToken || !state.helmDetail) return;
      state.helmDetail.detail = detail;
      render();
    })
    .catch((e) => {
      if (token !== helmDetailToken || !state.helmDetail) return;
      state.helmDetail.detailError = String(e);
      render();
    });
}

function closeHelmDetail() {
  helmDetailToken += 1;
  state.helmDetail = null;
  render();
}

function setHelmDetailView(view: HelmDetailState["view"]) {
  if (!state.helmDetail) return;
  state.helmDetail.view = view;
  // Each tab is a different document, so a query carried over from the last
  // one would report match counts against text that is no longer on screen.
  state.helmDetail.search = "";
  state.helmDetail.searchIndex = 0;
  render();
}

function toggleHelmDefaultValues() {
  if (!state.helmDetail) return;
  state.helmDetail.showDefaultValues = !state.helmDetail.showDefaultValues;
  state.helmDetail.searchIndex = 0;
  render();
}

/** The text on screen for the active tab — what search and copy operate over. */
function currentHelmText(hd: HelmDetailState): string {
  if (!hd.detail) return "";
  switch (hd.view) {
    case "values":
      return hd.showDefaultValues ? hd.detail.default_values_yaml : hd.detail.values_yaml;
    case "manifest":
      return hd.detail.manifest;
    case "notes":
      return hd.detail.notes;
  }
}

function setHelmSearch(_view: string, query: string) {
  if (!state.helmDetail) return;
  state.helmDetail.search = query;
  state.helmDetail.searchIndex = 0;
  pendingSearchScroll = true;
  render();
}

function moveHelmSearch(_view: string, delta: number) {
  const hd = state.helmDetail;
  if (!hd || !hd.search) return;
  const count = countSearchMatches(currentHelmText(hd), hd.search);
  if (count === 0) return;
  hd.searchIndex = (((hd.searchIndex + delta) % count) + count) % count;
  pendingSearchScroll = true;
  render();
}

// ---------------------------------------------------------------------------
// GitOps app detail panel (YAML / Events)
// ---------------------------------------------------------------------------

function openGitOpsDetail(ctx: string, namespace: string, name: string) {
  closePodDetail();
  closeNodeDetail();
  closeWorkloadDetail();
  closeHelmDetail();
  closeNapDetail();
  const token = ++gitOpsDetailToken;
  state.gitOpsDetail = {
    ctx,
    namespace,
    name,
    view: "yaml",
    manifest: null,
    manifestError: null,
    showManagedFields: false,
    yamlSearch: "",
    yamlSearchIndex: 0,
    events: null,
    eventsError: null,
    eventsLoading: false,
  };
  render();

  api
    .getGitOpsManifest(ctx, namespace, name)
    .then((manifest) => {
      if (token !== gitOpsDetailToken || !state.gitOpsDetail) return;
      state.gitOpsDetail.manifest = manifest;
      render();
    })
    .catch((e) => {
      if (token !== gitOpsDetailToken || !state.gitOpsDetail) return;
      state.gitOpsDetail.manifestError = String(e);
      render();
    });
}

function closeGitOpsDetail() {
  gitOpsDetailToken += 1;
  state.gitOpsDetail = null;
  render();
}

function setGitOpsDetailView(view: GitOpsDetailState["view"]) {
  if (!state.gitOpsDetail) return;
  state.gitOpsDetail.view = view;
  render();
  if (view === "events" && !state.gitOpsDetail.events && !state.gitOpsDetail.eventsLoading) {
    fetchGitOpsEvents();
  }
}

function toggleGitOpsManagedFields() {
  if (!state.gitOpsDetail) return;
  state.gitOpsDetail.showManagedFields = !state.gitOpsDetail.showManagedFields;
  render();
}

async function fetchGitOpsEvents() {
  const gd = state.gitOpsDetail;
  if (!gd) return;
  const token = gitOpsDetailToken;
  gd.eventsLoading = true;
  gd.eventsError = null;
  render();
  try {
    const events = await api.getGitOpsEvents(gd.ctx, gd.namespace, gd.name);
    if (token !== gitOpsDetailToken || !state.gitOpsDetail) return;
    state.gitOpsDetail.events = events;
  } catch (e) {
    if (token !== gitOpsDetailToken || !state.gitOpsDetail) return;
    state.gitOpsDetail.eventsError = String(e);
  } finally {
    if (token === gitOpsDetailToken && state.gitOpsDetail) state.gitOpsDetail.eventsLoading = false;
    render();
  }
}

/** The YAML text currently on screen — whichever of the two cached variants the toggle selects. */
function currentGitOpsYamlText(gd: GitOpsDetailState): string {
  if (!gd.manifest) return "";
  return gd.showManagedFields ? gd.manifest.yaml_full : gd.manifest.yaml_without_managed_fields;
}

function setGitOpsSearch(_view: string, query: string) {
  if (!state.gitOpsDetail) return;
  state.gitOpsDetail.yamlSearch = query;
  state.gitOpsDetail.yamlSearchIndex = 0;
  pendingSearchScroll = true;
  render();
}

function moveGitOpsSearch(_view: string, delta: number) {
  const gd = state.gitOpsDetail;
  if (!gd || !gd.yamlSearch) return;
  const count = countSearchMatches(currentGitOpsYamlText(gd), gd.yamlSearch);
  if (count === 0) return;
  gd.yamlSearchIndex = (((gd.yamlSearchIndex + delta) % count) + count) % count;
  pendingSearchScroll = true;
  render();
}

// ---------------------------------------------------------------------------
// NAP node pool detail panel (YAML / Events / Graph)
// ---------------------------------------------------------------------------

function openNapDetail(ctx: string, name: string) {
  closePodDetail();
  closeNodeDetail();
  closeWorkloadDetail();
  closeGitOpsDetail();
  closeHelmDetail();
  const token = ++napDetailToken;
  state.napDetail = {
    ctx,
    name,
    view: "yaml",
    manifest: null,
    manifestError: null,
    showManagedFields: false,
    yamlSearch: "",
    yamlSearchIndex: 0,
    events: null,
    eventsError: null,
    eventsLoading: false,
    ...EMPTY_METRICS_VIEW_STATE,
  };
  render();

  api
    .getNapNodePoolManifest(ctx, name)
    .then((manifest) => {
      if (token !== napDetailToken || !state.napDetail) return;
      state.napDetail.manifest = manifest;
      render();
    })
    .catch((e) => {
      if (token !== napDetailToken || !state.napDetail) return;
      state.napDetail.manifestError = String(e);
      render();
    });
}

function closeNapDetail() {
  napDetailToken += 1;
  state.napDetail = null;
  render();
}

function setNapDetailView(view: NapDetailState["view"]) {
  if (!state.napDetail) return;
  state.napDetail.view = view;
  render();
  if (view === "events" && !state.napDetail.events && !state.napDetail.eventsLoading) {
    fetchNapEvents();
  }
  if (view === "graph" && !state.napDetail.metrics && !state.napDetail.metricsLoading) {
    fetchNapMetrics();
  }
}

function setNapMetricsRange(minutes: number) {
  if (!state.napDetail) return;
  state.napDetail.metricsRangeMinutes = minutes;
  render();
  fetchNapMetrics();
}

async function fetchNapEvents() {
  const nd = state.napDetail;
  if (!nd) return;
  const token = napDetailToken;
  nd.eventsLoading = true;
  nd.eventsError = null;
  render();
  try {
    const events = await api.getNapNodePoolEvents(nd.ctx, nd.name);
    if (token !== napDetailToken || !state.napDetail) return;
    state.napDetail.events = events;
  } catch (e) {
    if (token !== napDetailToken || !state.napDetail) return;
    state.napDetail.eventsError = String(e);
  } finally {
    if (token === napDetailToken && state.napDetail) state.napDetail.eventsLoading = false;
    render();
  }
}

async function fetchNapMetrics() {
  const nd = state.napDetail;
  if (!nd) return;
  const token = napDetailToken;
  nd.metricsLoading = true;
  nd.metricsError = null;
  render();
  try {
    const result = await api.getNapNodePoolMetricsOverTime(nd.ctx, nd.name, nd.metricsRangeMinutes, metricsBackendFor(nd.ctx));
    if (token !== napDetailToken || !state.napDetail) return;
    state.napDetail.metrics = result;
  } catch (e) {
    if (token !== napDetailToken || !state.napDetail) return;
    state.napDetail.metricsError = String(e);
  } finally {
    if (token === napDetailToken && state.napDetail) state.napDetail.metricsLoading = false;
    render();
  }
}

function toggleNapManagedFields() {
  if (!state.napDetail) return;
  state.napDetail.showManagedFields = !state.napDetail.showManagedFields;
  render();
}

/** The YAML text currently on screen — whichever of the two cached variants the toggle selects. */
function currentNapYamlText(nd: NapDetailState): string {
  if (!nd.manifest) return "";
  return nd.showManagedFields ? nd.manifest.yaml_full : nd.manifest.yaml_without_managed_fields;
}

function setNapSearch(_view: string, query: string) {
  if (!state.napDetail) return;
  state.napDetail.yamlSearch = query;
  state.napDetail.yamlSearchIndex = 0;
  pendingSearchScroll = true;
  render();
}

function moveNapSearch(_view: string, delta: number) {
  const nd = state.napDetail;
  if (!nd || !nd.yamlSearch) return;
  const count = countSearchMatches(currentNapYamlText(nd), nd.yamlSearch);
  if (count === 0) return;
  nd.yamlSearchIndex = (((nd.yamlSearchIndex + delta) % count) + count) % count;
  pendingSearchScroll = true;
  render();
}

// ---------------------------------------------------------------------------
// Workload detail panel (YAML / Events)
// ---------------------------------------------------------------------------

function openWorkloadDetail(ctx: string, kind: string, namespace: string, name: string) {
  closePodDetail();
  closeNodeDetail();
  closeGitOpsDetail();
  closeHelmDetail();
  closeNapDetail();
  stopWorkloadLogFollow();
  const token = ++workloadDetailToken;
  state.workloadDetail = {
    ctx,
    kind,
    namespace,
    name,
    view: "yaml",
    manifest: null,
    manifestError: null,
    showManagedFields: false,
    yamlSearch: "",
    yamlSearchIndex: 0,
    events: null,
    eventsError: null,
    eventsLoading: false,
    pods: null,
    podsError: null,
    revisions: null,
    revisionsError: null,
    revisionsLoading: false,
    revisionCompare: [],
    podsLoading: false,
    activePod: "",
    activeContainer: "",
    logMode: "tail",
    logLines: 100,
    logText: "",
    logWrap: true,
    logSearch: "",
    logSearchIndex: 0,
    logLoading: false,
    logError: null,
    following: false,
    logStreamId: null,
    ...EMPTY_METRICS_VIEW_STATE,
  };
  render();

  api
    .getWorkloadManifest(ctx, kind, namespace, name)
    .then((manifest) => {
      if (token !== workloadDetailToken || !state.workloadDetail) return;
      state.workloadDetail.manifest = manifest;
      state.workloadDetail.activeContainer = manifest.containers[0] ?? "";
      render();
      maybeStartWorkloadLogs();
    })
    .catch((e) => {
      if (token !== workloadDetailToken || !state.workloadDetail) return;
      state.workloadDetail.manifestError = String(e);
      render();
    });
}

function closeWorkloadDetail() {
  stopWorkloadLogFollow();
  workloadDetailToken += 1;
  state.workloadDetail = null;
  render();
}

function setWorkloadDetailView(view: WorkloadDetailState["view"]) {
  if (!state.workloadDetail) return;
  state.workloadDetail.view = view;
  render();
  if (view === "events" && !state.workloadDetail.events && !state.workloadDetail.eventsLoading) {
    fetchWorkloadEvents();
  }
  if (view === "logs") {
    if (state.workloadDetail.pods === null && !state.workloadDetail.podsLoading) fetchWorkloadPods();
    else maybeStartWorkloadLogs();
  }
  if (view === "graph" && !state.workloadDetail.metrics && !state.workloadDetail.metricsLoading) {
    fetchWorkloadMetrics();
  }
  if (view === "revisions" && !state.workloadDetail.revisions && !state.workloadDetail.revisionsLoading) {
    fetchWorkloadRevisions();
  }
}

/**
 * Toggles a revision into or out of the comparison. Adding a third drops the
 * oldest selection rather than refusing, so switching what you're comparing
 * never needs an unchecking step first.
 */
function toggleWorkloadRevisionCompare(revision: number) {
  const wd = state.workloadDetail;
  if (!wd) return;
  const picked = wd.revisionCompare.filter((r) => r !== revision);
  if (picked.length === wd.revisionCompare.length) {
    picked.push(revision);
    if (picked.length > 2) picked.shift();
  }
  wd.revisionCompare = picked;
  render();
}

async function fetchWorkloadRevisions() {
  const wd = state.workloadDetail;
  if (!wd) return;
  const token = workloadDetailToken;
  wd.revisionsLoading = true;
  wd.revisionsError = null;
  render();
  try {
    const revisions = await api.getWorkloadRevisions(wd.ctx, wd.kind, wd.namespace, wd.name);
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.revisions = revisions;
    // Preselect the two newest so "what changed in the last rollout?" — the
    // question a revision list is usually opened to answer — is already shown.
    // `revisions` arrives newest-first, so [1] is the previous revision.
    state.workloadDetail.revisionCompare = revisions.slice(0, 2).map((r) => r.revision).reverse();
  } catch (e) {
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.revisionsError = String(e);
  } finally {
    if (token === workloadDetailToken && state.workloadDetail) state.workloadDetail.revisionsLoading = false;
    render();
  }
}

function setWorkloadMetricsRange(minutes: number) {
  if (!state.workloadDetail) return;
  state.workloadDetail.metricsRangeMinutes = minutes;
  render();
  fetchWorkloadMetrics();
}

async function fetchWorkloadMetrics() {
  const wd = state.workloadDetail;
  if (!wd) return;
  const token = workloadDetailToken;
  wd.metricsLoading = true;
  wd.metricsError = null;
  render();
  try {
    const result = await api.getWorkloadMetricsOverTime(wd.ctx, wd.kind, wd.namespace, wd.name, wd.metricsRangeMinutes, metricsBackendFor(wd.ctx));
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.metrics = result;
  } catch (e) {
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.metricsError = String(e);
  } finally {
    if (token === workloadDetailToken && state.workloadDetail) state.workloadDetail.metricsLoading = false;
    render();
  }
}

function toggleWorkloadManagedFields() {
  if (!state.workloadDetail) return;
  state.workloadDetail.showManagedFields = !state.workloadDetail.showManagedFields;
  render();
}

async function fetchWorkloadEvents() {
  const wd = state.workloadDetail;
  if (!wd) return;
  const token = workloadDetailToken;
  wd.eventsLoading = true;
  wd.eventsError = null;
  render();
  try {
    const events = await api.getWorkloadEvents(wd.ctx, wd.kind, wd.namespace, wd.name);
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.events = events;
  } catch (e) {
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.eventsError = String(e);
  } finally {
    if (token === workloadDetailToken && state.workloadDetail) state.workloadDetail.eventsLoading = false;
    render();
  }
}

/** The YAML text currently on screen — whichever of the two cached variants the toggle selects. */
function currentWorkloadYamlText(wd: WorkloadDetailState): string {
  if (!wd.manifest) return "";
  return wd.showManagedFields ? wd.manifest.yaml_full : wd.manifest.yaml_without_managed_fields;
}

function setWorkloadSearch(view: "yaml" | "logs", query: string) {
  if (!state.workloadDetail) return;
  if (view === "yaml") {
    state.workloadDetail.yamlSearch = query;
    state.workloadDetail.yamlSearchIndex = 0;
  } else {
    state.workloadDetail.logSearch = query;
    state.workloadDetail.logSearchIndex = 0;
  }
  pendingSearchScroll = true;
  render();
}

function moveWorkloadSearch(view: "yaml" | "logs", delta: number) {
  const wd = state.workloadDetail;
  if (!wd) return;
  const query = view === "yaml" ? wd.yamlSearch : wd.logSearch;
  if (!query) return;
  const text = view === "yaml" ? currentWorkloadYamlText(wd) : wd.logText;
  const count = countSearchMatches(text, query);
  if (count === 0) return;
  const current = view === "yaml" ? wd.yamlSearchIndex : wd.logSearchIndex;
  const next = (((current + delta) % count) + count) % count;
  if (view === "yaml") wd.yamlSearchIndex = next;
  else wd.logSearchIndex = next;
  pendingSearchScroll = true;
  render();
}

/** Pods owned by this workload (via `PodInfo.owner_kind`/`owner_name`, already resolved server-side) — scoped to the workload's own namespace rather than a full cluster-wide pod list. */
/** Sentinel `activePod` value meaning "merge logs from every pod this workload owns", rather than one specific pod. Default, since that's the more useful view for a workload (a single pod's logs are already one click away via the Pods tab). */
const ALL_WORKLOAD_PODS = "__all__";

async function fetchWorkloadPods() {
  const wd = state.workloadDetail;
  if (!wd) return;
  const token = workloadDetailToken;
  wd.podsLoading = true;
  wd.podsError = null;
  render();
  try {
    const allPods = await api.getPods(wd.ctx, wd.namespace);
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    const owned = allPods
      .filter((p) => p.owner_kind === wd.kind && p.owner_name === wd.name)
      .map((p) => p.name)
      .sort();
    state.workloadDetail.pods = owned;
    if (owned.length > 0 && !state.workloadDetail.activePod) {
      state.workloadDetail.activePod = ALL_WORKLOAD_PODS;
    }
  } catch (e) {
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.podsError = String(e);
  } finally {
    if (token === workloadDetailToken && state.workloadDetail) state.workloadDetail.podsLoading = false;
    render();
  }
  maybeStartWorkloadLogs();
}

/** The pod list and the manifest (for container names) load independently and can settle in either order — called from both, it only actually fetches once both are ready. */
function maybeStartWorkloadLogs() {
  const wd = state.workloadDetail;
  if (!wd || wd.view !== "logs") return;
  if (!wd.activePod || !wd.activeContainer) return;
  if (wd.logText || wd.logLoading || wd.following) return;
  fetchWorkloadLogs();
}

function setWorkloadDetailPod(podName: string) {
  const wd = state.workloadDetail;
  if (!wd || wd.activePod === podName) return;
  const wasFollowing = wd.following;
  stopWorkloadLogFollow();
  wd.activePod = podName;
  wd.logText = "";
  render();
  if (wasFollowing) startWorkloadLogFollow();
  else fetchWorkloadLogs();
}

function setWorkloadDetailContainer(container: string) {
  const wd = state.workloadDetail;
  if (!wd || wd.activeContainer === container) return;
  const wasFollowing = wd.following;
  stopWorkloadLogFollow();
  wd.activeContainer = container;
  wd.logText = "";
  render();
  if (wasFollowing) startWorkloadLogFollow();
  else fetchWorkloadLogs();
}

function setWorkloadLogMode(mode: "head" | "tail") {
  const wd = state.workloadDetail;
  if (!wd || wd.following || wd.logMode === mode) return;
  wd.logMode = mode;
  render();
  fetchWorkloadLogs();
}

function toggleWorkloadLogWrap() {
  const wd = state.workloadDetail;
  if (!wd) return;
  wd.logWrap = !wd.logWrap;
  render();
}

function setWorkloadLogLines(lines: number) {
  const wd = state.workloadDetail;
  if (!wd || wd.following) return;
  wd.logLines = Math.max(1, Math.min(5000, Math.round(lines) || 100));
  render();
  fetchWorkloadLogs();
}

function refreshWorkloadLogs() {
  const wd = state.workloadDetail;
  if (!wd || wd.following) return;
  fetchWorkloadLogs();
}

async function fetchWorkloadLogs() {
  const wd = state.workloadDetail;
  if (!wd || !wd.activePod || !wd.activeContainer) return;
  const token = workloadDetailToken;
  wd.logLoading = true;
  wd.logError = null;
  render();
  try {
    const text =
      wd.activePod === ALL_WORKLOAD_PODS
        ? await api.getWorkloadLogs(wd.ctx, wd.namespace, wd.pods ?? [], wd.activeContainer, wd.logMode === "tail", wd.logLines)
        : await api.getPodLogs(wd.ctx, wd.namespace, wd.activePod, wd.activeContainer, wd.logMode === "tail", wd.logLines);
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.logText = text;
    pendingLogScroll.set("workload-log", wd.logMode === "tail" ? "bottom" : "top");
  } catch (e) {
    if (token !== workloadDetailToken || !state.workloadDetail) return;
    state.workloadDetail.logError = String(e);
  } finally {
    if (token === workloadDetailToken && state.workloadDetail) state.workloadDetail.logLoading = false;
    render();
  }
}

function toggleWorkloadFollow() {
  const wd = state.workloadDetail;
  if (!wd) return;
  if (wd.following) stopWorkloadLogFollow();
  else startWorkloadLogFollow();
}

function startWorkloadLogFollow() {
  const wd = state.workloadDetail;
  if (!wd || !wd.activePod || !wd.activeContainer) return;
  wd.following = true;
  wd.logText = "";
  wd.logError = null;
  render();

  const onLine = (line: string) => {
    if (!state.workloadDetail?.following) return;
    state.workloadDetail.logText += (state.workloadDetail.logText ? "\n" : "") + line;
    scheduleLogRender();
  };
  const streamPromise =
    wd.activePod === ALL_WORKLOAD_PODS
      ? api.startWorkloadLogStream(wd.ctx, wd.namespace, wd.pods ?? [], wd.activeContainer, onLine)
      : api.startPodLogStream(wd.ctx, wd.namespace, wd.activePod, wd.activeContainer, onLine);

  streamPromise
    .then((streamId) => {
      if (!state.workloadDetail?.following) {
        // Follow was toggled off again before the stream finished starting up.
        api.stopPodLogStream(streamId).catch(() => {});
        return;
      }
      state.workloadDetail.logStreamId = streamId;
    })
    .catch((e) => {
      if (!state.workloadDetail) return;
      state.workloadDetail.following = false;
      state.workloadDetail.logError = String(e);
      render();
    });
}

function stopWorkloadLogFollow() {
  if (!state.workloadDetail?.following) return;
  state.workloadDetail.following = false;
  const streamId = state.workloadDetail.logStreamId;
  state.workloadDetail.logStreamId = null;
  if (streamId !== null) api.stopPodLogStream(streamId).catch(() => {});
}

function manualRefresh() {
  loadTabData();
  refreshSidebarBadges();
}

// ---------------------------------------------------------------------------
// Pod detail panel (YAML / Logs / Graph)
// ---------------------------------------------------------------------------

function openPodDetail(ctx: string, namespace: string, name: string) {
  closeNodeDetail();
  closeWorkloadDetail();
  closeGitOpsDetail();
  closeHelmDetail();
  closeNapDetail();
  stopPodLogFollow();
  const token = ++podDetailToken;
  state.podDetail = {
    ctx,
    namespace,
    name,
    view: "yaml",
    containers: [],
    activeContainer: "",
    manifest: null,
    manifestError: null,
    showManagedFields: false,
    yamlSearch: "",
    yamlSearchIndex: 0,
    logMode: "tail",
    logLines: 100,
    logText: "",
    logWrap: true,
    logSearch: "",
    logSearchIndex: 0,
    logLoading: false,
    logError: null,
    following: false,
    logStreamId: null,
    ...EMPTY_METRICS_VIEW_STATE,
  };
  render();

  api
    .getPodManifest(ctx, namespace, name)
    .then((manifest) => {
      if (token !== podDetailToken || !state.podDetail) return;
      state.podDetail.manifest = manifest;
      state.podDetail.containers = manifest.containers;
      state.podDetail.activeContainer = manifest.containers[0] ?? "";
      render();
      if (state.podDetail.activeContainer) fetchPodLogs();
    })
    .catch((e) => {
      if (token !== podDetailToken || !state.podDetail) return;
      state.podDetail.manifestError = String(e);
      render();
    });
}

function closePodDetail() {
  stopPodLogFollow();
  podDetailToken += 1;
  state.podDetail = null;
  render();
}

function setPodDetailView(view: PodDetailState["view"]) {
  if (!state.podDetail) return;
  state.podDetail.view = view;
  render();
  if (view === "graph" && !state.podDetail.metrics && !state.podDetail.metricsLoading) {
    fetchPodMetrics();
  }
}

function toggleManagedFields() {
  if (!state.podDetail) return;
  state.podDetail.showManagedFields = !state.podDetail.showManagedFields;
  render();
}

/** The YAML text currently on screen — whichever of the two cached variants the toggle selects. */
function currentYamlText(pd: PodDetailState): string {
  if (!pd.manifest) return "";
  return pd.showManagedFields ? pd.manifest.yaml_full : pd.manifest.yaml_without_managed_fields;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function countSearchMatches(text: string, query: string): number {
  if (!query) return 0;
  return (text.match(new RegExp(escapeRegExp(query), "gi")) || []).length;
}

function setPodSearch(view: "yaml" | "logs", query: string) {
  if (!state.podDetail) return;
  if (view === "yaml") {
    state.podDetail.yamlSearch = query;
    state.podDetail.yamlSearchIndex = 0;
  } else {
    state.podDetail.logSearch = query;
    state.podDetail.logSearchIndex = 0;
  }
  pendingSearchScroll = true;
  render();
}

function movePodSearch(view: "yaml" | "logs", delta: number) {
  const pd = state.podDetail;
  if (!pd) return;
  const query = view === "yaml" ? pd.yamlSearch : pd.logSearch;
  if (!query) return;
  const text = view === "yaml" ? currentYamlText(pd) : pd.logText;
  const count = countSearchMatches(text, query);
  if (count === 0) return;
  const current = view === "yaml" ? pd.yamlSearchIndex : pd.logSearchIndex;
  const next = (((current + delta) % count) + count) % count;
  if (view === "yaml") pd.yamlSearchIndex = next;
  else pd.logSearchIndex = next;
  pendingSearchScroll = true;
  render();
}

function setPodDetailContainer(container: string) {
  if (!state.podDetail || state.podDetail.activeContainer === container) return;
  const wasFollowing = state.podDetail.following;
  stopPodLogFollow();
  state.podDetail.activeContainer = container;
  state.podDetail.logText = "";
  render();
  if (wasFollowing) startPodLogFollow();
  else fetchPodLogs();
}

function setPodLogMode(mode: "head" | "tail") {
  if (!state.podDetail || state.podDetail.following || state.podDetail.logMode === mode) return;
  state.podDetail.logMode = mode;
  render();
  fetchPodLogs();
}

function togglePodLogWrap() {
  if (!state.podDetail) return;
  state.podDetail.logWrap = !state.podDetail.logWrap;
  render();
}

function setPodLogLines(lines: number) {
  if (!state.podDetail || state.podDetail.following) return;
  state.podDetail.logLines = Math.max(1, Math.min(5000, Math.round(lines) || 100));
  render();
  fetchPodLogs();
}

function refreshPodLogs() {
  if (!state.podDetail || state.podDetail.following) return;
  fetchPodLogs();
}

async function fetchPodLogs() {
  const pd = state.podDetail;
  if (!pd || !pd.activeContainer) return;
  const token = podDetailToken;
  pd.logLoading = true;
  pd.logError = null;
  render();
  try {
    const text = await api.getPodLogs(pd.ctx, pd.namespace, pd.name, pd.activeContainer, pd.logMode === "tail", pd.logLines);
    if (token !== podDetailToken || !state.podDetail) return;
    state.podDetail.logText = text;
    pendingLogScroll.set("pod-log", pd.logMode === "tail" ? "bottom" : "top");
  } catch (e) {
    if (token !== podDetailToken || !state.podDetail) return;
    state.podDetail.logError = String(e);
  } finally {
    if (token === podDetailToken && state.podDetail) state.podDetail.logLoading = false;
    render();
  }
}

function toggleFollow() {
  if (!state.podDetail) return;
  if (state.podDetail.following) stopPodLogFollow();
  else startPodLogFollow();
}

function startPodLogFollow() {
  const pd = state.podDetail;
  if (!pd || !pd.activeContainer) return;
  pd.following = true;
  pd.logText = "";
  pd.logError = null;
  render();

  api
    .startPodLogStream(pd.ctx, pd.namespace, pd.name, pd.activeContainer, (line) => {
      if (!state.podDetail?.following) return;
      state.podDetail.logText += (state.podDetail.logText ? "\n" : "") + line;
      scheduleLogRender();
    })
    .then((streamId) => {
      if (!state.podDetail?.following) {
        // Follow was toggled off again before the stream finished starting up.
        api.stopPodLogStream(streamId).catch(() => {});
        return;
      }
      state.podDetail.logStreamId = streamId;
    })
    .catch((e) => {
      if (!state.podDetail) return;
      state.podDetail.following = false;
      state.podDetail.logError = String(e);
      render();
    });
}

function stopPodLogFollow() {
  if (!state.podDetail?.following) return;
  state.podDetail.following = false;
  const streamId = state.podDetail.logStreamId;
  state.podDetail.logStreamId = null;
  if (streamId !== null) api.stopPodLogStream(streamId).catch(() => {});
}

/** Coalesces rapid log lines (potentially many per second) into one render per animation frame. */
function scheduleLogRender() {
  if (logRenderScheduled) return;
  logRenderScheduled = true;
  requestAnimationFrame(() => {
    logRenderScheduled = false;
    render();
  });
}

/** Coalesces the repaints driven by arriving pod pages — see the call site for why one-per-page is too many on a large cluster. */
function schedulePodsStreamRender() {
  if (podsStreamRenderScheduled) return;
  podsStreamRenderScheduled = true;
  requestAnimationFrame(() => {
    podsStreamRenderScheduled = false;
    render();
  });
}

function setPodMetricsRange(minutes: number) {
  if (!state.podDetail) return;
  state.podDetail.metricsRangeMinutes = minutes;
  render();
  fetchPodMetrics();
}

async function fetchPodMetrics() {
  const pd = state.podDetail;
  if (!pd) return;
  const token = podDetailToken;
  pd.metricsLoading = true;
  pd.metricsError = null;
  render();
  try {
    const result = await api.getPodMetricsOverTime(pd.ctx, pd.namespace, pd.name, pd.metricsRangeMinutes, metricsBackendFor(pd.ctx));
    if (token !== podDetailToken || !state.podDetail) return;
    state.podDetail.metrics = result;
  } catch (e) {
    if (token !== podDetailToken || !state.podDetail) return;
    state.podDetail.metricsError = String(e);
  } finally {
    if (token === podDetailToken && state.podDetail) state.podDetail.metricsLoading = false;
    render();
  }
}

function setAutoRefresh(seconds: number) {
  state.autoRefreshSeconds = seconds;
  scheduleAutoRefresh();
  render();
}

function toggleEventsFilter() {
  state.eventsWarningsOnly = !state.eventsWarningsOnly;
  loadTabData();
}

function setMetricsRange(minutes: number) {
  state.metricsRangeMinutes = minutes;
  loadTabData();
}

(window as any).__app = {
  setPageSize,
  setTablePage,
  setClusterFilter,
  toggleCluster,
  reconnectCluster,
  selectAllClusters,
  clearClusterSelection,
  openClusterPalette,
  closeClusterPalette,
  setClusterPaletteQuery,
  moveClusterPaletteHighlight,
  setClusterPaletteHighlight,
  toggleClusterPaletteHighlighted,
  selectTab,
  viewPodsForWorkload,
  viewPodsForNode,
  openPodDetail,
  closePodDetail,
  setPodDetailView,
  toggleManagedFields,
  setPodSearch,
  movePodSearch,
  setPodDetailContainer,
  setPodLogMode,
  togglePodLogWrap,
  setPodLogLines,
  refreshPodLogs,
  toggleFollow,
  setPodMetricsRange,
  openNodeDetail,
  closeNodeDetail,
  setNodeDetailView,
  toggleNodeManagedFields,
  setNodeSearch,
  moveNodeSearch,
  setNodeMetricsRange,
  openWorkloadDetail,
  closeWorkloadDetail,
  setWorkloadDetailView,
  toggleWorkloadManagedFields,
  setWorkloadSearch,
  moveWorkloadSearch,
  setWorkloadDetailPod,
  setWorkloadDetailContainer,
  setWorkloadLogMode,
  toggleWorkloadLogWrap,
  setWorkloadLogLines,
  refreshWorkloadLogs,
  toggleWorkloadFollow,
  setWorkloadMetricsRange,
  toggleWorkloadRevisionCompare,
  openGitOpsDetail,
  closeGitOpsDetail,
  setGitOpsDetailView,
  toggleGitOpsManagedFields,
  setGitOpsSearch,
  moveGitOpsSearch,
  openNapDetail,
  closeNapDetail,
  setNapDetailView,
  setNapMetricsRange,
  toggleNapManagedFields,
  setNapSearch,
  moveNapSearch,
  viewNodesForNodePool,
  openHelmDetail,
  closeHelmDetail,
  setHelmDetailView,
  toggleHelmDefaultValues,
  setHelmSearch,
  moveHelmSearch,
  manualRefresh,
  setAutoRefresh,
  toggleEventsFilter,
  toggleUnhealthyOnly,
  setMetricsRange,
  refreshClaudeAuth,
  toggleClaudePanel,
  saveClaudeApiKey,
  clearClaudeApiKey,
  explainError,
  closeClaudeExplain,
  diagnosePod,
  confirmDiagnose,
  closeClaudeDiagnose,
  toggleDiagnosePayload,
  openMetricsBackendEditor,
  closeMetricsBackendEditor,
  setMetricsBackendField,
  pickMetricsBackendCandidate,
  testMetricsBackendDraft,
  saveMetricsBackendOverride,
  clearMetricsBackendOverride,
  setSort,
  setStringFilter,
  setNumberFilter,
  setEnumFilter,
  toggleEnumFilterValue,
  toggleEnumDropdown,
  clearFilters,
  toggleTheme,
  cycleUiScale,
  toggleSidebar,
  startColumnResize,
  toggleRowSelected,
  toggleAllRowsSelected,
  clearRowSelection,
  copySelectedRows,
  copyPreToClipboard,
  handleChartHover,
  handleChartHoverEnd,
};

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

interface SelectionSnapshot {
  scrollId: string;
  start: number;
  end: number;
}

/**
 * A user's text selection (e.g. mid-copy from the YAML or Log view) lives on
 * DOM nodes that render() is about to discard and recreate — the browser
 * clears a Selection the instant its underlying nodes leave the document, so
 * without this, a selection made just before an auto-refresh tick (or, on
 * the Logs view, the next batch of streamed-in lines) would vanish out from
 * under the user's cursor before they finish copying. Captured as a plain
 * character offset within the `data-scroll-id`-tagged container's text,
 * which restoreSelectionSnapshot re-locates in the freshly rendered version
 * of that same container.
 */
function captureSelectionSnapshot(app: HTMLElement): SelectionSnapshot | null {
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0 || sel.isCollapsed) return null;
  const range = sel.getRangeAt(0);
  const anchor =
    range.commonAncestorContainer.nodeType === Node.ELEMENT_NODE
      ? (range.commonAncestorContainer as Element)
      : range.commonAncestorContainer.parentElement;
  const container = anchor?.closest<HTMLElement>("[data-scroll-id]");
  if (!container || !app.contains(container)) return null;

  const startRange = document.createRange();
  startRange.selectNodeContents(container);
  startRange.setEnd(range.startContainer, range.startOffset);
  const start = startRange.toString().length;
  return { scrollId: container.dataset.scrollId!, start, end: start + range.toString().length };
}

function restoreSelectionSnapshot(app: HTMLElement, snapshot: SelectionSnapshot | null) {
  if (!snapshot) return;
  const container = app.querySelector<HTMLElement>(`[data-scroll-id="${snapshot.scrollId}"]`);
  if (!container) return;

  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
  let charsBefore = 0;
  let startNode: Node | null = null;
  let startOffset = 0;
  let endNode: Node | null = null;
  let endOffset = 0;
  let node: Node | null;
  while ((node = walker.nextNode())) {
    const len = node.textContent?.length ?? 0;
    if (startNode === null && charsBefore + len >= snapshot.start) {
      startNode = node;
      startOffset = snapshot.start - charsBefore;
    }
    if (charsBefore + len >= snapshot.end) {
      endNode = node;
      endOffset = snapshot.end - charsBefore;
      break;
    }
    charsBefore += len;
  }
  if (!startNode || !endNode) return;

  const range = document.createRange();
  range.setStart(startNode, startOffset);
  range.setEnd(endNode, endOffset);
  const sel = window.getSelection();
  sel?.removeAllRanges();
  sel?.addRange(range);
}

// Every render() replaces the whole #app subtree, which would normally steal
// focus/cursor position out from under a filter `<input>` on each keystroke.
// `data-filter-key` tags each filter control with an identity that's stable
// across re-renders (same tab+column always renders to the same key), so we
// can find "the same" input in the new DOM and restore focus + selection.
function render() {
  const app = document.getElementById("app");
  if (!app) return;

  const active = document.activeElement;
  const activeKey = active instanceof HTMLElement ? active.dataset.filterKey : undefined;
  const selStart = active instanceof HTMLInputElement ? active.selectionStart : null;
  const selEnd = active instanceof HTMLInputElement ? active.selectionEnd : null;

  // Replacing #app's innerHTML on every render (including background
  // auto-refresh) would otherwise silently reset scrollTop to 0 on every
  // scrollable pane — `data-scroll-id` tags each one with an identity that's
  // stable across re-renders (same id always refers to "the same" pane, e.g.
  // "table:pods"), so we can restore its scroll position afterwards.
  const scrollPositions = new Map<string, { top: number; left: number }>();
  app.querySelectorAll<HTMLElement>("[data-scroll-id]").forEach((el) => {
    scrollPositions.set(el.dataset.scrollId!, { top: el.scrollTop, left: el.scrollLeft });
  });
  const selectionSnapshot = captureSelectionSnapshot(app);

  app.innerHTML = `
    ${renderSidebar()}
    <div class="flex min-w-0 flex-1 flex-col">
      ${renderTopbar()}
      ${renderTabs()}
      <div class="min-h-0 flex-1 overflow-auto p-5" data-scroll-id="main">
        ${state.selectedContexts.size > 0 ? renderTabContent() : renderEmptyState()}
      </div>
    </div>
    ${copyToastBanner()}
    ${renderPodDetailPanel()}
    ${renderNodeDetailPanel()}
    ${renderWorkloadDetailPanel()}
    ${renderNapDetailPanel()}
    ${renderGitOpsDetailPanel()}
    ${renderHelmDetailPanel()}
    ${renderMetricsBackendEditor()}
    ${renderClaudePanel()}
    ${renderClaudeExplainPanel()}
    ${renderClaudeDiagnosePanel()}
    ${renderClusterPalette()}
  `;

  app.querySelectorAll<HTMLElement>("[data-scroll-id]").forEach((el) => {
    const pos = scrollPositions.get(el.dataset.scrollId!);
    if (pos) {
      el.scrollTop = pos.top;
      el.scrollLeft = pos.left;
    }
  });
  restoreSelectionSnapshot(app, selectionSnapshot);

  // While following, new lines keep arriving — pin to the bottom instead of
  // the scroll-restore above (which would otherwise hold it at whatever
  // position it was at the first render, in a growing view of the log where
  // the reader actually wants to track the tail).
  if (state.podDetail?.following) {
    const logEl = app.querySelector<HTMLElement>('[data-scroll-id="pod-log"]');
    if (logEl) logEl.scrollTop = logEl.scrollHeight;
  }
  if (state.workloadDetail?.following) {
    const logEl = app.querySelector<HTMLElement>('[data-scroll-id="workload-log"]');
    if (logEl) logEl.scrollTop = logEl.scrollHeight;
  }
  // Not cleared unconditionally: the panel can open on the YAML tab while
  // logs prefetch silently in the background, so the log `<pre>` may not
  // exist in the DOM yet when its content first arrives. Left pending, it
  // gets applied (and only then cleared) whenever the Logs tab actually
  // becomes visible, however many renders later that is.
  pendingLogScroll.forEach((edge, scrollId) => {
    const logEl = app.querySelector<HTMLElement>(`[data-scroll-id="${scrollId}"]`);
    if (logEl) {
      logEl.scrollTop = edge === "top" ? 0 : logEl.scrollHeight;
      pendingLogScroll.delete(scrollId);
    }
  });

  // The enum-filter dropdown is `position: fixed` (so it can't be clipped by
  // the table's `overflow-auto` scroll container, which happens whenever the
  // table is shorter than the dropdown — e.g. a filtered-down single row) and
  // so needs its position computed from the trigger button's rect by hand.
  const enumPanel = app.querySelector<HTMLElement>("[data-enum-dropdown-panel]");
  const enumTrigger = enumPanel?.parentElement?.querySelector<HTMLElement>("button[data-filter-key]");
  if (enumPanel && enumTrigger) {
    const rect = enumTrigger.getBoundingClientRect();
    const viewportW = document.documentElement.clientWidth;
    const viewportH = document.documentElement.clientHeight;
    enumPanel.style.left = `${Math.max(8, Math.min(rect.left, viewportW - enumPanel.offsetWidth - 8))}px`;
    const fitsBelow = rect.bottom + 4 + enumPanel.offsetHeight <= viewportH - 8;
    enumPanel.style.top = fitsBelow
      ? `${rect.bottom + 4}px`
      : `${Math.max(8, rect.top - enumPanel.offsetHeight - 4)}px`;
  }

  restoreChartHovers(app);

  if (pendingSearchScroll) {
    pendingSearchScroll = false;
    app.querySelector<HTMLElement>("[data-search-current]")?.scrollIntoView({ block: "center" });
  }

  if (pendingClusterPaletteScroll) {
    pendingClusterPaletteScroll = false;
    app.querySelector<HTMLElement>("[data-cluster-palette-current]")?.scrollIntoView({ block: "nearest" });
  }

  // The row cursor is marked here rather than inside each table's row
  // template: one insertion point instead of ten, and it survives the
  // re-render an auto-refresh triggers. Clamped against the rows actually
  // present, so a cursor left pointing past the end — a filter narrowed the
  // table under it, say — lands on the last row instead of disappearing.
  const focusedRow = focusedRowElement();
  if (focusedRow) {
    focusedRow.setAttribute("data-row-focused", "");
    // Runs after the scroll-position restore above, so it wins over it.
    if (pendingRowFocusScroll) focusedRow.scrollIntoView({ block: "nearest" });
  }
  pendingRowFocusScroll = false;

  if (activeKey) {
    // `preventScroll` matters here: without it, re-focusing an input that's
    // currently scrolled out of view (e.g. a filter box for a column
    // scrolled off-screen) snaps every scrollable ancestor back to make it
    // visible — silently undoing the scroll-position restore just above.
    const restored = app.querySelector<HTMLElement>(`[data-filter-key="${activeKey}"]`);
    if (restored instanceof HTMLInputElement) {
      restored.focus({ preventScroll: true });
      if (selStart !== null && selEnd !== null) restored.setSelectionRange(selStart, selEnd);
    } else {
      restored?.focus({ preventScroll: true });
    }
  }

  // `autofocus` alone isn't reliable across engines for markup inserted via
  // `innerHTML` (as opposed to initial parse), so back it with an explicit
  // focus call for the palette's freshly-opened first render — a no-op once
  // it's already focused, since the `activeKey` restore above then takes
  // over on every render after that.
  if (state.clusterPalette) {
    const query = app.querySelector<HTMLInputElement>('[data-filter-key="cluster-palette-query"]');
    if (query && document.activeElement !== query) query.focus({ preventScroll: true });
  }
}

const collapseIcon = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>`;
const expandIcon = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>`;

function renderCollapsedSidebar(): string {
  const dots = state.clusters
    .filter((c) => state.selectedContexts.has(c.context_name))
    .map((c) => {
      const ov = state.overviews.get(c.context_name);
      const dot = ov ? statusDot(ov.reachable && ov.nodes_ready === ov.node_count) : statusDot(false, true);
      return `<div class="flex justify-center py-1" title="${esc(c.context_name)}">${dot}</div>`;
    })
    .join("");
  return `
    <aside class="flex w-10 shrink-0 flex-col items-center border-r border-gridline bg-surface-1 py-3">
      <button
        onclick="window.__app.toggleSidebar()"
        title="Expand cluster list"
        class="flex items-center justify-center rounded-md p-1.5 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary"
      >${expandIcon}</button>
      <div class="mt-3 flex flex-col gap-1">${dots}</div>
    </aside>`;
}

function renderSidebar(): string {
  if (state.sidebarCollapsed) return renderCollapsedSidebar();

  const filterText = state.clusterFilter.trim().toLowerCase();
  const visibleClusters = filterText
    ? state.clusters.filter(
        (c) => c.context_name.toLowerCase().includes(filterText) || c.cluster_name.toLowerCase().includes(filterText),
      )
    : state.clusters;

  const rows = visibleClusters
    .map((c) => {
      const checked = state.selectedContexts.has(c.context_name);
      const ov = checked ? state.overviews.get(c.context_name) : undefined;
      const reconnecting = state.reconnecting.has(c.context_name);
      const dot = ov ? statusDot(ov.reachable && ov.nodes_ready === ov.node_count) : statusDot(false, true);
      const statusText = !checked
        ? "not connected"
        : reconnecting
          ? "reconnecting…"
          : ov
            ? ov.reachable
              ? `${ov.nodes_ready}/${ov.node_count} nodes ready`
              : "unreachable"
            : "checking…";
      // Only once a fetch has actually come back unreachable — not while
      // still "checking…" on a first load, which looks the same as
      // "unreachable" for an instant but isn't something to retry yet.
      const showReconnect = checked && !reconnecting && ov && !ov.reachable;
      return `
        <label
          class="flex w-full cursor-pointer items-start gap-2 rounded-md px-3 py-2 text-left transition-colors ${
            checked ? "bg-surface-3" : "hover:bg-surface-2"
          }"
        >
          <input
            type="checkbox"
            class="mt-0.5 shrink-0 accent-series-blue"
            ${checked ? "checked" : ""}
            onchange="window.__app.toggleCluster(${jsArg(c.context_name)})"
          />
          <span class="flex min-w-0 flex-1 flex-col gap-0.5">
            <span class="flex items-center gap-2 text-sm font-medium text-ink-primary">
              ${dot}
              <span class="truncate">${esc(c.context_name)}</span>
            </span>
            <span class="ml-4 flex min-w-0 items-center gap-1.5 text-xs text-ink-muted">
              <span class="min-w-0 truncate">${statusText}</span>
              ${
                showReconnect
                  ? `<button
                       type="button"
                       onclick="event.stopPropagation(); window.__app.reconnectCluster(${jsArg(c.context_name)})"
                       class="shrink-0 font-medium text-series-blue hover:underline"
                       title="Retry connecting to this cluster"
                     >Reconnect</button>`
                  : ""
              }
            </span>
          </span>
        </label>`;
    })
    .join("");

  return `
    <aside class="flex w-64 shrink-0 flex-col border-r border-gridline bg-surface-1">
      <div class="border-b border-gridline px-4 py-4">
        <div class="flex items-center justify-between">
          <div class="text-sm font-semibold text-ink-primary">AKS Fleet Dashboard</div>
          <button
            onclick="window.__app.toggleSidebar()"
            title="Collapse cluster list"
            class="flex items-center justify-center rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary"
          >${collapseIcon}</button>
        </div>
        <div class="mt-0.5 flex items-center justify-between text-xs text-ink-muted">
          <span>${filterText ? `${visibleClusters.length} of ${state.clusters.length}` : state.clusters.length} cluster${state.clusters.length === 1 ? "" : "s"} · ${state.selectedContexts.size} selected</span>
          <span class="flex items-center gap-2">
            <button onclick="window.__app.selectAllClusters()" class="text-ink-secondary hover:text-ink-primary hover:underline">All</button>
            <button onclick="window.__app.clearClusterSelection()" class="text-ink-secondary hover:text-ink-primary hover:underline">None</button>
          </span>
        </div>
        <input
          type="text"
          placeholder="Filter clusters…"
          value="${esc(state.clusterFilter)}"
          data-filter-key="cluster-filter"
          oninput="window.__app.setClusterFilter(this.value)"
          class="mt-2 w-full rounded-md border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-primary outline-none focus:border-series-blue"
        />
      </div>
      <div class="flex-1 overflow-auto p-2" data-scroll-id="sidebar">
        ${
          state.loadingClusters
            ? `<div class="px-3 py-2 text-xs text-ink-muted">Loading contexts…</div>`
            : rows ||
              (filterText
                ? `<div class="px-3 py-2 text-xs text-ink-muted">No clusters match "${esc(state.clusterFilter)}".</div>`
                : `<div class="px-3 py-2 text-xs text-ink-muted">No clusters found.</div>`)
        }
      </div>
      <div class="truncate border-t border-gridline px-4 py-3 text-[11px] text-ink-muted" title="${esc(state.kubeconfigPath)}">
        ${esc(state.kubeconfigPath) || "no kubeconfig"}
      </div>
    </aside>`;
}

function renderClusterPalette(): string {
  const palette = state.clusterPalette;
  if (!palette) return "";

  const visible = clusterPaletteVisible();
  const rows = visible
    .map((c, i) => {
      const checked = state.selectedContexts.has(c.context_name);
      const ov = checked ? state.overviews.get(c.context_name) : undefined;
      const dot = ov ? statusDot(ov.reachable && ov.nodes_ready === ov.node_count) : statusDot(false, true);
      const statusText = !checked
        ? "not connected"
        : ov
          ? ov.reachable
            ? `${ov.nodes_ready}/${ov.node_count} nodes ready`
            : "unreachable"
          : "checking…";
      const highlighted = i === palette.highlightedIndex;
      return `
        <div
          ${highlighted ? "data-cluster-palette-current" : ""}
          onclick="window.__app.toggleCluster(${jsArg(c.context_name)})"
          onmouseenter="window.__app.setClusterPaletteHighlight(${i})"
          class="flex cursor-pointer items-center gap-2.5 rounded-md px-3 py-2 text-left ${highlighted ? "bg-surface-3" : ""}"
        >
          <input type="checkbox" class="pointer-events-none shrink-0 accent-series-blue" ${checked ? "checked" : ""} />
          ${dot}
          <span class="min-w-0 flex-1 truncate text-sm text-ink-primary">${esc(c.context_name)}</span>
          <span class="shrink-0 truncate text-xs text-ink-muted">${esc(statusText)}</span>
        </div>`;
    })
    .join("");

  return `
    <div class="fixed inset-0 z-50 flex items-start justify-center bg-black/40 p-6 pt-[12vh]" onclick="window.__app.closeClusterPalette()">
      <div class="flex max-h-[60vh] w-full max-w-lg flex-col overflow-hidden rounded-lg border border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="border-b border-gridline p-2">
          <input
            type="text"
            autofocus
            placeholder="Jump to cluster…"
            value="${esc(palette.query)}"
            data-filter-key="cluster-palette-query"
            oninput="window.__app.setClusterPaletteQuery(this.value)"
            onkeydown="
              if (event.key === 'ArrowDown') { event.preventDefault(); window.__app.moveClusterPaletteHighlight(1); }
              else if (event.key === 'ArrowUp') { event.preventDefault(); window.__app.moveClusterPaletteHighlight(-1); }
              else if (event.key === 'Enter') { event.preventDefault(); window.__app.toggleClusterPaletteHighlighted(); }
            "
            class="w-full rounded-md border-none bg-transparent px-2 py-1.5 text-sm text-ink-primary outline-none"
          />
        </div>
        <div class="flex items-center justify-between border-b border-gridline px-3 py-1.5 text-xs text-ink-muted">
          <span>${state.selectedContexts.size} selected</span>
          <span>↑↓ navigate · ↵ toggle · esc close</span>
        </div>
        <div class="flex-1 overflow-auto p-1.5" data-scroll-id="cluster-palette:${encodeURIComponent(palette.query)}">
          ${rows || `<div class="p-3 text-center text-xs text-ink-muted">No clusters match.</div>`}
        </div>
      </div>
    </div>`;
}

function themeToggleButton(): string {
  const isLight = state.theme === "light";
  const moonIcon = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
  const sunIcon = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
  return `
    <button
      onclick="window.__app.toggleTheme()"
      title="Switch to ${isLight ? "dark" : "light"} mode"
      class="flex items-center justify-center rounded-md border border-gridline bg-surface-2 p-1.5 text-ink-secondary hover:bg-surface-3 hover:text-ink-primary"
    >${isLight ? moonIcon : sunIcon}</button>`;
}

function uiScaleButton(): string {
  const index = currentUiScaleIndex();
  const next = UI_SCALE_STEPS[(index + 1) % UI_SCALE_STEPS.length];
  // Three glyph sizes across the whole ladder — enough for the button to hint
  // at the current scale without needing a class per step.
  const glyphClass = state.uiScale < DEFAULT_UI_SCALE ? "text-xs" : state.uiScale === DEFAULT_UI_SCALE ? "text-sm" : "text-base";
  return `
    <button
      onclick="window.__app.cycleUiScale()"
      title="Zoom: ${state.uiScale}% (click for ${next}% · ⌘+ / ⌘− to step, ⌘0 to reset)"
      class="flex items-center justify-center rounded-md border border-gridline bg-surface-2 px-2.5 py-1.5 text-ink-secondary hover:bg-surface-3 hover:text-ink-primary"
    ><span class="${glyphClass} font-semibold leading-none">A</span></button>`;
}


// ---------------------------------------------------------------------------
// Claude UI
// ---------------------------------------------------------------------------

/** Small "Explain" affordance, rendered only where an error string exists. */
function claudeExplainButton(subject: string, errorText: string): string {
  if (!errorText.trim()) return "";
  const signedIn = state.claudeAuth?.signed_in === true;
  const title = signedIn
    ? "Explain this error with Claude (sends only this message)"
    : "Sign in to Claude first — see the ✦ button in the top bar";
  return `
    <button
      type="button"
      title="${esc(title)}"
      ${signedIn ? "" : "disabled"}
      onclick="window.__app.explainError(${jsArg(subject)}, this.dataset.err)"
      data-err="${esc(errorText)}"
      class="shrink-0 rounded border border-gridline px-1.5 py-0.5 text-xs text-ink-secondary hover:bg-surface-3 hover:text-ink-primary disabled:cursor-not-allowed disabled:opacity-40"
    >Explain</button>`;
}

/** Top-bar Claude status/auth control. Click cycles: re-probe, or open the setup panel. */
function claudeAuthButton(): string {
  const auth = state.claudeAuth;
  const signedIn = auth?.signed_in === true;
  const label = signedIn
    ? `Claude connected${auth?.source ? ` (${auth.source})` : ""}`
    : "No Claude API key — click to add one";
  return `
    <button
      type="button"
      onclick="window.__app.toggleClaudePanel()"
      title="${esc(label)}"
      class="flex items-center justify-center rounded-md border border-gridline bg-surface-2 px-2.5 py-1.5 hover:bg-surface-3 ${
        signedIn ? "text-status-good" : "text-ink-muted"
      }"
    ><span class="text-sm font-semibold leading-none">✦</span></button>`;
}

/**
 * Setup/sign-in panel. The install commands live here rather than only in the
 * README so a teammate who installs the app via Homebrew isn't left guessing —
 * including the `xattr` step, which the CLI needs for the same Gatekeeper
 * reason this app does.
 */
function renderClaudePanel(): string {
  if (!state.claudePanelOpen) return "";
  const auth = state.claudeAuth;
  const signedIn = auth?.signed_in === true;

  const usingKeychainKey = auth?.source === "API key (Keychain)";

  // Never rendered with a `value` — the key is read from the DOM on save and
  // never round-trips through app state, which matters because render()
  // rebuilds the whole #app subtree and would re-emit it every time.
  const keyField = `
    <div class="flex flex-col gap-2">
      <div class="text-xs font-medium text-ink-primary">Paste an API key</div>
      <div class="flex items-center gap-2">
        <input
          type="password"
          autocomplete="off"
          spellcheck="false"
          placeholder="sk-ant-..."
          data-claude-key-input
          data-filter-key="claude-api-key"
          onkeydown="if (event.key === 'Enter') { event.preventDefault(); window.__app.saveClaudeApiKey(); }"
          class="min-w-0 flex-1 rounded border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-primary outline-none focus:border-series-blue"
        />
        <button type="button" onclick="window.__app.saveClaudeApiKey()" class="shrink-0 rounded-md bg-series-blue px-3 py-1.5 text-xs font-medium text-white">Save</button>
      </div>
      <div class="text-xs text-ink-muted">
        Stored in your macOS Keychain, not in the app. Create one at
        <span class="text-ink-secondary">console.anthropic.com &rarr; API keys</span>.
      </div>
    </div>`;

  const body = signedIn
    ? `<div class="flex flex-col gap-3">
        <div class="text-sm text-status-good">Connected${auth?.source ? ` via ${esc(auth.source)}` : ""}.</div>
        ${auth?.detail ? `<div class="text-xs text-ink-secondary">${esc(auth.detail)}</div>` : ""}
        ${
          usingKeychainKey
            ? `<button type="button" onclick="window.__app.clearClaudeApiKey()" class="self-start rounded-md border border-gridline px-3 py-1.5 text-xs text-ink-secondary hover:bg-surface-3 hover:text-ink-primary">Remove key</button>`
            : `<div class="text-xs text-ink-muted">Unset the environment variable to use a Keychain key instead.</div>`
        }
      </div>`
    : `<div class="flex flex-col gap-3">
        ${keyField}
        ${auth?.detail ? `<div class="text-xs text-status-critical">${esc(auth.detail)}</div>` : ""}
      </div>`;

  return `
    <div class="fixed inset-0 z-40 flex items-start justify-end bg-black/40 p-6" onclick="window.__app.toggleClaudePanel()">
      <div class="mt-12 flex w-full max-w-md flex-col rounded-lg border border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="text-sm font-medium text-ink-primary">Claude</div>
          <button type="button" onclick="window.__app.toggleClaudePanel()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>
        <div class="p-4">${body}</div>
      </div>
    </div>`;
}

function renderClaudeExplainPanel(): string {
  const ex = state.claudeExplain;
  if (!ex) return "";
  const scrollId = "claude-explain";

  const body = ex.error
    ? `<div class="text-sm text-status-critical">${esc(ex.error)}</div>`
    : ex.answer
      ? `<div class="whitespace-pre-wrap text-sm leading-relaxed text-ink-primary">${esc(ex.answer)}</div>`
      : `<div class="text-sm text-ink-muted">Thinking…</div>`;

  return `
    <div class="fixed inset-0 z-40 flex justify-end bg-black/40" onclick="window.__app.closeClaudeExplain()">
      <div class="flex h-full w-full max-w-2xl flex-col border-l border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">Explain error</div>
            <div class="truncate text-xs text-ink-muted">${esc(ex.subject)}</div>
          </div>
          <button type="button" onclick="window.__app.closeClaudeExplain()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>

        <div class="flex min-h-0 flex-1 flex-col gap-3 overflow-auto p-4" data-scroll-id="${scrollId}">
          <div>
            <div class="mb-1 text-xs font-medium text-ink-secondary">Sent to Claude</div>
            <pre class="max-h-32 overflow-auto whitespace-pre-wrap rounded-md border border-gridline bg-surface-2 p-2 text-xs text-ink-secondary">${esc(ex.errorText)}</pre>
          </div>
          <div class="border-t border-gridline pt-3">
            <div class="mb-1 flex items-center gap-2 text-xs font-medium text-ink-secondary">
              Explanation
              ${ex.streaming ? '<span class="text-ink-muted">streaming…</span>' : ""}
            </div>
            ${body}
          </div>
        </div>
      </div>
    </div>`;
}

function renderClaudeDiagnosePanel(): string {
  const d = state.claudeDiagnose;
  if (!d) return "";

  const review = d.payload
    ? `
      <div class="flex flex-col gap-2 rounded-md border border-gridline bg-surface-2 p-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="text-xs font-medium text-ink-primary">What will be sent</div>
          <button type="button" onclick="window.__app.toggleDiagnosePayload()" class="text-xs text-ink-secondary hover:text-ink-primary hover:underline">
            ${d.showPayload ? "Hide" : "Review"}
          </button>
        </div>
        <div class="flex flex-col gap-1 text-xs text-ink-muted">
          <div>Status, events, manifest and the recent logs of this container.</div>
          <div class="${d.payload.redaction_summary.startsWith("Redacted") ? "text-status-warning" : ""}">${esc(d.payload.redaction_summary)}</div>
          ${d.payload.log_note ? `<div>Logs: ${esc(d.payload.log_note)}.</div>` : ""}
          <div>Roughly ${d.payload.approx_tokens.toLocaleString()} tokens.</div>
        </div>
        ${
          d.showPayload
            ? `<pre class="max-h-64 select-text overflow-auto whitespace-pre-wrap rounded border border-gridline bg-surface-1 p-2 text-xs text-ink-secondary">${esc(d.payload.prompt)}</pre>`
            : ""
        }
      </div>`
    : d.error
      ? ""
      : `<div class="text-sm text-ink-muted">Gathering status, events, manifest and logs…</div>`;

  const action = d.payload && !d.sent
    ? `
      <div class="flex items-center gap-2">
        <button type="button" onclick="window.__app.confirmDiagnose()" class="rounded-md bg-series-blue px-3 py-1.5 text-xs font-medium text-white">Send to Claude</button>
        <button type="button" onclick="window.__app.closeClaudeDiagnose()" class="rounded-md border border-gridline px-3 py-1.5 text-xs text-ink-secondary hover:bg-surface-3 hover:text-ink-primary">Cancel</button>
      </div>`
    : "";

  const answer = d.error
    ? `<div class="text-sm text-status-critical">${esc(d.error)}</div>`
    : d.sent
      ? `<div class="border-t border-gridline pt-3">
          <div class="mb-1 flex items-center gap-2 text-xs font-medium text-ink-secondary">
            Diagnosis ${d.streaming ? '<span class="text-ink-muted">streaming…</span>' : ""}
          </div>
          ${
            d.answer
              ? `<div class="whitespace-pre-wrap text-sm leading-relaxed text-ink-primary">${esc(d.answer)}</div>`
              : `<div class="text-sm text-ink-muted">Thinking…</div>`
          }
        </div>`
      : "";

  return `
    <div class="fixed inset-0 z-40 flex justify-end bg-black/40" onclick="window.__app.closeClaudeDiagnose()">
      <div class="flex h-full w-full max-w-2xl flex-col border-l border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">Diagnose ${esc(d.podName)}</div>
            <div class="truncate text-xs text-ink-muted">${esc(d.ctx)} · ${esc(d.namespace)} · ${esc(d.container)}</div>
          </div>
          <button type="button" onclick="window.__app.closeClaudeDiagnose()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>
        <div class="flex min-h-0 flex-1 flex-col gap-3 overflow-auto p-4" data-scroll-id="claude-diagnose">
          ${review}
          ${action}
          ${answer}
        </div>
      </div>
    </div>`;
}

function renderTopbar(): string {
  const refreshOptions = [
    [0, "Off"],
    [15, "15s"],
    [30, "30s"],
    [60, "60s"],
    [300, "5m"],
  ] as const;

  const ctxs = selectedContextsList();
  const title =
    ctxs.length === 0 ? "Select a cluster" : ctxs.length === 1 ? ctxs[0] : `${ctxs.length} clusters selected`;

  return `
    <header class="flex items-center justify-between border-b border-gridline bg-surface-1 px-5 py-3">
      <div class="text-sm font-medium text-ink-primary" title="${esc(ctxs.join(", "))}">${esc(title)}</div>
      <div class="flex items-center gap-3 text-xs text-ink-muted">
        <span class="tabular">${state.lastUpdated ? `Updated ${relativeTime(state.lastUpdated.toISOString())}` : ""}</span>
        <select
          class="rounded-md border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-secondary outline-none"
          onchange="window.__app.setAutoRefresh(Number(this.value))"
        >
          ${refreshOptions
            .map(
              ([v, label]) =>
                `<option value="${v}" ${state.autoRefreshSeconds === v ? "selected" : ""}>Auto-refresh: ${label}</option>`,
            )
            .join("")}
        </select>
        <button
          onclick="window.__app.manualRefresh()"
          class="rounded-md border border-gridline bg-surface-2 px-3 py-1 text-xs font-medium text-ink-primary hover:bg-surface-3"
        >
          Refresh now
        </button>
        ${claudeAuthButton()}
        ${uiScaleButton()}
        ${themeToggleButton()}
      </div>
    </header>`;
}

function renderTabs(): string {
  return `
    <nav class="flex gap-1 border-b border-gridline bg-surface-1 px-5">
      ${TABS.map(
        (t) => `
        <button
          onclick="window.__app.selectTab(${jsArg(t.id)})"
          class="border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
            state.activeTab === t.id
              ? "border-series-blue text-ink-primary"
              : "border-transparent text-ink-muted hover:text-ink-secondary"
          }"
        >${t.label}</button>`,
      ).join("")}
    </nav>`;
}

function renderEmptyState(): string {
  if (state.clusters.length > 0) {
    return `
      <div class="flex h-full flex-col items-center justify-center gap-2 text-center text-ink-muted">
        <div class="text-sm">No clusters selected.</div>
        <div class="max-w-md text-xs">Check one or more clusters in the sidebar to see their data.</div>
      </div>`;
  }
  return `
    <div class="flex h-full flex-col items-center justify-center gap-2 text-center text-ink-muted">
      <div class="text-sm">No AKS clusters found in your kubeconfig.</div>
      <div class="max-w-md text-xs">
        Run <code class="rounded bg-surface-2 px-1 py-0.5">az login --use-device-code</code> and
        <code class="rounded bg-surface-2 px-1 py-0.5">az aks get-credentials --resource-group &lt;rg&gt; --name &lt;cluster&gt; --merge</code>
        for each cluster, then reopen this app. See README.md for details.
      </div>
    </div>`;
}

/**
 * A single cluster's fetch is one opaque Tauri round-trip with no
 * sub-progress to report, so its bar is indeterminate (a sliding highlight)
 * rather than a fake animated fill. Multiple clusters fetch concurrently, so
 * that case gets a real percentage — "done" reflects clusters whose fetch
 * has actually settled, not elapsed time — plus the names of any stragglers
 * once the list is short enough to be useful rather than overwhelming.
 */
function renderLoadingState(): string {
  const progress = state.tabLoadProgress;
  const elapsedSec = state.tabLoadStartedAt ? Math.max(0, Math.floor((Date.now() - state.tabLoadStartedAt) / 1000)) : 0;
  const total = progress?.total ?? 1;
  const multi = total > 1;
  const done = progress ? total - progress.pending.size : 0;
  const pct = multi ? Math.round((done / total) * 100) : 0;

  const label = multi ? `Loading ${total} clusters… (${done}/${total})` : "Loading…";
  const pending = progress && multi && progress.pending.size > 0 && progress.pending.size <= 4
    ? `<div class="mt-1.5 truncate text-xs text-ink-muted">Waiting on: ${Array.from(progress.pending).map(esc).join(", ")}</div>`
    : "";

  return `
    <div class="flex flex-col gap-2 py-10">
      <div class="flex items-center justify-between text-sm text-ink-secondary">
        <span>${esc(label)}</span>
        <span class="tabular text-xs text-ink-muted">${elapsedSec}s</span>
      </div>
      <div class="relative h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
        ${
          multi
            ? `<div class="h-full rounded-full bg-series-blue transition-all duration-300" style="width: ${pct}%"></div>`
            : `<div class="progress-indeterminate"></div>`
        }
      </div>
      ${pending}
    </div>`;
}

function renderTabContent(): string {
  const errorBanner = state.tabError
    ? `<div class="mb-4 whitespace-pre-line rounded-md border border-status-critical/40 bg-status-critical/10 p-3 text-sm text-status-critical">${esc(state.tabError)}</div>`
    : "";
  if (state.tabLoading && !hasAnyDataForTab()) {
    return renderLoadingState();
  }
  if (state.tabError && !hasAnyDataForTab()) {
    return errorBanner;
  }
  return errorBanner + renderTabContentBody();
}

function renderTabContentBody(): string {
  switch (state.activeTab) {
    case "overview":
      return renderOverview();
    case "nodes":
      return renderNodes();
    case "workloads":
      return renderWorkloads();
    case "pods":
      return renderPods();
    case "resources":
      return renderResources();
    case "metrics":
      return renderMetrics();
    case "events":
      return renderEvents();
    case "nap":
      return renderNap();
    case "keda":
      return renderKeda();
    case "gitops":
      return renderGitOps();
    case "helm":
      return renderHelm();
    case "cost":
      return renderCost();
  }
}

function hasAnyDataForTab(): boolean {
  return selectedContextsList().some((c) => tabHasDataForContext(state.activeTab, c));
}

function statTile(label: string, value: string, sub?: string, tone?: "good" | "warning" | "critical"): string {
  const toneClass = tone === "good" ? "text-status-good" : tone === "warning" ? "text-status-warning" : tone === "critical" ? "text-status-critical" : "text-ink-primary";
  return `
    <div class="rounded-lg border border-gridline bg-surface-1 p-4">
      <div class="text-xs text-ink-muted">${esc(label)}</div>
      <div class="mt-1 text-2xl font-semibold tabular ${toneClass}">${value}</div>
      ${sub ? `<div class="mt-0.5 text-xs text-ink-muted">${esc(sub)}</div>` : ""}
    </div>`;
}

function renderOverview(): string {
  const ctxs = selectedContextsList();

  if (ctxs.length === 1) {
    const ov = state.overviews.get(ctxs[0]);
    if (!ov) return `<div class="text-sm text-ink-muted">Loading…</div>`;
    if (!ov.reachable) {
      return `<div class="rounded-md border border-status-critical/40 bg-status-critical/10 p-4 text-sm text-status-critical">Cluster unreachable: ${esc(ov.error) || "unknown error"}</div>`;
    }
    return `
      <div class="grid grid-cols-2 gap-4 lg:grid-cols-4">
        ${statTile("Kubernetes version", ov.kubernetes_version || "—")}
        ${statTile("Nodes ready", `${ov.nodes_ready}/${ov.node_count}`, undefined, ov.nodes_ready === ov.node_count ? "good" : "critical")}
        ${statTile("Namespaces", String(ov.namespace_count))}
        ${statTile("Pods running", `${ov.pods_running}/${ov.pod_count}`, ov.pods_not_ready > 0 ? `${ov.pods_not_ready} not ready` : undefined, ov.pods_not_ready === 0 ? "good" : "warning")}
        ${statTile("Warning events", String(ov.warning_event_count), undefined, ov.warning_event_count === 0 ? "good" : "warning")}
      </div>`;
  }

  type OverviewRow = { ctx: string; ov: ClusterOverview | undefined };
  const rows: OverviewRow[] = ctxs.map((ctx) => ({ ctx, ov: state.overviews.get(ctx) }));
  const keyOf = (r: OverviewRow) => r.ctx;
  const columns: ColumnDef<OverviewRow>[] = [
    { key: "cluster", label: "Cluster", value: (r) => r.ctx, filter: "enum" },
    { key: "version", label: "K8s version", value: (r) => r.ov?.kubernetes_version ?? "", filter: "enum" },
    {
      key: "nodes_ready",
      label: "Nodes ready",
      value: (r) => r.ov?.nodes_ready ?? -1,
      filter: "number",
      copyText: (r) => (r.ov ? `${r.ov.nodes_ready}/${r.ov.node_count}` : ""),
    },
    { key: "namespaces", label: "Namespaces", value: (r) => r.ov?.namespace_count ?? -1, filter: "number" },
    {
      key: "pods_running",
      label: "Pods running",
      value: (r) => r.ov?.pods_running ?? -1,
      filter: "number",
      copyText: (r) => (r.ov ? `${r.ov.pods_running}/${r.ov.pod_count}` : ""),
    },
    { key: "warning_events", label: "Warning events", value: (r) => r.ov?.warning_event_count ?? -1, filter: "number" },
  ];
  const filtered = applyFilters("overview", rows, columns);
  const sorted = sortRows("overview", filtered, columns);
  recordTableSnapshot("overview", columns, sorted, keyOf, {
    header: "Status",
    text: (r) => (!r.ov ? "checking" : !r.ov.reachable ? "unreachable" : r.ov.nodes_ready === r.ov.node_count ? "healthy" : "degraded"),
  });

  return `
    ${filterSummary("overview", rows.length, filtered.length)}
    ${selectionToolbar("overview")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:overview">
      <table class="data-table">
        ${renderColGroup("overview", columns, [32, 36])}
        <thead>
          <tr>${selectAllCheckboxHeader("overview", sorted, keyOf)}<th></th>${sortableHeaderRow("overview", columns)}</tr>
          <tr class="filter-row"><th></th><th></th>${filterRowCells("overview", columns, rows)}</tr>
        </thead>
        <tbody>
          ${sorted
            .map(({ ctx, ov }) => {
              if (!ov) {
                return `<tr>${rowCheckboxCell("overview", ctx)}<td>${statusDot(false, true)}</td><td class="text-ink-primary">${esc(ctx)}</td><td colspan="5" class="text-ink-muted">checking…</td></tr>`;
              }
              if (!ov.reachable) {
                return `<tr>${rowCheckboxCell("overview", ctx)}<td>${statusDot(false)}</td><td class="text-ink-primary">${esc(ctx)}</td><td colspan="5" class="text-status-critical">unreachable: ${esc(ov.error) || "unknown error"}</td></tr>`;
              }
              return `
            <tr>
              ${rowCheckboxCell("overview", ctx)}
              <td>${statusDot(ov.nodes_ready === ov.node_count)}</td>
              <td class="text-ink-primary">${esc(ctx)}</td>
              <td>${esc(ov.kubernetes_version) || "—"}</td>
              <td class="tabular">${ov.nodes_ready}/${ov.node_count}</td>
              <td class="tabular">${ov.namespace_count}</td>
              <td class="tabular">${ov.pods_running}/${ov.pod_count}${ov.pods_not_ready > 0 ? ` <span class="text-status-warning">(${ov.pods_not_ready} not ready)</span>` : ""}</td>
              <td class="tabular ${ov.warning_event_count === 0 ? "" : "text-status-warning"}">${ov.warning_event_count}</td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
    </div>`;
}

function renderNodes(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;
  type NodeRow = { ctx: string; n: NodeInfo };
  const allRows: NodeRow[] = ctxs.flatMap((ctx) => (state.nodes.get(ctx) || []).map((n) => ({ ctx, n })));
  if (allRows.length === 0 && !state.tabLoading) return `<div class="text-sm text-ink-muted">No nodes found.</div>`;
  const rows = state.unhealthyOnly.nodes ? allRows.filter((r) => !r.n.ready) : allRows;
  const keyOf = (r: NodeRow) => `${r.ctx}:${r.n.name}`;

  const columns: ColumnDef<NodeRow>[] = [
    ...(multi ? [{ key: "cluster", label: "Cluster", value: (r: NodeRow) => r.ctx, filter: "enum" as const }] : []),
    { key: "name", label: "Name", value: (r) => r.n.name, filter: "string" },
    { key: "roles", label: "Roles", value: (r) => r.n.roles.join(", "), filter: "string" },
    {
      key: "cpu",
      label: "CPU (used/alloc)",
      value: (r) => r.n.cpu_usage_millicores ?? -1,
      filter: "number",
      copyText: (r) => `${formatMillicores(r.n.cpu_usage_millicores)} / ${r.n.cpu_allocatable}`,
    },
    {
      key: "memory",
      label: "Memory (used/alloc)",
      value: (r) => r.n.memory_usage_ki ?? -1,
      filter: "number",
      copyText: (r) => `${formatKi(r.n.memory_usage_ki)} / ${formatKi(r.n.memory_allocatable_ki)}`,
    },
    { key: "zone", label: "Zone", value: (r) => r.n.zone ?? "", filter: "enum" },
    { key: "instance_type", label: "Instance type", value: (r) => r.n.instance_type ?? "", filter: "enum" },
    { key: "node_pool", label: "Node Pool", value: (r) => r.n.node_pool ?? "", filter: "enum" },
    { key: "kubelet", label: "Kubelet", value: (r) => r.n.kubelet_version, filter: "enum" },
    {
      key: "age",
      label: "Age",
      value: (r) => r.n.age_days,
      filter: "number",
      copyText: (r) => formatAgeDetailed(r.n.age_days, r.n.age_seconds),
      sortValue: (r) => r.n.age_seconds,
    },
  ];
  const filtered = applyFilters("nodes", rows, columns);
  const sorted = sortRows("nodes", filtered, columns);
  recordTableSnapshot("nodes", columns, sorted, keyOf, {
    header: "Status",
    text: (r) => (r.n.ready ? "Ready" : "Not ready"),
  });
  const paged = pageSlice("nodes", sorted);

  return `
    <div class="mb-2 flex items-center justify-between">
      <div class="text-xs text-ink-muted">${state.unhealthyOnly.nodes ? `${rows.length} of ${allRows.length} unhealthy` : ""}</div>
      ${unhealthyOnlyToggle("nodes")}
    </div>
    ${filterSummary("nodes", rows.length, filtered.length)}
    ${selectionToolbar("nodes")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:nodes">
      <table class="data-table">
        ${renderColGroup("nodes", columns, [32, 36])}
        <thead>
          <tr>${selectAllCheckboxHeader("nodes", sorted, keyOf)}<th></th>${sortableHeaderRow("nodes", columns)}</tr>
          <tr class="filter-row"><th></th><th></th>${filterRowCells("nodes", columns, rows)}</tr>
        </thead>
        <tbody>
          ${paged
            .map(
              (row) => {
                const { ctx, n } = row;
                return `
            <tr>
              ${rowCheckboxCell("nodes", keyOf(row))}
              <td>${statusDot(n.ready)}</td>
              ${
                multi
                  ? `<td class="text-ink-muted"><button type="button" title="Filter nodes by this cluster" onclick="window.__app.setEnumFilter('nodes','cluster',[${jsArg(ctx)}])" class="hover:text-series-blue hover:underline">${esc(ctx)}</button></td>`
                  : ""
              }
              <td>
                <span class="inline-flex items-center gap-1.5">
                  <button
                    type="button"
                    title="View node details (YAML, Events, Graph)"
                    data-row-open onclick="window.__app.openNodeDetail(${jsArg(ctx)},${jsArg(n.name)})"
                    class="shrink-0 rounded p-0.5 text-ink-muted hover:bg-surface-3 hover:text-ink-primary"
                  >
                    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><line x1="12" y1="11" x2="12" y2="16.5"/><circle cx="12" cy="8" r="0.5" fill="currentColor" stroke="none"/></svg>
                  </button>
                  <button
                    type="button"
                    title="View pods on this node"
                    onclick="window.__app.viewPodsForNode(${jsArg(ctx)},${jsArg(n.name)})"
                    class="text-ink-primary hover:text-series-blue hover:underline"
                  >${esc(n.name)}</button>${n.unschedulable ? ' <span class="text-status-warning">(cordoned)</span>' : ""}
                </span>
              </td>
              <td>${n.roles.map(esc).join(", ")}</td>
              <td class="tabular">${formatMillicores(n.cpu_usage_millicores)} / ${esc(n.cpu_allocatable)}</td>
              <td class="tabular">${formatKi(n.memory_usage_ki)} / ${formatKi(n.memory_allocatable_ki)}</td>
              <td>${esc(n.zone) || "—"}</td>
              <td>
                ${
                  n.instance_type
                    ? `<button
                        type="button"
                        title="Filter nodes by this instance type"
                        onclick="window.__app.setEnumFilter('nodes','instance_type',[${jsArg(n.instance_type)}])"
                        class="hover:text-series-blue hover:underline"
                      >${esc(n.instance_type)}</button>`
                    : "—"
                }
              </td>
              <td>
                ${
                  n.node_pool
                    ? `<button
                        type="button"
                        title="Filter nodes by this node pool"
                        onclick="window.__app.setEnumFilter('nodes','node_pool',[${jsArg(n.node_pool)}])"
                        class="hover:text-series-blue hover:underline"
                      >${esc(n.node_pool)}</button>`
                    : "—"
                }
              </td>
              <td>${esc(n.kubelet_version)}</td>
              <td class="tabular">${formatAgeDetailed(n.age_days, n.age_seconds)}</td>
            </tr>`;
              },
            )
            .join("")}
        </tbody>
      </table>
      ${sorted.length === 0 && !state.tabLoading ? '<div class="p-4 text-sm text-ink-muted">No matching nodes.</div>' : ""}
    </div>
    ${renderPagination("nodes", sorted.length)}`;
}

function renderWorkloads(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;
  type WorkloadRow = { ctx: string; w: WorkloadInfo };
  const allRows: WorkloadRow[] = ctxs.flatMap((ctx) => (state.workloads.get(ctx) || []).map((w) => ({ ctx, w })));
  if (allRows.length === 0 && !state.tabLoading) return `<div class="text-sm text-ink-muted">No workloads found.</div>`;
  const rows = state.unhealthyOnly.workloads ? allRows.filter((r) => !r.w.healthy) : allRows;
  const keyOf = (r: WorkloadRow) => `${r.ctx}:${r.w.namespace}:${r.w.kind}:${r.w.name}`;

  const columns: ColumnDef<WorkloadRow>[] = [
    ...(multi ? [{ key: "cluster", label: "Cluster", value: (r: WorkloadRow) => r.ctx, filter: "enum" as const }] : []),
    { key: "kind", label: "Kind", value: (r) => r.w.kind, filter: "enum" },
    { key: "namespace", label: "Namespace", value: (r) => r.w.namespace, filter: "enum" },
    { key: "name", label: "Name", value: (r) => r.w.name, filter: "string" },
    { key: "version", label: "Version", value: (r) => r.w.version, filter: "string" },
    {
      key: "image",
      label: "Image",
      value: (r) => r.w.images.join(", "),
      filter: "string",
      copyText: (r) => r.w.images.join(", "),
    },
    { key: "desired", label: "Desired", value: (r) => r.w.desired, filter: "number" },
    { key: "ready", label: "Ready", value: (r) => r.w.ready, filter: "number" },
    { key: "updated", label: "Updated", value: (r) => r.w.updated, filter: "number" },
    { key: "available", label: "Available", value: (r) => r.w.available, filter: "number" },
    {
      key: "age",
      label: "Age",
      value: (r) => r.w.age_days,
      filter: "number",
      copyText: (r) => formatAgeDetailed(r.w.age_days, r.w.age_seconds),
      sortValue: (r) => r.w.age_seconds,
    },
  ];
  const filtered = applyFilters("workloads", rows, columns);
  const sorted = sortRows("workloads", filtered, columns);
  recordTableSnapshot("workloads", columns, sorted, keyOf, {
    header: "Status",
    text: (r) => (r.w.healthy ? "Healthy" : "Unhealthy"),
  });
  const paged = pageSlice("workloads", sorted);

  return `
    <div class="mb-2 flex items-center justify-between">
      <div class="text-xs text-ink-muted">${state.unhealthyOnly.workloads ? `${rows.length} of ${allRows.length} unhealthy` : ""}</div>
      ${unhealthyOnlyToggle("workloads")}
    </div>
    ${filterSummary("workloads", rows.length, filtered.length)}
    ${selectionToolbar("workloads")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:workloads">
      <table class="data-table">
        ${renderColGroup("workloads", columns, [32, 36])}
        <thead>
          <tr>${selectAllCheckboxHeader("workloads", sorted, keyOf)}<th></th>${sortableHeaderRow("workloads", columns)}</tr>
          <tr class="filter-row"><th></th><th></th>${filterRowCells("workloads", columns, rows)}</tr>
        </thead>
        <tbody>
          ${paged
            .map(
              (row) => {
                const { ctx, w } = row;
                return `
            <tr>
              ${rowCheckboxCell("workloads", keyOf(row))}
              <td>${statusDot(w.healthy)}</td>
              ${
                multi
                  ? `<td class="text-ink-muted"><button type="button" title="Filter workloads by this cluster" onclick="window.__app.setEnumFilter('workloads','cluster',[${jsArg(ctx)}])" class="hover:text-series-blue hover:underline">${esc(ctx)}</button></td>`
                  : ""
              }
              <td><button type="button" title="Filter workloads by this kind" onclick="window.__app.setEnumFilter('workloads','kind',[${jsArg(w.kind)}])" class="hover:text-series-blue hover:underline">${esc(w.kind)}</button></td>
              <td><button type="button" title="Filter workloads by this namespace" onclick="window.__app.setEnumFilter('workloads','namespace',[${jsArg(w.namespace)}])" class="hover:text-series-blue hover:underline">${esc(w.namespace)}</button></td>
              <td>
                <span class="inline-flex items-center gap-1.5">
                  <button
                    type="button"
                    title="View workload details (YAML, Events)"
                    data-row-open onclick="window.__app.openWorkloadDetail(${jsArg(ctx)},${jsArg(w.kind)},${jsArg(w.namespace)},${jsArg(w.name)})"
                    class="shrink-0 rounded p-0.5 text-ink-muted hover:bg-surface-3 hover:text-ink-primary"
                  >
                    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><line x1="12" y1="11" x2="12" y2="16.5"/><circle cx="12" cy="8" r="0.5" fill="currentColor" stroke="none"/></svg>
                  </button>
                  <button
                    type="button"
                    title="View pods for this workload"
                    onclick="window.__app.viewPodsForWorkload(${jsArg(ctx)},${jsArg(w.kind)},${jsArg(w.namespace)},${jsArg(w.name)})"
                    class="text-ink-primary hover:text-series-blue hover:underline"
                  >${esc(w.name)}</button>
                </span>
              </td>
              <td class="tabular" title="${esc(
                w.version
                  ? `${w.version_from_label ? "From the app.kubernetes.io/version label" : "Derived from the image tag"}${
                      w.chart ? ` · Helm chart ${w.chart}` : ""
                    }`
                  : "No version label and no image tag",
              )}">${esc(w.version) || "—"}${
                w.version && !w.version_from_label
                  ? ' <span class="text-ink-muted" title="Derived from the image tag, not a version label">~</span>'
                  : ""
              }</td>
              <td class="max-w-xs truncate" title="${esc(w.images.join(", "))}">${
                w.images.length > 0 ? esc(w.images.map(shortImageRef).join(", ")) : "—"
              }</td>
              <td class="tabular">${w.desired}</td>
              <td class="tabular">${w.ready}</td>
              <td class="tabular">${w.updated}</td>
              <td class="tabular">${w.available}</td>
              <td class="tabular">${formatAgeDetailed(w.age_days, w.age_seconds)}</td>
            </tr>`;
              },
            )
            .join("")}
        </tbody>
      </table>
      ${sorted.length === 0 && !state.tabLoading ? '<div class="p-4 text-sm text-ink-muted">No matching workloads.</div>' : ""}
    </div>
    ${renderPagination("workloads", sorted.length)}`;
}

/**
 * Drops the registry/org prefix from an image reference so the part that
 * actually varies between revisions — name and tag — is what's visible in a
 * narrow column. The full reference stays in the cell's tooltip.
 */
function shortImageRef(image: string): string {
  const lastSlash = image.lastIndexOf("/");
  return lastSlash === -1 ? image : image.slice(lastSlash + 1);
}

/** `"Deployment/foo"`, or "" for a pod with no resolved controller (e.g. a bare Pod). */
function ownerLabel(p: PodInfo): string {
  return p.owner_kind && p.owner_name ? `${p.owner_kind}/${p.owner_name}` : "";
}

function renderPods(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;
  type PodRow = { ctx: string; p: PodInfo };
  const allRows: PodRow[] = ctxs.flatMap((ctx) => (state.pods.get(ctx) || []).map((p) => ({ ctx, p })));
  if (allRows.length === 0 && !state.tabLoading) return `<div class="text-sm text-ink-muted">No pods found.</div>`;
  const podHealthy = (r: PodRow) => r.p.phase === "Running" || r.p.phase === "Succeeded";
  const rows = state.unhealthyOnly.pods ? allRows.filter((r) => !podHealthy(r)) : allRows;
  const keyOf = (r: PodRow) => `${r.ctx}:${r.p.namespace}:${r.p.name}`;

  const readyCount = (r: PodRow) => parseInt(r.p.ready.split("/")[0] ?? "0", 10) || 0;
  const columns: ColumnDef<PodRow>[] = [
    ...(multi ? [{ key: "cluster", label: "Cluster", value: (r: PodRow) => r.ctx, filter: "enum" as const }] : []),
    { key: "namespace", label: "Namespace", value: (r) => r.p.namespace, filter: "enum" },
    { key: "name", label: "Name", value: (r) => r.p.name, filter: "string" },
    { key: "ready", label: "Ready", value: readyCount, filter: "number", copyText: (r) => r.p.ready },
    { key: "restarts", label: "Restarts", value: (r) => r.p.restarts, filter: "number" },
    {
      key: "cpu",
      label: "CPU",
      value: (r) => r.p.cpu_usage_millicores ?? -1,
      filter: "number",
      copyText: (r) => formatMillicores(r.p.cpu_usage_millicores),
    },
    {
      key: "memory",
      label: "Memory",
      value: (r) => r.p.memory_usage_ki ?? -1,
      filter: "number",
      copyText: (r) => formatKi(r.p.memory_usage_ki),
    },
    { key: "node", label: "Node", value: (r) => r.p.node ?? "", filter: "enum" },
    { key: "owner", label: "Owner", value: (r) => ownerLabel(r.p), filter: "enum" },
    {
      key: "age",
      label: "Age",
      value: (r) => r.p.age_days,
      filter: "number",
      copyText: (r) => formatAgeDetailed(r.p.age_days, r.p.age_seconds),
      sortValue: (r) => r.p.age_seconds,
    },
  ];
  const filtered = applyFilters("pods", rows, columns);
  const sorted = sortRows("pods", filtered, columns);
  recordTableSnapshot("pods", columns, sorted, keyOf, {
    header: "Phase",
    text: (r) => r.p.phase,
  });
  const paged = pageSlice("pods", sorted);

  return `
    <div class="mb-2 flex items-center justify-between">
      <div class="text-xs text-ink-muted">${state.unhealthyOnly.pods ? `${rows.length} of ${allRows.length} unhealthy` : ""}</div>
      ${unhealthyOnlyToggle("pods")}
    </div>
    ${filterSummary("pods", rows.length, filtered.length)}
    ${selectionToolbar("pods")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:pods">
      <table class="data-table">
        ${renderColGroup("pods", columns, [32, 36])}
        <thead>
          <tr>${selectAllCheckboxHeader("pods", sorted, keyOf)}<th></th>${sortableHeaderRow("pods", columns)}</tr>
          <tr class="filter-row"><th></th><th></th>${filterRowCells("pods", columns, rows)}</tr>
        </thead>
        <tbody>
          ${paged
            .map((row) => {
              const { ctx, p } = row;
              return `
            <tr>
              ${rowCheckboxCell("pods", keyOf(row))}
              <td>${statusDot(podHealthy(row))}</td>
              ${
                multi
                  ? `<td class="text-ink-muted"><button type="button" title="Filter pods by this cluster" onclick="window.__app.setEnumFilter('pods','cluster',[${jsArg(ctx)}])" class="hover:text-series-blue hover:underline">${esc(ctx)}</button></td>`
                  : ""
              }
              <td><button type="button" title="Filter pods by this namespace" onclick="window.__app.setEnumFilter('pods','namespace',[${jsArg(p.namespace)}])" class="hover:text-series-blue hover:underline">${esc(p.namespace)}</button></td>
              <td>
                <button
                  type="button"
                  title="View pod details"
                  data-row-open onclick="window.__app.openPodDetail(${jsArg(ctx)},${jsArg(p.namespace)},${jsArg(p.name)})"
                  class="text-ink-primary hover:text-series-blue hover:underline"
                >${esc(p.name)}</button>
              </td>
              <td class="tabular">${esc(p.ready)}</td>
              <td class="tabular ${p.restarts > 0 ? "text-status-warning" : ""}">${p.restarts}</td>
              <td class="tabular">${formatMillicores(p.cpu_usage_millicores)}</td>
              <td class="tabular">${formatKi(p.memory_usage_ki)}</td>
              <td>
                ${
                  p.node
                    ? `<span class="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          title="View node details (YAML, Events, Graph)"
                          onclick="window.__app.openNodeDetail(${jsArg(ctx)},${jsArg(p.node)})"
                          class="shrink-0 rounded p-0.5 text-ink-muted hover:bg-surface-3 hover:text-ink-primary"
                        >
                          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><line x1="12" y1="11" x2="12" y2="16.5"/><circle cx="12" cy="8" r="0.5" fill="currentColor" stroke="none"/></svg>
                        </button>
                        <button
                          type="button"
                          title="View pods on this node"
                          onclick="window.__app.viewPodsForNode(${jsArg(ctx)},${jsArg(p.node)})"
                          class="text-ink-primary hover:text-series-blue hover:underline"
                        >${esc(p.node)}</button>
                      </span>`
                    : "—"
                }
              </td>
              <td class="text-ink-muted">
                ${
                  ownerLabel(p)
                    ? `<button
                        type="button"
                        title="Filter pods by this owner"
                        onclick="window.__app.setEnumFilter('pods','owner',[${jsArg(ownerLabel(p))}])"
                        class="hover:text-series-blue hover:underline"
                      >${esc(ownerLabel(p))}</button>`
                    : "—"
                }
              </td>
              <td class="tabular">${formatAgeDetailed(p.age_days, p.age_seconds)}</td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
      ${sorted.length === 0 && !state.tabLoading ? '<div class="p-4 text-sm text-ink-muted">No matching pods.</div>' : ""}
    </div>
    ${renderPagination("pods", sorted.length)}`;
}

function usageBar(pct: number): string {
  const tone = pct >= 90 ? "bg-status-critical" : pct >= 75 ? "bg-status-warning" : "bg-series-blue";
  return `
    <div class="h-2 w-full overflow-hidden rounded-full bg-surface-3">
      <div class="h-full ${tone}" style="width: ${pct}%"></div>
    </div>`;
}

function renderResources(): string {
  const ctxs = selectedContextsList();

  if (ctxs.length === 1) {
    const ru = state.resourceUsage.get(ctxs[0]);
    if (!ru) return `<div class="text-sm text-ink-muted">Loading…</div>`;
    if (!ru.metrics_available) {
      return `
        <div class="rounded-md border border-gridline bg-surface-1 p-4 text-sm text-ink-secondary">
          metrics-server does not appear to be reporting on this cluster, so live CPU/memory usage isn't available.
          Allocatable capacity below still reflects real node specs.
        </div>
        <div class="mt-4 grid grid-cols-2 gap-4">
          ${statTile("CPU allocatable", formatMillicores(ru.cpu_allocatable_millicores))}
          ${statTile("Memory allocatable", formatKi(ru.memory_allocatable_ki))}
        </div>`;
    }
    const cpuPct = formatPct(ru.cpu_used_millicores, ru.cpu_allocatable_millicores);
    const memPct = formatPct(ru.memory_used_ki, ru.memory_allocatable_ki);
    return `
      <div class="grid gap-4 lg:grid-cols-2">
        <div class="rounded-lg border border-gridline bg-surface-1 p-4">
          <div class="flex items-baseline justify-between">
            <div class="text-xs text-ink-muted">CPU usage</div>
            <div class="text-xs tabular text-ink-secondary">${formatMillicores(ru.cpu_used_millicores)} / ${formatMillicores(ru.cpu_allocatable_millicores)}</div>
          </div>
          <div class="mt-2 text-2xl font-semibold tabular">${cpuPct}%</div>
          <div class="mt-2">${usageBar(cpuPct)}</div>
        </div>
        <div class="rounded-lg border border-gridline bg-surface-1 p-4">
          <div class="flex items-baseline justify-between">
            <div class="text-xs text-ink-muted">Memory usage</div>
            <div class="text-xs tabular text-ink-secondary">${formatKi(ru.memory_used_ki)} / ${formatKi(ru.memory_allocatable_ki)}</div>
          </div>
          <div class="mt-2 text-2xl font-semibold tabular">${memPct}%</div>
          <div class="mt-2">${usageBar(memPct)}</div>
        </div>
      </div>`;
  }

  type ResourceRow = { ctx: string; ru: ResourceUsageSummary | undefined };
  const rows: ResourceRow[] = ctxs.map((ctx) => ({ ctx, ru: state.resourceUsage.get(ctx) }));
  const keyOf = (r: ResourceRow) => r.ctx;
  const cpuPctOf = (ru: ResourceUsageSummary) => formatPct(ru.cpu_used_millicores, ru.cpu_allocatable_millicores);
  const memPctOf = (ru: ResourceUsageSummary) => formatPct(ru.memory_used_ki, ru.memory_allocatable_ki);
  const columns: ColumnDef<ResourceRow>[] = [
    { key: "cluster", label: "Cluster", value: (r) => r.ctx, filter: "enum" },
    {
      key: "cpu_used",
      label: "CPU used/alloc",
      value: (r) => r.ru?.cpu_used_millicores ?? -1,
      filter: "number",
      copyText: (r) => (r.ru ? `${formatMillicores(r.ru.cpu_used_millicores)} / ${formatMillicores(r.ru.cpu_allocatable_millicores)}` : ""),
    },
    {
      key: "cpu_pct",
      label: "CPU %",
      value: (r) => (r.ru?.metrics_available ? cpuPctOf(r.ru) : -1),
      filter: "number",
      copyText: (r) => (r.ru?.metrics_available ? `${cpuPctOf(r.ru)}%` : "no metrics"),
    },
    {
      key: "mem_used",
      label: "Memory used/alloc",
      value: (r) => r.ru?.memory_used_ki ?? -1,
      filter: "number",
      copyText: (r) => (r.ru ? `${formatKi(r.ru.memory_used_ki)} / ${formatKi(r.ru.memory_allocatable_ki)}` : ""),
    },
    {
      key: "mem_pct",
      label: "Memory %",
      value: (r) => (r.ru?.metrics_available ? memPctOf(r.ru) : -1),
      filter: "number",
      copyText: (r) => (r.ru?.metrics_available ? `${memPctOf(r.ru)}%` : "no metrics"),
    },
  ];
  const filtered = applyFilters("resources", rows, columns);
  const sorted = sortRows("resources", filtered, columns);
  recordTableSnapshot("resources", columns, sorted, keyOf);

  return `
    ${filterSummary("resources", rows.length, filtered.length)}
    ${selectionToolbar("resources")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:resources">
      <table class="data-table">
        ${renderColGroup("resources", columns, [32])}
        <thead>
          <tr>${selectAllCheckboxHeader("resources", sorted, keyOf)}${sortableHeaderRow("resources", columns)}</tr>
          <tr class="filter-row"><th></th>${filterRowCells("resources", columns, rows)}</tr>
        </thead>
        <tbody>
          ${sorted
            .map((row) => {
              const { ctx, ru } = row;
              const checkbox = rowCheckboxCell("resources", keyOf(row));
              if (!ru) return `<tr>${checkbox}<td class="text-ink-primary">${esc(ctx)}</td><td colspan="4" class="text-ink-muted">checking…</td></tr>`;
              if (!ru.metrics_available) {
                return `
              <tr>
                ${checkbox}
                <td class="text-ink-primary">${esc(ctx)}</td>
                <td colspan="2" class="text-ink-muted">no metrics · ${formatMillicores(ru.cpu_allocatable_millicores)} allocatable</td>
                <td colspan="2" class="text-ink-muted">no metrics · ${formatKi(ru.memory_allocatable_ki)} allocatable</td>
              </tr>`;
              }
              const cpuPct = cpuPctOf(ru);
              const memPct = memPctOf(ru);
              return `
            <tr>
              ${checkbox}
              <td class="text-ink-primary">${esc(ctx)}</td>
              <td class="tabular">${formatMillicores(ru.cpu_used_millicores)} / ${formatMillicores(ru.cpu_allocatable_millicores)}</td>
              <td class="tabular">${cpuPct}%</td>
              <td class="tabular">${formatKi(ru.memory_used_ki)} / ${formatKi(ru.memory_allocatable_ki)}</td>
              <td class="tabular">${memPct}%</td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
    </div>`;
}

const METRICS_RANGE_OPTIONS: [number, string][] = [
  [15, "15m"],
  [30, "30m"],
  [60, "1h"],
  [180, "3h"],
  [360, "6h"],
  [1440, "24h"],
];

// ---------------------------------------------------------------------------
// Time-series charts (Metrics tab)
//
// Axis labels and the legend swatch are plain HTML/CSS around the SVG rather
// than SVG <text>, since the SVG itself uses `preserveAspectRatio="none"` to
// fill its container — text set in viewBox units would stretch unevenly
// under that non-uniform scaling, but a stretched line has no such
// readability problem. Hover tracking mutates the crosshair/dot/tooltip
// elements directly (via a per-chart registry, keyed by chartId) rather than
// going through the app's normal state+render() cycle: re-rendering the
// whole #app subtree on every mousemove would be far too janky for a
// tooltip that needs to track the cursor smoothly.
// ---------------------------------------------------------------------------

interface ChartInfo {
  samples: { timestamp: number; value: number }[];
  format: (v: number) => string;
  width: number;
  height: number;
}

const chartRegistry = new Map<string, ChartInfo>();

/**
 * Y-axis range used to *plot* a chart's line/area/crosshair — padded a bit
 * past the data's actual min/max so a metric that's nearly flat right at
 * its window's ceiling or floor (e.g. memory usage pinned near its limit)
 * doesn't render its line directly on top of the chart's own top/bottom
 * border gridline. Without the padding, tiny real fluctuations cause the
 * data line and the border line to interleave pixel-for-pixel — a
 * moiré-style flicker, far more visible against light theme's lower-contrast
 * gridline than dark theme's. Axis labels still show the true (unpadded)
 * min/max — only the plotted position gets this headroom.
 */
function chartPlotRange(samples: { value: number }[]): { min: number; max: number; range: number } {
  const values = samples.map((s) => s.value);
  const rawMax = Math.max(...values, 0);
  const rawMin = Math.min(...values, 0);
  const rawRange = rawMax - rawMin || 1;
  const padding = rawRange * 0.08;
  return { min: rawMin - padding, max: rawMax + padding, range: rawRange + padding * 2 };
}

// A background auto-refresh tick calls render(), which replaces the whole
// #app subtree — including whichever chart is mid-hover — with a freshly
// templated (and thus freshly hidden) tooltip/crosshair/dot. Nothing dispatches
// a mouseleave just because the old DOM node was discarded, so without this
// the tooltip would simply vanish out from under a cursor that never moved.
// Tracking the last hover position per chart (independent of the DOM) lets
// render() replay it against the new elements afterwards.
const hoveredCharts = new Map<string, { clientX: number; clientY: number }>();

function formatClockTime(epochSeconds: number): string {
  const d = new Date(epochSeconds * 1000);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

function positionChartHover(container: HTMLElement, chartId: string, clientX: number, clientY: number) {
  const info = chartRegistry.get(chartId);
  if (!info || info.samples.length === 0) return;
  const svg = container.querySelector<SVGSVGElement>("[data-chart-svg]");
  const tooltip = container.querySelector<HTMLElement>("[data-chart-tooltip]");
  const crosshair = container.querySelector<SVGLineElement>("[data-chart-crosshair]");
  const dot = container.querySelector<SVGCircleElement>("[data-chart-dot]");
  if (!svg || !tooltip || !crosshair || !dot) return;

  const { samples, format, width, height } = info;
  const svgRect = svg.getBoundingClientRect();
  if (svgRect.width === 0) return;
  const frac = Math.min(1, Math.max(0, (clientX - svgRect.left) / svgRect.width));
  const idx = Math.min(samples.length - 1, Math.max(0, Math.round(frac * (samples.length - 1))));
  const sample = samples[idx];

  const { min: plotMin, range: plotRange } = chartPlotRange(samples);
  const xVb = samples.length > 1 ? (idx / (samples.length - 1)) * width : width / 2;
  const yVb = height - ((sample.value - plotMin) / plotRange) * height;

  crosshair.setAttribute("x1", String(xVb));
  crosshair.setAttribute("x2", String(xVb));
  crosshair.style.display = "";
  dot.setAttribute("cx", String(xVb));
  dot.setAttribute("cy", String(yVb));
  dot.style.display = "";

  tooltip.textContent = `${formatClockTime(sample.timestamp)} · ${format(sample.value)}`;
  tooltip.classList.remove("hidden");

  // Positioned beside the cursor rather than on the data point: anchoring it
  // to the point put it under the pointer whenever the cursor was near the
  // line. Sits to the cursor's right by default and flips to the left when
  // that would overflow the container, so the gap is preserved on both edges.
  const containerRect = container.getBoundingClientRect();
  const cursorX = clientX - containerRect.left;
  const cursorY = clientY - containerRect.top;
  const gap = 14;
  const tipWidth = tooltip.offsetWidth;
  const tipHeight = tooltip.offsetHeight;

  const left = cursorX + gap + tipWidth <= container.clientWidth ? cursorX + gap : cursorX - gap - tipWidth;
  const top = cursorY - tipHeight - gap >= 0 ? cursorY - tipHeight - gap : cursorY + gap;

  tooltip.style.left = `${Math.min(Math.max(left, 0), Math.max(0, container.clientWidth - tipWidth))}px`;
  tooltip.style.top = `${Math.max(top, 0)}px`;
}

function handleChartHover(e: MouseEvent, chartId: string) {
  hoveredCharts.set(chartId, { clientX: e.clientX, clientY: e.clientY });
  positionChartHover(e.currentTarget as HTMLElement, chartId, e.clientX, e.clientY);
}

function handleChartHoverEnd(chartId: string) {
  hoveredCharts.delete(chartId);
  const container = document.querySelector<HTMLElement>(`[data-chart-id="${chartId}"]`);
  container?.querySelector<HTMLElement>("[data-chart-tooltip]")?.classList.add("hidden");
  const crosshair = container?.querySelector<SVGLineElement>("[data-chart-crosshair]");
  if (crosshair) crosshair.style.display = "none";
  const dot = container?.querySelector<SVGCircleElement>("[data-chart-dot]");
  if (dot) dot.style.display = "none";
}

/** Re-applies any still-active chart hover(s) after render() has rebuilt the DOM from scratch. */
function restoreChartHovers(app: HTMLElement) {
  hoveredCharts.forEach((pos, chartId) => {
    const container = app.querySelector<HTMLElement>(`[data-chart-id="${chartId}"]`);
    if (container) {
      positionChartHover(container, chartId, pos.clientX, pos.clientY);
    } else {
      hoveredCharts.delete(chartId);
    }
  });
}

function renderTimeSeriesChart(
  chartId: string,
  samples: { timestamp: number; value: number }[],
  color: string,
  format: (v: number) => string,
): string {
  if (samples.length === 0) {
    chartRegistry.delete(chartId);
    return `<div class="flex h-[140px] items-center justify-center text-xs text-ink-muted">No data returned for this range.</div>`;
  }
  const width = 600;
  const height = 140;
  chartRegistry.set(chartId, { samples, format, width, height });

  const values = samples.map((s) => s.value);
  const maxV = Math.max(...values, 0);
  const minV = Math.min(...values, 0);
  const midV = (maxV + minV) / 2;
  const { min: plotMin, range: plotRange } = chartPlotRange(samples);
  const xStep = samples.length > 1 ? width / (samples.length - 1) : 0;
  const points = samples.map((s, i) => {
    const x = i * xStep;
    const y = height - ((s.value - plotMin) / plotRange) * height;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const linePath = `M${points.join(" L")}`;
  const lastX = (samples.length > 1 ? (samples.length - 1) * xStep : width).toFixed(1);
  const areaPath = `${linePath} L${lastX},${height} L0,${height} Z`;

  const startLabel = formatClockTime(samples[0].timestamp);
  const endLabel = formatClockTime(samples[samples.length - 1].timestamp);
  const midLabel = formatClockTime(samples[Math.floor((samples.length - 1) / 2)].timestamp);

  return `
    <div class="flex gap-2">
      <div class="flex h-[140px] w-10 shrink-0 flex-col justify-between text-right text-[10px] tabular text-ink-muted">
        <span>${esc(format(maxV))}</span>
        <span>${esc(format(midV))}</span>
        <span>${esc(format(minV))}</span>
      </div>
      <div class="min-w-0 flex-1">
        <div
          class="relative"
          data-chart-id="${chartId}"
          onmousemove="window.__app.handleChartHover(event,${jsArg(chartId)})"
          onmouseleave="window.__app.handleChartHoverEnd(${jsArg(chartId)})"
        >
          <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" class="h-[140px] w-full cursor-crosshair" data-chart-svg>
            <line x1="0" y1="0" x2="${width}" y2="0" stroke="var(--gridline)" stroke-width="1" />
            <line x1="0" y1="${height / 2}" x2="${width}" y2="${height / 2}" stroke="var(--gridline)" stroke-width="1" stroke-dasharray="2,3" />
            <line x1="0" y1="${height}" x2="${width}" y2="${height}" stroke="var(--gridline)" stroke-width="1" />
            <path d="${areaPath}" fill="${color}" fill-opacity="0.12" stroke="none" />
            <path d="${linePath}" fill="none" stroke="${color}" stroke-width="1.5" />
            <line data-chart-crosshair x1="0" y1="0" x2="0" y2="${height}" stroke="var(--text-muted)" stroke-width="1" stroke-dasharray="2,2" style="display:none" />
            <circle data-chart-dot r="3" fill="${color}" stroke="var(--surface-1)" stroke-width="1.5" style="display:none" />
          </svg>
          <div data-chart-tooltip class="pointer-events-none absolute z-10 hidden whitespace-nowrap rounded-md border border-gridline bg-surface-3 px-2 py-1 text-xs text-ink-primary shadow-lg"></div>
        </div>
        <div class="mt-1 flex justify-between text-[10px] tabular text-ink-muted">
          <span>${esc(startLabel)}</span>
          <span>${esc(midLabel)}</span>
          <span>${esc(endLabel)}</span>
        </div>
      </div>
    </div>`;
}

function chartLegendLabel(color: string, label: string): string {
  return `<span class="inline-flex items-center gap-1.5"><span class="inline-block h-2 w-2 shrink-0 rounded-full" style="background:${color}"></span>${esc(label)}</span>`;
}

// ---------------------------------------------------------------------------
// Claude: auth + explain-error
// ---------------------------------------------------------------------------

function toggleClaudePanel() {
  state.claudePanelOpen = !state.claudePanelOpen;
  render();
  // Re-probe on open so a sign-in completed in a terminal is reflected without
  // restarting the app.
  if (state.claudePanelOpen) refreshClaudeAuth();
}

async function refreshClaudeAuth() {
  try {
    state.claudeAuth = await api.claudeAuthStatus();
  } catch {
    // Treated as "unavailable" rather than an error banner — Claude is an
    // optional add-on, and a failure here shouldn't disrupt cluster work.
    state.claudeAuth = { signed_in: false, source: null, detail: null };
  }
  render();
}

async function saveClaudeApiKey() {
  const input = document.querySelector<HTMLInputElement>("[data-claude-key-input]");
  const key = input?.value?.trim();
  if (!key) return;
  try {
    state.claudeAuth = await api.claudeSetApiKey(key);
    // Clear the field immediately — the key lives in the Keychain now, and
    // leaving it in the DOM serves no purpose.
    if (input) input.value = "";
  } catch (e) {
    if (state.claudeAuth) state.claudeAuth.detail = String(e);
  }
  render();
}

async function clearClaudeApiKey() {
  try {
    state.claudeAuth = await api.claudeClearApiKey();
  } catch (e) {
    if (state.claudeAuth) state.claudeAuth.detail = String(e);
  }
  render();
}

function closeClaudeDiagnose() {
  claudeDiagnoseToken += 1;
  state.claudeDiagnose = null;
  render();
}

function toggleDiagnosePayload() {
  if (!state.claudeDiagnose) return;
  state.claudeDiagnose.showPayload = !state.claudeDiagnose.showPayload;
  render();
}

/**
 * Step 1: assemble and show the payload. Nothing is sent yet — this exists so
 * the log data leaving the machine is reviewable rather than implied.
 */
async function diagnosePod(ctx: string, namespace: string, podName: string, container: string) {
  const token = ++claudeDiagnoseToken;
  closeClaudeExplain();
  state.claudeDiagnose = {
    ctx,
    namespace,
    podName,
    container,
    payload: null,
    sent: false,
    showPayload: false,
    answer: "",
    streaming: false,
    error: null,
  };
  render();

  try {
    const payload = await api.claudeBuildDiagnosis(ctx, namespace, podName, container);
    if (token !== claudeDiagnoseToken || !state.claudeDiagnose) return;
    state.claudeDiagnose.payload = payload;
  } catch (e) {
    if (token !== claudeDiagnoseToken || !state.claudeDiagnose) return;
    state.claudeDiagnose.error = String(e);
  }
  render();
}

/** Step 2: send the previewed payload verbatim. */
async function confirmDiagnose() {
  const d = state.claudeDiagnose;
  if (!d?.payload || d.sent) return;
  const token = claudeDiagnoseToken;
  d.sent = true;
  d.streaming = true;
  d.answer = "";
  render();

  try {
    // Sends the previewed prompt rather than re-gathering, so what goes out is
    // exactly what was shown.
    await api.claudeDiagnose(d.payload.prompt, (chunk) => {
      if (token !== claudeDiagnoseToken || !state.claudeDiagnose) return;
      state.claudeDiagnose.answer += chunk;
      if (!claudeRenderScheduled) {
        claudeRenderScheduled = true;
        requestAnimationFrame(() => {
          claudeRenderScheduled = false;
          render();
        });
      }
    });
    if (token !== claudeDiagnoseToken || !state.claudeDiagnose) return;
    state.claudeDiagnose.streaming = false;
  } catch (e) {
    if (token !== claudeDiagnoseToken || !state.claudeDiagnose) return;
    state.claudeDiagnose.streaming = false;
    state.claudeDiagnose.error = String(e);
  }
  render();
}

function closeClaudeExplain() {
  claudeExplainToken += 1;
  state.claudeExplain = null;
  render();
}

/**
 * Opens the explain panel for one error string. Only this string is sent —
 * no logs, manifests or cluster identifiers — which is what keeps this the
 * lowest-exposure Claude feature in the app.
 */
async function explainError(subject: string, errorText: string) {
  if (!errorText.trim()) return;
  const token = ++claudeExplainToken;
  state.claudeExplain = { errorText, subject, answer: "", streaming: true, error: null };
  render();

  try {
    await api.claudeExplainError(errorText, (chunk) => {
      if (token !== claudeExplainToken || !state.claudeExplain) return;
      state.claudeExplain.answer += chunk;
      // Coalesce bursts of deltas into one render per frame — a full re-render
      // per token would thrash, same reasoning as the log-follow path.
      if (!claudeRenderScheduled) {
        claudeRenderScheduled = true;
        requestAnimationFrame(() => {
          claudeRenderScheduled = false;
          render();
        });
      }
    });
    if (token !== claudeExplainToken || !state.claudeExplain) return;
    state.claudeExplain.streaming = false;
  } catch (e) {
    if (token !== claudeExplainToken || !state.claudeExplain) return;
    state.claudeExplain.streaming = false;
    state.claudeExplain.error = String(e);
  }
  render();
}

// ---------------------------------------------------------------------------
// Datasource editor (Metrics tab)
// ---------------------------------------------------------------------------

function openMetricsBackendEditor(ctx: string) {
  state.metricsBackendEditor = ctx;
  state.metricsBackendCandidates = null;
  state.metricsBackendTest = null;
  state.metricsBackendTesting = false;
  // Seed the form from the active override, or from whatever the last
  // discovery reported, so editing starts from the real current value rather
  // than an empty form.
  const active = metricsBackendFor(ctx) ?? state.metricsOverTime.get(ctx)?.backend ?? null;
  state.metricsBackendDraft = active
    ? { ...active }
    : { kind: "VictoriaMetrics", namespace: "", service_name: "", port: 8428, api_path_prefix: "" };
  render();

  api
    .listMetricsBackends(ctx)
    .then((candidates) => {
      if (state.metricsBackendEditor !== ctx) return;
      state.metricsBackendCandidates = candidates;
      render();
    })
    .catch(() => {
      if (state.metricsBackendEditor !== ctx) return;
      // Discovery failing doesn't block a manual override — that's arguably
      // the case where overriding matters most.
      state.metricsBackendCandidates = [];
      render();
    });
}

function closeMetricsBackendEditor() {
  state.metricsBackendEditor = null;
  state.metricsBackendCandidates = null;
  state.metricsBackendDraft = null;
  state.metricsBackendTest = null;
  render();
}

function setMetricsBackendField(field: keyof MetricsBackendInfo, value: string) {
  const draft = state.metricsBackendDraft;
  if (!draft) return;
  if (field === "port") draft.port = Math.max(1, Math.min(65535, Number(value) || 0));
  else if (field === "kind") draft.kind = value === "Prometheus" ? "Prometheus" : "VictoriaMetrics";
  else if (field === "namespace") draft.namespace = value.trim();
  else if (field === "service_name") draft.service_name = value.trim();
  else if (field === "api_path_prefix") draft.api_path_prefix = value.trim();
  // A previous verdict no longer describes the edited draft.
  state.metricsBackendTest = null;
  render();
}

/** Load one of the discovered candidates into the form. */
function pickMetricsBackendCandidate(index: number) {
  const candidate = state.metricsBackendCandidates?.[index];
  if (!candidate) return;
  state.metricsBackendDraft = { ...candidate };
  state.metricsBackendTest = null;
  render();
}

async function testMetricsBackendDraft() {
  const ctx = state.metricsBackendEditor;
  const draft = state.metricsBackendDraft;
  if (!ctx || !draft) return;
  state.metricsBackendTesting = true;
  state.metricsBackendTest = null;
  render();
  try {
    const result = await api.testMetricsBackend(ctx, draft);
    if (state.metricsBackendEditor !== ctx) return;
    state.metricsBackendTest = result;
  } catch (e) {
    if (state.metricsBackendEditor !== ctx) return;
    state.metricsBackendTest = { ok: false, message: String(e), container_series: null };
  } finally {
    if (state.metricsBackendEditor === ctx) state.metricsBackendTesting = false;
    render();
  }
}

function saveMetricsBackendOverride() {
  const ctx = state.metricsBackendEditor;
  const draft = state.metricsBackendDraft;
  if (!ctx || !draft || !draft.namespace || !draft.service_name) return;
  state.metricsBackendOverrides.set(ctx, { ...draft });
  saveMetricsBackendOverrides();
  closeMetricsBackendEditor();
  // Drop the cached series so the tab refetches through the new datasource
  // instead of showing the old backend's data until the next refresh tick.
  state.metricsOverTime.delete(ctx);
  loadTabData();
}

function clearMetricsBackendOverride() {
  const ctx = state.metricsBackendEditor;
  if (!ctx) return;
  state.metricsBackendOverrides.delete(ctx);
  saveMetricsBackendOverrides();
  closeMetricsBackendEditor();
  state.metricsOverTime.delete(ctx);
  loadTabData();
}

function datasourceEditButton(ctx: string, label: string): string {
  return `
    <button
      type="button"
      onclick="window.__app.openMetricsBackendEditor(${jsArg(ctx)})"
      class="rounded border border-gridline px-2 py-0.5 text-xs text-ink-secondary hover:bg-surface-3 hover:text-ink-primary"
    >${esc(label)}</button>`;
}

/** The "which datasource am I looking at" line above each cluster's charts. */
function renderDatasourceRow(ctx: string, backend: MetricsBackendInfo): string {
  const overridden = metricsBackendFor(ctx) !== null;
  const target = `${backend.namespace}/${backend.service_name}:${backend.port}${backend.api_path_prefix}`;
  return `
    <div class="mb-3 flex flex-wrap items-center gap-2 text-xs text-ink-muted">
      <span>${esc(backend.kind)} · ${esc(target)}</span>
      ${
        overridden
          ? '<span class="rounded bg-surface-3 px-1.5 py-0.5 text-ink-secondary" title="Set manually — auto-discovery is bypassed for this cluster">manual</span>'
          : '<span class="text-ink-muted" title="Chosen by scoring Service names in this cluster">auto-discovered</span>'
      }
      ${datasourceEditButton(ctx, "Change")}
    </div>`;
}

function renderMetricsBackendEditor(): string {
  const ctx = state.metricsBackendEditor;
  const draft = state.metricsBackendDraft;
  if (!ctx || !draft) return "";

  const candidates = state.metricsBackendCandidates;
  const overridden = metricsBackendFor(ctx) !== null;
  const test = state.metricsBackendTest;

  const candidateList =
    candidates === null
      ? `<div class="text-xs text-ink-muted">Scanning services…</div>`
      : candidates.length === 0
        ? `<div class="text-xs text-ink-muted">No candidates auto-detected — enter one below.</div>`
        : candidates
            .map((c, i) => {
              const same =
                c.namespace === draft.namespace &&
                c.service_name === draft.service_name &&
                c.port === draft.port &&
                c.api_path_prefix === draft.api_path_prefix;
              return `
        <button
          type="button"
          onclick="window.__app.pickMetricsBackendCandidate(${i})"
          class="flex w-full items-center justify-between gap-2 rounded border px-2 py-1.5 text-left text-xs ${
            same ? "border-series-blue bg-surface-3 text-ink-primary" : "border-gridline text-ink-secondary hover:bg-surface-3"
          }"
        >
          <span class="truncate">${esc(c.namespace)}/${esc(c.service_name)}:${c.port}${esc(c.api_path_prefix)}</span>
          <span class="shrink-0 text-ink-muted">${esc(c.kind)}${i === 0 ? " · best guess" : ""}</span>
        </button>`;
            })
            .join("");

  const field = (label: string, key: string, value: string, placeholder: string, type = "text") => `
    <label class="flex flex-col gap-1 text-xs text-ink-secondary">
      ${esc(label)}
      <input
        type="${type}"
        value="${esc(value)}"
        placeholder="${esc(placeholder)}"
        data-filter-key="metrics-backend:${key}"
        oninput="window.__app.setMetricsBackendField(${jsArg(key)}, this.value)"
        class="rounded border border-gridline bg-surface-2 px-2 py-1 text-ink-primary outline-none focus:border-series-blue"
      />
    </label>`;

  const verdict = test
    ? `<div class="rounded-md border p-2 text-xs ${
        test.ok
          ? "border-status-good/40 bg-status-good/10 text-status-good"
          : "border-status-critical/40 bg-status-critical/10 text-status-critical"
      }">${esc(test.message)}</div>`
    : "";

  const canSave = draft.namespace.length > 0 && draft.service_name.length > 0;

  return `
    <div class="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-6" onclick="window.__app.closeMetricsBackendEditor()">
      <div class="flex max-h-full w-full max-w-xl flex-col overflow-auto rounded-lg border border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">Time-series data source</div>
            <div class="truncate text-xs text-ink-muted">${esc(ctx)}</div>
          </div>
          <button type="button" onclick="window.__app.closeMetricsBackendEditor()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>

        <div class="flex flex-col gap-4 p-4">
          <div class="flex flex-col gap-1.5">
            <div class="text-xs font-medium text-ink-primary">Detected candidates</div>
            ${candidateList}
          </div>

          <div class="flex flex-col gap-2 border-t border-gridline pt-3">
            <div class="text-xs font-medium text-ink-primary">Connection</div>
            <div class="grid grid-cols-2 gap-2">
              ${field("Namespace", "namespace", draft.namespace, "monitoring")}
              ${field("Service", "service_name", draft.service_name, "prometheus-server")}
              ${field("Port", "port", String(draft.port), "8428", "number")}
              <label class="flex flex-col gap-1 text-xs text-ink-secondary">
                Kind
                <select
                  onchange="window.__app.setMetricsBackendField('kind', this.value)"
                  class="rounded border border-gridline bg-surface-2 px-2 py-1 text-ink-primary outline-none"
                >
                  <option value="VictoriaMetrics" ${draft.kind === "VictoriaMetrics" ? "selected" : ""}>VictoriaMetrics</option>
                  <option value="Prometheus" ${draft.kind === "Prometheus" ? "selected" : ""}>Prometheus</option>
                </select>
              </label>
            </div>
            ${field("API path prefix", "api_path_prefix", draft.api_path_prefix, "empty, or /select/0/prometheus for vmselect")}
            <div class="text-xs text-ink-muted">
              Queried through the API server proxy:
              <code class="rounded bg-surface-2 px-1 py-0.5">/api/v1/namespaces/${esc(draft.namespace || "&lt;ns&gt;")}/services/${esc(draft.service_name || "&lt;svc&gt;")}:${draft.port}/proxy${esc(draft.api_path_prefix)}/api/v1/query_range</code>
            </div>
          </div>

          ${verdict}

          <div class="flex flex-wrap items-center justify-between gap-2 border-t border-gridline pt-3">
            <div class="flex items-center gap-2">
              <button
                type="button"
                onclick="window.__app.testMetricsBackendDraft()"
                ${!canSave || state.metricsBackendTesting ? "disabled" : ""}
                class="rounded-md border border-gridline px-3 py-1.5 text-xs text-ink-primary hover:bg-surface-3 disabled:cursor-not-allowed disabled:opacity-50"
              >${state.metricsBackendTesting ? "Testing…" : "Test connection"}</button>
              ${
                overridden
                  ? `<button
                      type="button"
                      onclick="window.__app.clearMetricsBackendOverride()"
                      class="rounded-md px-3 py-1.5 text-xs text-ink-secondary hover:bg-surface-3 hover:text-ink-primary"
                      title="Go back to auto-discovery for this cluster"
                    >Reset to auto</button>`
                  : ""
              }
            </div>
            <button
              type="button"
              onclick="window.__app.saveMetricsBackendOverride()"
              ${!canSave ? "disabled" : ""}
              class="rounded-md bg-series-blue px-3 py-1.5 text-xs font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
            >Save</button>
          </div>
        </div>
      </div>
    </div>`;
}

function renderMetrics(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;

  const header = `
    <div class="mb-3 flex items-center justify-end">
      <select
        class="rounded-md border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-secondary outline-none"
        onchange="window.__app.setMetricsRange(Number(this.value))"
      >
        ${METRICS_RANGE_OPTIONS.map(
          ([v, label]) =>
            `<option value="${v}" ${state.metricsRangeMinutes === v ? "selected" : ""}>Last ${label}</option>`,
        ).join("")}
      </select>
    </div>`;

  const cards = ctxs
    .map((ctx) => {
      const heading = multi ? `<div class="mb-2 text-sm font-medium text-ink-primary">${esc(ctx)}</div>` : "";
      const result = state.metricsOverTime.get(ctx);

      if (!result) {
        return `<div class="rounded-lg border border-gridline bg-surface-1 p-4">${heading}<div class="text-sm text-ink-muted">Loading…</div></div>`;
      }
      if (!result.backend) {
        return `
          <div class="rounded-lg border border-gridline bg-surface-1 p-4">
            ${heading}
            <div class="text-sm text-ink-secondary">
              No Prometheus or VictoriaMetrics found in this cluster. Metrics-over-time needs a Prometheus-API-compatible
              time-series database reachable as a Service (commonly in a <code class="rounded bg-surface-2 px-1 py-0.5">monitoring</code> namespace).
            </div>
            <div class="mt-3">${datasourceEditButton(ctx, "Set data source manually")}</div>
          </div>`;
      }

      const backendLabel = renderDatasourceRow(ctx, result.backend);
      const errorNote = result.error
        ? `<div class="mb-3 rounded-md border border-status-warning/40 bg-status-warning/10 p-2 text-xs text-status-warning">${esc(result.error)}</div>`
        : "";
      const latestCpu = result.cpu_cores.length > 0 ? result.cpu_cores[result.cpu_cores.length - 1].value : null;
      const latestMem = result.memory_bytes.length > 0 ? result.memory_bytes[result.memory_bytes.length - 1].value : null;
      const latestStorage =
        result.ephemeral_storage_bytes.length > 0
          ? result.ephemeral_storage_bytes[result.ephemeral_storage_bytes.length - 1].value
          : null;

      const cpuColor = "var(--series-blue)";
      const memColor = "var(--series-orange)";
      const storageColor = "var(--series-aqua)";
      const formatCpu = (cores: number) => formatMillicores(Math.round(cores * 1000));
      const formatMem = (bytes: number) => formatKi(Math.round(bytes / 1024));

      return `
        <div class="rounded-lg border border-gridline bg-surface-1 p-4">
          ${heading}
          ${backendLabel}
          ${errorNote}
          <div class="flex flex-col gap-4">
            <div>
              <div class="flex items-baseline justify-between text-xs text-ink-muted">
                ${chartLegendLabel(cpuColor, "CPU usage")}
                <span class="tabular text-ink-secondary">${latestCpu !== null ? formatCpu(latestCpu) : "—"}</span>
              </div>
              <div class="mt-1">${renderTimeSeriesChart(`${ctx}:cpu`, result.cpu_cores, cpuColor, formatCpu)}</div>
            </div>
            <div>
              <div class="flex items-baseline justify-between text-xs text-ink-muted">
                ${chartLegendLabel(memColor, "Memory usage")}
                <span class="tabular text-ink-secondary">${latestMem !== null ? formatMem(latestMem) : "—"}</span>
              </div>
              <div class="mt-1">${renderTimeSeriesChart(`${ctx}:mem`, result.memory_bytes, memColor, formatMem)}</div>
            </div>
            <div>
              <div class="flex items-baseline justify-between text-xs text-ink-muted">
                ${chartLegendLabel(storageColor, "Ephemeral storage usage")}
                <span class="tabular text-ink-secondary">${latestStorage !== null ? formatMem(latestStorage) : "—"}</span>
              </div>
              <div class="mt-1">${renderTimeSeriesChart(`${ctx}:storage`, result.ephemeral_storage_bytes, storageColor, formatMem)}</div>
            </div>
          </div>
        </div>`;
    })
    .join("");

  return header + `<div class="flex flex-col gap-4">${cards}</div>`;
}

// ---------------------------------------------------------------------------
// Minimal YAML syntax highlighting for the pod manifest view. A line-based
// heuristic rather than a real parser — matches this codebase's existing
// preference for small hand-rolled logic over pulling in a dependency for a
// narrow, fixed-shape input (here, serde_yaml's own output). Doesn't handle
// every valid YAML shape (e.g. a '#' inside an unquoted bare value would be
// misread as a comment), which is an acceptable tradeoff for display only.
// ---------------------------------------------------------------------------

/** Index of a comment-starting `#` in `s` (preceded by start-of-string or a space, and not inside a quoted string), or -1. */
function findYamlCommentIndex(s: string): number {
  let inQuote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQuote) {
      if (c === inQuote) inQuote = null;
    } else if (c === '"' || c === "'") {
      inQuote = c;
    } else if (c === "#" && (i === 0 || s[i - 1] === " ")) {
      return i;
    }
  }
  return -1;
}

function highlightYamlValue(rest: string): string {
  const commentIdx = findYamlCommentIndex(rest);
  const valuePart = commentIdx >= 0 ? rest.slice(0, commentIdx) : rest;
  const commentPart = commentIdx >= 0 ? rest.slice(commentIdx) : "";

  const leadingWs = valuePart.match(/^\s*/)![0];
  const trailingWs = valuePart.slice(leadingWs.length).match(/\s*$/)![0];
  const token = valuePart.slice(leadingWs.length, valuePart.length - trailingWs.length);

  let coloredToken = esc(token);
  if (/^(['"]).*\1$/.test(token)) {
    coloredToken = `<span style="color:var(--series-aqua)">${esc(token)}</span>`;
  } else if (/^(true|false|null|~)$/i.test(token)) {
    coloredToken = `<span style="color:var(--status-warning)">${esc(token)}</span>`;
  } else if (/^-?\d+(\.\d+)?$/.test(token)) {
    coloredToken = `<span style="color:var(--series-orange)">${esc(token)}</span>`;
  } else if (/^[|>][+-]?$/.test(token)) {
    coloredToken = `<span style="color:var(--text-muted)">${esc(token)}</span>`;
  }

  const coloredComment = commentPart
    ? `<span style="color:var(--text-muted);font-style:italic">${esc(commentPart)}</span>`
    : "";
  return esc(leadingWs) + coloredToken + esc(trailingWs) + coloredComment;
}

function highlightYamlLine(rawLine: string): string {
  const indent = rawLine.match(/^\s*/)![0];
  let rest = rawLine.slice(indent.length);
  let prefix = esc(indent);

  const dashMatch = rest.match(/^-(\s+|$)/);
  if (dashMatch) {
    prefix += `<span style="color:var(--text-muted)">-</span>${esc(dashMatch[1])}`;
    rest = rest.slice(dashMatch[0].length);
  }

  const keyMatch = rest.match(/^([A-Za-z0-9_.\-/]+)(:)(\s|$)/);
  if (keyMatch) {
    const key = keyMatch[1];
    prefix += `<span style="color:var(--series-blue)">${esc(key)}</span><span style="color:var(--text-muted)">:</span>`;
    rest = rest.slice(key.length + 1);
  }

  return prefix + highlightYamlValue(rest);
}

function highlightYaml(yaml: string): string {
  return yaml.split("\n").map(highlightYamlLine).join("\n");
}

// 16-color ANSI base palette (standard 0-7, bright 8-15), reused both for
// plain SGR color codes (30-37/90-97) and as the low end of the 256-color
// cube below — so `\x1b[32m` and `\x1b[38;5;2m` render as the same green.
const ANSI_BASE16 = [
  "#3f3f3f", "#e6675a", "#3fae56", "#d9a441", "#4a90e2", "#b06fd1", "#3fb0ae", "#b8b8b0",
  "#7a7a72", "#f08a7e", "#6bd685", "#f0c46b", "#7bb0f0", "#d69ae8", "#6bd6d4", "#eeeee6",
];

function xterm256ToHex(n: number): string {
  if (n < 16) return ANSI_BASE16[n];
  if (n >= 232) {
    const level = 8 + (n - 232) * 10;
    const hex = level.toString(16).padStart(2, "0");
    return `#${hex}${hex}${hex}`;
  }
  const cube = n - 16;
  const levels = [0, 95, 135, 175, 215, 255];
  const r = levels[Math.floor(cube / 36)];
  const g = levels[Math.floor((cube % 36) / 6)];
  const b = levels[cube % 6];
  const toHex = (v: number) => v.toString(16).padStart(2, "0");
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

/**
 * Converts ANSI SGR (color/style) escape codes in log output — common from
 * container runtimes whose loggers colorize stdout (Nest.js, pino, chalk,
 * etc., as seen in the pod logs this dashboard displays) — into inline-
 * styled `<span>`s, so logs render as they would in a real terminal instead
 * of showing the literal escape bytes as garbage. Supports the standard
 * 16-color codes, the 256-color (`38;5;n`/`48;5;n`) and truecolor
 * (`38;2;r;g;b`/`48;2;r;g;b`) extended forms, and bold/dim/italic/underline.
 * Any other ANSI control sequence (cursor movement, OSC window-title sets)
 * is stripped rather than rendered, since a static log view has no cursor to
 * move. Output composes with `highlightSearchMatches` below, which already
 * skips over `<...>` tags when matching.
 */
function ansiToHtml(text: string): string {
  let fg: string | null = null;
  let bg: string | null = null;
  let bold = false;
  let dim = false;
  let italic = false;
  let underline = false;
  let openSpan = false;
  let out = "";

  const styleAttr = () => {
    const styles: string[] = [];
    if (fg) styles.push(`color:${fg}`);
    if (bg) styles.push(`background-color:${bg}`);
    if (bold) styles.push("font-weight:bold");
    if (dim) styles.push("opacity:0.65");
    if (italic) styles.push("font-style:italic");
    if (underline) styles.push("text-decoration:underline");
    return styles.join(";");
  };

  const applyCodes = (codes: number[]) => {
    if (codes.length === 0) codes = [0];
    for (let i = 0; i < codes.length; i++) {
      const code = codes[i];
      if (code === 0) {
        fg = bg = null;
        bold = dim = italic = underline = false;
      } else if (code === 1) bold = true;
      else if (code === 2) dim = true;
      else if (code === 3) italic = true;
      else if (code === 4) underline = true;
      else if (code === 22) {
        bold = false;
        dim = false;
      } else if (code === 23) italic = false;
      else if (code === 24) underline = false;
      else if (code === 39) fg = null;
      else if (code === 49) bg = null;
      else if (code === 38 || code === 48) {
        const mode = codes[i + 1];
        let color: string | null = null;
        if (mode === 5) {
          color = xterm256ToHex(codes[i + 2] ?? 0);
          i += 2;
        } else if (mode === 2) {
          const r = codes[i + 2] ?? 0;
          const g = codes[i + 3] ?? 0;
          const b = codes[i + 4] ?? 0;
          color = `#${[r, g, b].map((v) => Math.max(0, Math.min(255, v)).toString(16).padStart(2, "0")).join("")}`;
          i += 4;
        }
        if (color) {
          if (code === 38) fg = color;
          else bg = color;
        }
      } else if (code >= 30 && code <= 37) fg = ANSI_BASE16[code - 30];
      else if (code >= 90 && code <= 97) fg = ANSI_BASE16[code - 90 + 8];
      else if (code >= 40 && code <= 47) bg = ANSI_BASE16[code - 40];
      else if (code >= 100 && code <= 107) bg = ANSI_BASE16[code - 100 + 8];
      // Anything else (blink, strikethrough, reverse video, ...) is ignored.
    }
  };

  // OSC sequences (e.g. terminal window-title escapes) don't affect styling.
  const withoutOsc = text.replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "");

  const re = /\x1b\[([0-9;]*)([a-zA-Z])/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(withoutOsc))) {
    const chunk = withoutOsc.slice(lastIndex, match.index);
    if (chunk) out += esc(chunk);
    lastIndex = re.lastIndex;

    const [, paramStr, finalChar] = match;
    if (finalChar !== "m") continue; // drop non-SGR control sequences (cursor moves, etc.)
    if (openSpan) {
      out += "</span>";
      openSpan = false;
    }
    applyCodes(paramStr.length ? paramStr.split(";").map((n) => parseInt(n, 10) || 0) : [0]);
    const style = styleAttr();
    if (style) {
      out += `<span style="${style}">`;
      openSpan = true;
    }
  }
  const rest = withoutOsc.slice(lastIndex);
  if (rest) out += esc(rest);
  if (openSpan) out += "</span>";
  return out;
}

/**
 * Wraps case-insensitive matches of `query` in `<mark>`, skipping over any
 * HTML tags already in `html` — splitting on `<[^>]+>` and only touching the
 * text runs in between — so it composes with the YAML syntax-color spans
 * without corrupting them. Shared by both the YAML and Logs views (Logs has
 * no markup at all, so it's unaffected by the tag-skipping).
 *
 * One accepted gap: a match split across two adjacent tags (e.g. searching
 * "name:" where the key and colon are colored separately) won't be found.
 * Plain-text values, bare keys, and log lines are each a single untagged run
 * and highlight correctly — this only misses a key immediately followed by
 * its own colon, judged not worth restructuring the tokenizer to fix.
 */
function highlightSearchMatches(html: string, query: string, currentIndex: number): string {
  if (!query) return html;
  const re = new RegExp(escapeRegExp(query), "gi");
  let matchCounter = 0;
  return html
    .split(/(<[^>]+>)/g)
    .map((part) => {
      if (part.startsWith("<")) return part;
      return part.replace(re, (m) => {
        const isCurrent = matchCounter === currentIndex;
        matchCounter++;
        return `<mark ${isCurrent ? "data-search-current" : ""} class="rounded-sm text-ink-primary ${isCurrent ? "bg-series-orange" : "bg-series-blue/50"}">${m}</mark>`;
      });
    })
    .join("");
}

// ---------------------------------------------------------------------------
// Pod detail panel (YAML / Logs / Graph)
// ---------------------------------------------------------------------------

/**
 * Search box shared by every YAML/Logs-style view (pod YAML, pod Logs, node
 * YAML): a query input plus a match counter and prev/next buttons. `kind`
 * selects which detail panel's search/move functions it wires up to
 * (`window.__app.set${Kind}Search` / `move${Kind}Search`), `view` just needs
 * to be unique within that panel for the `data-filter-key` focus-restore tag.
 */
function renderSearchBox(
  kind: "Pod" | "Node" | "Workload" | "GitOps" | "Helm" | "Nap",
  view: string,
  query: string,
  matchCount: number,
  currentIndex: number,
): string {
  const status = query ? `${matchCount > 0 ? currentIndex + 1 : 0}/${matchCount}` : "";
  return `
    <div class="flex items-center gap-1.5">
      <input
        type="text"
        placeholder="Search…"
        value="${esc(query)}"
        data-detail-search
        data-filter-key="${kind.toLowerCase()}-detail-search:${view}"
        oninput="window.__app.set${kind}Search('${view}', this.value)"
        onkeydown="if (event.key === 'Enter') { event.preventDefault(); window.__app.move${kind}Search('${view}', event.shiftKey ? -1 : 1); }"
        class="w-36 rounded border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-primary outline-none focus:border-series-blue"
      />
      <span class="w-10 tabular text-ink-muted">${status}</span>
      <button
        type="button"
        title="Previous match"
        onclick="window.__app.move${kind}Search('${view}', -1)"
        ${matchCount === 0 ? "disabled" : ""}
        class="rounded px-1.5 py-1 text-ink-secondary hover:bg-surface-3 hover:text-ink-primary disabled:cursor-not-allowed disabled:opacity-40"
      >▲</button>
      <button
        type="button"
        title="Next match"
        onclick="window.__app.move${kind}Search('${view}', 1)"
        ${matchCount === 0 ? "disabled" : ""}
        class="rounded px-1.5 py-1 text-ink-secondary hover:bg-surface-3 hover:text-ink-primary disabled:cursor-not-allowed disabled:opacity-40"
      >▼</button>
    </div>`;
}

function renderPodYamlView(pd: PodDetailState): string {
  if (pd.manifestError) {
    return `<div class="text-sm text-status-critical">${esc(pd.manifestError)}</div>`;
  }
  if (!pd.manifest) {
    return `<div class="text-sm text-ink-muted">Loading…</div>`;
  }
  const yaml = currentYamlText(pd);
  const matchCount = countSearchMatches(yaml, pd.yamlSearch);
  const scrollId = `pod-yaml:${esc(pd.ctx)}:${esc(pd.namespace)}:${esc(pd.name)}`;
  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-3">
          <label class="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="checkbox" ${pd.showManagedFields ? "checked" : ""} onchange="window.__app.toggleManagedFields()" />
            Show managed fields
          </label>
          ${renderCopyButton(scrollId)}
        </div>
        ${renderSearchBox("Pod", "yaml", pd.yamlSearch, matchCount, pd.yamlSearchIndex)}
      </div>
      <pre data-scroll-id="${scrollId}" class="min-h-0 flex-1 select-text overflow-auto rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-primary">${highlightSearchMatches(highlightYaml(yaml), pd.yamlSearch, pd.yamlSearchIndex)}</pre>
    </div>`;
}

function renderPodLogsView(pd: PodDetailState): string {
  const controls = `
    <div class="flex flex-wrap items-center gap-3 text-xs text-ink-secondary">
      <div class="flex overflow-hidden rounded-md border border-gridline">
        <button
          type="button"
          onclick="window.__app.setPodLogMode('head')"
          ${pd.following ? "disabled" : ""}
          class="px-2 py-1 disabled:cursor-not-allowed disabled:opacity-50 ${pd.logMode === "head" ? "bg-surface-3 text-ink-primary" : ""}"
        >Head</button>
        <button
          type="button"
          onclick="window.__app.setPodLogMode('tail')"
          ${pd.following ? "disabled" : ""}
          class="px-2 py-1 disabled:cursor-not-allowed disabled:opacity-50 ${pd.logMode === "tail" ? "bg-surface-3 text-ink-primary" : ""}"
        >Tail</button>
      </div>
      <label class="flex items-center gap-1.5">
        Lines
        <input
          type="number"
          min="1"
          max="5000"
          value="${pd.logLines}"
          ${pd.following ? "disabled" : ""}
          onchange="window.__app.setPodLogLines(Number(this.value))"
          class="w-20 rounded border border-gridline bg-surface-2 px-1.5 py-1 disabled:cursor-not-allowed disabled:opacity-50"
        />
      </label>
      <label class="flex items-center gap-1.5">
        <input type="checkbox" ${pd.following ? "checked" : ""} onchange="window.__app.toggleFollow()" />
        Follow
      </label>
      <label class="flex items-center gap-1.5">
        <input type="checkbox" ${pd.logWrap ? "checked" : ""} onchange="window.__app.togglePodLogWrap()" />
        Wrap
      </label>
      ${!pd.following ? `<button type="button" onclick="window.__app.refreshPodLogs()" class="text-ink-secondary hover:text-ink-primary hover:underline">Refresh</button>` : ""}
      ${pd.logLoading ? `<span class="text-ink-muted">Loading…</span>` : ""}
      ${renderCopyButton("pod-log")}
    </div>`;

  const matchCount = countSearchMatches(pd.logText, pd.logSearch);
  const body = pd.logError
    ? `<div class="text-sm text-status-critical">${esc(pd.logError)}</div>`
    : `<pre data-scroll-id="pod-log" class="h-full select-text overflow-auto ${pd.logWrap ? "whitespace-pre-wrap" : "whitespace-pre"} rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-primary">${
        pd.logText
          ? highlightSearchMatches(ansiToHtml(pd.logText), pd.logSearch, pd.logSearchIndex)
          : '<span class="text-ink-muted">No log output.</span>'
      }</pre>`;

  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        ${controls}
        ${renderSearchBox("Pod", "logs", pd.logSearch, matchCount, pd.logSearchIndex)}
      </div>
      <div class="min-h-0 flex-1">${body}</div>
    </div>`;
}

/**
 * The Graph tab, shared by the Pod, Node and Workload detail panels — they
 * differ only in which `window.__app` setter the range dropdown calls, the
 * `chartKey` that keeps each panel's hover state distinct, and an optional
 * note explaining what the series covers. `m` is any state carrying the
 * `MetricsViewState` slice.
 */
function renderMetricsGraphView(m: MetricsViewState, rangeSetter: string, chartKey: string, scopeNote = ""): string {
  const header = `
    <div class="mb-3 flex items-center justify-end">
      <select
        class="rounded-md border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-secondary outline-none"
        onchange="window.__app.${rangeSetter}(Number(this.value))"
      >
        ${METRICS_RANGE_OPTIONS.map(
          ([v, label]) => `<option value="${v}" ${m.metricsRangeMinutes === v ? "selected" : ""}>Last ${label}</option>`,
        ).join("")}
      </select>
    </div>`;

  if (m.metricsError) {
    return header + `<div class="text-sm text-status-critical">${esc(m.metricsError)}</div>`;
  }
  if (!m.metrics) {
    return header + `<div class="text-sm text-ink-muted">${m.metricsLoading ? "Loading…" : ""}</div>`;
  }
  if (!m.metrics.backend) {
    return (
      header +
      `<div class="text-sm text-ink-secondary">
        No Prometheus or VictoriaMetrics found in this cluster. Metrics-over-time needs a Prometheus-API-compatible
        time-series database reachable as a Service (commonly in a <code class="rounded bg-surface-2 px-1 py-0.5">monitoring</code> namespace).
      </div>`
    );
  }

  const errorNote = m.metrics.error
    ? `<div class="mb-3 rounded-md border border-status-warning/40 bg-status-warning/10 p-2 text-xs text-status-warning">${esc(m.metrics.error)}</div>`
    : "";
  const latest = (samples: MetricSample[]) => (samples.length > 0 ? samples[samples.length - 1].value : null);
  const formatCpu = (cores: number) => formatMillicores(Math.round(cores * 1000));
  const formatMem = (bytes: number) => formatKi(Math.round(bytes / 1024));

  const series: { key: string; label: string; color: string; samples: MetricSample[]; format: (v: number) => string }[] = [
    { key: "cpu", label: "CPU usage", color: "var(--series-blue)", samples: m.metrics.cpu_cores, format: formatCpu },
    { key: "mem", label: "Memory usage", color: "var(--series-orange)", samples: m.metrics.memory_bytes, format: formatMem },
    {
      key: "storage",
      label: "Ephemeral storage usage",
      color: "var(--series-aqua)",
      samples: m.metrics.ephemeral_storage_bytes,
      format: formatMem,
    },
  ];

  return `
    ${header}
    ${errorNote}
    ${scopeNote}
    <div class="flex flex-col gap-4">
      ${series
        .map((s) => {
          const value = latest(s.samples);
          return `
        <div>
          <div class="flex items-baseline justify-between text-xs text-ink-muted">
            ${chartLegendLabel(s.color, s.label)}
            <span class="tabular text-ink-secondary">${value !== null ? s.format(value) : "—"}</span>
          </div>
          <div class="mt-1">${renderTimeSeriesChart(`${chartKey}:${s.key}`, s.samples, s.color, s.format)}</div>
        </div>`;
        })
        .join("")}
    </div>`;
}

function renderPodGraphView(pd: PodDetailState): string {
  return renderMetricsGraphView(pd, "setPodMetricsRange", `pod:${pd.ctx}:${pd.namespace}:${pd.name}`);
}

function renderNodeGraphView(nd: NodeDetailState): string {
  // Worth stating outright: this sums the containers scheduled on the node, so
  // it reads lower than `kubectl top node`, which also counts kubelet, the
  // container runtime and OS overhead living outside any container's cgroup.
  const note = `
    <div class="mb-3 text-xs text-ink-muted">
      Summed across containers running on this node — excludes kubelet, runtime and OS overhead.
    </div>`;
  return renderMetricsGraphView(nd, "setNodeMetricsRange", `node:${nd.ctx}:${nd.name}`, note);
}

function renderWorkloadGraphView(wd: WorkloadDetailState): string {
  const note = `
    <div class="mb-3 text-xs text-ink-muted">
      Summed across all pods of this ${esc(wd.kind.toLowerCase())}, including any replaced by an earlier rollout.
    </div>`;
  return renderMetricsGraphView(wd, "setWorkloadMetricsRange", `workload:${wd.ctx}:${wd.kind}:${wd.namespace}:${wd.name}`, note);
}

function renderPodDetailPanel(): string {
  const pd = state.podDetail;
  if (!pd) return "";

  const tabs: { id: PodDetailState["view"]; label: string }[] = [
    { id: "yaml", label: "YAML" },
    { id: "logs", label: "Logs" },
    { id: "graph", label: "Graph" },
  ];

  const containerSelector =
    pd.containers.length > 1
      ? `
      <select
        class="rounded-md border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-secondary outline-none"
        onchange="window.__app.setPodDetailContainer(this.value)"
      >
        ${pd.containers
          .map((c) => `<option value="${esc(c)}" ${c === pd.activeContainer ? "selected" : ""}>${esc(c)}</option>`)
          .join("")}
      </select>`
      : "";

  const body = pd.view === "yaml" ? renderPodYamlView(pd) : pd.view === "logs" ? renderPodLogsView(pd) : renderPodGraphView(pd);

  return `
    <div class="fixed inset-0 z-40 flex justify-end bg-black/40" onclick="window.__app.closePodDetail()">
      <div class="flex h-full w-full max-w-3xl flex-col border-l border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">${esc(pd.name)}</div>
            <div class="truncate text-xs text-ink-muted">${esc(pd.ctx)} · ${esc(pd.namespace)}</div>
          </div>
          <div class="flex shrink-0 items-center gap-2">
            ${
              state.claudeAuth?.signed_in
                ? `<button
                    type="button"
                    title="Diagnose this pod with Claude — you'll review exactly what is sent first"
                    onclick="window.__app.diagnosePod(${jsArg(pd.ctx)},${jsArg(pd.namespace)},${jsArg(pd.name)},${jsArg(pd.activeContainer)})"
                    class="rounded border border-gridline px-2 py-1 text-xs text-ink-secondary hover:bg-surface-3 hover:text-ink-primary"
                  >Diagnose</button>`
                : ""
            }
            <button type="button" onclick="window.__app.closePodDetail()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
          </div>
        </div>
        <div class="flex items-center justify-between gap-3 border-b border-gridline px-4 py-2">
          <div class="flex gap-1">
            ${tabs
              .map(
                (t) => `
              <button
                type="button"
                onclick="window.__app.setPodDetailView(${jsArg(t.id)})"
                data-detail-tab ${pd.view === t.id ? "data-detail-tab-active" : ""}
                class="rounded-md px-3 py-1.5 text-xs font-medium ${pd.view === t.id ? "bg-surface-3 text-ink-primary" : "text-ink-secondary hover:text-ink-primary"}"
              >${t.label}</button>`,
              )
              .join("")}
          </div>
          ${pd.view !== "graph" ? containerSelector : ""}
        </div>
        <div data-detail-body class="flex min-h-0 flex-1 flex-col overflow-y-auto p-4">${body}</div>
      </div>
    </div>`;
}

// ---------------------------------------------------------------------------
// Node detail panel (YAML / Events)
// ---------------------------------------------------------------------------

function renderNodeYamlView(nd: NodeDetailState): string {
  if (nd.manifestError) {
    return `<div class="text-sm text-status-critical">${esc(nd.manifestError)}</div>`;
  }
  if (!nd.manifest) {
    return `<div class="text-sm text-ink-muted">Loading…</div>`;
  }
  const yaml = currentNodeYamlText(nd);
  const matchCount = countSearchMatches(yaml, nd.yamlSearch);
  const scrollId = `node-yaml:${esc(nd.ctx)}:${esc(nd.name)}`;
  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-3">
          <label class="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="checkbox" ${nd.showManagedFields ? "checked" : ""} onchange="window.__app.toggleNodeManagedFields()" />
            Show managed fields
          </label>
          ${renderCopyButton(scrollId)}
        </div>
        ${renderSearchBox("Node", "yaml", nd.yamlSearch, matchCount, nd.yamlSearchIndex)}
      </div>
      <pre data-scroll-id="${scrollId}" class="min-h-0 flex-1 select-text overflow-auto rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-primary">${highlightSearchMatches(highlightYaml(yaml), nd.yamlSearch, nd.yamlSearchIndex)}</pre>
    </div>`;
}

/** Plain (non-sortable/filterable) events table shared by the Node and Workload detail panels — a small, already-scoped set doesn't need the full grid machinery the main Events tab has. */
function renderEventsList(scrollId: string, events: EventInfo[] | null, error: string | null): string {
  if (error) {
    return `<div class="text-sm text-status-critical">${esc(error)}</div>`;
  }
  if (!events) {
    return `<div class="text-sm text-ink-muted">Loading…</div>`;
  }
  if (events.length === 0) {
    return `<div class="text-sm text-ink-muted">No events found.</div>`;
  }
  return `
    <div class="h-full min-h-0 select-text overflow-auto rounded-md border border-gridline" data-scroll-id="${esc(scrollId)}">
      <table class="data-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Reason</th>
            <th>Message</th>
            <th>Count</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          ${events
            .map(
              (e) => `
            <tr>
              <td class="${e.event_type === "Warning" ? "text-status-warning" : ""}">${esc(e.event_type)}</td>
              <td>${esc(e.reason)}</td>
              <td class="whitespace-normal break-words">${esc(e.message)}</td>
              <td class="tabular">${e.count}</td>
              <td class="tabular">${esc(relativeTime(e.last_seen))}</td>
            </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>`;
}

function renderNodeEventsView(nd: NodeDetailState): string {
  return renderEventsList(`node-events:${nd.ctx}:${nd.name}`, nd.events, nd.eventsError);
}

function renderNodeDetailPanel(): string {
  const nd = state.nodeDetail;
  if (!nd) return "";

  const tabs: { id: NodeDetailState["view"]; label: string }[] = [
    { id: "yaml", label: "YAML" },
    { id: "events", label: "Events" },
    { id: "graph", label: "Graph" },
  ];

  const body =
    nd.view === "yaml" ? renderNodeYamlView(nd) : nd.view === "events" ? renderNodeEventsView(nd) : renderNodeGraphView(nd);

  return `
    <div class="fixed inset-0 z-40 flex justify-end bg-black/40" onclick="window.__app.closeNodeDetail()">
      <div class="flex h-full w-full max-w-3xl flex-col border-l border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">${esc(nd.name)}</div>
            <div class="truncate text-xs text-ink-muted">${esc(nd.ctx)}</div>
          </div>
          <button type="button" onclick="window.__app.closeNodeDetail()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>
        <div class="flex items-center gap-1 border-b border-gridline px-4 py-2">
          ${tabs
            .map(
              (t) => `
            <button
              type="button"
              onclick="window.__app.setNodeDetailView(${jsArg(t.id)})"
              data-detail-tab ${nd.view === t.id ? "data-detail-tab-active" : ""}
              class="rounded-md px-3 py-1.5 text-xs font-medium ${nd.view === t.id ? "bg-surface-3 text-ink-primary" : "text-ink-secondary hover:text-ink-primary"}"
            >${t.label}</button>`,
            )
            .join("")}
        </div>
        <div data-detail-body class="flex min-h-0 flex-1 flex-col overflow-y-auto p-4">${body}</div>
      </div>
    </div>`;
}

// ---------------------------------------------------------------------------
// Workload detail panel (YAML / Events)
// ---------------------------------------------------------------------------

function renderWorkloadYamlView(wd: WorkloadDetailState): string {
  if (wd.manifestError) {
    return `<div class="text-sm text-status-critical">${esc(wd.manifestError)}</div>`;
  }
  if (!wd.manifest) {
    return `<div class="text-sm text-ink-muted">Loading…</div>`;
  }
  const yaml = currentWorkloadYamlText(wd);
  const matchCount = countSearchMatches(yaml, wd.yamlSearch);
  const scrollId = `workload-yaml:${esc(wd.ctx)}:${esc(wd.kind)}:${esc(wd.namespace)}:${esc(wd.name)}`;
  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-3">
          <label class="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="checkbox" ${wd.showManagedFields ? "checked" : ""} onchange="window.__app.toggleWorkloadManagedFields()" />
            Show managed fields
          </label>
          ${renderCopyButton(scrollId)}
        </div>
        ${renderSearchBox("Workload", "yaml", wd.yamlSearch, matchCount, wd.yamlSearchIndex)}
      </div>
      <pre data-scroll-id="${scrollId}" class="min-h-0 flex-1 select-text overflow-auto rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-primary">${highlightSearchMatches(highlightYaml(yaml), wd.yamlSearch, wd.yamlSearchIndex)}</pre>
    </div>`;
}

function renderWorkloadEventsView(wd: WorkloadDetailState): string {
  return renderEventsList(`workload-events:${wd.ctx}:${wd.kind}:${wd.namespace}:${wd.name}`, wd.events, wd.eventsError);
}

/**
 * Line diff via a longest-common-subsequence table, so unchanged regions stay
 * aligned instead of a first difference cascading into "everything after this
 * changed". O(n*m) in lines, which for pod templates (hundreds of lines) is a
 * table of a few hundred KB at worst — well within budget, and it avoids a
 * diffing dependency for what is a small, stable algorithm.
 */
type DiffOp = { kind: "same" | "add" | "del" | "gap"; text: string };

function diffLines(before: string, after: string): DiffOp[] {
  const a = before.length > 0 ? before.split("\n") : [];
  const b = after.length > 0 ? after.split("\n") : [];
  const n = a.length;
  const m = b.length;

  const lcs: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const ops: DiffOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ kind: "same", text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      ops.push({ kind: "del", text: a[i] });
      i++;
    } else {
      ops.push({ kind: "add", text: b[j] });
      j++;
    }
  }
  while (i < n) ops.push({ kind: "del", text: a[i++] });
  while (j < m) ops.push({ kind: "add", text: b[j++] });
  return ops;
}

/** Replaces long unchanged stretches with a marker, keeping `context` lines around each change. */
function collapseUnchanged(ops: DiffOp[], context = 3): DiffOp[] {
  const keep = new Array(ops.length).fill(false);
  ops.forEach((op, idx) => {
    if (op.kind === "same") return;
    for (let k = Math.max(0, idx - context); k <= Math.min(ops.length - 1, idx + context); k++) keep[k] = true;
  });

  const out: DiffOp[] = [];
  let skipped = 0;
  const flush = () => {
    if (skipped > 0) {
      out.push({ kind: "gap", text: `\u22ef ${skipped} unchanged line${skipped === 1 ? "" : "s"}` });
      skipped = 0;
    }
  };
  ops.forEach((op, idx) => {
    if (keep[idx]) {
      flush();
      out.push(op);
    } else {
      skipped++;
    }
  });
  flush();
  return out;
}

function renderRevisionDiff(wd: WorkloadDetailState, revisions: WorkloadRevisionInfo[]): string {
  if (wd.revisionCompare.length !== 2) {
    return `
      <div class="rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-muted">
        Select two revisions above to compare their pod templates.
      </div>`;
  }

  const [olderNum, newerNum] = [...wd.revisionCompare].sort((x, y) => x - y);
  const older = revisions.find((r) => r.revision === olderNum);
  const newer = revisions.find((r) => r.revision === newerNum);
  if (!older || !newer) {
    return `<div class="text-sm text-ink-muted">Those revisions are no longer in the list.</div>`;
  }

  const ops = diffLines(older.template_yaml, newer.template_yaml);
  const added = ops.filter((o) => o.kind === "add").length;
  const removed = ops.filter((o) => o.kind === "del").length;
  const scrollId = `workload-revision-diff:${wd.ctx}:${wd.kind}:${wd.namespace}:${wd.name}`;

  if (added === 0 && removed === 0) {
    return `
      <div class="rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-secondary">
        Revisions ${olderNum} and ${newerNum} have identical pod templates.
        <span class="text-ink-muted">(Template-hash labels are excluded, since they change on every revision by construction.)</span>
      </div>`;
  }

  const rows = collapseUnchanged(ops)
    .map((op) => {
      if (op.kind === "gap") {
        return `<div class="select-none px-3 py-1 text-center text-ink-muted">${esc(op.text)}</div>`;
      }
      const marker = op.kind === "add" ? "+" : op.kind === "del" ? "-" : " ";
      const tone =
        op.kind === "add"
          ? "bg-status-good/15 text-ink-primary"
          : op.kind === "del"
            ? "bg-status-critical/15 text-ink-primary"
            : "text-ink-secondary";
      return `<div class="flex ${tone}"><span class="w-5 shrink-0 select-none text-center text-ink-muted">${marker}</span><span class="whitespace-pre-wrap break-all">${esc(op.text)}</span></div>`;
    })
    .join("");

  return `
    <div class="flex min-h-0 flex-1 flex-col gap-1.5">
      <div class="flex items-center justify-between text-xs">
        <div class="text-ink-secondary">
          Comparing <span class="font-medium text-ink-primary">rev ${olderNum}</span>
          &rarr; <span class="font-medium text-ink-primary">rev ${newerNum}</span>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-status-good">+${added}</span>
          <span class="text-status-critical">-${removed}</span>
          ${renderCopyButton(scrollId)}
        </div>
      </div>
      <div data-scroll-id="${esc(scrollId)}" class="min-h-0 flex-1 select-text overflow-auto rounded-md border border-gridline bg-surface-2 py-2 font-mono text-xs leading-relaxed">${rows}</div>
    </div>`;
}

/**
 * Rollout history, with any two revisions comparable. Deployments get a
 * Replicas column (their revisions are ReplicaSets, which hold the replica
 * count — the current one at full scale and older ones parked at zero, which
 * is what makes a rollback possible); StatefulSet/DaemonSet revisions are
 * immutable ControllerRevision templates with no replica count of their own,
 * so the column is dropped for them rather than filled with a meaningless
 * value.
 */
function renderWorkloadRevisionsView(wd: WorkloadDetailState): string {
  if (wd.revisionsError) {
    return `<div class="text-sm text-status-critical">${esc(wd.revisionsError)}</div>`;
  }
  if (!wd.revisions) {
    return `<div class="text-sm text-ink-muted">Loading\u2026</div>`;
  }
  if (wd.revisions.length === 0) {
    return `<div class="text-sm text-ink-muted">No revision history found for this ${esc(wd.kind.toLowerCase())}.</div>`;
  }

  const showReplicas = wd.kind === "Deployment";
  const scrollId = `workload-revisions:${wd.ctx}:${wd.kind}:${wd.namespace}:${wd.name}`;

  const table = `
    <div class="max-h-56 shrink-0 select-text overflow-auto rounded-md border border-gridline" data-scroll-id="${esc(scrollId)}">
      <table class="data-table">
        <thead>
          <tr>
            <th title="Pick two revisions to compare"></th>
            <th>Revision</th>
            <th>Name</th>
            ${showReplicas ? "<th>Replicas</th>" : ""}
            <th>Image</th>
            <th>Age</th>
          </tr>
        </thead>
        <tbody>
          ${wd.revisions
            .map(
              (r) => `
          <tr class="${r.current ? "text-ink-primary" : "text-ink-secondary"}">
            <td>
              <input
                type="checkbox"
                ${wd.revisionCompare.includes(r.revision) ? "checked" : ""}
                onchange="window.__app.toggleWorkloadRevisionCompare(${r.revision})"
                title="Compare revision ${r.revision}"
              />
            </td>
            <td class="tabular ${r.current ? "font-semibold" : ""}">
              ${r.revision}${r.current ? ' <span class="text-status-good" title="Current revision">\u25cf</span>' : ""}
            </td>
            <td class="${r.current ? "font-medium" : ""}">${esc(r.name)}</td>
            ${
              showReplicas
                ? `<td class="tabular">${r.replicas ?? 0}${
                    r.ready_replicas !== null && r.replicas !== null && r.ready_replicas !== r.replicas
                      ? ` <span class="text-ink-muted">(${r.ready_replicas} ready)</span>`
                      : ""
                  }</td>`
                : ""
            }
            <td class="max-w-xs truncate" title="${esc(r.images.join(", "))}">${
              r.images.length > 0 ? esc(r.images.map(shortImageRef).join(", ")) : "\u2014"
            }</td>
            <td class="tabular">${formatAgeDetailed(r.age_days, r.age_seconds)}</td>
          </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>`;

  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="text-xs text-ink-muted">
        ${wd.revisions.length} revision${wd.revisions.length === 1 ? "" : "s"} retained${
          showReplicas ? "" : " (ControllerRevision templates \u2014 no per-revision replica count)"
        }
      </div>
      ${table}
      ${renderRevisionDiff(wd, wd.revisions)}
    </div>`;
}

function renderWorkloadLogsView(wd: WorkloadDetailState): string {
  if (wd.podsError) {
    return `<div class="text-sm text-status-critical">${esc(wd.podsError)}</div>`;
  }
  if (wd.pods === null) {
    return `<div class="text-sm text-ink-muted">Loading…</div>`;
  }
  if (wd.pods.length === 0) {
    return `<div class="text-sm text-ink-muted">No pods found for this workload.</div>`;
  }

  const controls = `
    <div class="flex flex-wrap items-center gap-3 text-xs text-ink-secondary">
      <div class="flex overflow-hidden rounded-md border border-gridline">
        <button
          type="button"
          onclick="window.__app.setWorkloadLogMode('head')"
          ${wd.following ? "disabled" : ""}
          class="px-2 py-1 disabled:cursor-not-allowed disabled:opacity-50 ${wd.logMode === "head" ? "bg-surface-3 text-ink-primary" : ""}"
        >Head</button>
        <button
          type="button"
          onclick="window.__app.setWorkloadLogMode('tail')"
          ${wd.following ? "disabled" : ""}
          class="px-2 py-1 disabled:cursor-not-allowed disabled:opacity-50 ${wd.logMode === "tail" ? "bg-surface-3 text-ink-primary" : ""}"
        >Tail</button>
      </div>
      <label class="flex items-center gap-1.5">
        Lines
        <input
          type="number"
          min="1"
          max="5000"
          value="${wd.logLines}"
          ${wd.following ? "disabled" : ""}
          onchange="window.__app.setWorkloadLogLines(Number(this.value))"
          class="w-20 rounded border border-gridline bg-surface-2 px-1.5 py-1 disabled:cursor-not-allowed disabled:opacity-50"
        />
      </label>
      <label class="flex items-center gap-1.5">
        <input type="checkbox" ${wd.following ? "checked" : ""} onchange="window.__app.toggleWorkloadFollow()" />
        Follow
      </label>
      <label class="flex items-center gap-1.5">
        <input type="checkbox" ${wd.logWrap ? "checked" : ""} onchange="window.__app.toggleWorkloadLogWrap()" />
        Wrap
      </label>
      ${!wd.following ? `<button type="button" onclick="window.__app.refreshWorkloadLogs()" class="text-ink-secondary hover:text-ink-primary hover:underline">Refresh</button>` : ""}
      ${wd.logLoading ? `<span class="text-ink-muted">Loading…</span>` : ""}
      ${renderCopyButton("workload-log")}
    </div>`;

  const matchCount = countSearchMatches(wd.logText, wd.logSearch);
  const body = wd.logError
    ? `<div class="text-sm text-status-critical">${esc(wd.logError)}</div>`
    : `<pre data-scroll-id="workload-log" class="h-full select-text overflow-auto ${wd.logWrap ? "whitespace-pre-wrap" : "whitespace-pre"} rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-primary">${
        wd.logText
          ? highlightSearchMatches(ansiToHtml(wd.logText), wd.logSearch, wd.logSearchIndex)
          : '<span class="text-ink-muted">No log output.</span>'
      }</pre>`;

  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        ${controls}
        ${renderSearchBox("Workload", "logs", wd.logSearch, matchCount, wd.logSearchIndex)}
      </div>
      <div class="min-h-0 flex-1">${body}</div>
    </div>`;
}

function renderWorkloadDetailPanel(): string {
  const wd = state.workloadDetail;
  if (!wd) return "";

  const tabs: { id: WorkloadDetailState["view"]; label: string }[] = [
    { id: "yaml", label: "YAML" },
    { id: "logs", label: "Logs" },
    { id: "events", label: "Events" },
    { id: "revisions", label: "Revisions" },
    { id: "graph", label: "Graph" },
  ];

  const podSelector =
    wd.view === "logs" && wd.pods && wd.pods.length > 0
      ? `
      <select
        class="min-w-0 flex-1 rounded-md border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-secondary outline-none"
        onchange="window.__app.setWorkloadDetailPod(this.value)"
      >
        <option value="${ALL_WORKLOAD_PODS}" ${wd.activePod === ALL_WORKLOAD_PODS ? "selected" : ""}>All pods (${wd.pods.length})</option>
        ${wd.pods.map((p) => `<option value="${esc(p)}" ${p === wd.activePod ? "selected" : ""}>${esc(p)}</option>`).join("")}
      </select>`
      : "";

  const containerSelector =
    wd.view === "logs" && wd.manifest && wd.manifest.containers.length > 1
      ? `
      <select
        class="rounded-md border border-gridline bg-surface-2 px-2 py-1 text-xs text-ink-secondary outline-none"
        onchange="window.__app.setWorkloadDetailContainer(this.value)"
      >
        ${wd.manifest.containers
          .map((c) => `<option value="${esc(c)}" ${c === wd.activeContainer ? "selected" : ""}>${esc(c)}</option>`)
          .join("")}
      </select>`
      : "";

  const body =
    wd.view === "yaml"
      ? renderWorkloadYamlView(wd)
      : wd.view === "logs"
        ? renderWorkloadLogsView(wd)
        : wd.view === "events"
          ? renderWorkloadEventsView(wd)
          : wd.view === "revisions"
            ? renderWorkloadRevisionsView(wd)
            : renderWorkloadGraphView(wd);

  return `
    <div class="fixed inset-0 z-40 flex justify-end bg-black/40" onclick="window.__app.closeWorkloadDetail()">
      <div class="flex h-full w-full max-w-3xl flex-col border-l border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">${esc(wd.name)}</div>
            <div class="truncate text-xs text-ink-muted">${esc(wd.ctx)} · ${esc(wd.kind)} · ${esc(wd.namespace)}</div>
          </div>
          <button type="button" onclick="window.__app.closeWorkloadDetail()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>
        <div class="flex items-center justify-between gap-3 border-b border-gridline px-4 py-2">
          <div class="flex shrink-0 gap-1">
            ${tabs
              .map(
                (t) => `
              <button
                type="button"
                onclick="window.__app.setWorkloadDetailView(${jsArg(t.id)})"
                data-detail-tab ${wd.view === t.id ? "data-detail-tab-active" : ""}
                class="rounded-md px-3 py-1.5 text-xs font-medium ${wd.view === t.id ? "bg-surface-3 text-ink-primary" : "text-ink-secondary hover:text-ink-primary"}"
              >${t.label}</button>`,
              )
              .join("")}
          </div>
          ${wd.view === "logs" ? `<div class="flex min-w-0 items-center gap-2">${podSelector}${containerSelector}</div>` : ""}
        </div>
        <div data-detail-body class="flex min-h-0 flex-1 flex-col overflow-y-auto p-4">${body}</div>
      </div>
    </div>`;
}

// ---------------------------------------------------------------------------
// GitOps app detail panel (YAML / Events)
// ---------------------------------------------------------------------------

function renderGitOpsYamlView(gd: GitOpsDetailState): string {
  if (gd.manifestError) {
    return `<div class="text-sm text-status-critical">${esc(gd.manifestError)}</div>`;
  }
  if (!gd.manifest) {
    return `<div class="text-sm text-ink-muted">Loading…</div>`;
  }
  const yaml = currentGitOpsYamlText(gd);
  const matchCount = countSearchMatches(yaml, gd.yamlSearch);
  const scrollId = `gitops-yaml:${esc(gd.ctx)}:${esc(gd.namespace)}:${esc(gd.name)}`;
  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-3">
          <label class="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="checkbox" ${gd.showManagedFields ? "checked" : ""} onchange="window.__app.toggleGitOpsManagedFields()" />
            Show managed fields
          </label>
          ${renderCopyButton(scrollId)}
        </div>
        ${renderSearchBox("GitOps", "yaml", gd.yamlSearch, matchCount, gd.yamlSearchIndex)}
      </div>
      <pre data-scroll-id="${scrollId}" class="min-h-0 flex-1 select-text overflow-auto rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-primary">${highlightSearchMatches(highlightYaml(yaml), gd.yamlSearch, gd.yamlSearchIndex)}</pre>
    </div>`;
}

function renderNapYamlView(nd: NapDetailState): string {
  if (nd.manifestError) {
    return `<div class="text-sm text-status-critical">${esc(nd.manifestError)}</div>`;
  }
  if (!nd.manifest) {
    return `<div class="text-sm text-ink-muted">Loading…</div>`;
  }
  const yaml = currentNapYamlText(nd);
  const matchCount = countSearchMatches(yaml, nd.yamlSearch);
  const scrollId = `nap-yaml:${esc(nd.ctx)}:${esc(nd.name)}`;
  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-3">
          <label class="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="checkbox" ${nd.showManagedFields ? "checked" : ""} onchange="window.__app.toggleNapManagedFields()" />
            Show managed fields
          </label>
          ${renderCopyButton(scrollId)}
        </div>
        ${renderSearchBox("Nap", "yaml", nd.yamlSearch, matchCount, nd.yamlSearchIndex)}
      </div>
      <pre data-scroll-id="${scrollId}" class="min-h-0 flex-1 select-text overflow-auto rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-primary">${highlightSearchMatches(highlightYaml(yaml), nd.yamlSearch, nd.yamlSearchIndex)}</pre>
    </div>`;
}

function renderNapGraphView(nd: NapDetailState): string {
  const note = `
    <div class="mb-3 text-xs text-ink-muted">
      Summed across every node this pool currently owns — excludes kubelet, runtime and OS overhead, same as the Node detail Graph.
    </div>`;
  return renderMetricsGraphView(nd, "setNapMetricsRange", `nap:${nd.ctx}:${nd.name}`, note);
}

function renderNapDetailPanel(): string {
  const nd = state.napDetail;
  if (!nd) return "";

  const tabs: { id: NapDetailState["view"]; label: string }[] = [
    { id: "yaml", label: "YAML" },
    { id: "events", label: "Events" },
    { id: "graph", label: "Graph" },
  ];

  const body =
    nd.view === "yaml"
      ? renderNapYamlView(nd)
      : nd.view === "events"
        ? renderEventsList(`nap-events:${nd.ctx}:${nd.name}`, nd.events, nd.eventsError)
        : renderNapGraphView(nd);

  return `
    <div class="fixed inset-0 z-40 flex justify-end bg-black/40" onclick="window.__app.closeNapDetail()">
      <div class="flex h-full w-full max-w-3xl flex-col border-l border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">${esc(nd.name)}</div>
            <div class="truncate text-xs text-ink-muted">${esc(nd.ctx)}</div>
          </div>
          <button type="button" onclick="window.__app.closeNapDetail()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>
        <div class="flex items-center gap-1 border-b border-gridline px-4 py-2">
          ${tabs
            .map(
              (t) => `
            <button
              type="button"
              onclick="window.__app.setNapDetailView(${jsArg(t.id)})"
              data-detail-tab ${nd.view === t.id ? "data-detail-tab-active" : ""}
              class="rounded-md px-3 py-1.5 text-xs font-medium ${nd.view === t.id ? "bg-surface-3 text-ink-primary" : "text-ink-secondary hover:text-ink-primary"}"
            >${t.label}</button>`,
            )
            .join("")}
        </div>
        <div data-detail-body class="flex min-h-0 flex-1 flex-col overflow-y-auto p-4">${body}</div>
      </div>
    </div>`;
}

function renderGitOpsDetailPanel(): string {
  const gd = state.gitOpsDetail;
  if (!gd) return "";

  const tabs: { id: GitOpsDetailState["view"]; label: string }[] = [
    { id: "yaml", label: "YAML" },
    { id: "events", label: "Events" },
  ];

  const body = gd.view === "yaml" ? renderGitOpsYamlView(gd) : renderEventsList(`gitops-events:${gd.ctx}:${gd.namespace}:${gd.name}`, gd.events, gd.eventsError);

  return `
    <div class="fixed inset-0 z-40 flex justify-end bg-black/40" onclick="window.__app.closeGitOpsDetail()">
      <div class="flex h-full w-full max-w-3xl flex-col border-l border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">${esc(gd.name)}</div>
            <div class="truncate text-xs text-ink-muted">${esc(gd.ctx)} · ${esc(gd.namespace)}</div>
          </div>
          <button type="button" onclick="window.__app.closeGitOpsDetail()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>
        <div class="flex items-center gap-1 border-b border-gridline px-4 py-2">
          ${tabs
            .map(
              (t) => `
            <button
              type="button"
              onclick="window.__app.setGitOpsDetailView(${jsArg(t.id)})"
              data-detail-tab ${gd.view === t.id ? "data-detail-tab-active" : ""}
              class="rounded-md px-3 py-1.5 text-xs font-medium ${gd.view === t.id ? "bg-surface-3 text-ink-primary" : "text-ink-secondary hover:text-ink-primary"}"
            >${t.label}</button>`,
            )
            .join("")}
        </div>
        <div data-detail-body class="flex min-h-0 flex-1 flex-col overflow-y-auto p-4">${body}</div>
      </div>
    </div>`;
}

function renderEvents(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;
  type EventRow = { ctx: string; e: EventInfo };
  const rows: EventRow[] = ctxs.flatMap((ctx) => (state.events.get(ctx) || []).map((e) => ({ ctx, e })));
  // Events have no stable id from the API; this composite is unique enough in practice.
  const keyOf = (r: EventRow) => `${r.ctx}:${r.e.namespace}:${r.e.involved_object}:${r.e.reason}:${r.e.count}:${r.e.last_seen ?? ""}`;

  const columns: ColumnDef<EventRow>[] = [
    ...(multi ? [{ key: "cluster", label: "Cluster", value: (r: EventRow) => r.ctx, filter: "enum" as const }] : []),
    { key: "type", label: "Type", value: (r) => r.e.event_type, filter: "enum" },
    { key: "namespace", label: "Namespace", value: (r) => r.e.namespace, filter: "enum" },
    { key: "object", label: "Object", value: (r) => r.e.involved_object, filter: "string" },
    { key: "reason", label: "Reason", value: (r) => r.e.reason, filter: "enum" },
    { key: "message", label: "Message", value: (r) => r.e.message, filter: "string" },
    { key: "count", label: "Count", value: (r) => r.e.count, filter: "number" },
    // Not filterable: a min/max range over a raw epoch timestamp isn't a usable control.
    {
      key: "last_seen",
      label: "Last seen",
      value: (r) => (r.e.last_seen ? Date.parse(r.e.last_seen) : 0),
      copyText: (r) => r.e.last_seen ?? "",
    },
  ];
  const filtered = applyFilters("events", rows, columns);
  const sorted = sortRows("events", filtered, columns);
  recordTableSnapshot("events", columns, sorted, keyOf);
  const paged = pageSlice("events", sorted);

  return `
    <div class="mb-3 flex items-center justify-between">
      <div class="text-xs text-ink-muted">${filtered.length} of ${rows.length} event${rows.length === 1 ? "" : "s"}</div>
      <label class="flex items-center gap-2 text-xs text-ink-secondary">
        <input type="checkbox" ${state.eventsWarningsOnly ? "checked" : ""} onchange="window.__app.toggleEventsFilter()" />
        Warnings only
      </label>
    </div>
    ${hasActiveFilters("events") ? `<div class="mb-2 flex justify-end"><button onclick="window.__app.clearFilters('events')" class="text-xs text-ink-secondary hover:text-ink-primary hover:underline">Clear filters</button></div>` : ""}
    ${selectionToolbar("events")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:events">
      <table class="data-table">
        ${renderColGroup("events", columns, [32])}
        <thead>
          <tr>${selectAllCheckboxHeader("events", sorted, keyOf)}${sortableHeaderRow("events", columns)}</tr>
          <tr class="filter-row"><th></th>${filterRowCells("events", columns, rows)}</tr>
        </thead>
        <tbody>
          ${paged
            .map(
              (row) => {
                const { ctx, e } = row;
                return `
            <tr>
              ${rowCheckboxCell("events", keyOf(row))}
              ${
                multi
                  ? `<td class="text-ink-muted"><button type="button" title="Filter events by this cluster" onclick="window.__app.setEnumFilter('events','cluster',[${jsArg(ctx)}])" class="hover:text-series-blue hover:underline">${esc(ctx)}</button></td>`
                  : ""
              }
              <td><span class="${e.event_type === "Warning" ? "text-status-warning" : "text-ink-muted"}">${esc(e.event_type)}</span></td>
              <td>
                <button
                  type="button"
                  title="Filter events by this namespace"
                  onclick="window.__app.setEnumFilter('events','namespace',[${jsArg(e.namespace)}])"
                  class="hover:text-series-blue hover:underline"
                >${esc(e.namespace)}</button>
              </td>
              <td>
                <button
                  type="button"
                  title="Filter events by this object"
                  onclick="window.__app.setStringFilter('events','object',${jsArg(e.involved_object)})"
                  class="hover:text-series-blue hover:underline"
                >${esc(e.involved_object)}</button>
              </td>
              <td>${esc(e.reason)}</td>
              <td class="max-w-md truncate" title="${esc(e.message)}">${esc(e.message)}</td>
              <td class="tabular">${e.count}</td>
              <td class="tabular">${relativeTime(e.last_seen)}</td>
            </tr>`;
              },
            )
            .join("")}
        </tbody>
      </table>
      ${filtered.length === 0 && !state.tabLoading ? '<div class="p-4 text-sm text-ink-muted">No matching events.</div>' : ""}
    </div>
    ${renderPagination("events", sorted.length)}`;
}

function gitOpsAppHealthy(a: GitOpsAppInfo): boolean {
  return a.sync_status === "Synced" && a.health_status === "Healthy";
}

/** Shared "the CRDs aren't there" panel for the addon-backed tabs, so NAP and KEDA explain an empty table the same way GitOps does rather than looking broken. */
function addonNotInstalledPanel(title: string, product: string, crds: string, multi: boolean): string {
  return `
    <div class="rounded-lg border border-gridline bg-surface-1 p-5 text-sm text-ink-secondary">
      <div class="mb-2 text-sm font-medium text-ink-primary">${esc(title)}</div>
      <p>
        No <span class="text-ink-primary">${esc(product)}</span> (<code class="rounded bg-surface-2 px-1 py-0.5">${esc(crds)}</code>)
        was found in ${multi ? "any of the selected clusters" : "this cluster"}.
      </p>
    </div>`;
}

/** Banner for the mixed case: some selected clusters have the addon, some don't. */
function addonPartialNotice(product: string, missing: string[]): string {
  if (missing.length === 0) return "";
  return `
    <div class="mb-3 rounded-md border border-gridline bg-surface-2 px-3 py-2 text-xs text-ink-secondary">
      No ${esc(product)} in ${missing.map(esc).join(", ")}.
    </div>`;
}

function renderNap(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;
  const results = ctxs.map((ctx) => ({ ctx, result: state.nap.get(ctx) }));
  const answered = results.filter((r) => r.result);
  const notInstalled = answered.filter((r) => !r.result!.installed).map((r) => r.ctx);

  type NapRow = { ctx: string; p: NapNodePoolInfo };
  const allRows: NapRow[] = results.flatMap((r) => (r.result?.node_pools ?? []).map((p) => ({ ctx: r.ctx, p })));

  if (allRows.length === 0 && !state.tabLoading) {
    if (notInstalled.length > 0 && notInstalled.length === answered.length) {
      return addonNotInstalledPanel(
        "Node Auto Provisioning not enabled",
        "Karpenter / NAP",
        "nodepools.karpenter.sh",
        ctxs.length > 1,
      );
    }
    // Some clusters have the addon and simply have nothing to show, while
    // others may not have it at all — keep naming the latter, or this mixed
    // case reads as "nothing is configured anywhere". Renders to nothing
    // when every answering cluster does have the addon.
    return `
      ${addonPartialNotice('Karpenter / NAP', notInstalled)}
      <div class="text-sm text-ink-muted">No NAP node pools found.</div>`;
  }

  const rows = state.unhealthyOnly.nap ? allRows.filter((r) => !r.p.ready) : allRows;
  const keyOf = (r: NapRow) => `${r.ctx}:${r.p.name}`;

  const columns: ColumnDef<NapRow>[] = [
    ...(multi ? [{ key: "cluster", label: "Cluster", value: (r: NapRow) => r.ctx, filter: "enum" as const }] : []),
    { key: "name", label: "Name", value: (r) => r.p.name, filter: "string" },
    { key: "nodeclass", label: "Node class", value: (r) => r.p.node_class, filter: "enum" },
    { key: "capacity", label: "Capacity", value: (r) => r.p.capacity_types, filter: "enum" },
    { key: "nodes", label: "Nodes", value: (r) => r.p.nodes, filter: "number" },
    {
      key: "cpu",
      label: "CPU Usage/Limit",
      value: (r) => r.p.cpu_used_millicores,
      filter: "number",
      copyText: (r) => `${formatMillicores(r.p.cpu_used_millicores)} / ${formatMillicores(r.p.cpu_limit_millicores)}`,
    },
    {
      key: "memory",
      label: "Memory Usage/Limit",
      value: (r) => r.p.memory_used_ki,
      filter: "number",
      copyText: (r) => `${formatKi(r.p.memory_used_ki)} / ${formatKi(r.p.memory_limit_ki)}`,
    },
    { key: "weight", label: "Weight", value: (r) => r.p.weight, filter: "number" },
    {
      key: "age",
      label: "Age",
      value: (r) => r.p.age_days,
      filter: "number",
      copyText: (r) => formatAgeDetailed(r.p.age_days, r.p.age_seconds),
      sortValue: (r) => r.p.age_seconds,
    },
  ];
  const filtered = applyFilters("nap", rows, columns);
  const sorted = sortRows("nap", filtered, columns);
  recordTableSnapshot("nap", columns, sorted, keyOf, {
    header: "Status",
    text: (r) => (r.p.ready ? "Ready" : r.p.status_reason || "Not ready"),
  });

  return `
    ${addonPartialNotice("Karpenter / NAP", notInstalled)}
    <div class="mb-2 flex items-center justify-between">
      <div class="text-xs text-ink-muted">${state.unhealthyOnly.nap ? `${rows.length} of ${allRows.length} not ready` : ""}</div>
      ${unhealthyOnlyToggle("nap")}
    </div>
    ${filterSummary("nap", rows.length, filtered.length)}
    ${selectionToolbar("nap")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:nap">
      <table class="data-table">
        ${renderColGroup("nap", columns, [32, 36])}
        <thead>
          <tr>${selectAllCheckboxHeader("nap", sorted, keyOf)}<th></th>${sortableHeaderRow("nap", columns)}</tr>
          <tr class="filter-row"><th></th><th></th>${filterRowCells("nap", columns, rows)}</tr>
        </thead>
        <tbody>
          ${sorted
            .map((row) => {
              const { ctx, p } = row;
              return `
            <tr>
              ${rowCheckboxCell("nap", keyOf(row))}
              <td title="${esc(p.ready ? "Ready" : p.status_reason || "Not ready")}">${statusDot(p.ready)}</td>
              ${
                multi
                  ? `<td class="text-ink-muted"><button type="button" title="Filter by this cluster" onclick="window.__app.setEnumFilter('nap','cluster',[${jsArg(ctx)}])" class="hover:text-series-blue hover:underline">${esc(ctx)}</button></td>`
                  : ""
              }
              <td>
                <span class="inline-flex items-center gap-1.5">
                  <button
                    type="button"
                    title="View node pool details (YAML, Events, Graph)"
                    data-row-open onclick="window.__app.openNapDetail(${jsArg(ctx)},${jsArg(p.name)})"
                    class="shrink-0 rounded p-0.5 text-ink-muted hover:bg-surface-3 hover:text-ink-primary"
                  >
                    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><line x1="12" y1="11" x2="12" y2="16.5"/><circle cx="12" cy="8" r="0.5" fill="currentColor" stroke="none"/></svg>
                  </button>
                  <button
                    type="button"
                    title="View nodes provisioned by this pool"
                    onclick="window.__app.viewNodesForNodePool(${jsArg(ctx)},${jsArg(p.name)})"
                    class="text-ink-primary hover:text-series-blue hover:underline"
                  >${esc(p.name)}</button>
                </span>
              </td>
              <td>${esc(p.node_class) || "—"}</td>
              <td>${esc(p.capacity_types) || "—"}</td>
              <td class="tabular">${p.nodes}</td>
              <td class="tabular">${formatMillicores(p.cpu_used_millicores)} / ${formatMillicores(p.cpu_limit_millicores)}</td>
              <td class="tabular">${formatKi(p.memory_used_ki)} / ${formatKi(p.memory_limit_ki)}</td>
              <td class="tabular">${p.weight}</td>
              <td class="tabular">${formatAgeDetailed(p.age_days, p.age_seconds)}</td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
      ${sorted.length === 0 && !state.tabLoading ? '<div class="p-4 text-sm text-ink-muted">No matching node pools.</div>' : ""}
    </div>`;
}

function renderKeda(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;
  const results = ctxs.map((ctx) => ({ ctx, result: state.keda.get(ctx) }));
  const answered = results.filter((r) => r.result);
  const notInstalled = answered.filter((r) => !r.result!.installed).map((r) => r.ctx);

  type KedaRow = { ctx: string; s: KedaScaledObjectInfo };
  const allRows: KedaRow[] = results.flatMap((r) => (r.result?.scaled_objects ?? []).map((s) => ({ ctx: r.ctx, s })));

  if (allRows.length === 0 && !state.tabLoading) {
    if (notInstalled.length > 0 && notInstalled.length === answered.length) {
      return addonNotInstalledPanel("KEDA not enabled", "KEDA", "scaledobjects.keda.sh", ctxs.length > 1);
    }
    // Some clusters have the addon and simply have nothing to show, while
    // others may not have it at all — keep naming the latter, or this mixed
    // case reads as "nothing is configured anywhere". Renders to nothing
    // when every answering cluster does have the addon.
    return `
      ${addonPartialNotice('KEDA', notInstalled)}
      <div class="text-sm text-ink-muted">No KEDA scaled objects found.</div>`;
  }

  const rows = state.unhealthyOnly.keda ? allRows.filter((r) => !r.s.ready) : allRows;
  const keyOf = (r: KedaRow) => `${r.ctx}:${r.s.namespace}:${r.s.kind}:${r.s.name}`;

  const columns: ColumnDef<KedaRow>[] = [
    ...(multi ? [{ key: "cluster", label: "Cluster", value: (r: KedaRow) => r.ctx, filter: "enum" as const }] : []),
    { key: "namespace", label: "Namespace", value: (r) => r.s.namespace, filter: "enum" },
    { key: "name", label: "Name", value: (r) => r.s.name, filter: "string" },
    { key: "kind", label: "Kind", value: (r) => r.s.kind, filter: "enum" },
    { key: "target", label: "Target", value: (r) => (r.s.target_name ? `${r.s.target_kind}/${r.s.target_name}` : r.s.target_kind), filter: "string" },
    { key: "triggers", label: "Triggers", value: (r) => r.s.triggers, filter: "string" },
    { key: "min", label: "Min", value: (r) => r.s.min_replicas, filter: "number" },
    { key: "max", label: "Max", value: (r) => r.s.max_replicas, filter: "number" },
    { key: "active", label: "Active", value: (r) => (r.s.active ? "Active" : "Idle"), filter: "enum" },
    {
      key: "age",
      label: "Age",
      value: (r) => r.s.age_days,
      filter: "number",
      copyText: (r) => formatAgeDetailed(r.s.age_days, r.s.age_seconds),
      sortValue: (r) => r.s.age_seconds,
    },
  ];
  const filtered = applyFilters("keda", rows, columns);
  const sorted = sortRows("keda", filtered, columns);
  recordTableSnapshot("keda", columns, sorted, keyOf, {
    header: "Status",
    text: (r) => (r.s.paused ? "Paused" : r.s.ready ? "Ready" : "Not ready"),
  });

  return `
    ${addonPartialNotice("KEDA", notInstalled)}
    <div class="mb-2 flex items-center justify-between">
      <div class="text-xs text-ink-muted">${state.unhealthyOnly.keda ? `${rows.length} of ${allRows.length} not ready` : ""}</div>
      ${unhealthyOnlyToggle("keda")}
    </div>
    ${filterSummary("keda", rows.length, filtered.length)}
    ${selectionToolbar("keda")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:keda">
      <table class="data-table">
        ${renderColGroup("keda", columns, [32, 36])}
        <thead>
          <tr>${selectAllCheckboxHeader("keda", sorted, keyOf)}<th></th>${sortableHeaderRow("keda", columns)}</tr>
          <tr class="filter-row"><th></th><th></th>${filterRowCells("keda", columns, rows)}</tr>
        </thead>
        <tbody>
          ${sorted
            .map((row) => {
              const { ctx, s: so } = row;
              const status = so.paused ? "Paused" : so.ready ? "Ready" : "Not ready";
              return `
            <tr>
              ${rowCheckboxCell("keda", keyOf(row))}
              <td title="${esc(status)}">${statusDot(so.ready, so.paused)}</td>
              ${
                multi
                  ? `<td class="text-ink-muted"><button type="button" title="Filter by this cluster" onclick="window.__app.setEnumFilter('keda','cluster',[${jsArg(ctx)}])" class="hover:text-series-blue hover:underline">${esc(ctx)}</button></td>`
                  : ""
              }
              <td><button type="button" title="Filter by this namespace" onclick="window.__app.setEnumFilter('keda','namespace',[${jsArg(so.namespace)}])" class="hover:text-series-blue hover:underline">${esc(so.namespace)}</button></td>
              <td class="text-ink-primary">${esc(so.name)}</td>
              <td>${esc(so.kind)}</td>
              <td>${esc(so.target_name ? `${so.target_kind}/${so.target_name}` : so.target_kind)}</td>
              <td class="max-w-md truncate" title="${esc(so.triggers)}">${esc(so.triggers) || "—"}</td>
              <td class="tabular">${so.min_replicas}</td>
              <td class="tabular">${so.max_replicas}</td>
              <td><span class="${so.active ? "text-status-good" : "text-ink-muted"}">${so.active ? "Active" : "Idle"}</span></td>
              <td class="tabular">${formatAgeDetailed(so.age_days, so.age_seconds)}</td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
      ${sorted.length === 0 && !state.tabLoading ? '<div class="p-4 text-sm text-ink-muted">No matching scaled objects.</div>' : ""}
    </div>`;
}

function renderGitOps(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;
  const results = ctxs.map((ctx) => ({ ctx, result: state.gitops.get(ctx) }));
  const notInstalled = results.filter((r) => r.result && !r.result.installed).map((r) => r.ctx);

  type GitOpsRow = { ctx: string; a: GitOpsAppInfo };
  const allRows: GitOpsRow[] = results.flatMap((r) => (r.result?.apps ?? []).map((a) => ({ ctx: r.ctx, a })));

  if (allRows.length === 0 && !state.tabLoading) {
    if (notInstalled.length > 0 && notInstalled.length === results.filter((r) => r.result).length) {
      return `
        <div class="rounded-lg border border-gridline bg-surface-1 p-5 text-sm text-ink-secondary">
          <div class="mb-2 text-sm font-medium text-ink-primary">No GitOps controller detected</div>
          <p>
            No <span class="text-ink-primary">ArgoCD</span> (<code class="rounded bg-surface-2 px-1 py-0.5">applications.argoproj.io</code>)
            was found in ${ctxs.length > 1 ? "any of the selected clusters" : "this cluster"}.
          </p>
        </div>`;
    }
    return `<div class="text-sm text-ink-muted">No ArgoCD applications found.</div>`;
  }

  const rows = state.unhealthyOnly.gitops ? allRows.filter((r) => !gitOpsAppHealthy(r.a)) : allRows;
  const keyOf = (r: GitOpsRow) => `${r.ctx}:${r.a.namespace}:${r.a.name}`;

  const columns: ColumnDef<GitOpsRow>[] = [
    ...(multi ? [{ key: "cluster", label: "Cluster", value: (r: GitOpsRow) => r.ctx, filter: "enum" as const }] : []),
    { key: "namespace", label: "Namespace", value: (r) => r.a.namespace, filter: "enum" },
    { key: "name", label: "Name", value: (r) => r.a.name, filter: "string" },
    { key: "destination", label: "Destination NS", value: (r) => r.a.destination_namespace, filter: "enum" },
    {
      key: "sync",
      label: "Sync",
      // `value` stays the status string: it's what the enum filter dropdown
      // lists, and a per-row timestamp there would make that dropdown a
      // useless wall of one-off values instead of ~3 checkable states.
      value: (r) => r.a.sync_status,
      filter: "enum",
      // Sorting overrides to the timestamp instead: recency is the more
      // common reason to sort this column (finding what's gone stale),
      // while status still has its own filter for narrowing to OutOfSync.
      sortValue: (r) => (r.a.last_synced_at ? Date.parse(r.a.last_synced_at) : 0),
      copyText: (r) => `${r.a.sync_status}${r.a.last_synced_at ? ` (${r.a.last_synced_at})` : ""}`,
    },
    { key: "health", label: "Health", value: (r) => r.a.health_status, filter: "enum" },
    { key: "repo", label: "Repo", value: (r) => r.a.repo_url, filter: "string" },
    { key: "path", label: "Path", value: (r) => r.a.path, filter: "string" },
    { key: "revision", label: "Revision", value: (r) => r.a.revision, filter: "string" },
    {
      key: "age",
      label: "Age",
      value: (r) => r.a.age_days,
      filter: "number",
      copyText: (r) => formatAgeDetailed(r.a.age_days, r.a.age_seconds),
      sortValue: (r) => r.a.age_seconds,
    },
  ];
  const filtered = applyFilters("gitops", rows, columns);
  const sorted = sortRows("gitops", filtered, columns);
  recordTableSnapshot("gitops", columns, sorted, keyOf, {
    header: "Status",
    text: (r) => (gitOpsAppHealthy(r.a) ? "Healthy" : `${r.a.sync_status}/${r.a.health_status}`),
  });
  const paged = pageSlice("gitops", sorted);

  const notice =
    notInstalled.length > 0
      ? `<div class="mb-2 text-xs text-ink-muted">ArgoCD not detected in: ${notInstalled.map(esc).join(", ")}</div>`
      : "";

  return `
    ${notice}
    <div class="mb-2 flex items-center justify-between">
      <div class="text-xs text-ink-muted">${state.unhealthyOnly.gitops ? `${rows.length} of ${allRows.length} unhealthy` : ""}</div>
      ${unhealthyOnlyToggle("gitops")}
    </div>
    ${filterSummary("gitops", rows.length, filtered.length)}
    ${selectionToolbar("gitops")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:gitops">
      <table class="data-table">
        ${renderColGroup("gitops", columns, [32, 36])}
        <thead>
          <tr>${selectAllCheckboxHeader("gitops", sorted, keyOf)}<th></th>${sortableHeaderRow("gitops", columns)}</tr>
          <tr class="filter-row"><th></th><th></th>${filterRowCells("gitops", columns, rows)}</tr>
        </thead>
        <tbody>
          ${paged
            .map((row) => {
              const { ctx, a } = row;
              return `
            <tr>
              ${rowCheckboxCell("gitops", keyOf(row))}
              <td>${statusDot(gitOpsAppHealthy(row.a))}</td>
              ${
                multi
                  ? `<td class="text-ink-muted"><button type="button" title="Filter GitOps apps by this cluster" onclick="window.__app.setEnumFilter('gitops','cluster',[${jsArg(ctx)}])" class="hover:text-series-blue hover:underline">${esc(ctx)}</button></td>`
                  : ""
              }
              <td><button type="button" title="Filter GitOps apps by this namespace" onclick="window.__app.setEnumFilter('gitops','namespace',[${jsArg(a.namespace)}])" class="hover:text-series-blue hover:underline">${esc(a.namespace)}</button></td>
              <td>
                <button
                  type="button"
                  title="View Application details (YAML, Events)"
                  data-row-open onclick="window.__app.openGitOpsDetail(${jsArg(ctx)},${jsArg(a.namespace)},${jsArg(a.name)})"
                  class="text-ink-primary hover:text-series-blue hover:underline"
                >${esc(a.name)}</button>
              </td>
              <td>${esc(a.destination_namespace)}</td>
              <td class="${a.sync_status === "Synced" ? "" : "text-status-warning"}" title="${esc(a.last_synced_at ?? "")}">
                ${esc(a.sync_status)}${a.last_synced_at ? ` <span class="tabular text-ink-muted">· ${relativeTime(a.last_synced_at)}</span>` : ""}
              </td>
              <td class="${a.health_status === "Healthy" ? "" : a.health_status === "Degraded" ? "text-status-critical" : "text-status-warning"}">${esc(a.health_status)}</td>
              <td class="max-w-xs truncate" title="${esc(a.repo_url)}">${esc(a.repo_url)}</td>
              <td class="max-w-xs truncate" title="${esc(a.path)}">${esc(a.path) || "—"}</td>
              <td class="tabular">${esc(a.revision) || "—"}</td>
              <td class="tabular">${formatAgeDetailed(a.age_days, a.age_seconds)}</td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
      ${sorted.length === 0 && !state.tabLoading ? '<div class="p-4 text-sm text-ink-muted">No matching applications.</div>' : ""}
    </div>
    ${renderPagination("gitops", sorted.length)}`;
}

/** `deployed` is Helm's own success status; everything else (failed, pending-*, superseded, unknown) is worth flagging. */
function helmReleaseHealthy(r: HelmReleaseInfo): boolean {
  return r.status === "deployed";
}

function helmStatusClass(status: string): string {
  if (status === "deployed") return "";
  if (status === "failed") return "text-status-critical";
  return "text-status-warning";
}

function renderHelm(): string {
  const ctxs = selectedContextsList();
  const multi = ctxs.length > 1;
  type HelmRow = { ctx: string; r: HelmReleaseInfo };
  const allRows: HelmRow[] = ctxs.flatMap((ctx) => (state.helm.get(ctx) || []).map((r) => ({ ctx, r })));

  if (allRows.length === 0 && !state.tabLoading) {
    return `
      <div class="rounded-lg border border-gridline bg-surface-1 p-5 text-sm text-ink-secondary">
        <div class="mb-2 text-sm font-medium text-ink-primary">No Helm releases found</div>
        <p>
          Helm stores each release as a <code class="rounded bg-surface-2 px-1 py-0.5">helm.sh/release.v1</code>
          Secret. None were found in ${ctxs.length > 1 ? "any of the selected clusters" : "this cluster"} —
          either nothing is installed via Helm, or the releases live in namespaces this kubeconfig can't read.
        </p>
      </div>`;
  }

  const rows = state.unhealthyOnly.helm ? allRows.filter((r) => !helmReleaseHealthy(r.r)) : allRows;
  const keyOf = (row: HelmRow) => `${row.ctx}:${row.r.namespace}:${row.r.name}`;

  const columns: ColumnDef<HelmRow>[] = [
    ...(multi ? [{ key: "cluster", label: "Cluster", value: (row: HelmRow) => row.ctx, filter: "enum" as const }] : []),
    { key: "namespace", label: "Namespace", value: (row) => row.r.namespace, filter: "enum" },
    { key: "name", label: "Release", value: (row) => row.r.name, filter: "string" },
    { key: "status", label: "Status", value: (row) => row.r.status, filter: "enum" },
    { key: "chart", label: "Chart", value: (row) => row.r.chart_name, filter: "enum" },
    { key: "chart_version", label: "Chart ver.", value: (row) => row.r.chart_version, filter: "string" },
    { key: "app_version", label: "App ver.", value: (row) => row.r.app_version, filter: "string" },
    { key: "revision", label: "Rev", value: (row) => row.r.revision, filter: "number" },
    {
      key: "updated",
      label: "Updated",
      value: (row) => row.r.age_days,
      filter: "number",
      copyText: (row) => formatAgeDetailed(row.r.age_days, row.r.age_seconds),
      sortValue: (row) => row.r.age_seconds,
    },
    { key: "description", label: "Description", value: (row) => row.r.description, filter: "string" },
  ];
  const filtered = applyFilters("helm", rows, columns);
  const sorted = sortRows("helm", filtered, columns);
  recordTableSnapshot("helm", columns, sorted, keyOf, {
    header: "Health",
    text: (row) => (helmReleaseHealthy(row.r) ? "Healthy" : row.r.status),
  });
  const paged = pageSlice("helm", sorted);

  return `
    <div class="mb-2 flex items-center justify-between">
      <div class="text-xs text-ink-muted">${state.unhealthyOnly.helm ? `${rows.length} of ${allRows.length} not deployed` : ""}</div>
      ${unhealthyOnlyToggle("helm")}
    </div>
    ${filterSummary("helm", rows.length, filtered.length)}
    ${selectionToolbar("helm")}
    <div class="overflow-auto rounded-lg border border-gridline" data-scroll-id="table:helm">
      <table class="data-table">
        ${renderColGroup("helm", columns, [32, 36])}
        <thead>
          <tr>${selectAllCheckboxHeader("helm", sorted, keyOf)}<th></th>${sortableHeaderRow("helm", columns)}</tr>
          <tr class="filter-row"><th></th><th></th>${filterRowCells("helm", columns, rows)}</tr>
        </thead>
        <tbody>
          ${paged
            .map((row) => {
              const { ctx, r } = row;
              return `
            <tr>
              ${rowCheckboxCell("helm", keyOf(row))}
              <td>${statusDot(helmReleaseHealthy(r))}</td>
              ${
                multi
                  ? `<td class="text-ink-muted"><button type="button" title="Filter releases by this cluster" onclick="window.__app.setEnumFilter('helm','cluster',[${jsArg(ctx)}])" class="hover:text-series-blue hover:underline">${esc(ctx)}</button></td>`
                  : ""
              }
              <td><button type="button" title="Filter releases by this namespace" onclick="window.__app.setEnumFilter('helm','namespace',[${jsArg(r.namespace)}])" class="hover:text-series-blue hover:underline">${esc(r.namespace)}</button></td>
              <td>
                <button
                  type="button"
                  title="View release details (Values, Manifest, Notes)"
                  data-row-open onclick="window.__app.openHelmDetail(${jsArg(ctx)},${jsArg(r.namespace)},${jsArg(r.name)},${r.revision})"
                  class="text-ink-primary hover:text-series-blue hover:underline"
                >${esc(r.name)}</button>
              </td>
              <td class="${helmStatusClass(r.status)}">${esc(r.status)}</td>
              <td>${esc(r.chart_name) || "—"}</td>
              <td class="tabular">${esc(r.chart_version) || "—"}</td>
              <td class="tabular">${esc(r.app_version) || "—"}</td>
              <td class="tabular" title="${r.revision_count} revision${r.revision_count === 1 ? "" : "s"} retained">${r.revision}</td>
              <td class="tabular">${formatAgeDetailed(r.age_days, r.age_seconds)}</td>
              <td class="max-w-xs" title="${esc(r.description)}">
                <span class="inline-flex items-center gap-1.5">
                  <span class="min-w-0 truncate">${esc(r.description) || "—"}</span>
                  ${helmReleaseHealthy(r) ? "" : claudeExplainButton(`${r.name} (Helm release)`, r.description)}
                </span>
              </td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
      ${sorted.length === 0 && !state.tabLoading ? '<div class="p-4 text-sm text-ink-muted">No matching releases.</div>' : ""}
    </div>
    ${renderPagination("helm", sorted.length)}`;
}

// ---------------------------------------------------------------------------
// Helm release detail panel (Values / Manifest / Notes)
// ---------------------------------------------------------------------------

function renderHelmDetailBody(hd: HelmDetailState): string {
  if (hd.detailError) {
    return `<div class="text-sm text-status-critical">${esc(hd.detailError)}</div>`;
  }
  if (!hd.detail) {
    return `<div class="text-sm text-ink-muted">Loading…</div>`;
  }

  const text = currentHelmText(hd);
  const scrollId = `helm-${hd.view}:${esc(hd.ctx)}:${esc(hd.namespace)}:${esc(hd.name)}`;
  const matchCount = countSearchMatches(text, hd.search);

  // Notes are plain prose from the chart author, so the YAML colouriser would
  // only add noise; Values and Manifest are both YAML.
  const highlighted =
    hd.view === "notes"
      ? highlightSearchMatches(esc(text), hd.search, hd.searchIndex)
      : highlightSearchMatches(highlightYaml(text), hd.search, hd.searchIndex);

  const emptyMessage =
    hd.view === "values"
      ? hd.showDefaultValues
        ? "This chart ships no default values."
        : "No user-supplied values — the release uses the chart defaults."
      : hd.view === "notes"
        ? "This chart provides no notes."
        : "This release has no rendered manifest.";

  const valuesToggle =
    hd.view === "values"
      ? `<label class="flex items-center gap-2 text-xs text-ink-secondary">
          <input type="checkbox" ${hd.showDefaultValues ? "checked" : ""} onchange="window.__app.toggleHelmDefaultValues()" />
          Show chart defaults
        </label>`
      : "";

  return `
    <div class="flex h-full min-h-0 flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-3">
          ${valuesToggle}
          ${renderCopyButton(scrollId)}
        </div>
        ${renderSearchBox("Helm", hd.view, hd.search, matchCount, hd.searchIndex)}
      </div>
      <pre data-scroll-id="${scrollId}" class="min-h-0 flex-1 select-text overflow-auto whitespace-pre-wrap rounded-md border border-gridline bg-surface-2 p-3 text-xs text-ink-primary">${
        text ? highlighted : `<span class="text-ink-muted">${esc(emptyMessage)}</span>`
      }</pre>
    </div>`;
}

function renderHelmDetailPanel(): string {
  const hd = state.helmDetail;
  if (!hd) return "";

  const tabs: { id: HelmDetailState["view"]; label: string }[] = [
    { id: "values", label: "Values" },
    { id: "manifest", label: "Manifest" },
    { id: "notes", label: "Notes" },
  ];

  return `
    <div class="fixed inset-0 z-40 flex justify-end bg-black/40" onclick="window.__app.closeHelmDetail()">
      <div class="flex h-full w-full max-w-3xl flex-col border-l border-gridline bg-surface-1 shadow-2xl" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between border-b border-gridline px-4 py-3">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium text-ink-primary">${esc(hd.name)}</div>
            <div class="truncate text-xs text-ink-muted">${esc(hd.ctx)} · ${esc(hd.namespace)} · revision ${hd.revision}</div>
          </div>
          <button type="button" onclick="window.__app.closeHelmDetail()" class="rounded-md p-1 text-ink-secondary hover:bg-surface-2 hover:text-ink-primary" title="Close">✕</button>
        </div>
        <div class="flex items-center gap-1 border-b border-gridline px-4 py-2">
          ${tabs
            .map(
              (t) => `
            <button
              type="button"
              onclick="window.__app.setHelmDetailView(${jsArg(t.id)})"
              data-detail-tab ${hd.view === t.id ? "data-detail-tab-active" : ""}
              class="rounded-md px-3 py-1.5 text-xs font-medium ${hd.view === t.id ? "bg-surface-3 text-ink-primary" : "text-ink-secondary hover:text-ink-primary"}"
            >${t.label}</button>`,
            )
            .join("")}
        </div>
        <div data-detail-body class="flex min-h-0 flex-1 flex-col overflow-y-auto p-4">${renderHelmDetailBody(hd)}</div>
      </div>
    </div>`;
}

function renderCost(): string {
  return `
    <div class="rounded-lg border border-gridline bg-surface-1 p-5 text-sm text-ink-secondary">
      <div class="mb-2 text-sm font-medium text-ink-primary">Cost breakdown — not wired up yet</div>
      <p class="mb-2">
        Kubernetes' own API doesn't carry Azure billing data, so this tab needs the
        <span class="text-ink-primary">Azure Cost Management API</span> (or Kubecost /
        OpenCost if you run one in-cluster) rather than kubeconfig access alone.
      </p>
      <p>
        To wire this up: create an app registration with <span class="text-ink-primary">Cost Management Reader</span>
        on the subscription(s) these AKS clusters live in, then add a Rust command in
        <code class="rounded bg-surface-2 px-1 py-0.5">src-tauri/src/cost.rs</code> that calls the
        Cost Management "query" REST API scoped to each cluster's resource group and renders it here.
        See README.md for a fuller sketch.
      </p>
    </div>`;
}

// Attached once on `document` rather than re-attached per render, since
// render() replaces the whole #app subtree — a listener on the dropdown
// itself would be destroyed along with it. Clicks inside the dropdown
// (the toggle button or a checkbox) are excluded via closest() so checking
// multiple boxes doesn't close the menu after each one.
document.addEventListener("click", (e) => {
  if (state.openEnumFilter === null) return;
  const target = e.target instanceof Element ? e.target : null;
  if (target?.closest("[data-enum-dropdown]")) return;
  closeEnumDropdown();
});

/** True for inputs/textareas/contenteditable — used to keep Cmd+Left as native cursor-to-line-start there instead of app back-navigation. */
function isEditableTarget(target: EventTarget | null): boolean {
  return target instanceof HTMLElement && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
}

/**
 * Every full-screen detail panel, in the priority order `closeOpenDetailPanel`
 * closes them in. Single source of truth for that and for
 * `isAnyDetailPanelOpen` below — adding a panel means adding one entry here,
 * not hand-updating every place that used to enumerate them separately. That
 * duplication is exactly what let the NAP panel ship without being wired
 * into Escape/Cmd+Left or the Cmd+Right guard.
 */
const DETAIL_PANEL_CLOSERS: { isOpen: () => boolean; close: () => void }[] = [
  { isOpen: () => !!state.podDetail, close: closePodDetail },
  { isOpen: () => !!state.nodeDetail, close: closeNodeDetail },
  { isOpen: () => !!state.workloadDetail, close: closeWorkloadDetail },
  { isOpen: () => !!state.gitOpsDetail, close: closeGitOpsDetail },
  { isOpen: () => !!state.helmDetail, close: closeHelmDetail },
  { isOpen: () => !!state.napDetail, close: closeNapDetail },
];

function isAnyDetailPanelOpen(): boolean {
  return DETAIL_PANEL_CLOSERS.some((p) => p.isOpen());
}

/**
 * Elements that give the *unmodified* navigation keys — the four arrows,
 * PageUp/PageDown and Home/End — their own meaning, so tab stepping and the
 * row cursor must not steal them.
 *
 * Deliberately broader than `isEditableTarget`: a focused `<select>` (the
 * auto-refresh interval, page size, metrics range, pod/container pickers)
 * moves through its own options on every one of these keys, whereas
 * Cmd+Left/Right — which `isEditableTarget` guards — has no competing
 * meaning there, so widening that helper instead would needlessly disable
 * view-history navigation while a dropdown happens to hold focus.
 */
function consumesPlainNavKeys(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target instanceof HTMLInputElement && (target.type === "checkbox" || target.type === "radio")) {
    // Neither has any arrow/Home/End behavior of its own, and the row-select
    // checkbox is focusable — so treating every <input> alike would leave the
    // row cursor dead after tabbing onto one. They do still consume Enter and
    // Space, which `consumesActivationKeys` accounts for separately.
    return false;
  }
  return (
    target.tagName === "INPUT" ||
    target.tagName === "TEXTAREA" ||
    target.tagName === "SELECT" ||
    target.isContentEditable
  );
}

/**
 * True while something is layered over the tab content that fully *takes*
 * a plain arrow key: the cluster palette, Claude's panel/explain/diagnose
 * views, the metrics-backend editor, or an open enum dropdown.
 *
 * Detail panels are deliberately excluded, which is the whole reason this is
 * separate from `isAnyOverlayOpen`. A panel doesn't swallow Left/Right, it
 * redirects them to its own tab bar (see `stepDetailTab`) — so adding panels
 * back into this predicate would silently kill that. Use `isAnyOverlayOpen`
 * for the "is anything at all on top" question; use this one only where a
 * detail panel should still get a say.
 */
function isNonPanelOverlayOpen(): boolean {
  return (
    !!state.clusterPalette ||
    !!state.claudeExplain ||
    !!state.claudeDiagnose ||
    state.claudePanelOpen ||
    !!state.metricsBackendEditor ||
    state.openEnumFilter !== null
  );
}

/** True while anything at all covers the tab content, detail panels included — the broad guard for keys that no overlay should let through. */
function isAnyOverlayOpen(): boolean {
  return isNonPanelOverlayOpen() || isAnyDetailPanelOpen();
}

/** How far one arrow press scrolls a detail panel, in px — roughly what a browser's own arrow scrolling moves, since that's the feel this is standing in for. */
const DETAIL_SCROLL_LINE_PX = 40;

/**
 * Whether `el` can actually be scrolled by setting `scrollTop`.
 *
 * Overflowing is not enough: an element with `overflow: visible` still
 * reports a scrollHeight larger than its clientHeight, but silently ignores
 * scrollTop because it is not a scroll container. Treating that as scrollable
 * would make the caller claim the key and then do nothing — worse than not
 * handling it, since preventDefault also stops the browser's own scrolling.
 */
function isScrollable(el: HTMLElement): boolean {
  if (el.scrollHeight <= el.clientHeight + 1) return false;
  const overflowY = getComputedStyle(el).overflowY;
  return overflowY !== "visible" && overflowY !== "clip";
}

/**
 * The scrollable region of the open detail panel, if it has one.
 *
 * Needed because the panes that actually overflow — the YAML `<pre>`, the log
 * `<pre>`, the events list — aren't focusable, so the browser's own arrow
 * scrolling never reaches them: it scrolls the focused element's nearest
 * scrollable ancestor, and with focus on `<body>` that isn't the panel at all.
 * Hence scrolling it explicitly.
 *
 * Prefers a `data-scroll-id` descendant, since those are the panes built to
 * scroll (and whose position render() already preserves), falling back to the
 * panel body itself. Returns null when nothing overflows — the Graph tab,
 * or a short manifest — so the caller can leave the key alone.
 */
function detailPanelScroller(): HTMLElement | null {
  const body = document.querySelector<HTMLElement>("[data-detail-body]");
  if (!body) return null;
  const pane = [...body.querySelectorAll<HTMLElement>("[data-scroll-id]")].find(isScrollable);
  return pane ?? (isScrollable(body) ? body : null);
}

/** Scrolls the open detail panel by a line, a near-full page, or to either edge. */
function scrollDetailPanel(mode: "line" | "page" | "edge", direction: 1 | -1): boolean {
  const el = detailPanelScroller();
  if (!el) return false;
  if (mode === "edge") {
    el.scrollTop = direction > 0 ? el.scrollHeight : 0;
  } else {
    // A page leaves a sliver of overlap so the reader keeps their place.
    el.scrollTop += direction * (mode === "page" ? el.clientHeight * 0.9 : DETAIL_SCROLL_LINE_PX);
  }
  return true;
}

/**
 * Cmd+F: puts the cursor in the open detail panel's search box.
 *
 * Only some views have one — YAML and the log panes do, Events and Graph
 * don't — so this reports whether it found one, letting the caller leave the
 * key alone rather than swallowing it on a view with nothing to search.
 *
 * Selects the existing query so a second Cmd+F retypes rather than appends,
 * which is what the browser's own find bar does. The input already carries a
 * `data-filter-key`, so `render()`'s focus restoration keeps the caret there
 * across the re-render that typing triggers.
 */
function focusDetailSearch(): boolean {
  const input = document.querySelector<HTMLInputElement>("[data-detail-search]");
  if (!input) return false;
  input.focus();
  input.select();
  return true;
}

/**
 * Left/Right inside an open detail panel step that panel's own tabs (YAML /
 * Events / Graph, and the wider sets Pods and Workloads carry) rather than
 * the main tab bar hidden behind it.
 *
 * Reads the rendered buttons instead of consulting each panel's tab list:
 * six panels define those lists locally, with different lengths and members,
 * and a second copy here would be six chances to drift. Only one panel is
 * ever open — they close each other — so a document-wide query is
 * unambiguous, and a panel added later is picked up with no change here.
 */
function stepDetailTab(delta: number): boolean {
  const tabs = [...document.querySelectorAll<HTMLElement>("[data-detail-tab]")];
  if (tabs.length === 0) return false;
  const active = tabs.findIndex((t) => t.hasAttribute("data-detail-tab-active"));
  const from = active === -1 ? 0 : active;
  // Clamped, like the main tab bar it mirrors.
  const next = Math.min(tabs.length - 1, Math.max(0, from + delta));
  if (next !== active) tabs[next].click();
  return true;
}

/**
 * Adds the natively-clickable elements to `consumesPlainNavKeys`. A focused
 * `<button>` or link already responds to Enter and Space on its own, so the
 * row cursor must not act on top of it and fire two things at once.
 */
function consumesActivationKeys(target: EventTarget | null): boolean {
  if (consumesPlainNavKeys(target)) return true;
  if (!(target instanceof HTMLElement)) return false;
  // Checkbox and radio are deliberately re-included here after being excluded
  // from the nav guard: they ignore the arrows but do act on Enter/Space, so
  // the row cursor must not fire on top of them.
  return (
    target.tagName === "BUTTON" ||
    target.tagName === "A" ||
    (target instanceof HTMLInputElement && (target.type === "checkbox" || target.type === "radio"))
  );
}

/** The `<tr>` the row cursor currently sits on, clamped to the rows actually rendered. */
function focusedRowElement(): HTMLElement | null {
  const tbody = document.querySelector<HTMLElement>(`[data-scroll-id="table:${state.activeTab}"] tbody`);
  const index = state.focusedRow[state.activeTab];
  if (!tbody || index === undefined || tbody.children.length === 0) return null;
  return tbody.children[Math.min(index, tbody.children.length - 1)] as HTMLElement;
}

/** The selection key of the row at `index` among those currently rendered, read off the shared checkbox cell. */
function renderedRowKey(index: number): string | null {
  const tbody = document.querySelector<HTMLElement>(`[data-scroll-id="table:${state.activeTab}"] tbody`);
  const row = tbody?.children[index];
  return row?.querySelector<HTMLElement>("[data-row-key]")?.dataset.rowKey ?? null;
}

/** Home/End: jumps the cursor to the first or last row on screen. Shared with `pageTableRows`, which falls back to exactly this once there is no page left to turn. */
function jumpRowFocus(toEnd: boolean): boolean {
  const tbody = document.querySelector<HTMLElement>(`[data-scroll-id="table:${state.activeTab}"] tbody`);
  const count = tbody?.children.length ?? 0;
  if (count === 0) return false;
  const target = toEnd ? count - 1 : 0;
  if (state.focusedRow[state.activeTab] !== target) {
    state.focusedRow[state.activeTab] = target;
    pendingRowFocusScroll = true;
    render();
  }
  return true;
}

/**
 * Shift+Up/Down: moves the cursor and selects what it passes over, so a run
 * of rows can be picked without reaching for the mouse.
 *
 * Additive rather than a true anchored range: reversing direction leaves the
 * rows already picked selected instead of deselecting them. That keeps the
 * behavior honest about what the model underneath actually is — a set of
 * selected keys with no anchor — rather than implying a range that
 * `toggleAllRowsSelected` and the header checkbox would then contradict.
 * Space still un-picks any single row, and the toolbar's Clear resets.
 */
function extendRowSelection(delta: number): boolean {
  const tbody = document.querySelector<HTMLElement>(`[data-scroll-id="table:${state.activeTab}"] tbody`);
  const count = tbody?.children.length ?? 0;
  if (count === 0) return false;

  const current = state.focusedRow[state.activeTab];
  // A first Shift+Arrow selects where the cursor lands rather than sweeping
  // from an imagined position off the end of the table.
  const from = current ?? (delta > 0 ? 0 : count - 1);
  const to = current === undefined ? from : Math.min(count - 1, Math.max(0, from + delta));

  const selection = rowSelection(state.activeTab);
  let selectionGrew = false;
  for (const index of new Set([from, to])) {
    const key = renderedRowKey(index);
    if (key && !selection.has(key)) {
      selection.add(key);
      selectionGrew = true;
    }
  }

  // Held at an end with everything already picked, repeated Shift+Arrow has
  // nothing to show — and render() replaces the whole app's innerHTML, so
  // skipping it there keeps a held key from rebuilding the table per repeat.
  const cursorMoved = to !== current;
  if (cursorMoved) state.focusedRow[state.activeTab] = to;
  if (cursorMoved || selectionGrew) {
    // Only a moved cursor needs scrolling into view; a selection change
    // alone happens on a row already on screen.
    if (cursorMoved) pendingRowFocusScroll = true;
    render();
  }
  return true;
}

/** Cmd+A: selects every row the current filters match, not just the page on screen — the same set the header's select-all checkbox covers. */
function selectAllRowsInTable(): boolean {
  const tab = state.activeTab;
  if (!tableSnapshots[tab]?.rows.length) return false;
  toggleAllRowsSelected(tab, true);
  return true;
}

/**
 * PageUp/PageDown.
 *
 * Where the table holds more rows than are on screen, these step the app's
 * own pagination — the most literal reading of the key when the pager
 * already says "Page 3 of 11", and the only way to cross a page boundary
 * from the keyboard, which the row cursor deliberately can't do. Whether a
 * table paginates is derived from the row counts rather than a list of which
 * tabs do: fewer rows rendered than the snapshot holds is exactly what "there
 * are other pages" means, and it stays right if a table's pagination is
 * later added or removed.
 *
 * Otherwise — every row already on screen, or already on the last/first page
 * — the cursor jumps to the far end instead, so the key always does
 * something rather than silently no-opping on the short tables.
 */
function pageTableRows(delta: number): boolean {
  const tab = state.activeTab;
  const tbody = document.querySelector<HTMLElement>(`[data-scroll-id="table:${tab}"] tbody`);
  const visible = tbody?.children.length ?? 0;
  if (visible === 0) return false;

  const total = tableSnapshots[tab]?.rows.length ?? visible;
  if (total > visible) {
    const current = currentPage(tab, total);
    const next = Math.min(pageCount(total), Math.max(1, current + delta));
    if (next !== current) {
      // Set before `setTablePage`, whose render then draws the cursor on the
      // newly shown page in the same pass rather than needing a second one.
      state.focusedRow[tab] = 0;
      pendingRowFocusScroll = true;
      setTablePage(tab, next);
      return true;
    }
  }

  return jumpRowFocus(delta > 0);
}

/**
 * Enter: opens the focused row's detail panel.
 *
 * Dispatched by clicking the row's own marked button rather than
 * reconstructing the call — that button already carries the right
 * identifiers, so this needs no row-key lookup and, crucially, no mapping
 * from the cursor's on-screen index back to a paginated offset. Tables whose
 * rows have no detail panel (Overview, Resource Usage, Events, KEDA) simply
 * have nothing to find, so Enter is a no-op there by construction.
 */
function activateFocusedRow(): boolean {
  const open = focusedRowElement()?.querySelector<HTMLElement>("[data-row-open]");
  if (!open) return false;
  open.click();
  return true;
}

/** Space: toggles the focused row's selection — the same checkbox the "N rows selected" toolbar and its Copy to clipboard act on. Clicked rather than called directly, for the same reason as `activateFocusedRow`. */
function toggleFocusedRowSelection(): boolean {
  const box = focusedRowElement()?.querySelector<HTMLInputElement>('input[type="checkbox"]');
  if (!box) return false;
  box.click();
  return true;
}

/**
 * Moves the active table's keyboard row cursor by `delta`.
 *
 * Returns whether the key was consumed: false when there is no row to move
 * to — the tab has no table at all (Metrics, Cost), or its table is filtered
 * down to nothing — so Up/Down still scroll normally in exactly the cases
 * where a cursor would have nowhere to go. True once the table has rows,
 * including at the clamped ends, where a list cursor stopping dead is less
 * jarring than the page suddenly scrolling instead.
 */
function moveTableRowFocus(delta: number): boolean {
  const tbody = document.querySelector<HTMLElement>(`[data-scroll-id="table:${state.activeTab}"] tbody`);
  const count = tbody?.children.length ?? 0;
  if (count === 0) return false;

  const current = state.focusedRow[state.activeTab];
  // A first press lands on the near end rather than stepping one row from an
  // imagined position just off the table.
  const next =
    current === undefined
      ? delta > 0
        ? 0
        : count - 1
      : Math.min(count - 1, Math.max(0, current + delta));

  if (next !== current) {
    state.focusedRow[state.activeTab] = next;
    pendingRowFocusScroll = true;
    render();
  }
  return true;
}

/**
 * Steps the active tab along the visible tab bar.
 *
 * Clamped rather than wrapped: both directions are always available, so each
 * end stays one keypress away without wrapping, and a Cost -> Overview jump
 * from one extra keypress reads as a mis-key rather than a shortcut.
 * `selectTab` no-ops when the target equals the current tab, so the clamped
 * ends cost nothing.
 */
function stepTab(delta: number) {
  const ids = TABS.map((t) => t.id);
  const current = ids.indexOf(state.activeTab);
  if (current === -1) return;
  selectTab(ids[Math.min(ids.length - 1, Math.max(0, current + delta))]);
}

/** Closes whichever detail panel is open, reporting whether there was one. */
function closeOpenDetailPanel(): boolean {
  const panel = DETAIL_PANEL_CLOSERS.find((p) => p.isOpen());
  if (!panel) return false;
  panel.close();
  return true;
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (state.clusterPalette) closeClusterPalette();
    else if (state.claudeExplain) closeClaudeExplain();
    else if (state.claudeDiagnose) closeClaudeDiagnose();
    else if (state.claudePanelOpen) toggleClaudePanel();
    else if (state.metricsBackendEditor) closeMetricsBackendEditor();
    else if (state.openEnumFilter !== null) closeEnumDropdown();
    else if (!closeOpenDetailPanel() && hasActiveFilters(state.activeTab)) clearFilters(state.activeTab);
    return;
  }
  // Plain Left/Right step the tab bar. Checked before the Cmd gate below,
  // since this is the unmodified key — Cmd+Left/Right keep their existing
  // view-history meaning. Any other modifier is left alone too: Shift+Arrow
  // is a text-selection gesture, and Alt/Ctrl+Arrow are word-wise or
  // platform-level movement.
  if ((e.key === "ArrowLeft" || e.key === "ArrowRight") && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
    // Deliberately not `isAnyOverlayOpen`: a detail panel doesn't swallow the
    // key, it redirects it to its own tabs. Only the things layered *above* a
    // panel take it away entirely.
    if (consumesPlainNavKeys(e.target) || isNonPanelOverlayOpen()) return;
    const delta = e.key === "ArrowRight" ? 1 : -1;
    if (isAnyDetailPanelOpen()) {
      if (stepDetailTab(delta)) e.preventDefault();
      return;
    }
    // Prevents the key also scrolling a horizontally-scrollable table.
    e.preventDefault();
    stepTab(delta);
    return;
  }
  // Plain Up/Down step the active table's row cursor, the vertical
  // counterpart to Left/Right above and gated on exactly the same two
  // guards.
  if ((e.key === "ArrowUp" || e.key === "ArrowDown") && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
    if (consumesPlainNavKeys(e.target) || isNonPanelOverlayOpen()) return;
    const delta = e.key === "ArrowDown" ? 1 : -1;
    // With a panel open these scroll its content instead of moving the row
    // cursor hidden behind it — see `detailPanelScroller` for why the browser
    // won't do this on its own.
    if (isAnyDetailPanelOpen()) {
      if (scrollDetailPanel("line", delta)) e.preventDefault();
      return;
    }
    // Conditional, unlike the horizontal case: a tab with no table (Metrics,
    // Cost) must keep Up/Down as ordinary scrolling.
    if (moveTableRowFocus(delta)) e.preventDefault();
    return;
  }
  // Shift+Up/Down carry the selection along with the cursor.
  if ((e.key === "ArrowUp" || e.key === "ArrowDown") && e.shiftKey && !e.metaKey && !e.ctrlKey && !e.altKey) {
    // Still the broad guard: a panel has no row selection to extend, and
    // Shift+Arrow is a text-selection gesture worth leaving to the pane.
    if (consumesPlainNavKeys(e.target) || isAnyOverlayOpen()) return;
    if (extendRowSelection(e.key === "ArrowDown" ? 1 : -1)) e.preventDefault();
    return;
  }
  // Home/End jump the cursor to the ends of what's on screen.
  if ((e.key === "Home" || e.key === "End") && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
    if (consumesPlainNavKeys(e.target) || isNonPanelOverlayOpen()) return;
    const toEnd = e.key === "End";
    if (isAnyDetailPanelOpen()) {
      if (scrollDetailPanel("edge", toEnd ? 1 : -1)) e.preventDefault();
      return;
    }
    if (jumpRowFocus(toEnd)) e.preventDefault();
    return;
  }
  // PageUp/PageDown step the table's pagination where there is any, else
  // jump the cursor to the far end. Same two guards as the arrows.
  if ((e.key === "PageUp" || e.key === "PageDown") && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
    if (consumesPlainNavKeys(e.target) || isNonPanelOverlayOpen()) return;
    const delta = e.key === "PageDown" ? 1 : -1;
    if (isAnyDetailPanelOpen()) {
      if (scrollDetailPanel("page", delta)) e.preventDefault();
      return;
    }
    if (pageTableRows(delta)) e.preventDefault();
    return;
  }
  // Enter opens the cursor's row; Space selects it. Guarded one step wider
  // than the navigation keys, since a focused button or link already handles
  // both of these itself.
  if ((e.key === "Enter" || e.key === " ") && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
    if (consumesActivationKeys(e.target) || isAnyOverlayOpen()) return;
    if (e.key === "Enter" ? activateFocusedRow() : toggleFocusedRowSelection()) e.preventDefault();
    return;
  }
  if (!e.metaKey) return;

  // Not gated on isEditableTarget: unlike Cmd+Left's native cursor-movement
  // conflict, Cmd+K has no competing meaning inside a plain text input, so it
  // should open the switcher no matter where focus currently is.
  if (e.key === "k" || e.key === "K") {
    e.preventDefault();
    openClusterPalette();
    return;
  }

  // Cmd+F focuses an open detail panel's search box. Not gated on
  // isEditableTarget, for the same reason as Cmd+K above: there's no
  // competing meaning inside a text field, and re-pressing it to reselect
  // the current query is useful rather than surprising.
  //
  // It is gated on isNonPanelOverlayOpen, though: the palette and Claude's
  // views don't close a detail panel when they open, so both can be up at
  // once. Without this, Cmd+F would move focus into the panel's search box
  // *behind* the overlay — every subsequent keystroke would vanish into a
  // hidden input while the overlay looked focused.
  if (e.key === "f" || e.key === "F") {
    if (isNonPanelOverlayOpen()) return;
    if (focusDetailSearch()) e.preventDefault();
    return;
  }

  // Cmd+R refreshes the fleet, matching the "Refresh now" button.
  //
  // Always claimed, overlay or not: the alternative is the webview's own
  // reload, which throws away the entire session — selected clusters, every
  // cached tab, scroll positions, an open panel — to fetch the same data
  // this does in place. Refreshing behind an overlay is harmless, since it
  // re-fetches data rather than changing what's on screen.
  if (e.key === "r" || e.key === "R") {
    e.preventDefault();
    manualRefresh();
    return;
  }

  // Cmd+A selects every matching row. Guarded on `isEditableTarget` rather
  // than the wider activation set: Cmd+A inside a text field is select-all-
  // text and must stay that way, but a focused button has no such meaning.
  if (e.key === "a" || e.key === "A") {
    if (isEditableTarget(e.target) || isAnyOverlayOpen()) return;
    if (selectAllRowsInTable()) e.preventDefault();
    return;
  }

  if (e.key === "ArrowLeft" && !isEditableTarget(e.target)) {
    if (!closeOpenDetailPanel()) goBackView();
    return;
  }
  // Deliberately no panel handling here: a detail panel is a full-screen
  // overlay, so stepping the tab underneath it would change something the
  // reader can't see. Cmd+Left closing a panel is an Escape-like convenience
  // that costs no history, which is why it has no forward counterpart.
  if (e.key === "ArrowRight" && !isEditableTarget(e.target)) {
    if (!isAnyDetailPanelOpen()) goForwardView();
    return;
  }
  // "=" is the unshifted key that carries "+" on a US layout, and some layouts
  // report the numpad key as "Add" — accept all three so Cmd+Plus works
  // however the user's keyboard sends it. Same for Cmd+Minus ("_" when
  // shifted, "Subtract" on the numpad).
  if (e.key === "+" || e.key === "=" || e.key === "Add") {
    e.preventDefault();
    stepUiScale(1);
    return;
  }
  if (e.key === "-" || e.key === "_" || e.key === "Subtract") {
    e.preventDefault();
    stepUiScale(-1);
    return;
  }
  if (e.key === "0") {
    e.preventDefault();
    resetUiScale();
  }
});

init();
