export function formatMillicores(m: number | null | undefined): string {
  if (m === null || m === undefined) return "—";
  if (m >= 1000) return `${(m / 1000).toFixed(2)} cores`;
  return `${m}m`;
}

export function formatKi(ki: number | null | undefined): string {
  if (ki === null || ki === undefined) return "—";
  const mi = ki / 1024;
  if (mi >= 1024) return `${(mi / 1024).toFixed(2)} GiB`;
  return `${mi.toFixed(0)} MiB`;
}

/** A byte count for a reader: "512 B", "1.4 KiB", "2.1 MiB". */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kib = bytes / 1024;
  if (kib < 1024) return `${kib.toFixed(1)} KiB`;
  return `${(kib / 1024).toFixed(1)} MiB`;
}

export function formatAge(days: number): string {
  if (days < 1) return "<1d";
  if (days < 90) return `${days}d`;
  const months = Math.floor(days / 30);
  if (months < 24) return `${months}mo`;
  return `${Math.floor(months / 12)}y`;
}

/** Like `formatAge`, but shows sub-day ages in hours (or minutes) instead of the "<1d" bucket. */
export function formatAgeDetailed(days: number, seconds: number): string {
  if (days >= 1) return formatAge(days);
  const hours = Math.floor(seconds / 3600);
  if (hours < 1) return `${Math.max(1, Math.floor(seconds / 60))}m`;
  return `${hours}h`;
}

export function formatPct(used: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(100, Math.round((used / total) * 1000) / 10);
}

export function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diffSec = Math.max(0, Math.round((now - then) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.round(diffHr / 24)}d ago`;
}

/**
 * The exact moment behind a relative figure ("3h", "2m ago"), for a cell's
 * tooltip: local time with its zone, then the same instant in UTC on a second
 * line — the one to compare against logs and the API server. Empty for a
 * missing or unparseable timestamp, which leaves the cell without a tooltip
 * rather than showing "Invalid Date".
 */
export function exactTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const local = d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "long" });
  const utc = `${d.toISOString().slice(0, 19).replace("T", " ")} UTC`;
  return `${local}\n${utc}`;
}

/** `exactTime` with what the moment was, e.g. "Created …" for an Age column. */
export function timeTitle(what: string, iso: string | null | undefined): string {
  const at = exactTime(iso);
  return at ? `${what} ${at}` : "";
}
