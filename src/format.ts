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
