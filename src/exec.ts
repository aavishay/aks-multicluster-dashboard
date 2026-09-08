import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { api } from "./api";

/**
 * An interactive shell in a pod container.
 *
 * The one part of this app that opts out of the render model, and it has to.
 * `render()` replaces all of `#app`'s innerHTML on every state change and on
 * every auto-refresh tick, which would destroy a terminal mid-keystroke and
 * throw away its scrollback several times a minute. A terminal emulator is
 * inherently stateful — scrollback, cursor position, the alternate screen
 * buffer a full-screen program like `top` switches into — and none of that
 * survives being re-serialised to a string.
 *
 * So the overlay is built imperatively, mounted on `document.body` rather than
 * inside `#app`, and owned entirely by this module. `render()` never sees it.
 *
 * Nothing about a session lives in the app's `state`: it is all held in the
 * module-level `session` below, and the keyboard handler asks `isExecOpen()`
 * rather than reading a flag. That keeps the terminal's lifetime out of the
 * object `render()` derives the DOM from, which is the whole point.
 */

/** Bytes in, bytes out — a terminal is not a text stream, and its encoding must survive the trip. */
const encoder = new TextEncoder();

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(data: string): Uint8Array {
  const binary = atob(data);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

interface OpenSession {
  root: HTMLDivElement;
  term: Terminal;
  fit: FitAddon;
  observer: ResizeObserver;
  /**
   * null only until the backend hands one back. It is deliberately NOT
   * cleared when the session ends — `closeExec` still needs it to release the
   * backend's registry entry. `ended` is what gates input.
   */
  sessionId: number | null;
  /** Set when the remote process exits, so input stops being forwarded. */
  ended: boolean;
  target: ExecTarget;
}

export interface ExecTarget {
  ctx: string;
  namespace: string;
  pod: string;
  container: string;
  /** argv, unwrapped by a shell. The caller decides which shell to try. */
  command: string[];
}

let session: OpenSession | null = null;

/** True while a shell is on screen — the keyboard handler uses this to stay out of the way. */
export function isExecOpen(): boolean {
  return session !== null;
}

/** The pod a session is attached to, for the header and for reopening. */
export function execTarget(): ExecTarget | null {
  return session?.target ?? null;
}

/**
 * Colours pulled from the app's own CSS variables rather than hardcoded, so
 * the terminal follows the light/dark theme like everything else. Read at open
 * time: a theme switch while a shell is open is rare enough not to warrant
 * observing, and re-reading on open keeps it correct for the next one.
 */
function themeColors(): { background: string; foreground: string; cursor: string } {
  const css = getComputedStyle(document.documentElement);
  const pick = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  return {
    // Terminals conventionally sit darker than the surrounding chrome, and
    // xterm needs concrete colours rather than var() references.
    background: pick("--surface-1", "#111318"),
    foreground: pick("--ink-primary", "#e6e6e6"),
    cursor: pick("--ink-primary", "#e6e6e6"),
  };
}

function buildChrome(target: ExecTarget): { root: HTMLDivElement; mount: HTMLDivElement; status: HTMLSpanElement } {
  const root = document.createElement("div");
  // Mounted on body, so it needs its own stacking and geometry — it cannot
  // borrow the app's layout. z-index sits above the detail panels (z-50).
  root.setAttribute("data-pod-exec", "");
  root.className = "fixed inset-0 z-[60] flex items-center justify-center bg-black/50 p-6";

  const frame = document.createElement("div");
  frame.className =
    "flex h-full max-h-[80vh] w-full max-w-5xl flex-col overflow-hidden rounded-lg border border-gridline bg-surface-1 shadow-2xl";

  const header = document.createElement("div");
  header.className = "flex shrink-0 items-center justify-between gap-3 border-b border-gridline px-3 py-2";

  const title = document.createElement("div");
  title.className = "flex min-w-0 items-center gap-2 text-xs";
  const name = document.createElement("span");
  name.className = "truncate font-medium text-ink-primary";
  name.textContent = `${target.pod} · ${target.container}`;
  const where = document.createElement("span");
  where.className = "truncate text-ink-muted";
  where.textContent = `${target.ctx} / ${target.namespace}`;
  title.append(name, where);

  const right = document.createElement("div");
  right.className = "flex shrink-0 items-center gap-2 text-xs";
  const status = document.createElement("span");
  // Addressed by attribute, not by class: the ctx/namespace label carries the
  // same muted class and is earlier in the DOM, so a class selector finds that
  // one instead and writes the status over the pod's location.
  status.setAttribute("data-exec-status", "");
  status.className = "text-ink-muted";
  status.textContent = "connecting…";
  const close = document.createElement("button");
  close.className =
    "rounded-md border border-gridline bg-surface-2 px-2 py-1 text-xs font-medium text-ink-primary hover:bg-surface-3";
  close.textContent = "Close";
  close.onclick = () => closeExec();
  right.append(status, close);

  header.append(title, right);

  const mount = document.createElement("div");
  mount.className = "min-h-0 flex-1 p-2";

  const hint = document.createElement("div");
  hint.className = "shrink-0 border-t border-gridline px-3 py-1.5 text-xs text-ink-muted";
  // Esc is deliberately not the close key: it belongs to the shell, or vim
  // would be unusable. Say so, since every other overlay here closes on Esc.
  hint.textContent = "Keys go to the container — Esc included. Exit the shell, or use Close.";

  frame.append(header, mount, hint);
  root.append(frame);
  return { root, mount, status };
}

/**
 * Opens a shell. Idempotent per pod: asking for the session already on screen
 * just focuses it, rather than stacking a second terminal over the first.
 */
export async function openExec(target: ExecTarget, onStateChange: () => void): Promise<void> {
  if (session) {
    const s = session.target;
    if (s.ctx === target.ctx && s.namespace === target.namespace && s.pod === target.pod && s.container === target.container) {
      session.term.focus();
      return;
    }
    closeExec();
  }

  const { root, mount, status } = buildChrome(target);
  document.body.append(root);

  const colors = themeColors();
  const term = new Terminal({
    convertEol: false,
    cursorBlink: true,
    fontSize: 12,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, "Cascadia Mono", monospace',
    theme: colors,
    // The remote PTY owns wrapping and scrollback trimming; this only bounds
    // how much the webview keeps in memory for scrolling back.
    scrollback: 5000,
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(mount);
  fit.fit();
  term.focus();

  const observer = new ResizeObserver(() => {
    if (!session || session.ended) return;
    fit.fit();
    if (session.sessionId !== null) {
      void api.resizePodExec(session.sessionId, term.cols, term.rows).catch(() => {});
    }
  });
  observer.observe(mount);

  session = { root, term, fit, observer, sessionId: null, ended: false, target };
  onStateChange();

  // Keystrokes out. Queued input before the session id arrives is dropped
  // rather than buffered: the shell has not printed a prompt yet, so there is
  // nothing sensible for early keystrokes to apply to.
  term.onData((data) => {
    if (!session || session.sessionId === null || session.ended) return;
    void api.sendPodExecStdin(session.sessionId, toBase64(encoder.encode(data))).catch((e) => {
      markEnded(String(e));
    });
  });

  try {
    const id = await api.startPodExec(target, term.cols, term.rows, (event) => {
      if (!session) return;
      if (event.kind === "output") {
        session.term.write(fromBase64(event.data));
      } else {
        markEnded(event.message);
      }
    });
    // Closed while the handshake was still in flight.
    if (!session) {
      void api.stopPodExec(id).catch(() => {});
      return;
    }
    session.sessionId = id;
    status.textContent = "connected";
    // The shell sized its first prompt from whatever we sent at start; if the
    // window changed during the handshake, correct it now.
    void api.resizePodExec(id, term.cols, term.rows).catch(() => {});
  } catch (e) {
    // Written into the terminal rather than raised as a toast: the reader is
    // looking here, and a failure to start is part of this session's history.
    term.write(`\r\n\x1b[31m${String(e)}\x1b[0m\r\n`);
    status.textContent = "failed";
    if (session) session.ended = true;
    onStateChange();
  }
}

function markEnded(message: string) {
  if (!session || session.ended) return;
  session.ended = true;
  session.term.write(`\r\n\x1b[90m${message}\x1b[0m\r\n`);
  const status = session.root.querySelector("[data-exec-status]");
  if (status) status.textContent = "ended";
  // `sessionId` is deliberately kept. Clearing it here made `closeExec` skip
  // `stopPodExec`, so a shell that exited on its own left its entry in the
  // backend registry — and its stdin task parked on a receive — until the app
  // restarted. `ended` is what stops input being forwarded; the id is what
  // still has to be handed back to be cleaned up.
}

/** Tears the session down. Safe to call when nothing is open. */
export function closeExec(): void {
  const s = session;
  if (!s) return;
  session = null;

  s.observer.disconnect();
  // Called even for a session that already ended: the backend's `stop` is a
  // documented no-op for an unknown id, so this is the cheap way to guarantee
  // the registry entry goes rather than hoping the exit path removed it.
  if (s.sessionId !== null) void api.stopPodExec(s.sessionId).catch(() => {});
  s.term.dispose();
  s.root.remove();
}
