import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { ANSI_BASE16 } from "./ansi";
import { api } from "./api";
import { MONO_TEXT_CLASSES } from "./typography";

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

/** Keystrokes waiting for the next frame's flush; see `term.onData` below. */
let pendingInput = "";
let inputFlushHandle: number | null = null;

/** True while a shell is on screen — the keyboard handler uses this to stay out of the way. */
export function isExecOpen(): boolean {
  return session !== null;
}

/**
 * True when a shell is on screen whose remote process has already exited.
 *
 * The app's keyboard handler needs this because it swallows every key while a
 * shell is open: an ended session has nothing to swallow keys on behalf of, so
 * Escape should reach the close path when focus happens to be outside the
 * terminal.
 *
 * When focus is inside the terminal instead, the `attachCustomKeyEventHandler`
 * registered in `openExec` gets there first — xterm stops Escape propagating,
 * so it never reaches the app's listener at all. Named rather than pointed at,
 * because a relative direction is wrong the moment either moves.
 */
export function isExecEnded(): boolean {
  return session?.ended === true;
}

/** The pod a session is attached to, for the header and for reopening. */
export function execTarget(): ExecTarget | null {
  return session?.target ?? null;
}

/**
 * Font metrics measured from a throwaway element wearing the YAML viewer's
 * classes, rather than numbers written out here.
 *
 * Two reasons not to hardcode. Tailwind supplies the mono stack and `text-xs`
 * from its own theme, so duplicating either would drift the moment the theme
 * changed. And more importantly `text-xs` is rem-based, while the app's zoom is
 * an inline `font-size` percentage on `:root` — so the viewer's text follows the
 * zoom and a fixed pixel size would not. At 125% the viewer sat at 15px while
 * this terminal stayed at 12.
 */
function yamlFontMetrics(): { fontFamily: string; fontSize: number; lineHeight: number; lineHeightPx: number } {
  const probe = document.createElement("div");
  probe.className = MONO_TEXT_CLASSES;
  probe.style.cssText = "position:absolute;visibility:hidden;pointer-events:none";
  probe.textContent = "0";
  document.body.append(probe);
  const style = getComputedStyle(probe);
  const fontFamily = style.fontFamily;
  const fontSize = Number.parseFloat(style.fontSize) || 12;
  const lineHeightPx = Number.parseFloat(style.lineHeight);
  probe.remove();
  const usableLineHeight = Number.isFinite(lineHeightPx) && lineHeightPx > 0 ? lineHeightPx : 0;
  return {
    fontFamily,
    fontSize,
    // A starting multiplier only. xterm's `lineHeight` scales its own measured
    // glyph height rather than the font size, and that glyph height is
    // font-specific, so this ratio does not land on `lineHeightPx` — it is
    // corrected by measurement in `matchRowPitch` once a row exists.
    lineHeight: usableLineHeight && fontSize > 0 ? usableLineHeight / fontSize : 1.0,
    lineHeightPx: usableLineHeight,
  };
}

/**
 * Nudges the row pitch onto the YAML viewer's line height.
 *
 * Needed because xterm's `lineHeight` is a multiple of the glyph height it
 * measures for the chosen font, not of the font size — at 12px this font
 * measures ~13.5px, so the viewer's 1.625 ratio produced 22px rows against the
 * viewer's 19.5px. Rather than hardcode a per-font fudge factor, read what one
 * row actually came out as and scale the multiplier by the error.
 *
 * Clamped because a bad measurement (a hidden or zero-height mount) would
 * otherwise drive the multiplier to something unreadable, and exact equality is
 * not always reachable anyway — xterm rounds cell height up to whole pixels.
 */
function matchRowPitch(term: Terminal, mount: HTMLElement, targetPx: number): void {
  if (!targetPx) return;
  const row = mount.querySelector<HTMLElement>(".xterm-rows > div");
  const actual = row?.getBoundingClientRect().height ?? 0;
  const current = typeof term.options.lineHeight === "number" ? term.options.lineHeight : 1;
  if (!actual || !current) return;
  const corrected = current * (targetPx / actual);
  if (!Number.isFinite(corrected) || corrected < 0.5 || corrected > 3) return;
  term.options.lineHeight = corrected;
}

/**
 * Re-applies those metrics to an open shell, for when the zoom changes under it.
 *
 * Unreachable as things stand, and deliberately kept anyway: the overlay is
 * modal, so ⌘+/⌘−/⌘0 are swallowed by the keyboard gate and the zoom button
 * sits behind it — verified, not assumed. The metrics read in `openExec` are
 * therefore what actually keeps the two panes aligned today. This exists so the
 * invariant survives the overlay ceasing to be modal, which is the change that
 * would otherwise leave the terminal as the one pane ignoring the zoom.
 *
 * Changing the font size changes the cell size, so the grid is remeasured and
 * the remote PTY told its new dimensions, or full-screen programs would draw to
 * the old one.
 */
export function syncExecFontMetrics(): void {
  if (!session) return;
  // Measured once and reused: probing twice was extra layout work for no gain,
  // and the two reads could in principle disagree.
  const { fontFamily, fontSize, lineHeight, lineHeightPx } = yamlFontMetrics();
  session.term.options.fontFamily = fontFamily;
  session.term.options.fontSize = fontSize;
  session.term.options.lineHeight = lineHeight;
  matchRowPitch(session.term, session.root, lineHeightPx);
  session.fit.fit();
  if (session.sessionId !== null && !session.ended) {
    void api.resizePodExec(session.sessionId, session.term.cols, session.term.rows).catch(() => {});
  }
}

/**
 * Colours pulled from the app's own CSS variables rather than hardcoded, so
 * the terminal follows the light/dark theme like everything else. Read at open
 * time: a theme switch while a shell is open is rare enough not to warrant
 * observing, and re-reading on open keeps it correct for the next one.
 *
 * The 16 ANSI slots come from the same `ANSI_BASE16` the log viewer uses. Left
 * unset, xterm substitutes its own defaults, so identical output rendered in
 * the Logs tab and in a shell came out in two different palettes — and the
 * shell's clashed with the surrounding chrome.
 */
function themeColors(): Record<string, string> {
  const css = getComputedStyle(document.documentElement);
  const pick = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  const [black, red, green, yellow, blue, magenta, cyan, white, brightBlack, brightRed, brightGreen, brightYellow, brightBlue, brightMagenta, brightCyan, brightWhite] =
    ANSI_BASE16;
  return {
    // Terminals conventionally sit darker than the surrounding chrome, and
    // xterm needs concrete colours rather than var() references.
    background: pick("--surface-1", "#111318"),
    foreground: pick("--ink-primary", "#e6e6e6"),
    cursor: pick("--ink-primary", "#e6e6e6"),
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    brightBlack,
    brightRed,
    brightGreen,
    brightYellow,
    brightBlue,
    brightMagenta,
    brightCyan,
    brightWhite,
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
  hint.setAttribute("data-exec-hint", "");
  hint.className = "shrink-0 border-t border-gridline px-3 py-1.5 text-xs text-ink-muted";
  // Esc is deliberately not the close key while the shell is live: it belongs
  // to the container, or vim would be unusable. Say so, since every other
  // overlay here closes on Esc. `markEnded` rewrites this once the process is
  // gone, because from then on Esc does close the panel.
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
  const metrics = yamlFontMetrics();
  const term = new Terminal({
    convertEol: false,
    cursorBlink: true,
    fontFamily: metrics.fontFamily,
    fontSize: metrics.fontSize,
    lineHeight: metrics.lineHeight,
    theme: colors,
    // The remote PTY owns wrapping and scrollback trimming; this only bounds
    // how much the webview keeps in memory for scrolling back.
    scrollback: 5000,
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(mount);
  // Pitch is corrected before the first fit, so the grid is measured at the
  // size it will actually render at rather than being refitted a frame later.
  matchRowPitch(term, mount, metrics.lineHeightPx);
  fit.fit();
  term.focus();

  // Escape has to be caught here and not in the app's document handler: xterm
  // stops its propagation, so a real Escape keypress inside the terminal never
  // reaches `document` at all — verified, after first writing the handler in
  // the wrong place. `b` and other keys do bubble; Escape specifically does not.
  //
  // While the shell is live this returns true and Escape goes to the container.
  // Once the process has gone there is nothing to send keys to, so Escape does
  // what every other overlay's Escape does and closes the panel.
  term.attachCustomKeyEventHandler((e) => {
    if (e.type !== "keydown" || e.key !== "Escape") return true;
    if (!session?.ended) return true;
    // Deferred rather than closed inline: `closeExec` disposes the terminal,
    // and disposing it from inside its own key dispatch is asking for trouble.
    setTimeout(() => closeExec(), 0);
    return false;
  });

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
  //
  // Coalesced into one send per frame rather than one per keystroke. Each send
  // is an IPC hop into Rust, and `onData` fires per character — so a 2000-byte
  // paste was 2000 round trips, and fast typing was one per key. Batching
  // costs at most a frame of added latency and collapses both to a single
  // call. Order is preserved because the bytes are concatenated in arrival
  // order, which is exactly what a fast typist produces on a real terminal
  // anyway.
  term.onData((data) => {
    if (!session || session.sessionId === null || session.ended) return;
    pendingInput += data;
    if (inputFlushHandle !== null) return;
    inputFlushHandle = requestAnimationFrame(() => {
      inputFlushHandle = null;
      const batch = pendingInput;
      pendingInput = "";
      if (!batch || !session || session.sessionId === null || session.ended) return;
      void api.sendPodExecStdin(session.sessionId, toBase64(encoder.encode(batch))).catch((e) => {
        markEnded(String(e));
      });
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
  // The live-session hint is now false — there is nothing left to send keys to
  // — and Escape has become the close key, so say that instead.
  const hint = session.root.querySelector("[data-exec-hint]");
  if (hint) hint.textContent = "Session ended. Press Esc, or use Close.";
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
  // Anything typed in the last frame belongs to the session being torn down,
  // not to whichever one opens next.
  if (inputFlushHandle !== null) cancelAnimationFrame(inputFlushHandle);
  inputFlushHandle = null;
  pendingInput = "";
  // Called even for a session that already ended: the backend's `stop` is a
  // documented no-op for an unknown id, so this is the cheap way to guarantee
  // the registry entry goes rather than hoping the exit path removed it.
  if (s.sessionId !== null) void api.stopPodExec(s.sessionId).catch(() => {});
  s.term.dispose();
  s.root.remove();
}
