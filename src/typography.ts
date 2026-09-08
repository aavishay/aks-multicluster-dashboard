/**
 * The one place the app's monospace body typography is declared.
 *
 * Every pane that renders machine text — the YAML viewer and its editor
 * overlay, the revision diff, the logs list, and the interactive shell — has to
 * agree on family, size and line height, or the same output looks different
 * depending on which pane you happen to read it in.
 *
 * Pulled out when the shell arrived: it measures these values off a probe
 * element rather than restating them, and a second copy of the string would
 * have defeated the point the first time either half changed.
 *
 * Deliberately without padding, which differs per pane — `p-3` inside the
 * editor overlay, `py-2` in the scrolling lists — so callers append their own.
 */
export const MONO_TEXT_CLASSES = "font-mono text-xs leading-relaxed";
