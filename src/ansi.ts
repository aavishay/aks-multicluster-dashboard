/**
 * One ANSI palette for everything that renders terminal colour.
 *
 * Lifted out of `main.ts` when the pod shell arrived: log output and the shell
 * both display the same escape codes, and two palettes would mean the same
 * program's output looked different depending on which pane you read it in.
 */

/** 16-color ANSI base palette (standard 0-7, then bright 8-15). */
export const ANSI_BASE16 = [
  "#3f3f3f",
  "#e6675a",
  "#3fae56",
  "#d9a441",
  "#4a90e2",
  "#b06fd1",
  "#3fb0ae",
  "#b8b8b0",
  "#7a7a72",
  "#f08a7e",
  "#6bd685",
  "#f0c46b",
  "#7bb0f0",
  "#d69ae8",
  "#6bd6d4",
  "#eeeee6",
];

/**
 * An xterm-256 index to a hex colour: the 16 base colours, then the 6×6×6
 * colour cube, then the 24-step greyscale ramp.
 */
export function xterm256ToHex(n: number): string {
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
