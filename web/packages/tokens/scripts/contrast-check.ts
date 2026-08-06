/*
 * WCAG AA contrast gate for packages/tokens/theme.css. Run via `bun run check`
 * (root) or `bun packages/tokens/scripts/contrast-check.ts`.
 *
 * Parses the raw-palette blocks of theme.css (`:root` light values and the
 * `[data-theme="dark"]` overrides), converts each `--pub-*` OKLCH value to
 * sRGB, and asserts a WCAG 2.x contrast ratio of at least 4.5:1 for every
 * ink-on-surface pair the UI actually renders. Computation, not eyeballing:
 * a token edit that breaks AA fails the pipeline.
 */

import { join } from "node:path";

const THEME_CSS_PATH = join(import.meta.dir, "..", "theme.css");
const AA_NORMAL_TEXT = 4.5;

type Oklch = { l: number; c: number; h: number };
type Palette = Map<string, Oklch>;

/** [foreground token, background token] — checked in BOTH themes at 4.5:1. */
const TEXT_PAIRS: ReadonlyArray<readonly [string, string]> = [
  // Neutral text on the two base surfaces.
  ["ink", "canvas"],
  ["ink", "surface"],
  ["ink-muted", "canvas"],
  ["ink-muted", "surface"],
  // Accent as text (links) and text on accent fills (primary buttons).
  ["accent", "canvas"],
  ["accent", "surface"],
  ["accent", "accent-soft"],
  ["on-accent", "accent"],
  ["on-accent", "accent-strong"],
  // Inverted tooltip surface: canvas-colored text on ink background.
  ["canvas", "ink"],
  // Status colors: text on solid fill, status ink on soft tint and surfaces.
  ["on-success", "success"],
  ["success-ink", "success-soft"],
  ["success-ink", "canvas"],
  ["success-ink", "surface"],
  ["on-warning", "warning"],
  ["warning-ink", "warning-soft"],
  ["warning-ink", "canvas"],
  ["warning-ink", "surface"],
  ["on-danger", "danger"],
  ["danger-ink", "danger-soft"],
  ["danger-ink", "canvas"],
  ["danger-ink", "surface"],
];

function fail(message: string): never {
  console.error(`contrast-check: ${message}`);
  process.exit(1);
}

/** Extracts `--pub-<name>: oklch(L C H)` declarations from a CSS block body. */
function parsePalette(blockBody: string): Palette {
  const palette: Palette = new Map();
  const declaration = /--pub-([a-z0-9-]+)\s*:\s*oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*\)/g;
  for (const match of blockBody.matchAll(declaration)) {
    const [, name, l, c, h] = match;
    if (name === undefined || l === undefined || c === undefined || h === undefined) continue;
    palette.set(name, { l: Number(l), c: Number(c), h: Number(h) });
  }
  return palette;
}

/** Finds the body of the first `selector { … }` block in the source. */
function blockBody(source: string, selector: string): string {
  const start = source.indexOf(selector);
  if (start === -1) fail(`selector "${selector}" not found in theme.css`);
  const open = source.indexOf("{", start);
  const close = source.indexOf("}", open);
  if (open === -1 || close === -1) fail(`unbalanced block for "${selector}"`);
  return source.slice(open + 1, close);
}

/** OKLCH → linear sRGB (Björn Ottosson's OKLab reference matrices). */
function oklchToLinearSrgb({ l, c, h }: Oklch): [number, number, number] {
  const hRad = (h * Math.PI) / 180;
  const a = c * Math.cos(hRad);
  const b = c * Math.sin(hRad);

  const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;

  return [
    4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
    -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
    -0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_,
  ];
}

/**
 * WCAG relative luminance. The linear channels feed the WCAG formula
 * directly (its 2.4-gamma decode is the inverse of sRGB encoding). Values are
 * clamped to [0, 1]: tokens must stay in the sRGB gamut, and a slight
 * out-of-gamut excursion clamps exactly like the browser's gamut mapping.
 */
function relativeLuminance(color: Oklch): number {
  const [r, g, b] = oklchToLinearSrgb(color);
  const clamp = (v: number): number => Math.min(1, Math.max(0, v));
  return 0.2126 * clamp(r) + 0.7152 * clamp(g) + 0.0722 * clamp(b);
}

function contrastRatio(fg: Oklch, bg: Oklch): number {
  const lumA = relativeLuminance(fg);
  const lumB = relativeLuminance(bg);
  const [hi, lo] = lumA >= lumB ? [lumA, lumB] : [lumB, lumA];
  return (hi + 0.05) / (lo + 0.05);
}

/*
 * Strip CSS comments before locating selectors: the header comment mentions
 * `:root` and `[data-theme="dark"]` as literal text, and a plain indexOf on
 * the raw source would match the mention instead of the rule (silently
 * re-parsing the light block as the dark palette).
 */
const source = (await Bun.file(THEME_CSS_PATH).text()).replace(/\/\*[\s\S]*?\*\//g, "");
const themes: ReadonlyArray<readonly [string, Palette]> = [
  ["light", parsePalette(blockBody(source, ":root"))],
  ["dark", parsePalette(blockBody(source, '[data-theme="dark"]'))],
];

let failures = 0;
let checked = 0;

for (const [themeName, palette] of themes) {
  for (const [fgName, bgName] of TEXT_PAIRS) {
    const fg = palette.get(fgName);
    const bg = palette.get(bgName);
    if (!fg) fail(`${themeName}: token "--pub-${fgName}" missing or not a plain oklch() value`);
    if (!bg) fail(`${themeName}: token "--pub-${bgName}" missing or not a plain oklch() value`);
    const ratio = contrastRatio(fg, bg);
    checked += 1;
    if (ratio < AA_NORMAL_TEXT) {
      failures += 1;
      console.error(
        `FAIL  [${themeName}] ${fgName} on ${bgName}: ` +
          `${ratio.toFixed(2)}:1 < ${AA_NORMAL_TEXT}:1`,
      );
    }
  }
}

if (failures > 0) {
  fail(`${failures} of ${checked} pairs below WCAG AA ${AA_NORMAL_TEXT}:1`);
}
console.log(`contrast-check: ${checked} pairs (2 themes) pass WCAG AA ${AA_NORMAL_TEXT}:1`);
