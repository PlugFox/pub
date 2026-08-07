/*
 * THEME REGISTRY — the runtime half (the CSS half is the named
 * `[data-theme="…"]` blocks in packages/tokens/theme.css). Pure data and
 * resolution logic, deliberately free of Solid/Kobalte imports so state code
 * and tests can use it without a DOM.
 *
 * Persistence contract (shared with the anti-FOUC inline script in
 * apps/site/src/layouts/base-layout.astro, which cannot import this module):
 * localStorage "pub_theme" holds a ThemeMode — "system" or a THEMES name;
 * anything else counts as "system". The RESOLVED theme name is stamped as
 * `data-theme` on <html>, which drives the token palette. "system" resolves
 * to light/dark by OS preference — amoled is only ever an explicit choice.
 *
 * Registering a theme = a theme.css block + THEMES here + the anti-FOUC list
 * (see the registry note in theme.css for the full checklist).
 */

/** Registered theme names, in picker order. Must match theme.css blocks. */
export const THEMES = ["light", "dark", "amoled"] as const;
export type ThemeName = (typeof THEMES)[number];
/** What the picker persists: an explicit theme, or following the OS. */
export type ThemeMode = ThemeName | "system";

export const THEME_STORAGE_KEY = "pub_theme";

const MODES: readonly string[] = ["system", ...THEMES];

/** Narrows an untrusted stored string to a mode; unknown counts as "system". */
export function normalizeMode(stored: string | null): ThemeMode {
  return stored !== null && MODES.includes(stored) ? (stored as ThemeMode) : "system";
}

/**
 * Resolves a mode to the theme name to stamp. Pure — the anti-FOUC inline
 * script implements the same rule; packages/ui/test/theme-picker.test.ts
 * pins the behavior.
 */
export function resolveTheme(mode: string | null, prefersDark: boolean): ThemeName {
  const normalized = normalizeMode(mode);
  if (normalized !== "system") return normalized;
  return prefersDark ? "dark" : "light";
}
