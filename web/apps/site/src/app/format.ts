import { getLocale } from "@pub/i18n";

/*
 * Locale-aware formatting for the app's metadata columns.
 *
 * `Intl` is used directly rather than through i18n messages: a date is data,
 * not prose, and CLDR already knows how every locale writes one. The formatter
 * is rebuilt per call from `getLocale()` so a language switch is reflected
 * without a reload; these run over table rows, not in a loop, so the cost is
 * irrelevant next to the correctness of never caching a stale locale.
 */

/** Absolute date + time, e.g. "6 Aug 2026, 21:15". `null` inputs render as an em dash. */
export function formatDateTime(value: string | null | undefined): string {
  if (value === null || value === undefined) return "—";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return "—";
  return new Intl.DateTimeFormat(getLocale(), {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(parsed);
}

/** Date only, for "member since" and token expiry. */
export function formatDate(value: string | null | undefined): string {
  if (value === null || value === undefined) return "—";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return "—";
  return new Intl.DateTimeFormat(getLocale(), { dateStyle: "medium" }).format(parsed);
}

/**
 * Trims a user-agent string down to something a table cell can show.
 *
 * The server already stores a coarse UA (S-10); this only caps the pathological
 * case so one weird client cannot blow the column open.
 */
export function shortenUserAgent(value: string | null | undefined, max = 48): string | null {
  if (value === null || value === undefined || value.trim() === "") return null;
  const trimmed = value.trim();
  return trimmed.length <= max ? trimmed : `${trimmed.slice(0, max - 1)}…`;
}
