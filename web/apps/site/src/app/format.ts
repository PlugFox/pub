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
 * Whole number with the locale's grouping — counters, totals, download counts.
 *
 * Not `notation: "compact"`: "1.2M downloads" is a marketing number, and this
 * registry's dashboards are read by people deciding whether a rollup ran.
 */
export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat(getLocale()).format(value);
}

/**
 * Byte size with a binary unit, e.g. "4.2 MiB".
 *
 * `Intl.NumberFormat`'s `unit` style has no binary units, so the unit word is
 * appended after the locale formats the mantissa — the digits, grouping, and
 * decimal separator still come from CLDR. Storage is reported in KiB/MiB/GiB
 * because that is what the operator's disk reports.
 */
const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"] as const;

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return "—";
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < BYTE_UNITS.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const digits = unit === 0 || size >= 100 ? 0 : 1;
  const formatted = new Intl.NumberFormat(getLocale(), {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(size);
  return `${formatted} ${BYTE_UNITS[unit]}`;
}

/**
 * Coarse relative time ("3 days ago"), for freshness columns.
 *
 * Falls back to the absolute date past a year: "14 months ago" is harder to
 * act on than "Jun 2025", and a stale row is exactly where precision matters.
 */
export function formatRelative(value: string | null | undefined): string {
  if (value === null || value === undefined) return "—";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return "—";
  const seconds = Math.round((parsed - Date.now()) / 1000);
  const magnitude = Math.abs(seconds);
  const formatter = new Intl.RelativeTimeFormat(getLocale(), { numeric: "auto" });
  if (magnitude < 60) return formatter.format(Math.round(seconds), "second");
  if (magnitude < 3600) return formatter.format(Math.round(seconds / 60), "minute");
  if (magnitude < 86400) return formatter.format(Math.round(seconds / 3600), "hour");
  if (magnitude < 2592000) return formatter.format(Math.round(seconds / 86400), "day");
  if (magnitude < 31536000) return formatter.format(Math.round(seconds / 2592000), "month");
  return formatDate(value);
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
