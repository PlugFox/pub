/*
 * Locale resolution and dictionary loading (decision 41, closing the last
 * clause of decision 15).
 *
 * The codegen has written `/locales/<code>/<ns>.json` for ten locales since the
 * first slice, and until now nothing fetched them: `registerLocale` and
 * `setLocale` had no call sites anywhere in the app. This is the fetch the
 * service worker's stale-while-revalidate rule has been describing.
 *
 * RESOLVED BEFORE THE FIRST RENDER, not after. `t()` is not reactive —
 * `onLocaleChange` has no consumers, and making 650 call sites reactive is a
 * different change — so the dictionaries have to be in place before the tree
 * that reads them mounts. Doing it the other way would render English and then
 * repaint, which is worse than the short blank the gate in `App.tsx` costs.
 *
 * A FAILED FETCH RENDERS ENGLISH. English is bundled into the generated
 * modules, so a missing dictionary is a degraded page; a gate that waited for a
 * network that is not there would be a broken one. This is also what makes the
 * app boot offline on its very first run after a deploy.
 *
 * Runtime locale *switching* and the picker are roadmap item 6; this module is
 * what that control will call.
 */

import type { Locale, LocaleDict } from "@pub/i18n";
import { DEFAULT_LOCALE, LOCALES, registerLocale, setLocale } from "@pub/i18n";

/** Where an explicit choice will live once the picker exists (roadmap item 6). */
export const LOCALE_STORAGE_KEY = "pub_locale";

/** The namespaces the island reads. `landing` belongs to the static pages. */
const NAMESPACES = ["common", "app"] as const;

/** Fetches one dictionary; `null` on any failure, which the caller treats as English. */
export type DictionaryLoader = (locale: Locale, namespace: string) => Promise<LocaleDict | null>;

/**
 * The locale to render in: an explicit choice, else the reader's preferences,
 * else English.
 *
 * Matching is by exact tag or by subtag prefix, so `ru-RU` finds `ru` and
 * `zh-Hans-CN` finds `zh-Hans`. It deliberately does **not** map `zh-CN` onto
 * `zh-Hans`: inventing a script for a tag that did not name one is a guess, and
 * the honest outcome of an unsupported tag is the next preference in the list.
 */
export function resolveLocale(stored: string | null, preferred: readonly string[]): Locale {
  const chosen = matchLocale(stored);
  if (chosen !== null) return chosen;

  for (const tag of preferred) {
    const hit = matchLocale(tag);
    if (hit !== null) return hit;
  }
  return DEFAULT_LOCALE;
}

/** The supported locale a BCP 47 tag selects, or `null`. */
function matchLocale(tag: string | null): Locale | null {
  if (tag === null || tag === "") return null;
  const lower = tag.toLowerCase();
  for (const locale of LOCALES) {
    const candidate = locale.toLowerCase();
    if (lower === candidate || lower.startsWith(`${candidate}-`)) return locale;
  }
  return null;
}

/**
 * Loads `locale`'s dictionaries and activates it.
 *
 * Returns the locale that ended up active, which is `en` when nothing could be
 * loaded — the caller renders either way, so the return value is for the `lang`
 * attribute and for tests, not for a decision about whether to mount.
 */
export async function activateLocale(
  locale: Locale,
  load: DictionaryLoader = fetchDictionary,
): Promise<Locale> {
  if (locale === DEFAULT_LOCALE) return DEFAULT_LOCALE;

  const loaded = await Promise.all(NAMESPACES.map((namespace) => load(locale, namespace)));
  const dictionaries = loaded.filter((dictionary) => dictionary !== null);
  // Not a single namespace arrived: stay on the bundled English rather than
  // switching to a locale with no messages, which would keep English text but
  // select plural categories for a language whose forms we do not have.
  if (dictionaries.length === 0) return DEFAULT_LOCALE;

  for (const dictionary of dictionaries) registerLocale(locale, dictionary);
  setLocale(locale);
  return locale;
}

/** Resolves from the environment and activates, reporting the active locale. */
export async function bootLocale(load: DictionaryLoader = fetchDictionary): Promise<Locale> {
  const locale = resolveLocale(readStoredLocale(), navigator.languages ?? []);
  const active = await activateLocale(locale, load);
  document.documentElement.lang = active;
  return active;
}

/** Storage access is wrapped: Safari private mode throws on touch. */
function readStoredLocale(): string | null {
  try {
    return localStorage.getItem(LOCALE_STORAGE_KEY);
  } catch {
    return null;
  }
}

async function fetchDictionary(locale: Locale, namespace: string): Promise<LocaleDict | null> {
  try {
    const response = await fetch(`/locales/${locale}/${namespace}.json`);
    if (!response.ok) return null;
    return (await response.json()) as LocaleDict;
  } catch {
    return null;
  }
}
