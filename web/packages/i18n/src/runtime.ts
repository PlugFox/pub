/*
 * Dependency-free i18n runtime (decision 15, foxic-style).
 *
 * Message descriptors come from generated modules (`src/generated/*`, produced
 * by `bun run i18n:gen`): each carries a stable id (`namespace.key`) and the
 * bundled English text — English is always available without any fetch.
 * Non-English dictionaries are plain JSON (`/locales/<code>/<ns>.json`) loaded
 * lazily by the app and handed to `registerLocale`.
 *
 * Locale state is module-level with a subscribe callback so the same instance
 * drives Astro static pages, Solid islands, and plain scripts alike.
 */

export const LOCALES = ["en", "ru", "fr", "it", "de", "es", "pt", "ja", "ko", "zh-Hans"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

export type MessageParams = Record<string, string | number>;

/** CLDR plural forms; `other` is the universal required category. */
export type PluralForms = {
  readonly zero?: string;
  readonly one?: string;
  readonly two?: string;
  readonly few?: string;
  readonly many?: string;
  readonly other: string;
};

/** A generated message: stable id + bundled-English fallback. */
export type Message = { readonly id: string; readonly en: string };
export type PluralMessage = { readonly id: string; readonly en: PluralForms };

/** A loaded locale dictionary, keyed by message id. */
export type LocaleDict = Record<string, string | PluralForms>;

let currentLocale: Locale = DEFAULT_LOCALE;
const dictionaries = new Map<Locale, LocaleDict>();
const listeners = new Set<(locale: Locale) => void>();
const pluralRulesCache = new Map<string, Intl.PluralRules>();

export function getLocale(): Locale {
  return currentLocale;
}

/** Switches the active locale and notifies subscribers (no-op if unchanged). */
export function setLocale(next: Locale): void {
  if (next === currentLocale) return;
  currentLocale = next;
  for (const listener of listeners) listener(next);
}

/** Subscribes to locale changes; returns an unsubscribe function. */
export function onLocaleChange(listener: (locale: Locale) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Merges a fetched dictionary into the store for `locale`. */
export function registerLocale(locale: Locale, dict: LocaleDict): void {
  const existing = dictionaries.get(locale);
  dictionaries.set(locale, existing ? { ...existing, ...dict } : { ...dict });
}

/**
 * Replaces `{name}` placeholders with values from `params`.
 * Missing params leave the placeholder untouched (visible, greppable);
 * extra params are ignored; empty strings substitute normally.
 */
function interpolate(template: string, params?: MessageParams): string {
  return template.replace(/\{(\w+)\}/g, (placeholder, name: string) => {
    const value = params?.[name];
    return value === undefined ? placeholder : String(value);
  });
}

/** Dictionary lookup for the active locale; English uses the bundled text. */
function lookup(id: string): string | PluralForms | undefined {
  if (currentLocale === DEFAULT_LOCALE) return undefined;
  return dictionaries.get(currentLocale)?.[id];
}

/** Translates a simple message with optional `{param}` interpolation. */
export function t(msg: Message, params?: MessageParams): string {
  const found = lookup(msg.id);
  const template = typeof found === "string" ? found : msg.en;
  return interpolate(template, params);
}

function pluralRules(locale: string): Intl.PluralRules {
  let rules = pluralRulesCache.get(locale);
  if (!rules) {
    rules = new Intl.PluralRules(locale);
    pluralRulesCache.set(locale, rules);
  }
  return rules;
}

/**
 * Translates a plural message, selecting the CLDR category for `count` via
 * `Intl.PluralRules`. `{count}` is always available to templates; when the
 * active locale misses the whole message, the bundled English forms are used
 * (with English's own categories falling back to `other`).
 */
export function tp(msg: PluralMessage, count: number, params?: MessageParams): string {
  const found = lookup(msg.id);
  const forms = found !== undefined && typeof found !== "string" ? found : msg.en;
  const category = pluralRules(currentLocale).select(count);
  const template = forms[category] ?? forms.other;
  return interpolate(template, { count, ...params });
}
