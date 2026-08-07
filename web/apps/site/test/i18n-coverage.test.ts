import { describe, expect, test } from "bun:test";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { LOCALES } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { common } from "@pub/i18n/generated/common";
import { landing } from "@pub/i18n/generated/landing";

/*
 * i18n coverage.
 *
 * Two failure modes this catches, both of which typecheck happily today and
 * break only at runtime or only for a translator:
 *
 *   1. a message reference the generator no longer produces (a key renamed in
 *      the YAML, a screen still asking for the old one) — a `t()` of
 *      `undefined` renders "undefined" in the UI;
 *   2. a generated key missing from a locale dictionary — silently falls back
 *      to English forever, which nobody notices until a user complains.
 *
 * The scan is source-text based rather than type based ON PURPOSE: the type
 * system already guarantees that `app.foo` exists at the call site, but it
 * cannot see a key that exists and is never used, nor a locale JSON that
 * drifted from the generated module.
 */

const WEB_ROOT = join(import.meta.dir, "..", "..", "..");
const LOCALES_DIR = join(WEB_ROOT, "apps", "site", "public", "locales");
const SCAN_ROOTS = [join(WEB_ROOT, "apps", "site", "src"), join(WEB_ROOT, "packages", "ui", "src")];
const SCAN_EXTENSIONS = [".ts", ".tsx", ".astro"];

type Namespace = "app" | "common" | "landing";
const MODULES: Record<Namespace, Record<string, { id: string }>> = { app, common, landing };

/**
 * Message references in source text.
 *
 * Two shapes, both precise enough to avoid matching prose:
 *   `t(app.foo)` / `tp(common.bar, n)` — the call sites;
 *   `label: app.navTokens`             — descriptors held in a table.
 */
const REFERENCE_PATTERNS = [
  /\bt[p]?\(\s*(app|common|landing)\.([A-Za-z0-9]+)/g,
  /:\s*(app|common|landing)\.([A-Za-z0-9]+)/g,
];

async function collectFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await collectFiles(full)));
    else if (SCAN_EXTENSIONS.some((extension) => entry.name.endsWith(extension))) files.push(full);
  }
  return files;
}

type Reference = { readonly namespace: Namespace; readonly key: string; readonly file: string };

async function collectReferences(): Promise<Reference[]> {
  const references: Reference[] = [];
  for (const root of SCAN_ROOTS) {
    for (const file of await collectFiles(root)) {
      const source = await Bun.file(file).text();
      for (const pattern of REFERENCE_PATTERNS) {
        for (const match of source.matchAll(pattern)) {
          const namespace = match[1] as Namespace;
          const key = match[2];
          if (key !== undefined) {
            references.push({ namespace, key, file: file.slice(WEB_ROOT.length + 1) });
          }
        }
      }
    }
  }
  return references;
}

const references = await collectReferences();

describe("message references", () => {
  test("the scan actually found the app's messages (guards against a broken scanner)", () => {
    const appRefs = references.filter((reference) => reference.namespace === "app");
    expect(appRefs.length).toBeGreaterThan(50);
    expect(references.some((r) => r.namespace === "common")).toBe(true);
  });

  test("every referenced key exists in its generated module", () => {
    const missing = references
      .filter((reference) => MODULES[reference.namespace][reference.key] === undefined)
      .map((reference) => `${reference.file}: ${reference.namespace}.${reference.key}`);
    expect(missing).toEqual([]);
  });

  test("every referenced descriptor carries the id the runtime looks up", () => {
    for (const reference of references) {
      const message = MODULES[reference.namespace][reference.key];
      expect(message?.id).toBe(`${reference.namespace}.${reference.key}`);
    }
  });

  test("no generated app message is dead weight", () => {
    // A key nobody uses is either a screen that was cut or a rename that only
    // half landed; either way it should not be sent to nine translators.
    const used = new Set(
      references.filter((r) => r.namespace === "app").map((reference) => reference.key),
    );
    const unused = Object.keys(app).filter((key) => !used.has(key));
    expect(unused).toEqual([]);
  });
});

describe("locale dictionaries", () => {
  const namespaces: readonly Namespace[] = ["app", "common", "landing"];

  test("every locale ships every key of every namespace", async () => {
    const gaps: string[] = [];
    for (const locale of LOCALES) {
      for (const namespace of namespaces) {
        const raw: unknown = await Bun.file(join(LOCALES_DIR, locale, `${namespace}.json`)).json();
        const dict = raw as Record<string, unknown>;
        for (const key of Object.keys(MODULES[namespace])) {
          if (dict[`${namespace}.${key}`] === undefined) {
            gaps.push(`${locale}/${namespace}.json: ${namespace}.${key}`);
          }
        }
      }
    }
    expect(gaps).toEqual([]);
  });

  test("en and ru are fully translated; the other eight carry the TODO marker", async () => {
    const untranslated: string[] = [];
    const missingMarker: string[] = [];
    for (const locale of LOCALES) {
      for (const namespace of namespaces) {
        const raw: unknown = await Bun.file(join(LOCALES_DIR, locale, `${namespace}.json`)).json();
        const marker = (raw as Record<string, unknown>).__todo__;
        if (locale === "en" || locale === "ru") {
          if (marker !== undefined) untranslated.push(`${locale}/${namespace}.json`);
        } else if (marker === undefined) {
          missingMarker.push(`${locale}/${namespace}.json`);
        }
      }
    }
    expect(untranslated).toEqual([]);
    expect(missingMarker).toEqual([]);
  });

  test("the Russian app dictionary differs from English on every key", async () => {
    // A ru value identical to en is almost always a forgotten translation.
    // Product name and the email placeholder are deliberately identical.
    const KEPT_IDENTICAL = new Set(["app.loginEmailPlaceholder"]);
    const en = (await Bun.file(join(LOCALES_DIR, "en", "app.json")).json()) as Record<
      string,
      unknown
    >;
    const ru = (await Bun.file(join(LOCALES_DIR, "ru", "app.json")).json()) as Record<
      string,
      unknown
    >;
    const identical = Object.keys(en).filter(
      (key) => !KEPT_IDENTICAL.has(key) && JSON.stringify(en[key]) === JSON.stringify(ru[key]),
    );
    expect(identical).toEqual([]);
  });
});
