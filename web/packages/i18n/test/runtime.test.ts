import { beforeEach, describe, expect, test } from "bun:test";
import { getLocale, onLocaleChange, registerLocale, setLocale, t, tp } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";

// Values mirror messages/common.yaml (ru) — registered manually so the test
// stays hermetic and also exercises the registerLocale API surface.
const RU_DICT = {
  "common.navHome": "Главная",
  "common.packagesCount": {
    one: "{count} пакет",
    few: "{count} пакета",
    many: "{count} пакетов",
    other: "{count} пакета",
  },
} as const;

const HELLO = { id: "test.hello", en: "Hello, {name}!" } as const;

beforeEach(() => {
  setLocale("en");
});

describe("interpolation", () => {
  test("substitutes provided params", () => {
    expect(t(HELLO, { name: "Ada" })).toBe("Hello, Ada!");
  });

  test("missing param leaves the placeholder visible", () => {
    expect(t(HELLO)).toBe("Hello, {name}!");
    expect(t(HELLO, {})).toBe("Hello, {name}!");
  });

  test("extra params are ignored", () => {
    expect(t(HELLO, { name: "Ada", unused: "x" })).toBe("Hello, Ada!");
  });

  test("empty string substitutes normally", () => {
    expect(t(HELLO, { name: "" })).toBe("Hello, !");
  });

  test("numeric params are stringified", () => {
    expect(t({ id: "test.n", en: "{n} items" }, { n: 0 })).toBe("0 items");
  });
});

describe("plurals (en)", () => {
  test("0 / 1 / many", () => {
    expect(tp(common.packagesCount, 0)).toBe("0 packages");
    expect(tp(common.packagesCount, 1)).toBe("1 package");
    expect(tp(common.packagesCount, 42)).toBe("42 packages");
  });
});

describe("plurals (ru)", () => {
  beforeEach(() => {
    registerLocale("ru", RU_DICT);
    setLocale("ru");
  });

  test("one / few / many categories", () => {
    expect(tp(common.packagesCount, 1)).toBe("1 пакет");
    expect(tp(common.packagesCount, 2)).toBe("2 пакета");
    expect(tp(common.packagesCount, 5)).toBe("5 пакетов");
  });

  test("0 is 'many' in Russian", () => {
    expect(tp(common.packagesCount, 0)).toBe("0 пакетов");
  });

  test("21 wraps back to 'one', 11 stays 'many'", () => {
    expect(tp(common.packagesCount, 21)).toBe("21 пакет");
    expect(tp(common.packagesCount, 11)).toBe("11 пакетов");
  });
});

describe("fallback", () => {
  test("key missing from the active locale falls back to bundled English", () => {
    registerLocale("ru", RU_DICT);
    setLocale("ru");
    // RU_DICT deliberately has no common.navApp entry.
    expect(t(common.navApp)).toBe("Open app");
    // ...while a translated key resolves from the dictionary.
    expect(t(common.navHome)).toBe("Главная");
  });

  test("locale with no registered dictionary falls back entirely", () => {
    setLocale("fr");
    expect(t(common.notFound)).toBe("Page not found");
    expect(tp(common.packagesCount, 3)).toBe("3 packages");
  });
});

describe("locale state", () => {
  test("setLocale notifies subscribers; unsubscribe stops notifications", () => {
    const seen: string[] = [];
    const unsubscribe = onLocaleChange((locale) => seen.push(locale));
    setLocale("de");
    setLocale("de"); // no-op: unchanged locale must not notify
    expect(seen).toEqual(["de"]);
    expect(getLocale()).toBe("de");
    unsubscribe();
    setLocale("ja");
    expect(seen).toEqual(["de"]);
  });
});
