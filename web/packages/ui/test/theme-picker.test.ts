import { describe, expect, test } from "bun:test";
import { normalizeMode, resolveTheme, THEMES } from "@pub/ui/theme";

/*
 * Pins the theme-registry persistence contract shared by three places:
 * THEMES here, the [data-theme] blocks in packages/tokens/theme.css, and the
 * anti-FOUC inline script in apps/site/src/layouts/base-layout.astro (which
 * cannot import this module and re-implements the same resolution rule).
 */

describe("theme registry", () => {
  test("registers exactly the themes theme.css declares, light first", () => {
    expect(THEMES).toEqual(["light", "dark", "amoled"]);
  });

  test("theme.css carries a [data-theme] block for every non-light theme", async () => {
    const css = await Bun.file(new URL("../../tokens/theme.css", import.meta.url).pathname).text();
    for (const theme of THEMES) {
      if (theme === "light") continue; // light lives on :root by contract
      expect(css).toContain(`[data-theme="${theme}"]`);
    }
  });
});

describe("normalizeMode", () => {
  test("accepts every registered theme and system verbatim", () => {
    for (const theme of THEMES) expect(normalizeMode(theme)).toBe(theme);
    expect(normalizeMode("system")).toBe("system");
  });

  test("unknown, legacy, or absent values count as system", () => {
    expect(normalizeMode(null)).toBe("system");
    expect(normalizeMode("")).toBe("system");
    expect(normalizeMode("midnight")).toBe("system");
    expect(normalizeMode("DARK")).toBe("system"); // case-sensitive by contract
    expect(normalizeMode("light ")).toBe("system"); // no trimming: exact match only
  });
});

describe("resolveTheme", () => {
  test("an explicit registered theme wins regardless of the OS preference", () => {
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
    expect(resolveTheme("amoled", false)).toBe("amoled");
    expect(resolveTheme("amoled", true)).toBe("amoled");
  });

  test("system follows the OS preference and never resolves to amoled", () => {
    expect(resolveTheme("system", false)).toBe("light");
    expect(resolveTheme("system", true)).toBe("dark");
  });

  test("unknown or absent stored values fall back to system resolution", () => {
    expect(resolveTheme(null, false)).toBe("light");
    expect(resolveTheme(null, true)).toBe("dark");
    expect(resolveTheme("midnight", true)).toBe("dark");
    expect(resolveTheme("", false)).toBe("light");
  });
});
