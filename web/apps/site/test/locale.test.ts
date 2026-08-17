import { describe, expect, test } from "bun:test";
import type { LocaleDict } from "@pub/i18n";
import { getLocale, setLocale, t } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { activateLocale, resolveLocale } from "../src/app/state/locale";

/*
 * Locale resolution and dictionary loading (decision 41, closing decision 15's
 * last clause).
 *
 * `activateLocale` is the boot gate, so its failure behaviour is the important
 * half: a reader whose dictionaries cannot be fetched must get an English page,
 * never a page that never renders.
 */

/** Restores the module-level locale so tests cannot leak into each other. */
function withLocale(body: () => Promise<void>): Promise<void> {
  return body().finally(() => setLocale("en"));
}

describe("resolveLocale", () => {
  test("an explicit choice wins over the browser's preferences", () => {
    expect(resolveLocale("ja", ["ru-RU", "en-US"])).toBe("ja");
  });

  test("a regional tag finds its base locale", () => {
    expect(resolveLocale(null, ["ru-RU"])).toBe("ru");
    expect(resolveLocale(null, ["pt-BR"])).toBe("pt");
  });

  test("a script-bearing tag matches the script-bearing locale", () => {
    expect(resolveLocale(null, ["zh-Hans-CN"])).toBe("zh-Hans");
    expect(resolveLocale(null, ["ZH-HANS"])).toBe("zh-Hans");
  });

  test("a tag that names no script is not given one", () => {
    // `zh-CN` is not mapped onto `zh-Hans`: inventing a script for a tag that
    // did not name one is a guess. The next preference answers instead.
    expect(resolveLocale(null, ["zh-CN", "de"])).toBe("de");
  });

  test("preferences are read in order and unsupported ones are skipped", () => {
    expect(resolveLocale(null, ["nl", "sv", "fr-CA", "de"])).toBe("fr");
  });

  test("nothing supported anywhere is English", () => {
    expect(resolveLocale(null, ["nl", "sv"])).toBe("en");
    expect(resolveLocale("", [])).toBe("en");
    expect(resolveLocale("klingon", [])).toBe("en");
  });
});

describe("activateLocale", () => {
  test("English never fetches, because its messages are bundled", async () => {
    let calls = 0;
    const active = await activateLocale("en", async () => {
      calls += 1;
      return null;
    });

    expect(active).toBe("en");
    expect(calls).toBe(0);
  });

  test("a loaded dictionary becomes the rendered text", () =>
    withLocale(async () => {
      const active = await activateLocale(
        "ru",
        async (_locale, namespace): Promise<LocaleDict | null> =>
          namespace === "common" ? { [common.notFound.id]: "Страница не найдена" } : {},
      );

      expect(active).toBe("ru");
      expect(getLocale()).toBe("ru");
      expect(t(common.notFound)).toBe("Страница не найдена");
    }));

  test("a partial failure still activates, with English filling the gaps", () =>
    withLocale(async () => {
      const active = await activateLocale(
        "ru",
        async (_locale, namespace): Promise<LocaleDict | null> =>
          namespace === "common" ? { [common.notFound.id]: "Страница не найдена" } : null,
      );

      expect(active).toBe("ru");
      expect(t(common.notFound)).toBe("Страница не найдена");
      // Absent from the one dictionary that loaded: the bundled English.
      expect(t(common.siteTitle)).toBe(common.siteTitle.en);
    }));

  test("a total failure stays on English instead of half-switching", () =>
    withLocale(async () => {
      // Switching with no dictionary at all would keep English text while
      // selecting plural categories for a language whose forms we do not have.
      const active = await activateLocale("ru", async () => null);

      expect(active).toBe("en");
      expect(getLocale()).toBe("en");
      expect(t(common.notFound)).toBe(common.notFound.en);
    }));
});
