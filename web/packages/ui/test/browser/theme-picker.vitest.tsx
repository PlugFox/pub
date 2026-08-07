import { THEME_STORAGE_KEY } from "@pub/ui/theme";
import { ThemePicker } from "@pub/ui/theme-picker";
import type { JSX } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, describe, expect, test } from "vitest";
import { page, userEvent } from "vitest/browser";

/*
 * ThemePicker end to end in a REAL browser: a Kobalte dropdown actually
 * opening from a trusted click, `menuitemradio` semantics, and the select
 * side effects — `data-theme` stamped on <html> and the mode persisted to
 * real localStorage. The pure half (mode normalization, resolution rule) is
 * already pinned in test/theme-picker.test.ts; this file covers what needs
 * a browser. Labels are the bundled-English i18n fallbacks.
 */

let dispose: (() => void) | null = null;
let container: HTMLDivElement | null = null;

function mount(ui: () => JSX.Element): void {
  container = document.createElement("div");
  document.body.append(container);
  dispose = render(ui, container);
}

afterEach(() => {
  dispose?.();
  dispose = null;
  container?.remove();
  container = null;
  localStorage.removeItem(THEME_STORAGE_KEY);
  document.documentElement.removeAttribute("data-theme");
});

const trigger = () => page.getByRole("button", { name: "Choose theme" });

describe("ThemePicker (real browser)", () => {
  test("the trigger opens a Kobalte menu listing every mode as menuitemradio, system checked", async () => {
    mount(() => <ThemePicker />);
    await userEvent.click(trigger());
    await expect.element(page.getByRole("menu")).toBeInTheDocument();
    for (const name of ["System", "Light", "Dark", "AMOLED"]) {
      await expect.element(page.getByRole("menuitemradio", { name })).toBeInTheDocument();
    }
    await expect
      .element(page.getByRole("menuitemradio", { name: "System" }))
      .toHaveAttribute("aria-checked", "true");
  });

  test("selecting Dark stamps data-theme on <html>, persists the mode, and closes the menu", async () => {
    mount(() => <ThemePicker />);
    await userEvent.click(trigger());
    await userEvent.click(page.getByRole("menuitemradio", { name: "Dark" }));
    await expect.poll(() => document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    await expect.element(page.getByRole("menu")).not.toBeInTheDocument();
  });

  test("a persisted mode is restored from real localStorage on mount", async () => {
    localStorage.setItem(THEME_STORAGE_KEY, "amoled");
    mount(() => <ThemePicker />);
    await userEvent.click(trigger());
    await expect
      .element(page.getByRole("menuitemradio", { name: "AMOLED" }))
      .toHaveAttribute("aria-checked", "true");
  });
});
