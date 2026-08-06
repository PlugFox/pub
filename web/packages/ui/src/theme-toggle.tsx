import { t } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { createSignal, type JSX, onCleanup, onMount, splitProps } from "solid-js";
import { buttonVariants } from "./button";
import { cn } from "./cn";

/**
 * Light/dark/system theme switcher. Contract shared with the base layout's
 * anti-FOUC inline script: the chosen mode is persisted under the
 * `pub_theme` localStorage key ("light" | "dark" | "system"; anything else
 * counts as "system"), and the resolved theme is stamped as
 * `data-theme="light" | "dark"` on <html>, which drives the token palette.
 */

export type ThemeMode = "light" | "dark" | "system";

const STORAGE_KEY = "pub_theme";
const MODES: readonly ThemeMode[] = ["light", "dark", "system"];
const MODE_ICONS: Record<ThemeMode, string> = { light: "☀", dark: "☾", system: "◐" };

function prefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function applyTheme(mode: ThemeMode): void {
  const resolved = mode === "system" ? (prefersDark() ? "dark" : "light") : mode;
  document.documentElement.dataset.theme = resolved;
}

export type ThemeToggleProps = JSX.ButtonHTMLAttributes<HTMLButtonElement>;

export function ThemeToggle(props: ThemeToggleProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  const [mode, setMode] = createSignal<ThemeMode>("system");

  // All window/localStorage access lives in onMount: the island is
  // server-rendered by Astro before hydration.
  onMount(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") {
      setMode(stored);
    }
    // While in "system" mode, follow live OS theme changes.
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onMediaChange = (): void => {
      if (mode() === "system") applyTheme("system");
    };
    media.addEventListener("change", onMediaChange);
    onCleanup(() => media.removeEventListener("change", onMediaChange));
  });

  const cycle = (): void => {
    const next = MODES[(MODES.indexOf(mode()) + 1) % MODES.length] ?? "system";
    setMode(next);
    localStorage.setItem(STORAGE_KEY, next);
    applyTheme(next);
  };

  return (
    <button
      type="button"
      {...rest}
      aria-label={t(common.themeToggle)}
      title={`${t(common.themeToggle)}: ${mode()}`}
      onClick={cycle}
      class={cn(buttonVariants({ intent: "ghost", size: "sm" }), local.class)}
    >
      <span aria-hidden="true">{MODE_ICONS[mode()]}</span>
    </button>
  );
}
