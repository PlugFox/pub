import { type Message, t } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { createSignal, For, type JSX, onCleanup, onMount, splitProps } from "solid-js";
import { buttonVariants } from "./button";
import { cn } from "./cn";
import { feedback } from "./feedback";
import { Menu, MenuContent, MenuRadioGroup, MenuRadioItem, MenuTrigger } from "./menu";
import { normalizeMode, resolveTheme, THEME_STORAGE_KEY, THEMES, type ThemeMode } from "./theme";

/**
 * Theme picker — a ghost-pill trigger opening a Kobalte dropdown of radio
 * items: "system" plus one entry per registered theme. The registry itself
 * (THEMES, the persistence contract, the resolution rule shared with the
 * anti-FOUC inline script) lives in ./theme — pure, DOM-free, tested.
 */

const MODES: readonly ThemeMode[] = ["system", ...THEMES];
const MODE_ICONS: Record<ThemeMode, string> = {
  system: "◐",
  light: "☀",
  dark: "☾",
  amoled: "●",
};
const MODE_LABELS: Record<ThemeMode, Message> = {
  system: common.themeSystem,
  light: common.themeLight,
  dark: common.themeDark,
  amoled: common.themeAmoled,
};

function prefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function applyMode(mode: ThemeMode): void {
  document.documentElement.dataset.theme = resolveTheme(mode, prefersDark());
}

export type ThemePickerProps = JSX.ButtonHTMLAttributes<HTMLButtonElement>;

export function ThemePicker(props: ThemePickerProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "ref"]);
  const [mode, setMode] = createSignal<ThemeMode>("system");

  // All window/localStorage access lives in onMount: the island is
  // server-rendered by Astro before hydration.
  onMount(() => {
    setMode(normalizeMode(localStorage.getItem(THEME_STORAGE_KEY)));
    // While in "system" mode, follow live OS theme changes.
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onMediaChange = (): void => {
      if (mode() === "system") applyMode("system");
    };
    media.addEventListener("change", onMediaChange);
    onCleanup(() => media.removeEventListener("change", onMediaChange));
  });

  const select = (next: ThemeMode): void => {
    setMode(next);
    localStorage.setItem(THEME_STORAGE_KEY, next);
    applyMode(next);
  };

  return (
    <Menu>
      <MenuTrigger
        {...rest}
        ref={(el: HTMLButtonElement) => {
          feedback(el);
          if (typeof local.ref === "function") local.ref(el);
        }}
        aria-label={t(common.themePicker)}
        title={t(common.themePicker)}
        class={cn(
          buttonVariants({ intent: "ghost", size: "sm" }),
          "w-8 rounded-full px-0",
          local.class,
        )}
      >
        <span aria-hidden="true">{MODE_ICONS[mode()]}</span>
      </MenuTrigger>
      <MenuContent>
        <MenuRadioGroup value={mode()} onChange={(value) => select(normalizeMode(value))}>
          <For each={MODES}>
            {(entry) => (
              <MenuRadioItem value={entry}>
                <span aria-hidden="true">{MODE_ICONS[entry]}</span>
                {t(MODE_LABELS[entry])}
              </MenuRadioItem>
            )}
          </For>
        </MenuRadioGroup>
      </MenuContent>
    </Menu>
  );
}
