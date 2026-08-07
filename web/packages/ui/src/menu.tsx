import * as MenuPrimitive from "@kobalte/core/dropdown-menu";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";
import { feedback } from "./feedback";

/**
 * Dropdown menu — thin Kobalte wrapper (subpath import per docs/rules/web.md).
 * Kobalte owns the typeahead, roving focus, escape/outside dismissal, and
 * `aria-expanded` wiring. Transient surface, so it earns a shadow
 * (web/DESIGN.md §5): `shadow-md` + border.
 *
 * Usage:
 *   <Menu>
 *     <MenuTrigger class={buttonVariants({ intent: "ghost" })}>…</MenuTrigger>
 *     <MenuContent>
 *       <MenuItem onSelect={…}>…</MenuItem>
 *       <MenuSeparator />
 *     </MenuContent>
 *   </Menu>
 */

export const Menu = MenuPrimitive.Root;
export const MenuTrigger = MenuPrimitive.Trigger;

export type MenuContentProps = JSX.HTMLAttributes<HTMLDivElement>;

export function MenuContent(props: MenuContentProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.Content
        {...rest}
        class={cn(
          "z-50 min-w-48 overflow-hidden rounded-lg border border-line bg-surface p-1",
          "text-ink shadow-md outline-none",
          local.class,
        )}
      />
    </MenuPrimitive.Portal>
  );
}

export type MenuItemProps = JSX.HTMLAttributes<HTMLDivElement> & {
  readonly onSelect?: () => void;
  readonly disabled?: boolean;
};

export function MenuItem(props: MenuItemProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "ref"]);
  return (
    <MenuPrimitive.Item
      {...rest}
      ref={(el: HTMLDivElement) => {
        feedback(el);
        if (typeof local.ref === "function") local.ref(el);
      }}
      class={cn(
        "fx-sheen fx-ripple flex cursor-pointer items-center gap-2 rounded-md px-3 py-2 text-sm",
        "transition-colors outline-none select-none",
        "highlighted:bg-accent-soft highlighted:text-accent",
        "aria-disabled:pointer-events-none aria-disabled:opacity-50",
        local.class,
      )}
    />
  );
}

/**
 * Single-choice group inside a menu (theme picker, sort order). Kobalte wires
 * `role="menuitemradio"` + `aria-checked`; the checked item shows a check
 * glyph in a fixed-width slot so labels stay aligned either way. Selecting an
 * item closes the menu (Kobalte default), which is right for a picker.
 */
export const MenuRadioGroup = MenuPrimitive.RadioGroup;

export type MenuRadioItemProps = JSX.HTMLAttributes<HTMLDivElement> & {
  readonly value: string;
  readonly onSelect?: () => void;
  readonly disabled?: boolean;
};

export function MenuRadioItem(props: MenuRadioItemProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "children", "ref"]);
  return (
    <MenuPrimitive.RadioItem
      {...rest}
      ref={(el: HTMLDivElement) => {
        feedback(el);
        if (typeof local.ref === "function") local.ref(el);
      }}
      class={cn(
        "fx-sheen fx-ripple flex cursor-pointer items-center gap-2 rounded-md px-3 py-2 text-sm",
        "transition-colors outline-none select-none",
        "highlighted:bg-accent-soft highlighted:text-accent",
        "aria-disabled:pointer-events-none aria-disabled:opacity-50",
        local.class,
      )}
    >
      <span class="flex w-4 shrink-0 justify-center" aria-hidden="true">
        <MenuPrimitive.ItemIndicator>
          <svg aria-hidden="true" viewBox="0 0 16 16" class="size-3.5" fill="none">
            <path
              d="M3 8.5l3.5 3.5L13 5"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
        </MenuPrimitive.ItemIndicator>
      </span>
      {local.children}
    </MenuPrimitive.RadioItem>
  );
}

/** Non-interactive group heading inside a menu (Kobalte renders a `<span>`). */
export function MenuLabel(props: JSX.HTMLAttributes<HTMLSpanElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <MenuPrimitive.GroupLabel
      {...rest}
      class={cn("px-3 py-2 text-xs font-medium text-ink-muted", local.class)}
    />
  );
}

export function MenuSeparator(props: JSX.HTMLAttributes<HTMLDivElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <MenuPrimitive.Separator {...rest} class={cn("my-1 h-px bg-line", local.class)} />;
}
