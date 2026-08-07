import * as MenuPrimitive from "@kobalte/core/dropdown-menu";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

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
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <MenuPrimitive.Item
      {...rest}
      class={cn(
        "flex cursor-pointer items-center gap-2 rounded-md px-3 py-2 text-sm outline-none",
        "transition-colors select-none highlighted:bg-accent-soft highlighted:text-accent",
        "aria-disabled:pointer-events-none aria-disabled:opacity-50",
        local.class,
      )}
    />
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
