import * as TabsPrimitive from "@kobalte/core/tabs";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Tabs — thin Kobalte wrapper (subpath import per docs/rules/web.md).
 * Kobalte owns roving focus, arrow-key navigation, and the aria wiring; this
 * file provides the underline skin. Used by the Account screen
 * (Profile / Security).
 *
 * Usage:
 *   <Tabs value={tab()} onChange={setTab}>
 *     <TabsList>
 *       <TabsTrigger value="profile">…</TabsTrigger>
 *     </TabsList>
 *     <TabsContent value="profile">…</TabsContent>
 *   </Tabs>
 */

export const Tabs = TabsPrimitive.Root;

export function TabsList(props: JSX.HTMLAttributes<HTMLDivElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <TabsPrimitive.List
      {...rest}
      class={cn("relative flex items-center gap-1 border-b border-line", local.class)}
    >
      {local.children}
      <TabsPrimitive.Indicator class="absolute bottom-0 h-0.5 bg-accent transition-all" />
    </TabsPrimitive.List>
  );
}

/** `type` is fixed to "button" by Kobalte — a tab is never a submit control. */
export type TabsTriggerProps = Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, "type"> & {
  readonly value: string;
};

export function TabsTrigger(props: TabsTriggerProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <TabsPrimitive.Trigger
      {...rest}
      class={cn(
        "cursor-pointer rounded-t-md px-4 py-2 text-sm font-medium text-ink-muted outline-none",
        "transition-colors hover:text-ink focus-visible:ring-2 focus-visible:ring-accent",
        "selected:text-ink disabled:pointer-events-none disabled:opacity-50",
        local.class,
      )}
    />
  );
}

export type TabsContentProps = JSX.HTMLAttributes<HTMLDivElement> & { readonly value: string };

export function TabsContent(props: TabsContentProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <TabsPrimitive.Content
      {...rest}
      class={cn("pt-6 outline-none focus-visible:ring-2 focus-visible:ring-accent", local.class)}
    />
  );
}
