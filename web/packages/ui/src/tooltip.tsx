import * as TooltipPrimitive from "@kobalte/core/tooltip";
import { type JSX, mergeProps, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Tooltip — thin Kobalte wrapper (subpath import per docs/rules/web.md).
 * Inverted surface (ink background, canvas text — an AA-checked pair) so it
 * reads above any content in either theme. Spec: web/DESIGN.md “Tooltip”.
 *
 * Usage:
 *   <Tooltip>
 *     <TooltipTrigger as={...}>…</TooltipTrigger>
 *     <TooltipContent>Hint text</TooltipContent>
 *   </Tooltip>
 */

export type TooltipProps = TooltipPrimitive.TooltipRootProps;

export function Tooltip(props: TooltipProps): JSX.Element {
  // mergeProps keeps reactivity while defaulting the open delay.
  const merged = mergeProps({ openDelay: 300, gutter: 6 }, props);
  return <TooltipPrimitive.Root {...merged} />;
}

export const TooltipTrigger = TooltipPrimitive.Trigger;

export type TooltipContentProps = JSX.HTMLAttributes<HTMLDivElement>;

export function TooltipContent(props: TooltipContentProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        {...rest}
        class={cn(
          "z-50 max-w-xs rounded-md bg-ink px-3 py-1.5 text-xs text-canvas shadow-md",
          local.class,
        )}
      >
        <TooltipPrimitive.Arrow />
        {local.children}
      </TooltipPrimitive.Content>
    </TooltipPrimitive.Portal>
  );
}
