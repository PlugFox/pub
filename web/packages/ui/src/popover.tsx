import * as PopoverPrimitive from "@kobalte/core/popover";
import { t } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Popover — thin Kobalte wrapper (subpath import per docs/rules/web.md).
 *
 * The difference from Tooltip is not visual, it is behavioural, and it decides
 * which one a screen may use: a Tooltip is a hover hint that is never
 * focusable and must hold no controls; a Popover opens on CLICK, traps nothing
 * but takes focus, closes on Escape, and may contain headings, links, and
 * copyable text. Reference documentation — the search-syntax help — is
 * therefore a Popover; a one-line explanation of an icon is a Tooltip.
 *
 * Transient surface, so it earns a shadow (web/DESIGN.md §5 level 3).
 *
 * Usage:
 *   <Popover>
 *     <PopoverTrigger as={Button} intent="ghost">?</PopoverTrigger>
 *     <PopoverContent title="Search syntax">…</PopoverContent>
 *   </Popover>
 */

export const Popover = PopoverPrimitive.Root;
export const PopoverTrigger = PopoverPrimitive.Trigger;

export type PopoverContentProps = JSX.HTMLAttributes<HTMLDivElement> & {
  /** Accessible title; rendered as the panel's heading. */
  readonly title: string;
};

export function PopoverContent(props: PopoverContentProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "children", "title"]);
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        {...rest}
        class={cn(
          "z-50 w-80 max-w-sm rounded-lg border border-line bg-surface p-4",
          "text-sm text-ink shadow-md outline-none",
          local.class,
        )}
      >
        <PopoverPrimitive.Arrow />
        <div class="flex items-start justify-between gap-3 pb-2">
          <PopoverPrimitive.Title class="text-sm font-semibold text-ink">
            {local.title}
          </PopoverPrimitive.Title>
          <PopoverPrimitive.CloseButton
            aria-label={t(common.close)}
            class={cn(
              "-mt-1 inline-flex size-6 shrink-0 cursor-pointer items-center justify-center",
              "rounded-md text-ink-muted transition-colors outline-none hover:bg-line/40",
              "hover:text-ink focus-visible:ring-2 focus-visible:ring-accent",
            )}
          >
            <svg aria-hidden="true" viewBox="0 0 16 16" class="size-3.5" fill="none">
              <path
                d="M4 4l8 8M12 4l-8 8"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
              />
            </svg>
          </PopoverPrimitive.CloseButton>
        </div>
        {local.children}
      </PopoverPrimitive.Content>
    </PopoverPrimitive.Portal>
  );
}
