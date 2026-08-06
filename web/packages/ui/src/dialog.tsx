import * as DialogPrimitive from "@kobalte/core/dialog";
import { t } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Modal dialog — thin Kobalte wrapper (subpath import per docs/rules/web.md).
 * Kobalte provides focus trap, escape/overlay dismiss, and aria wiring;
 * this file provides the SaaS skin. Spec: web/DESIGN.md “Dialog”.
 *
 * Usage:
 *   <Dialog>
 *     <DialogTrigger as={...}>Open</DialogTrigger>
 *     <DialogContent>
 *       <DialogTitle>…</DialogTitle>
 *       <DialogDescription>…</DialogDescription>
 *       …
 *     </DialogContent>
 *   </Dialog>
 */

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;

export type DialogContentProps = JSX.HTMLAttributes<HTMLDivElement>;

/** Portal + dimmed overlay + centered panel + close button, in one slot. */
export function DialogContent(props: DialogContentProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay class="fixed inset-0 z-50 bg-ink/40" />
      <div class="fixed inset-0 z-50 flex items-center justify-center p-4">
        <DialogPrimitive.Content
          {...rest}
          class={cn(
            "relative flex w-full max-w-md flex-col gap-4 rounded-xl border border-line",
            "bg-surface p-6 text-ink shadow-lg outline-none",
            local.class,
          )}
        >
          {local.children}
          <DialogPrimitive.CloseButton
            aria-label={t(common.close)}
            class={cn(
              "absolute top-4 right-4 inline-flex size-8 cursor-pointer items-center",
              "justify-center rounded-md text-ink-muted transition-colors outline-none",
              "hover:bg-line/40 hover:text-ink focus-visible:ring-2 focus-visible:ring-accent",
            )}
          >
            <svg aria-hidden="true" viewBox="0 0 16 16" class="size-4" fill="none">
              <path
                d="M4 4l8 8M12 4l-8 8"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
              />
            </svg>
          </DialogPrimitive.CloseButton>
        </DialogPrimitive.Content>
      </div>
    </DialogPrimitive.Portal>
  );
}

export function DialogTitle(props: JSX.HTMLAttributes<HTMLHeadingElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <DialogPrimitive.Title
      {...rest}
      class={cn("pr-8 text-lg font-semibold text-ink", local.class)}
    />
  );
}

export function DialogDescription(props: JSX.HTMLAttributes<HTMLParagraphElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <DialogPrimitive.Description {...rest} class={cn("text-sm text-ink-muted", local.class)} />
  );
}
