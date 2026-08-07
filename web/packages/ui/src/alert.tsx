import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Inline status message attached to a form or a section — soft tints only,
 * same palette rules as Badge (web/DESIGN.md §2). Not a toast: an Alert is
 * part of the layout and stays until the underlying condition changes.
 *
 * The `danger` intent renders `role="alert"` (assertive) so a form error is
 * announced immediately; the informational intents use `role="status"`
 * (polite) so they never interrupt a screen-reader user mid-sentence.
 */
export const alertVariants = cva("flex w-full gap-3 rounded-lg border p-4 text-sm", {
  variants: {
    intent: {
      info: "border-line bg-canvas text-ink",
      success: "border-transparent bg-success-soft text-success-ink",
      warning: "border-transparent bg-warning-soft text-warning-ink",
      danger: "border-transparent bg-danger-soft text-danger-ink",
    },
  },
  defaultVariants: {
    intent: "info",
  },
});

export type AlertProps = JSX.HTMLAttributes<HTMLDivElement> & VariantProps<typeof alertVariants>;

export function Alert(props: AlertProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "intent"]);
  return (
    <div
      role={local.intent === "danger" ? "alert" : "status"}
      {...rest}
      class={cn(alertVariants({ intent: local.intent }), local.class)}
    />
  );
}

/** Optional bold first line inside an Alert. */
export function AlertTitle(props: JSX.HTMLAttributes<HTMLParagraphElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <p {...rest} class={cn("font-medium", local.class)} />;
}
