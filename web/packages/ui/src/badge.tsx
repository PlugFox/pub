import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Status/metadata chip. Soft tinted backgrounds with AA-checked ink tokens —
 * never solid status fills (those belong to buttons). Version numbers inside
 * a badge get `font-mono` from the caller. Spec: web/DESIGN.md “Badge”.
 */
export const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium whitespace-nowrap",
  {
    variants: {
      variant: {
        neutral: "border-line bg-canvas text-ink-muted",
        accent: "border-transparent bg-accent-soft text-accent",
        success: "border-transparent bg-success-soft text-success-ink",
        warning: "border-transparent bg-warning-soft text-warning-ink",
        danger: "border-transparent bg-danger-soft text-danger-ink",
      },
    },
    defaultVariants: {
      variant: "neutral",
    },
  },
);

export type BadgeProps = JSX.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>;

export function Badge(props: BadgeProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "variant"]);
  return <span {...rest} class={cn(badgeVariants({ variant: local.variant }), local.class)} />;
}
