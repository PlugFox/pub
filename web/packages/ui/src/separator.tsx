import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Purely decorative divider, hidden from assistive technology. When the
 * separation is semantic (a new content section), use a real `<hr>` or a
 * heading instead — do not bolt roles onto this. Spec: web/DESIGN.md
 * “Separator”.
 */
export const separatorVariants = cva("shrink-0 bg-line", {
  variants: {
    orientation: {
      horizontal: "h-px w-full",
      vertical: "w-px self-stretch",
    },
  },
  defaultVariants: {
    orientation: "horizontal",
  },
});

export type SeparatorProps = JSX.HTMLAttributes<HTMLDivElement> &
  VariantProps<typeof separatorVariants>;

export function Separator(props: SeparatorProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "orientation"]);
  return (
    <div
      {...rest}
      aria-hidden="true"
      class={cn(separatorVariants({ orientation: local.orientation }), local.class)}
    />
  );
}
