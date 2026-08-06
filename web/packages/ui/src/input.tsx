import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Text input recipe. Invalid state is driven by `aria-invalid` (set it from
 * form validation) so styling and accessibility can never drift apart.
 * Spec: web/DESIGN.md “Input & Label”.
 */
export const inputVariants = cva(
  [
    "w-full rounded-md border border-line bg-surface px-3 text-ink",
    "placeholder:text-ink-muted transition-colors outline-none",
    "focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30",
    "disabled:cursor-not-allowed disabled:opacity-50",
    "aria-invalid:border-danger aria-invalid:focus-visible:ring-danger/30",
  ],
  {
    variants: {
      size: {
        sm: "h-8 text-sm",
        md: "h-10 text-sm",
      },
    },
    defaultVariants: {
      size: "md",
    },
  },
);

/** `size` (native, numeric) is dropped in favor of the visual size variant. */
export type InputProps = Omit<JSX.InputHTMLAttributes<HTMLInputElement>, "size"> &
  VariantProps<typeof inputVariants>;

export function Input(props: InputProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "size"]);
  return <input {...rest} class={cn(inputVariants({ size: local.size }), local.class)} />;
}
