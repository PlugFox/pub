import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Button recipe, exported separately so links styled as buttons can reuse it
 * (`<a class={buttonVariants({ intent: "primary" })}>`). No margins on the
 * root — spacing belongs to the parent layout.
 */
export const buttonVariants = cva(
  [
    "inline-flex cursor-pointer items-center justify-center gap-2 rounded-md font-medium",
    "transition-colors outline-none select-none",
    "focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2",
    "focus-visible:ring-offset-canvas",
    "disabled:pointer-events-none disabled:opacity-50",
  ],
  {
    variants: {
      intent: {
        primary: "bg-accent text-on-accent hover:bg-accent-strong",
        ghost: "bg-transparent text-ink hover:bg-line/40",
      },
      size: {
        sm: "h-8 px-3 text-sm",
        md: "h-10 px-4 text-base",
      },
    },
    defaultVariants: {
      intent: "primary",
      size: "md",
    },
  },
);

export type ButtonProps = JSX.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants>;

export function Button(props: ButtonProps): JSX.Element {
  // splitProps, never destructuring — destructuring breaks Solid reactivity.
  const [local, rest] = splitProps(props, ["class", "intent", "size"]);
  return (
    <button
      type="button"
      {...rest}
      class={cn(buttonVariants({ intent: local.intent, size: local.size }), local.class)}
    />
  );
}
