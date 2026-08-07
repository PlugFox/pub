import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";
import { feedback } from "./feedback";

/**
 * Button recipe, exported separately so links styled as buttons can reuse it
 * (`<a class={buttonVariants({ intent: "primary" })}>`). No margins on the
 * root — spacing belongs to the parent layout. Spec: web/DESIGN.md “Button”.
 *
 * The recipe carries the interaction-feedback classes (web/DESIGN.md §5a):
 * every button-styled surface shows the hover sheen (center-anchored until
 * the directive tracks the pointer), and `Button` itself attaches the
 * directives for tracking + the press ripple.
 */
export const buttonVariants = cva(
  [
    "fx-sheen fx-ripple",
    "inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg font-medium",
    "transition-colors outline-none select-none whitespace-nowrap",
    "focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2",
    "focus-visible:ring-offset-canvas",
    "disabled:pointer-events-none disabled:opacity-50",
  ],
  {
    variants: {
      intent: {
        primary: "bg-accent text-on-accent hover:bg-accent-strong",
        ghost: "bg-transparent text-ink hover:bg-line/40",
        outline: "border border-line bg-surface text-ink hover:border-accent hover:text-accent",
        danger: "bg-danger text-on-danger hover:bg-danger/90",
      },
      size: {
        sm: "h-8 px-3 text-sm",
        md: "h-10 px-4 text-sm",
        lg: "h-12 px-6 text-base",
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
  const [local, rest] = splitProps(props, ["class", "intent", "size", "ref"]);
  return (
    <button
      type="button"
      {...rest}
      ref={(el) => {
        feedback(el);
        // Across a component boundary Solid always passes refs as functions.
        if (typeof local.ref === "function") local.ref(el);
      }}
      class={cn(buttonVariants({ intent: local.intent, size: local.size }), local.class)}
    />
  );
}
