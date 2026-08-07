import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";
import { feedback } from "./feedback";

/**
 * Static content surface: border + `bg-surface`, no shadow (elevation is
 * reserved for transient surfaces — web/DESIGN.md “Radii & Elevation”).
 * Compose with CardHeader / CardContent / CardFooter; all slots optional.
 *
 * `interactive` is the explicit opt-in for cards that act as one big press
 * target (web/DESIGN.md §5a): it adds the hover sheen + press ripple and the
 * pointer cursor — and NOTHING else. The card stays a `<div>`; the caller
 * must supply the real interactive semantics (a stretched link or button
 * inside), because a click-bound div is banned (ui-accessibility rules).
 */
export const cardVariants = cva("rounded-xl border border-line bg-surface text-ink", {
  variants: {
    interactive: {
      true: "fx-sheen fx-ripple cursor-pointer",
    },
  },
});

export type CardProps = JSX.HTMLAttributes<HTMLDivElement> & VariantProps<typeof cardVariants>;

export function Card(props: CardProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "interactive", "ref"]);
  return (
    <div
      {...rest}
      ref={(el) => {
        // Read once at mount: an interactive card does not become static.
        if (local.interactive === true) feedback(el);
        if (typeof local.ref === "function") local.ref(el);
      }}
      class={cn(cardVariants({ interactive: local.interactive }), local.class)}
    />
  );
}

export function CardHeader(props: JSX.HTMLAttributes<HTMLDivElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <div {...rest} class={cn("flex flex-col gap-1.5 p-6", local.class)} />;
}

export function CardContent(props: JSX.HTMLAttributes<HTMLDivElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <div {...rest} class={cn("p-6 pt-0", local.class)} />;
}

export function CardFooter(props: JSX.HTMLAttributes<HTMLDivElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <div {...rest} class={cn("flex items-center gap-3 p-6 pt-0", local.class)} />;
}
