import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Static content surface: border + `bg-surface`, no shadow (elevation is
 * reserved for transient surfaces — web/DESIGN.md “Radii & Elevation”).
 * Compose with CardHeader / CardContent / CardFooter; all slots optional.
 */
export type CardProps = JSX.HTMLAttributes<HTMLDivElement>;

export function Card(props: CardProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div {...rest} class={cn("rounded-xl border border-line bg-surface text-ink", local.class)} />
  );
}

export function CardHeader(props: CardProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <div {...rest} class={cn("flex flex-col gap-1.5 p-6", local.class)} />;
}

export function CardContent(props: CardProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <div {...rest} class={cn("p-6 pt-0", local.class)} />;
}

export function CardFooter(props: CardProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <div {...rest} class={cn("flex items-center gap-3 p-6 pt-0", local.class)} />;
}
