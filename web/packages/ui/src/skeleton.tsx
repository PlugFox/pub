import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Loading placeholder. Size it from the caller (`class="h-4 w-32"`) to match
 * the content it stands in for; screen readers skip it (`aria-hidden`).
 * Spec: web/DESIGN.md “Skeleton”.
 */
export type SkeletonProps = JSX.HTMLAttributes<HTMLDivElement>;

export function Skeleton(props: SkeletonProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      {...rest}
      aria-hidden="true"
      class={cn("animate-pulse rounded-md bg-line/60", local.class)}
    />
  );
}
