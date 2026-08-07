import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * The "there is nothing here yet" slot of a list screen.
 *
 * Deliberately not a Card: an empty state is a *hole* in the layout, not a
 * raised object, so it is a dashed outline on the canvas. Every use should
 * offer the action that fills it (`children` is the action slot) — an empty
 * state with no way out is a dead end.
 */
export type EmptyStateProps = JSX.HTMLAttributes<HTMLDivElement> & {
  readonly title: string;
  readonly description?: string;
};

export function EmptyState(props: EmptyStateProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "title", "description", "children"]);
  return (
    <div
      {...rest}
      class={cn(
        "flex flex-col items-center gap-3 rounded-xl border border-dashed border-line",
        "px-6 py-12 text-center",
        local.class,
      )}
    >
      <p class="text-base font-semibold text-ink">{local.title}</p>
      {local.description !== undefined && (
        <p class="max-w-md text-sm leading-relaxed text-ink-muted">{local.description}</p>
      )}
      {local.children}
    </div>
  );
}
