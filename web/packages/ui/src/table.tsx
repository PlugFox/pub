import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/*
 * Data table for the app's dense surfaces (sessions, tokens).
 *
 * `Table` renders its own horizontal-scroll container: per web/DESIGN.md
 * §8 the app keeps tabular layouts and lets them scroll inside their box
 * rather than reflowing into cards on narrow screens. The wrapper is
 * focusable (`tabindex="0"`) so a keyboard user can scroll it — a scrollable
 * region that only a mouse can reach is a WCAG 2.1.1 failure.
 */

export type TableProps = JSX.HTMLAttributes<HTMLTableElement> & {
  /** Accessible name for the scroll region; also the table's `aria-label`. */
  readonly label: string;
};

export function Table(props: TableProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "label"]);
  return (
    // A named <section> is a landmark, which is exactly right for a scroll
    // container: it gets an accessible name and shows up in the landmark list.
    <section
      tabindex="0"
      aria-label={local.label}
      class="w-full overflow-x-auto rounded-xl border border-line focus-visible:ring-2 focus-visible:ring-accent"
    >
      <table
        {...rest}
        aria-label={local.label}
        class={cn("w-full border-collapse text-left text-sm", local.class)}
      />
    </section>
  );
}

export function TableHead(props: JSX.HTMLAttributes<HTMLTableSectionElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <thead {...rest} class={cn("border-b border-line bg-canvas", local.class)} />;
}

export function TableBody(props: JSX.HTMLAttributes<HTMLTableSectionElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <tbody {...rest} class={cn("divide-y divide-line", local.class)} />;
}

export function TableRow(props: JSX.HTMLAttributes<HTMLTableRowElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <tr {...rest} class={cn("bg-surface", local.class)} />;
}

export type TableHeaderCellProps = JSX.ThHTMLAttributes<HTMLTableCellElement>;

export function TableHeaderCell(props: TableHeaderCellProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <th
      scope="col"
      {...rest}
      class={cn("px-4 py-3 font-medium whitespace-nowrap text-ink-muted", local.class)}
    />
  );
}

export function TableCell(props: JSX.TdHTMLAttributes<HTMLTableCellElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <td {...rest} class={cn("px-4 py-3 align-middle text-ink", local.class)} />;
}
