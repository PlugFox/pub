import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Form field label. Pair with Input via `for`/`id`; the `peer-disabled`
 * classes dim it when the labelled control (marked `peer`) is disabled.
 * Spec: web/DESIGN.md “Input & Label”.
 */
export type LabelProps = JSX.LabelHTMLAttributes<HTMLLabelElement>;

export function Label(props: LabelProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    // biome-ignore lint/a11y/noLabelWithoutControl: pairing happens at the call site via `for`/`id`.
    <label
      {...rest}
      class={cn(
        "text-sm font-medium text-ink select-none",
        "peer-disabled:cursor-not-allowed peer-disabled:opacity-50",
        local.class,
      )}
    />
  );
}
