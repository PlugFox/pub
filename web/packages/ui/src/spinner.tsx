import { t } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/**
 * Indeterminate busy indicator for actions whose duration is unknown (a form
 * submit, a step-up verification). For *content* that is loading and whose
 * shape is known, prefer Skeleton — it says more and moves less.
 *
 * The SVG is decorative; the accessible name lives on the wrapper, which is a
 * live region so the wait is announced rather than silent.
 */
export const spinnerVariants = cva("animate-spin text-current", {
  variants: {
    size: {
      sm: "size-4",
      md: "size-5",
      lg: "size-8",
    },
  },
  defaultVariants: {
    size: "sm",
  },
});

export type SpinnerProps = JSX.HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof spinnerVariants> & {
    /** Overrides the default "Loading…" accessible name. */
    readonly label?: string;
  };

export function Spinner(props: SpinnerProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "size", "label"]);
  return (
    <span
      role="status"
      aria-label={local.label ?? t(common.loading)}
      {...rest}
      class={cn("inline-flex items-center justify-center", local.class)}
    >
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        fill="none"
        class={cn(spinnerVariants({ size: local.size }))}
      >
        <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2.5" opacity="0.25" />
        <path
          d="M21 12a9 9 0 0 0-9-9"
          stroke="currentColor"
          stroke-width="2.5"
          stroke-linecap="round"
        />
      </svg>
    </span>
  );
}
