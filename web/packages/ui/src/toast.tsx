import { t } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { cva, type VariantProps } from "class-variance-authority";
import { For, type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/*
 * Transient notifications.
 *
 * Presentational only — the queue lives in the app's module-level toast store,
 * because the same store is written from places that have no component tree
 * around them (an interceptor reporting a rate limit, a store reacting to a
 * lost session). Keeping the queue out of `packages/ui` also keeps this
 * package free of app state, which is what makes the ui-kit page able to
 * render a toast without booting the app.
 */

export const toastVariants = cva(
  ["pointer-events-auto flex w-full items-start gap-3 rounded-lg border p-4", "text-sm shadow-md"],
  {
    variants: {
      intent: {
        info: "border-line bg-surface text-ink",
        success: "border-transparent bg-success-soft text-success-ink",
        warning: "border-transparent bg-warning-soft text-warning-ink",
        danger: "border-transparent bg-danger-soft text-danger-ink",
      },
    },
    defaultVariants: {
      intent: "info",
    },
  },
);

export type ToastProps = JSX.HTMLAttributes<HTMLDivElement> &
  VariantProps<typeof toastVariants> & {
    readonly onDismiss?: () => void;
  };

export function Toast(props: ToastProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "intent", "children", "onDismiss"]);
  return (
    <div {...rest} class={cn(toastVariants({ intent: local.intent }), local.class)}>
      <div class="flex-1 leading-relaxed">{local.children}</div>
      {local.onDismiss !== undefined && (
        <button
          type="button"
          aria-label={t(common.close)}
          onClick={local.onDismiss}
          class={cn(
            "-m-1 inline-flex size-6 shrink-0 cursor-pointer items-center justify-center",
            "rounded-md opacity-70 transition-opacity outline-none hover:opacity-100",
            "focus-visible:ring-2 focus-visible:ring-accent",
          )}
        >
          <svg aria-hidden="true" viewBox="0 0 16 16" class="size-3.5" fill="none">
            <path
              d="M4 4l8 8M12 4l-8 8"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
            />
          </svg>
        </button>
      )}
    </div>
  );
}

export type ToastItem = {
  readonly id: number;
  readonly message: string;
  readonly intent?: "info" | "success" | "warning" | "danger";
};

export type ToastRegionProps = {
  readonly items: readonly ToastItem[];
  readonly onDismiss: (id: number) => void;
  /** Accessible name of the region (e.g. "Notifications"). */
  readonly label: string;
};

/**
 * Fixed bottom-right stack. `aria-live="polite"` on the region means new
 * children are announced without stealing focus; the region itself is
 * `pointer-events-none` so it never blocks clicks on the page behind it.
 */
export function ToastRegion(props: ToastRegionProps): JSX.Element {
  return (
    <section
      aria-label={props.label}
      aria-live="polite"
      class="pointer-events-none fixed inset-x-0 bottom-0 z-50 flex flex-col items-end gap-3 p-6 sm:inset-x-auto sm:right-0 sm:w-96"
    >
      <For each={props.items}>
        {(item) => (
          <Toast intent={item.intent} onDismiss={() => props.onDismiss(item.id)}>
            {item.message}
          </Toast>
        )}
      </For>
    </section>
  );
}
