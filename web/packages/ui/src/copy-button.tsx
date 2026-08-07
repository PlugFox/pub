import { t } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { createSignal, type JSX, onCleanup, splitProps } from "solid-js";
import { Button, type ButtonProps } from "./button";

/**
 * Copies a string to the clipboard and confirms it for two seconds.
 *
 * Copying is the primary interaction on three show-once surfaces (the TOTP
 * secret, the recovery codes, the token secret), so the confirmation is part
 * of the control rather than a toast: the user's eyes are already on the
 * button, and a toast would be missed.
 *
 * `navigator.clipboard` requires a secure context and can be refused by the
 * user. On failure the label stays unchanged, and the value is always visible
 * next to the button — the copy is a convenience, never the only path.
 */

export type CopyButtonProps = Omit<ButtonProps, "onClick" | "children"> & {
  /** The text placed on the clipboard. */
  readonly value: string;
  /** Overrides the idle label ("Copy"). */
  readonly label?: string;
};

export function CopyButton(props: CopyButtonProps): JSX.Element {
  const [local, rest] = splitProps(props, ["value", "label"]);
  const [copied, setCopied] = createSignal(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  onCleanup(() => clearTimeout(timer));

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(local.value);
      setCopied(true);
      clearTimeout(timer);
      timer = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Denied or unavailable (insecure context): the value is on screen.
    }
  };

  return (
    <Button
      intent="outline"
      size="sm"
      {...rest}
      // `aria-live` on the button makes the label change itself the confirmation.
      aria-live="polite"
      onClick={() => void copy()}
    >
      {copied() ? t(common.copied) : (local.label ?? t(common.copy))}
    </Button>
  );
}
