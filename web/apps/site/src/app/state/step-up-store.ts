import { createSignal } from "solid-js";

/*
 * Step-up prompt controller (S-06).
 *
 * The server answers a stale session with a distinct `step_up_required` 403 so
 * the UI can prompt instead of dead-ending. Two things must then happen, and
 * they belong to different owners:
 *
 *   - the PROMPT opens — an interceptor can do this, because it sees every
 *     response and the user should see the dialog even if the caller forgot to
 *     handle the case;
 *   - the ACTION retries — only the caller can do this, because only the
 *     caller knows what it was doing and whether it is still wanted.
 *
 * Hence one shared prompt with many waiters: `requestStepUp` (interceptor)
 * opens it and returns nothing; `promptStepUp` (caller) opens it if needed and
 * resolves `true` when the user satisfied it, `false` when they cancelled.
 * Concurrent callers join the SAME prompt rather than stacking dialogs.
 */

const [open, setOpen] = createSignal(false);
let waiters: ((satisfied: boolean) => void)[] = [];

/** Whether the step-up dialog should be on screen. */
export const isStepUpOpen = open;

/** Opens the prompt without waiting — the interceptor's entry point. */
export function requestStepUp(): void {
  setOpen(true);
}

/** Opens the prompt (or joins the open one) and resolves with the outcome. */
export function promptStepUp(): Promise<boolean> {
  setOpen(true);
  return new Promise<boolean>((resolve) => {
    waiters.push(resolve);
  });
}

/** Called by the dialog: `true` after a verified code, `false` on cancel/dismiss. */
export function resolveStepUp(satisfied: boolean): void {
  const pending = waiters;
  waiters = [];
  setOpen(false);
  for (const resolve of pending) resolve(satisfied);
}
