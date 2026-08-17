/*
 * "This tab is not being looked at" as a rule rather than as a listener.
 *
 * The S-32 per-user cap is five concurrent streams per account per instance,
 * and the ordinary way a person reaches it is tabs, not attacks. So a hidden
 * document gives its slot back (decision 40, S-32.b) and takes one again when
 * it returns.
 *
 * THE GRACE PERIOD IS THE DESIGN, not a tunable. A slot lingers for up to one
 * heartbeat after the client is gone (S-32.a's second residue), so pausing on
 * every tab switch would spend more slots than it frees: glancing at another
 * tab for four seconds would cost a slot for a full heartbeat and gain nothing.
 * This pauses a document that has been hidden for a while.
 *
 * DOM-FREE BY CONSTRUCTION. The caller reports `hidden`; nothing here reads
 * `document`. That keeps the rules testable without a browser and leaves
 * exactly one place in the app that touches `visibilityState`.
 */

export type VisibilityPauser = {
  /** Report a visibility change. Repeating the current state does nothing. */
  readonly changed: (hidden: boolean) => void;
  /** Whether the pause has actually fired (not merely been scheduled). */
  readonly paused: () => boolean;
  /** Cancels a pending pause. Deliberately does not resume: the caller is leaving. */
  readonly dispose: () => void;
};

/** How long a document must stay hidden before its stream is released. */
export const DEFAULT_HIDDEN_GRACE_MS = 60_000;

export type VisibilityPauserOptions = {
  readonly onPause: () => void;
  readonly onResume: () => void;
  readonly graceMs?: number;
  /** Injectable timer for tests; must behave like `setTimeout`. */
  readonly setTimeoutImpl?: (handler: () => void, ms: number) => unknown;
  readonly clearTimeoutImpl?: (handle: unknown) => void;
};

export function createVisibilityPauser(options: VisibilityPauserOptions): VisibilityPauser {
  const schedule =
    options.setTimeoutImpl ?? ((handler: () => void, ms: number) => setTimeout(handler, ms));
  const cancel = options.clearTimeoutImpl ?? ((handle: unknown) => clearTimeout(handle as number));
  const graceMs = options.graceMs ?? DEFAULT_HIDDEN_GRACE_MS;

  let hidden = false;
  let paused = false;
  let handle: unknown = null;

  const clearPending = (): void => {
    if (handle === null) return;
    cancel(handle);
    handle = null;
  };

  return {
    changed(next: boolean): void {
      // Browsers fire `visibilitychange` for state the caller may already hold
      // (a re-registered listener, a synthesized event). Restarting the grace
      // timer on those would let an idle background tab keep its slot forever.
      if (next === hidden) return;
      hidden = next;
      if (hidden) {
        handle = schedule(() => {
          handle = null;
          paused = true;
          options.onPause();
        }, graceMs);
        return;
      }
      clearPending();
      if (!paused) return;
      paused = false;
      options.onResume();
    },
    paused(): boolean {
      return paused;
    },
    dispose(): void {
      clearPending();
    },
  };
}
