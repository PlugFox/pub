import type { ToastItem } from "@pub/ui/toast";
import { createSignal } from "solid-js";

/*
 * Toast queue — a module-level signal, no context provider (decision 14's
 * "one island" shape means there is exactly one app; a provider would only add
 * a tree the writers cannot always reach).
 *
 * The writers include an interceptor reporting a 429 and the session store
 * reacting to a dead refresh — neither has a component around it, so the queue
 * must be addressable as a plain function call.
 */

export type ToastIntent = NonNullable<ToastItem["intent"]>;

/** How long a toast stays before it auto-dismisses. */
const DEFAULT_TTL_MS = 6000;

const [items, setItems] = createSignal<readonly ToastItem[]>([]);
let nextId = 1;

/** The live queue, oldest first. */
export const toasts = items;

/** Queues a toast and returns its id. Auto-dismisses unless `ttlMs` is 0. */
export function pushToast(
  message: string,
  intent: ToastIntent = "info",
  ttlMs: number = DEFAULT_TTL_MS,
): number {
  const id = nextId;
  nextId += 1;
  setItems((current) => [...current, { id, message, intent }]);
  if (ttlMs > 0) setTimeout(() => dismissToast(id), ttlMs);
  return id;
}

export function dismissToast(id: number): void {
  setItems((current) => current.filter((item) => item.id !== id));
}

/** Test/teardown helper — drops everything without waiting for the timers. */
export function clearToasts(): void {
  setItems([]);
}
