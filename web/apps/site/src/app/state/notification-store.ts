import { createSignal } from "solid-js";

/*
 * The unread badge.
 *
 * A single number with two writers, which is exactly why it is a store rather
 * than a screen-local signal:
 *
 *   - the notification screen, from the `unread` field every feed and
 *     mark-read response carries (the server's count, always authoritative);
 *   - the SSE stream, which increments optimistically on a `notification.new`
 *     frame so the header reacts before anybody opens the feed.
 *
 * The optimistic increment can only ever be TOO HIGH for a moment — the next
 * authoritative read replaces it wholesale. It is never decremented by the
 * stream: marking read happens through the REST API, which answers with the
 * recomputed count.
 */

const [unread, setUnread] = createSignal(0);

/** Unread notifications; drives the header badge. */
export const unreadCount = unread;

/** Adopts the server's count (feed load, mark-read response). */
export function setUnreadCount(value: number): void {
  setUnread(Math.max(0, Math.trunc(value)));
}

/** A live `notification.new` frame arrived before the feed was reloaded. */
export function bumpUnread(): void {
  setUnread((current) => current + 1);
}

/** Sign-out: the badge belongs to the session that is ending. */
export function resetUnread(): void {
  setUnread(0);
}
