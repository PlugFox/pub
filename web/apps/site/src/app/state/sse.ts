import { createEventStream, type EventStream, type StreamStatus } from "@pub/api/events";
import { DEFAULT_BASE_URL } from "@pub/api/pub-api";
import type { StreamEventDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { createSignal } from "solid-js";
import { bumpUnread, setUnreadCount } from "./notification-store";
import { pushToast } from "./toast-store";

/*
 * The app's single subscription to `GET /api/v1/events` (decision 20).
 *
 * The transport lives in `@pub/api/events` (framework-free, tested against a
 * mocked stream); this module owns the LIFECYCLE and the DISPATCH:
 *
 *   - opened when a credential exists, closed on sign-out and on a stream that
 *     reported `unauthorized`. Nothing here retries a dead credential: the
 *     access token is repaired by the API client's refresh, and a reconnect
 *     loop against a revoked session is a self-inflicted denial of service;
 *   - `notification.new` carries the recomputed unread count, so the badge is
 *     set from the event rather than incremented — one fewer request, and it
 *     cannot drift. The increment is the fallback for a frame that somehow
 *     omits it;
 *   - a small allowlist of events raises a toast. The rest update state
 *     silently. A stream that toasts everything is a stream users mute, and
 *     the point of the alarm-shaped events (`upstream.shadowing`) is that they
 *     are not lost in a firehose.
 *
 * The stream is a HINT CHANNEL. Every screen still reads the REST API; nothing
 * here is the source of truth for anything rendered.
 *
 * The access token is passed IN rather than read from `state/api.ts`: the api
 * module owns the interceptor callbacks that write to the stores, so importing
 * it here would close a cycle — and it would make this module untestable
 * without a DOM, since creating the client touches `localStorage`.
 */

const [status, setStatus] = createSignal<StreamStatus>("stopped");

/** Connection state of the event stream — for a "live / reconnecting" hint. */
export const streamStatus = status;

/** Events that deserve interrupting the user. Everything else lands in the feed. */
const TOASTED_EVENTS = new Set(["upstream.shadowing", "upstream.quarantine", "org.member"]);

let stream: EventStream | null = null;

/** Reads a numeric field out of the untyped event document. */
function numberField(event: StreamEventDto, key: string): number | null {
  const value = (event.data as Record<string, unknown>)[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringField(event: StreamEventDto, key: string): string | null {
  const value = (event.data as Record<string, unknown>)[key];
  return typeof value === "string" && value !== "" ? value : null;
}

/** Turns one frame into UI state. Exported for the dispatch test. */
export function dispatchStreamEvent(event: StreamEventDto): void {
  if (event.type === "notification.new") {
    const unread = numberField(event, "unread");
    if (unread === null) bumpUnread();
    else setUnreadCount(unread);
    const title = stringField(event, "title");
    if (title !== null) pushToast(title, "info");
    return;
  }
  if (!TOASTED_EVENTS.has(event.type)) return;
  if (event.type === "upstream.shadowing") {
    pushToast(t(app.eventShadowing, { name: event.package ?? "" }), "warning");
    return;
  }
  if (event.type === "upstream.quarantine") {
    pushToast(t(app.eventQuarantine, { name: event.package ?? "" }), "danger");
    return;
  }
  pushToast(t(app.eventOrgMembership), "info");
}

/**
 * Opens the stream if a credential exists. Idempotent — safe to call on every
 * mount and after every sign-in.
 *
 * `token` is called at CONNECT time, not captured: a reconnect after a refresh
 * must present the new access token, not the one the stream opened with.
 */
export function startEventStream(token: () => string | null): void {
  if (stream !== null) return;
  if (token() === null) return;
  stream = createEventStream({
    url: `${DEFAULT_BASE_URL}/events`,
    token,
    onEvent: dispatchStreamEvent,
    onStatus: setStatus,
    onStopped: (reason) => {
      stream = null;
      // S-32's per-user stream cap is the one stop worth explaining: the
      // symptom (no live updates) is otherwise indistinguishable from a quiet
      // instance. An `unauthorized` stop is already visible as a sign-out.
      if (reason === "rate_limited") pushToast(t(app.eventStreamCapped), "warning");
    },
  });
  stream.start();
}

/** Closes the stream and forgets it. Called on sign-out and on auth loss. */
export function stopEventStream(): void {
  stream?.stop();
  stream = null;
  setStatus("stopped");
}
