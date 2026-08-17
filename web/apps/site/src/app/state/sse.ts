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
 *     loop against a revoked session is a self-inflicted denial of service.
 *     A cap refusal is NOT that case — the transport retries it on the delay
 *     the server named (decision 40), and all this module does is decide how
 *     often a person hears about it;
 *   - stopped two ways, and the difference is one value. `stopEventStream` is
 *     the credential going away and forgets everything; `pauseEventStream` is
 *     a tab nobody is looking at (S-32.b) and remembers the last event id, so
 *     the resume replays the gap instead of starting blind;
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

/**
 * The resume point a PAUSE leaves behind — the last event id seen before a
 * hidden tab gave up its S-32 slot. A sign-out clears it: the next credential
 * may not be the same account, and replay is filtered per principal anyway.
 */
let resumeFrom: string | null = null;

/**
 * Whether the cap toast has already fired for the episode in progress. The
 * transport reports every refusal; a warning every five minutes is how the one
 * alarm this stream raises becomes noise. Rearmed when a connection opens.
 */
let capNotified = false;

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
export function startEventStream(token: () => string | null, onUnauthorized?: () => void): void {
  if (stream !== null) return;
  if (token() === null) return;
  stream = createEventStream({
    url: `${DEFAULT_BASE_URL}/events`,
    token,
    initialLastEventId: resumeFrom,
    onEvent: dispatchStreamEvent,
    onStatus: (next) => {
      // A granted slot ends the episode: the next refusal is news again.
      if (next === "open") capNotified = false;
      setStatus(next);
    },
    onThrottled: () => {
      // S-32's per-user stream cap is the one delay worth explaining: the
      // symptom (no live updates) is otherwise indistinguishable from a quiet
      // instance. Once per episode, not once per attempt.
      if (capNotified) return;
      capNotified = true;
      pushToast(t(app.eventStreamCapped), "warning");
    },
    onStopped: () => {
      // The only terminal reason left is `unauthorized`. The resume point goes
      // with it: it was minted under a credential the server just refused.
      stream = null;
      resumeFrom = null;
      // Whether that credential can be repaired is not this module's call —
      // the refresh lives in the api client, which this module may not import.
      onUnauthorized?.();
    },
  });
  stream.start();
}

/** Closes the stream and forgets it. Called on sign-out and on auth loss. */
export function stopEventStream(): void {
  stream?.stop();
  stream = null;
  resumeFrom = null;
  capNotified = false;
  setStatus("stopped");
}

/**
 * Releases the stream's S-32 slot while keeping the place in the log.
 *
 * For a document nobody is looking at (decision 40): the next
 * `startEventStream` presents this id as `Last-Event-ID`, so the instance's
 * ring buffer replays what was missed. Replay is bounded and best-effort, which
 * is why the resume path also re-seeds the unread count from the API.
 */
export function pauseEventStream(): void {
  if (stream === null) return;
  resumeFrom = stream.lastEventId();
  stream.stop();
  stream = null;
  setStatus("stopped");
}
