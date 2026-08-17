import { parseRetryAfter } from "./errors";
import type { StreamEventDto } from "./types";

/*
 * The `GET /api/v1/events` client (decision 20, S-32).
 *
 * FETCH-STREAMING, NOT `EventSource`. The stream is authenticated with the
 * same access JWT every other route uses, and `EventSource` cannot set an
 * `Authorization` header — its only credential channel is cookies, which
 * decision 03 forbids as an API credential. So the transport is `fetch` with a
 * `ReadableStream` body and a hand-written SSE frame parser. The parser is
 * small on purpose; the format is small.
 *
 * Four behaviours here are load-bearing and separately tested:
 *
 *  1. **Frame parsing is buffered across chunks.** A network chunk boundary
 *     has nothing to do with a frame boundary: `data: {"id":"01J…` can arrive
 *     in one read and the rest of the JSON in the next. The decoder keeps a
 *     tail buffer and only emits on a blank line.
 *  2. **`Last-Event-ID` survives the reconnect.** The id of the last frame
 *     delivered is sent back on the next attempt, so the instance's ring
 *     buffer can replay what was missed. Replay is best-effort and filtered
 *     identically to live delivery — the REST API remains the source of truth.
 *  3. **Backoff is exponential with jitter, and it resets on a healthy
 *     stream.** Without the reset, a connection that lives for an hour and
 *     then drops would reconnect at the maximum delay; without the jitter,
 *     every browser on an instance that just restarted reconnects in the same
 *     millisecond.
 *  4. **A 401 is not a retry; a 429 is.** The access token is refreshed by the
 *     API client, not here — reconnecting in a loop against a dead credential
 *     is how a client turns its own logout into a denial-of-service, so an
 *     unauthorized stream stops and reports it, and the app reopens after a
 *     successful sign-in. A 429 is the opposite case ([decision 40], S-32.b):
 *     the S-32 per-user cap refuses with `Retry-After`, the slot is released
 *     by whichever of the account's other streams ends first, and the delay
 *     the server named is honoured as a FLOOR — see `capRetryDelay`.
 */

/** A parsed SSE frame: the `event:` name, the `data:` payload, and the `id:`. */
export type SseFrame = {
  readonly event: string;
  readonly data: string;
  readonly id: string | null;
};

/**
 * Why the stream stopped for good.
 *
 * One member, and the narrowing is the point (decision 40): `rate_limited` used
 * to live here, and a cap refusal is not a stop — it is a delay the server
 * named. The only terminal condition left is a credential this transport cannot
 * repair.
 */
export type StreamStopReason = "unauthorized";

/**
 * The slice of `fetch` this module needs.
 *
 * Narrower than `typeof fetch` on purpose, exactly like `FetchLike` in
 * `client.ts`: the global signature carries runtime-specific extras (Bun adds
 * `preconnect`), so typing the injection point against it would force every
 * test double to fake them.
 */
export type StreamFetch = (
  url: string,
  init: { headers: Record<string, string>; signal: AbortSignal },
) => Promise<Response>;

export type EventStreamOptions = {
  /** Absolute or same-origin URL of the stream, e.g. `/api/v1/events`. */
  readonly url: string;
  /** Returns the current access token, or `null` when there is none (stop). */
  readonly token: () => string | null;
  /** One decoded domain event, in delivery order. */
  readonly onEvent: (event: StreamEventDto) => void;
  /** Connection state changes, for a "live/reconnecting" indicator. */
  readonly onStatus?: (status: StreamStatus) => void;
  /** The stream gave up; the app decides what to do (usually nothing). */
  readonly onStopped?: (reason: StreamStopReason) => void;
  /**
   * The S-32 cap refused this connection and a retry is scheduled in `delayMs`.
   *
   * Fired on EVERY refusal, deliberately: the transport reports facts and the
   * app decides how often a person should hear about them (decision 40 — the
   * shipped client toasts once per episode, not once per attempt).
   */
  readonly onThrottled?: (delayMs: number) => void;
  /**
   * Resume point for a stream that was paused rather than signed out — the
   * `Last-Event-ID` of a previous connection. `null` starts blind.
   */
  readonly initialLastEventId?: string | null;
  readonly fetchImpl?: StreamFetch;
  /** Injectable timer for tests; must behave like `setTimeout`. */
  readonly setTimeoutImpl?: (handler: () => void, ms: number) => unknown;
  readonly clearTimeoutImpl?: (handle: unknown) => void;
  /** Injectable jitter source in [0, 1); defaults to `Math.random`. */
  readonly random?: () => number;
  readonly backoff?: BackoffOptions;
  readonly capRetry?: CapRetryOptions;
};

export type StreamStatus = "connecting" | "open" | "reconnecting" | "stopped";

export type BackoffOptions = {
  /** First retry delay. */
  readonly baseMs?: number;
  /** Ceiling for the exponential growth. */
  readonly maxMs?: number;
  /** Fraction of the delay that is randomized, 0..1. */
  readonly jitter?: number;
};

export const DEFAULT_BACKOFF: Required<BackoffOptions> = {
  baseMs: 1_000,
  maxMs: 30_000,
  jitter: 0.5,
};

export type CapRetryOptions = {
  /** Used when the refusal carries no parseable `Retry-After`. */
  readonly fallbackMs?: number;
  /** Ceiling for the ladder, raised to the server's number when it asks for longer. */
  readonly ceilingMs?: number;
  /** Fraction of the delay added on top, 0..1. */
  readonly jitter?: number;
};

/**
 * The ladder for an S-32 cap refusal: thirty seconds by the server's own
 * default, doubling per consecutive refusal, five minutes at the top.
 */
export const DEFAULT_CAP_RETRY: Required<CapRetryOptions> = {
  fallbackMs: 30_000,
  ceilingMs: 300_000,
  jitter: 0.25,
};

/**
 * Delay before cap-refusal number `attempt` (1-based) is retried.
 *
 * TWO PROPERTIES, both the opposite of `backoffDelay`'s, and both because the
 * server named a number rather than merely failing:
 *
 *   - **the jitter is additive**, so the delay is never *below* the
 *     `Retry-After` the refusal carried — coming back sooner than the server
 *     asked is ignoring it, and the whole point of the ladder is to be a good
 *     citizen of a cap that clears by itself;
 *   - **the ceiling is `max(ceilingMs, base)`**, so a server that asks for
 *     longer than five minutes is obeyed instead of clamped.
 */
export function capRetryDelay(
  attempt: number,
  retryAfterMs: number | undefined,
  options: CapRetryOptions = {},
  random: () => number = Math.random,
): number {
  const { fallbackMs, ceilingMs, jitter } = { ...DEFAULT_CAP_RETRY, ...options };
  const base = retryAfterMs !== undefined && retryAfterMs > 0 ? retryAfterMs : fallbackMs;
  const grown = base * 2 ** Math.max(0, attempt - 1);
  return Math.round(Math.min(Math.max(ceilingMs, base), grown * (1 + jitter * random())));
}

/**
 * Delay before retry number `attempt` (1-based), exponential and jittered.
 *
 * The jitter is subtractive (`delay * (1 - jitter * r)`), so the value never
 * exceeds `maxMs` — a cap that the jitter can overshoot is not a cap.
 */
export function backoffDelay(
  attempt: number,
  options: BackoffOptions = {},
  random: () => number = Math.random,
): number {
  const { baseMs, maxMs, jitter } = { ...DEFAULT_BACKOFF, ...options };
  const exponential = Math.min(maxMs, baseMs * 2 ** Math.max(0, attempt - 1));
  return Math.round(exponential * (1 - jitter * random()));
}

/**
 * Incremental SSE frame decoder.
 *
 * Handles the parts of the format the server actually uses: `event:`, `data:`
 * (possibly repeated — joined with newlines, per the spec), `id:`, and comment
 * lines (`:heartbeat`) which are keep-alives and yield nothing. `\r\n` is
 * normalized because a proxy may rewrite line endings.
 */
export function createSseDecoder(): { push(chunk: string): SseFrame[] } {
  let buffer = "";
  return {
    push(chunk: string): SseFrame[] {
      buffer += chunk.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
      const frames: SseFrame[] = [];
      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const frame = parseBlock(block);
        if (frame !== null) frames.push(frame);
        boundary = buffer.indexOf("\n\n");
      }
      return frames;
    },
  };
}

function parseBlock(block: string): SseFrame | null {
  let event = "message";
  let id: string | null = null;
  const data: string[] = [];
  for (const line of block.split("\n")) {
    // A line starting with ':' is a comment — the keep-alive heartbeat.
    if (line === "" || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    // "If value starts with a space, remove it" (WHATWG SSE).
    const rawValue = colon === -1 ? "" : line.slice(colon + 1);
    const value = rawValue.startsWith(" ") ? rawValue.slice(1) : rawValue;
    if (field === "event") event = value;
    else if (field === "data") data.push(value);
    else if (field === "id") id = value;
  }
  if (data.length === 0) return null;
  return { event, data: data.join("\n"), id };
}

/** Parses a frame's `data` into a stream event, or `null` when it is not one. */
export function decodeStreamEvent(frame: SseFrame): StreamEventDto | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(frame.data);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const candidate = parsed as StreamEventDto;
  // `id` and `type` are what every consumer keys off; a frame missing either
  // is a protocol violation, and rendering `undefined` in a toast is worse
  // than dropping it.
  return typeof candidate.id === "string" && typeof candidate.type === "string" ? candidate : null;
}

export type EventStream = {
  /** Opens the stream (idempotent while running). */
  start(): void;
  /** Closes it and cancels any pending reconnect. Safe to call twice. */
  stop(): void;
  /** The last event id seen — what a reconnect replays from. */
  lastEventId(): string | null;
  /** Current connection state. */
  status(): StreamStatus;
};

export function createEventStream(options: EventStreamOptions): EventStream {
  const fetchImpl: StreamFetch = options.fetchImpl ?? ((url, init) => fetch(url, init));
  const schedule =
    options.setTimeoutImpl ?? ((handler: () => void, ms: number) => setTimeout(handler, ms));
  const cancel = options.clearTimeoutImpl ?? ((handle: unknown) => clearTimeout(handle as number));
  const random = options.random ?? Math.random;

  let running = false;
  let attempt = 0;
  /** Consecutive S-32 cap refusals. Counted apart from `attempt`: a refused
   * slot and an unreachable server are different conditions with different
   * ladders, and mixing them would let one reset the other. */
  let capAttempt = 0;
  let lastId: string | null = options.initialLastEventId ?? null;
  let controller: AbortController | null = null;
  let retryHandle: unknown = null;
  let status: StreamStatus = "stopped";

  const setStatus = (next: StreamStatus): void => {
    if (status === next) return;
    status = next;
    options.onStatus?.(next);
  };

  const stopFor = (reason: StreamStopReason): void => {
    running = false;
    controller?.abort();
    controller = null;
    if (retryHandle !== null) {
      cancel(retryHandle);
      retryHandle = null;
    }
    setStatus("stopped");
    options.onStopped?.(reason);
  };

  const scheduleAt = (delayMs: number): void => {
    retryHandle = schedule(() => {
      retryHandle = null;
      void connect();
    }, delayMs);
  };

  const scheduleRetry = (): void => {
    if (!running) return;
    attempt += 1;
    setStatus("reconnecting");
    scheduleAt(backoffDelay(attempt, options.backoff, random));
  };

  /** The S-32 cap refused the connection; come back no sooner than it asked. */
  const scheduleCapRetry = (retryAfterMs: number | undefined): void => {
    if (!running) return;
    capAttempt += 1;
    const delay = capRetryDelay(capAttempt, retryAfterMs, options.capRetry, random);
    setStatus("reconnecting");
    options.onThrottled?.(delay);
    scheduleAt(delay);
  };

  const connect = async (): Promise<void> => {
    if (!running) return;
    const token = options.token();
    if (token === null) {
      stopFor("unauthorized");
      return;
    }

    controller = new AbortController();
    const headers: Record<string, string> = {
      accept: "text/event-stream",
      authorization: `Bearer ${token}`,
    };
    if (lastId !== null) headers["last-event-id"] = lastId;

    let response: Response;
    try {
      setStatus(attempt === 0 ? "connecting" : "reconnecting");
      response = await fetchImpl(options.url, { headers, signal: controller.signal });
    } catch {
      // Transport failure (offline, DNS, abort). An abort while stopping is
      // covered by the `running` check inside scheduleRetry.
      scheduleRetry();
      return;
    }

    if (response.status === 401) {
      stopFor("unauthorized");
      return;
    }
    if (response.status === 429) {
      const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
      scheduleCapRetry(retryAfter === undefined ? undefined : retryAfter * 1_000);
      return;
    }
    if (!response.ok || response.body === null) {
      scheduleRetry();
      return;
    }

    // A stream that produced its headers is healthy enough to reset both
    // ladders: the next drop should retry fast, not an hour later, and a slot
    // that was granted says the cap episode is over.
    attempt = 0;
    capAttempt = 0;
    setStatus("open");

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const sse = createSseDecoder();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        for (const frame of sse.push(chunk)) {
          if (frame.id !== null) lastId = frame.id;
          const event = decodeStreamEvent(frame);
          if (event !== null) options.onEvent(event);
        }
      }
    } catch {
      // Read error mid-stream — same handling as a clean end: reconnect.
    } finally {
      reader.cancel().catch(() => {});
    }

    // The server ends the stream at the token's `exp` and on revocation
    // (S-32). Reconnecting is right for the first, and the retry will get a
    // 401 for the second — which stops the loop.
    scheduleRetry();
  };

  return {
    start(): void {
      if (running) return;
      running = true;
      attempt = 0;
      capAttempt = 0;
      void connect();
    },
    stop(): void {
      if (!running && retryHandle === null && controller === null) return;
      running = false;
      controller?.abort();
      controller = null;
      if (retryHandle !== null) {
        cancel(retryHandle);
        retryHandle = null;
      }
      setStatus("stopped");
    },
    lastEventId(): string | null {
      return lastId;
    },
    status(): StreamStatus {
      return status;
    },
  };
}
