import { describe, expect, test } from "bun:test";
import {
  backoffDelay,
  createEventStream,
  createSseDecoder,
  DEFAULT_BACKOFF,
  decodeStreamEvent,
  type StreamStopReason,
} from "../src/events";
import type { StreamEventDto } from "../src/types";

/*
 * The SSE client, driven against a mocked stream.
 *
 * Everything here is deterministic: the fetch, the clock, and the jitter are
 * injected, so "reconnects with backoff" is an assertion about the delays that
 * were scheduled rather than a test that sleeps.
 */

/** Builds a Response whose body streams the given chunks, then ends. */
function streamingResponse(chunks: readonly string[], status = 200): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
  return new Response(body, { status, headers: { "content-type": "text/event-stream" } });
}

/** A never-ending stream, so a connection stays "open" until the test aborts it. */
function openResponse(): { response: Response; push: (chunk: string) => void; end: () => void } {
  const encoder = new TextEncoder();
  let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      controller = c;
    },
  });
  return {
    response: new Response(body, { status: 200 }),
    push: (chunk) => controller?.enqueue(encoder.encode(chunk)),
    end: () => controller?.close(),
  };
}

function frame(event: string, data: unknown, id?: string): string {
  const lines = [`event: ${event}`, `data: ${JSON.stringify(data)}`];
  if (id !== undefined) lines.unshift(`id: ${id}`);
  return `${lines.join("\n")}\n\n`;
}

function streamEvent(overrides: Partial<StreamEventDto> = {}): StreamEventDto {
  return {
    id: "01JABCDEF",
    type: "package.publish",
    at: "2026-08-07T10:00:00Z",
    data: {} as StreamEventDto["data"],
    ...overrides,
  };
}

/** A controllable scheduler: nothing runs until the test says so. */
function fakeTimers(): {
  schedule: (handler: () => void, ms: number) => unknown;
  cancel: (handle: unknown) => void;
  delays: number[];
  runNext: () => Promise<void>;
  pending: () => number;
} {
  const queue: { handler: () => void; cancelled: boolean }[] = [];
  const delays: number[] = [];
  return {
    schedule(handler, ms) {
      delays.push(ms);
      const entry = { handler, cancelled: false };
      queue.push(entry);
      return entry;
    },
    cancel(handle) {
      (handle as { cancelled: boolean }).cancelled = true;
    },
    delays,
    async runNext() {
      const entry = queue.shift();
      if (entry !== undefined && !entry.cancelled) entry.handler();
      await flush();
    },
    pending() {
      return queue.filter((entry) => !entry.cancelled).length;
    },
  };
}

/** Lets pending microtasks and stream reads settle. */
async function flush(): Promise<void> {
  for (let i = 0; i < 12; i += 1) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
}

// --------------------------------------------------------------- frame parsing

describe("createSseDecoder", () => {
  test("emits one frame per blank-line-terminated block", () => {
    const decoder = createSseDecoder();
    const frames = decoder.push(`${frame("a", { id: "1" })}${frame("b", { id: "2" })}`);
    expect(frames.map((f) => f.event)).toEqual(["a", "b"]);
  });

  test("buffers across chunk boundaries — a network read is not a frame", () => {
    const decoder = createSseDecoder();
    expect(decoder.push('event: package.publish\ndata: {"id":"01J')).toEqual([]);
    const frames = decoder.push('ABC","type":"package.publish"}\n\n');
    expect(frames).toHaveLength(1);
    expect(frames[0]?.data).toBe('{"id":"01JABC","type":"package.publish"}');
  });

  test("splits a boundary that itself arrives in two chunks", () => {
    const decoder = createSseDecoder();
    expect(decoder.push("data: x\n")).toEqual([]);
    expect(decoder.push("\n")).toHaveLength(1);
  });

  test("ignores comment lines — the heartbeat is not an event", () => {
    const decoder = createSseDecoder();
    expect(decoder.push(":heartbeat\n\n")).toEqual([]);
    expect(decoder.push(": another\ndata: real\n\n")).toHaveLength(1);
  });

  test("normalizes CRLF, because a proxy may rewrite line endings", () => {
    const decoder = createSseDecoder();
    const frames = decoder.push("id: 7\r\nevent: x\r\ndata: y\r\n\r\n");
    expect(frames[0]).toEqual({ event: "x", data: "y", id: "7" });
  });

  test("joins repeated data lines with newlines, per the SSE spec", () => {
    const decoder = createSseDecoder();
    expect(decoder.push("data: one\ndata: two\n\n")[0]?.data).toBe("one\ntwo");
  });

  test("strips exactly one leading space after the colon", () => {
    const decoder = createSseDecoder();
    expect(decoder.push("data:  padded\n\n")[0]?.data).toBe(" padded");
  });

  test("defaults the event name to `message` when the field is absent", () => {
    const decoder = createSseDecoder();
    expect(decoder.push("data: x\n\n")[0]?.event).toBe("message");
  });

  test("a block with no data field yields nothing", () => {
    const decoder = createSseDecoder();
    expect(decoder.push("event: x\nid: 1\n\n")).toEqual([]);
  });
});

describe("decodeStreamEvent", () => {
  test("parses a well-formed frame", () => {
    const event = decodeStreamEvent({
      event: "package.publish",
      data: JSON.stringify(streamEvent()),
      id: "01JABCDEF",
    });
    expect(event?.type).toBe("package.publish");
  });

  test.each([
    ["not JSON", "{"],
    ["a JSON scalar", '"nope"'],
    ["null", "null"],
    ["an object without an id", '{"type":"package.publish"}'],
    ["an object without a type", '{"id":"01J"}'],
    ["a non-string id", '{"id":1,"type":"x"}'],
  ])("drops %s rather than rendering undefined", (_label, data) => {
    expect(decodeStreamEvent({ event: "x", data, id: null })).toBeNull();
  });
});

// -------------------------------------------------------------------- backoff

describe("backoffDelay", () => {
  test("grows exponentially without jitter", () => {
    const zero = () => 0;
    expect(backoffDelay(1, { jitter: 0 }, zero)).toBe(DEFAULT_BACKOFF.baseMs);
    expect(backoffDelay(2, { jitter: 0 }, zero)).toBe(DEFAULT_BACKOFF.baseMs * 2);
    expect(backoffDelay(3, { jitter: 0 }, zero)).toBe(DEFAULT_BACKOFF.baseMs * 4);
  });

  test("saturates at the ceiling", () => {
    expect(backoffDelay(40, { jitter: 0 }, () => 0)).toBe(DEFAULT_BACKOFF.maxMs);
  });

  test("jitter only ever subtracts, so the cap is a real cap", () => {
    for (const random of [0, 0.25, 0.5, 0.999]) {
      const delay = backoffDelay(40, {}, () => random);
      expect(delay).toBeLessThanOrEqual(DEFAULT_BACKOFF.maxMs);
      expect(delay).toBeGreaterThanOrEqual(DEFAULT_BACKOFF.maxMs * (1 - DEFAULT_BACKOFF.jitter));
    }
  });

  test("never returns a negative delay", () => {
    expect(backoffDelay(1, { jitter: 1 }, () => 0.999)).toBeGreaterThanOrEqual(0);
  });
});

// --------------------------------------------------------------- the stream

describe("createEventStream", () => {
  test("delivers decoded events in order and reports `open`", async () => {
    const received: StreamEventDto[] = [];
    const statuses: string[] = [];
    const timers = fakeTimers();
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access",
      onEvent: (event) => received.push(event),
      onStatus: (status) => statuses.push(status),
      fetchImpl: async () =>
        streamingResponse([
          frame("package.publish", streamEvent({ id: "1" }), "1"),
          ":heartbeat\n\n",
          frame("package.retract", streamEvent({ id: "2", type: "package.retract" }), "2"),
        ]),
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
    });

    stream.start();
    await flush();

    expect(received.map((event) => event.type)).toEqual(["package.publish", "package.retract"]);
    expect(statuses).toContain("open");
    stream.stop();
  });

  test("sends the bearer token, and Last-Event-ID only after a first event", async () => {
    const headers: (Headers | undefined)[] = [];
    const timers = fakeTimers();
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access-1",
      onEvent: () => {},
      fetchImpl: async (_url, init) => {
        headers.push(new Headers(init?.headers));
        return streamingResponse([frame("package.publish", streamEvent(), "01JLAST")]);
      },
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
    });

    stream.start();
    await flush();
    expect(headers[0]?.get("authorization")).toBe("Bearer access-1");
    expect(headers[0]?.has("last-event-id")).toBe(false);
    expect(stream.lastEventId()).toBe("01JLAST");

    // The stream ended, so a reconnect was scheduled; run it.
    await timers.runNext();
    expect(headers[1]?.get("last-event-id")).toBe("01JLAST");
    stream.stop();
  });

  test("a reconnect presents the CURRENT token, not the one it opened with", async () => {
    const tokens: (string | null)[] = [];
    const timers = fakeTimers();
    let current = "first";
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => current,
      onEvent: () => {},
      fetchImpl: async (_url, init) => {
        tokens.push(new Headers(init?.headers).get("authorization"));
        return streamingResponse([]);
      },
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
    });

    stream.start();
    await flush();
    current = "refreshed";
    await timers.runNext();

    expect(tokens).toEqual(["Bearer first", "Bearer refreshed"]);
    stream.stop();
  });

  test("reconnects with growing delays while the connection keeps failing", async () => {
    const timers = fakeTimers();
    let attempts = 0;
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access",
      onEvent: () => {},
      fetchImpl: async () => {
        attempts += 1;
        throw new Error("offline");
      },
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
      backoff: { baseMs: 100, maxMs: 1000, jitter: 0 },
    });

    stream.start();
    await flush();
    await timers.runNext();
    await timers.runNext();

    expect(attempts).toBe(3);
    expect(timers.delays.slice(0, 3)).toEqual([100, 200, 400]);
    expect(stream.status()).toBe("reconnecting");
    stream.stop();
  });

  test("a healthy connection resets the backoff, so a late drop retries fast", async () => {
    const timers = fakeTimers();
    const responses: (() => Response)[] = [
      () => {
        throw new Error("offline");
      },
      () => {
        throw new Error("offline");
      },
      // Third attempt succeeds and then ends: the next delay must be the base
      // again, not the escalated one.
      () => streamingResponse([]),
    ];
    let index = 0;
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access",
      onEvent: () => {},
      fetchImpl: async () => (responses[index++] ?? (() => streamingResponse([])))(),
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
      backoff: { baseMs: 100, maxMs: 10_000, jitter: 0 },
    });

    stream.start();
    await flush();
    await timers.runNext();
    await timers.runNext();

    expect(timers.delays).toEqual([100, 200, 100]);
    stream.stop();
  });

  test("a 401 stops the stream — a reconnect loop on a dead credential is self-DoS", async () => {
    const timers = fakeTimers();
    const stopped: StreamStopReason[] = [];
    let attempts = 0;
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "expired",
      onEvent: () => {},
      onStopped: (reason) => stopped.push(reason),
      fetchImpl: async () => {
        attempts += 1;
        return new Response("{}", { status: 401 });
      },
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
    });

    stream.start();
    await flush();

    expect(attempts).toBe(1);
    expect(stopped).toEqual(["unauthorized"]);
    expect(timers.pending()).toBe(0);
    expect(stream.status()).toBe("stopped");
  });

  test("a 429 (the S-32 per-user stream cap) is terminal too", async () => {
    const timers = fakeTimers();
    const stopped: StreamStopReason[] = [];
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access",
      onEvent: () => {},
      onStopped: (reason) => stopped.push(reason),
      fetchImpl: async () => new Response("{}", { status: 429 }),
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
    });

    stream.start();
    await flush();
    expect(stopped).toEqual(["rate_limited"]);
    expect(timers.pending()).toBe(0);
  });

  test("a 5xx is retried — the server is unwell, the credential is not", async () => {
    const timers = fakeTimers();
    let attempts = 0;
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access",
      onEvent: () => {},
      fetchImpl: async () => {
        attempts += 1;
        return new Response("{}", { status: 503 });
      },
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
    });

    stream.start();
    await flush();
    expect(timers.pending()).toBe(1);
    await timers.runNext();
    expect(attempts).toBe(2);
    stream.stop();
  });

  test("no token means no connection attempt at all", async () => {
    const timers = fakeTimers();
    const stopped: StreamStopReason[] = [];
    let attempts = 0;
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => null,
      onEvent: () => {},
      onStopped: (reason) => stopped.push(reason),
      fetchImpl: async () => {
        attempts += 1;
        return streamingResponse([]);
      },
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
    });

    stream.start();
    await flush();
    expect(attempts).toBe(0);
    expect(stopped).toEqual(["unauthorized"]);
  });

  test("stop() cancels a pending reconnect and delivers nothing more", async () => {
    const timers = fakeTimers();
    const received: StreamEventDto[] = [];
    let attempts = 0;
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access",
      onEvent: (event) => received.push(event),
      fetchImpl: async () => {
        attempts += 1;
        return streamingResponse([frame("package.publish", streamEvent(), "1")]);
      },
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
      random: () => 0,
    });

    stream.start();
    await flush();
    expect(received).toHaveLength(1);

    stream.stop();
    await timers.runNext();

    expect(attempts).toBe(1);
    expect(stream.status()).toBe("stopped");
  });

  test("start() is idempotent — one subscription per session", async () => {
    const timers = fakeTimers();
    let attempts = 0;
    const live = openResponse();
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access",
      onEvent: () => {},
      fetchImpl: async () => {
        attempts += 1;
        return live.response;
      },
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
    });

    stream.start();
    stream.start();
    await flush();
    expect(attempts).toBe(1);
    stream.stop();
  });

  test("events arriving on a live connection are dispatched as they come", async () => {
    const timers = fakeTimers();
    const received: string[] = [];
    const live = openResponse();
    const stream = createEventStream({
      url: "/api/v1/events",
      token: () => "access",
      onEvent: (event) => received.push(event.type),
      fetchImpl: async () => live.response,
      setTimeoutImpl: timers.schedule,
      clearTimeoutImpl: timers.cancel,
    });

    stream.start();
    await flush();
    expect(received).toEqual([]);

    live.push(frame("notification.new", streamEvent({ type: "notification.new" }), "9"));
    await flush();
    expect(received).toEqual(["notification.new"]);
    expect(stream.lastEventId()).toBe("9");

    live.end();
    stream.stop();
  });
});
