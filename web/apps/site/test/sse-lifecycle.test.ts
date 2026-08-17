import { afterEach, describe, expect, test } from "bun:test";
import {
  pauseEventStream,
  startEventStream,
  stopEventStream,
  streamStatus,
} from "../src/app/state/sse";
import { clearToasts, toasts } from "../src/app/state/toast-store";

/*
 * The lifecycle half of `state/sse.ts` (decision 40): what a PAUSE keeps and a
 * STOP forgets, and what a capped stream tells the reader.
 *
 * The transport is real here and only `fetch` is stubbed, because the property
 * under test is a header this module makes the transport send; stubbing the
 * transport would prove the test's own wiring instead.
 */

const realFetch = globalThis.fetch;

/**
 * Answers every attempt with an open stream that has already delivered one
 * frame, and records the request headers.
 */
function captureAttempts(): Headers[] {
  const headers: Headers[] = [];
  const encoder = new TextEncoder();
  globalThis.fetch = (async (_input: unknown, init?: { headers?: HeadersInit }) => {
    const attempt = headers.push(new Headers(init?.headers));
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        const id = `01JSEEN${attempt}`;
        controller.enqueue(encoder.encode(`id: ${id}\ndata: {"id":"${id}","type":"x"}\n\n`));
        // Deliberately left open: a stream that ends would reconnect on a real
        // timer and add attempts this test never asked for.
      },
    });
    return new Response(body, { status: 200 });
  }) as unknown as typeof fetch;
  return headers;
}

/** A capped instance: every attempt is the S-32 refusal, with the delay it names. */
function refuseWithCap(): { attempts: number } {
  const state = { attempts: 0 };
  globalThis.fetch = (async () => {
    state.attempts += 1;
    return new Response("{}", { status: 429, headers: { "retry-after": "600" } });
  }) as unknown as typeof fetch;
  return state;
}

/** Lets the stream's pending microtasks and body reads settle. */
async function flush(): Promise<void> {
  for (let index = 0; index < 12; index += 1) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
}

afterEach(() => {
  // Also cancels any retry the transport scheduled on a real timer.
  stopEventStream();
  clearToasts();
  globalThis.fetch = realFetch;
});

describe("pause versus stop", () => {
  test("a pause resumes from the last event id; a stop starts blind", async () => {
    const attempts = captureAttempts();

    startEventStream(() => "access");
    await flush();
    expect(attempts).toHaveLength(1);
    expect(attempts[0]?.has("last-event-id")).toBe(false);

    // A hidden tab gives the slot back and keeps its place in the log.
    pauseEventStream();
    startEventStream(() => "access");
    await flush();
    expect(attempts).toHaveLength(2);
    expect(attempts[1]?.get("last-event-id")).toBe("01JSEEN1");

    // A sign-out is not a pause: the place in the log was minted under a
    // credential that is gone, and the next one may be another account's.
    stopEventStream();
    startEventStream(() => "access");
    await flush();
    expect(attempts).toHaveLength(3);
    expect(attempts[2]?.has("last-event-id")).toBe(false);
  });

  test("pausing a stream that is not running is a no-op", () => {
    expect(() => pauseEventStream()).not.toThrow();
    expect(streamStatus()).toBe("stopped");
  });

  test("no credential means no connection attempt at all", async () => {
    const attempts = captureAttempts();
    startEventStream(() => null);
    await flush();
    expect(attempts).toHaveLength(0);
  });

  test("start is idempotent — one subscription per session, pause or not", async () => {
    const attempts = captureAttempts();
    startEventStream(() => "access");
    startEventStream(() => "access");
    await flush();
    expect(attempts).toHaveLength(1);
  });
});

describe("the cap toast", () => {
  test("a capped stream explains itself, and a new episode may explain itself again", async () => {
    // WHAT THIS DOES NOT PROVE: that a SECOND refusal inside one episode stays
    // silent. The retry is 600 s away by the server's own `Retry-After`, and
    // this test drives real timers. The transport side — `onThrottled` fires on
    // every refusal, so the suppression has to live here — is asserted in
    // `packages/api/test/events.test.ts`.
    const capped = refuseWithCap();

    startEventStream(() => "access");
    await flush();
    expect(capped.attempts).toBe(1);
    expect(toasts()).toHaveLength(1);

    // A stop ends the episode, so the next capped stream is news again.
    stopEventStream();
    startEventStream(() => "access");
    await flush();
    expect(toasts()).toHaveLength(2);
  });
});
