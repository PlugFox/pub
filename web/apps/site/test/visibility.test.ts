import { describe, expect, test } from "bun:test";
import { createVisibilityPauser } from "../src/app/state/visibility";

/*
 * The rules that decide when a tab gives up its S-32 stream slot (decision 40).
 *
 * The timer is injected, so every assertion here is about what was scheduled
 * and what fired — no test sleeps, and "the grace period elapsed" is something
 * the test performs rather than waits for.
 */

/** A scheduler the test drives by hand. */
function fakeTimers(): {
  schedule: (handler: () => void, ms: number) => unknown;
  cancel: (handle: unknown) => void;
  delays: number[];
  run: () => void;
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
    run() {
      const entry = queue.shift();
      if (entry !== undefined && !entry.cancelled) entry.handler();
    },
    pending() {
      return queue.filter((entry) => !entry.cancelled).length;
    },
  };
}

function pauser(graceMs = 1_000): {
  timers: ReturnType<typeof fakeTimers>;
  events: string[];
  subject: ReturnType<typeof createVisibilityPauser>;
} {
  const timers = fakeTimers();
  const events: string[] = [];
  const subject = createVisibilityPauser({
    graceMs,
    onPause: () => events.push("pause"),
    onResume: () => events.push("resume"),
    setTimeoutImpl: timers.schedule,
    clearTimeoutImpl: timers.cancel,
  });
  return { timers, events, subject };
}

describe("createVisibilityPauser", () => {
  test("a hidden document pauses only after the grace period", () => {
    const { timers, events, subject } = pauser();
    subject.changed(true);

    expect(events).toEqual([]);
    expect(timers.delays).toEqual([1_000]);
    expect(subject.paused()).toBe(false);

    timers.run();
    expect(events).toEqual(["pause"]);
    expect(subject.paused()).toBe(true);
  });

  test("coming back inside the grace period cancels the pause entirely", () => {
    // The case the grace period exists for: a glance at another tab must not
    // cost a slot that lingers for a heartbeat after the client is gone.
    const { timers, events, subject } = pauser();
    subject.changed(true);
    subject.changed(false);
    timers.run();

    expect(events).toEqual([]);
    expect(timers.pending()).toBe(0);
    expect(subject.paused()).toBe(false);
  });

  test("becoming visible after a pause resumes exactly once", () => {
    const { timers, events, subject } = pauser();
    subject.changed(true);
    timers.run();
    subject.changed(false);

    expect(events).toEqual(["pause", "resume"]);
    expect(subject.paused()).toBe(false);
  });

  test("repeating the current state is a no-op, so an idle tab cannot keep its slot", () => {
    // Browsers fire `visibilitychange` for states the listener may already
    // hold. Restarting the grace timer on each would postpone the pause
    // forever, which is the failure this rule exists to refuse.
    const { timers, events, subject } = pauser();
    subject.changed(true);
    subject.changed(true);
    subject.changed(true);

    expect(timers.delays).toEqual([1_000]);
    timers.run();
    expect(events).toEqual(["pause"]);
  });

  test("a visible document that reports visible again neither pauses nor resumes", () => {
    const { events, subject } = pauser();
    subject.changed(false);
    expect(events).toEqual([]);
  });

  test("dispose cancels a pending pause and does not resume", () => {
    const { timers, events, subject } = pauser();
    subject.changed(true);
    subject.dispose();
    timers.run();

    expect(events).toEqual([]);
    expect(subject.paused()).toBe(false);
  });

  test("hide → pause → show → hide runs the whole cycle again", () => {
    const { timers, events, subject } = pauser();
    subject.changed(true);
    timers.run();
    subject.changed(false);
    subject.changed(true);
    timers.run();

    expect(events).toEqual(["pause", "resume", "pause"]);
    expect(subject.paused()).toBe(true);
  });
});
