import { describe, expect, test } from "bun:test";
import { ApiError, NetworkError } from "@pub/api/errors";
import type { LoginDto } from "@pub/api/types";
import {
  classifyLoginError,
  initialLoginState,
  type LoginEvent,
  type LoginState,
  loginReducer,
  RESEND_COOLDOWN_SECONDS,
  resendAvailableAt,
} from "../src/app/state/login-machine";

/*
 * The sign-in machine is the branchiest thing in the app, so it is a pure
 * reducer and every branch is asserted here — including the ones a happy-path
 * click-through would never reach (an event arriving on the wrong step, a
 * failure landing after the user already advanced).
 */

const COMPLETE: LoginDto = {
  mfa_required: false,
  access_token: "a.b.c",
  refresh_token: "opaque",
  session_id: "s1",
  user: {
    id: "u1",
    email: "ada@example.com",
    email_verified: true,
    display_name: "Ada",
    created_at: "2026-01-01T00:00:00Z",
  },
};

const NEEDS_MFA: LoginDto = { mfa_required: true, mfa_token: "pending-mfa" };

/** Applies a list of events in order — the transitions read as a script. */
function run(events: readonly LoginEvent[], from: LoginState = initialLoginState()): LoginState {
  return events.reduce(loginReducer, from);
}

const codeSent: LoginEvent = {
  type: "codeSent",
  email: "ada@example.com",
  pendingId: "p1",
  resendAvailableAt: 1_000,
};

describe("happy paths", () => {
  test("email → code → done", () => {
    const state = run([
      { type: "editEmail", email: "ada@example.com" },
      { type: "submit" },
      codeSent,
      { type: "submit" },
      { type: "loginResolved", login: COMPLETE },
    ]);
    expect(state.step).toBe("done");
    expect(state.step === "done" && state.login).toBe(COMPLETE);
  });

  test("email → code → mfa → done", () => {
    const afterMfa = run([
      { type: "editEmail", email: "ada@example.com" },
      { type: "submit" },
      codeSent,
      { type: "submit" },
      { type: "loginResolved", login: NEEDS_MFA },
    ]);
    expect(afterMfa.step).toBe("mfa");
    expect(afterMfa.step === "mfa" && afterMfa.mfaToken).toBe("pending-mfa");
    expect(afterMfa.step === "mfa" && afterMfa.mode).toBe("totp");
    expect(afterMfa.step !== "done" && afterMfa.busy).toBe(false);

    const done = run([{ type: "submit" }, { type: "loginResolved", login: COMPLETE }], afterMfa);
    expect(done.step).toBe("done");
  });

  test("a resend replaces the pending id and the cool-down without leaving the step", () => {
    const onCode = run([{ type: "submit" }, codeSent]);
    const resent = loginReducer(onCode, {
      type: "codeSent",
      email: "ada@example.com",
      pendingId: "p2",
      resendAvailableAt: 9_000,
    });
    expect(resent.step).toBe("code");
    expect(resent.step === "code" && resent.pendingId).toBe("p2");
    expect(resent.step === "code" && resent.resendAvailableAt).toBe(9_000);
  });

  test("changeEmail returns to the email step with the address preserved", () => {
    const back = run([
      { type: "editEmail", email: "ada@example.com" },
      { type: "submit" },
      codeSent,
      { type: "changeEmail" },
    ]);
    expect(back.step).toBe("email");
    expect(back.step === "email" && back.email).toBe("ada@example.com");
    expect(back.step === "email" && back.error).toBeNull();
  });

  test("the MFA mode toggles and survives an MFA→MFA resolution", () => {
    const onMfa = loginReducer(run([{ type: "submit" }, codeSent, { type: "submit" }]), {
      type: "loginResolved",
      login: NEEDS_MFA,
    });
    const recovery = loginReducer(onMfa, { type: "setMfaMode", mode: "recovery" });
    expect(recovery.step === "mfa" && recovery.mode).toBe("recovery");

    // A second MFA response (e.g. a retried handle) must not silently reset
    // the user back to the authenticator field they already gave up on.
    const again = loginReducer(recovery, { type: "loginResolved", login: NEEDS_MFA });
    expect(again.step === "mfa" && again.mode).toBe("recovery");
  });
});

describe("busy flag", () => {
  test("submit sets it, an outcome clears it", () => {
    const busy = loginReducer(initialLoginState("a@b.c"), { type: "submit" });
    expect(busy.step !== "done" && busy.busy).toBe(true);
    const sent = loginReducer(busy, codeSent);
    expect(sent.step !== "done" && sent.busy).toBe(false);
    const failed = loginReducer(busy, { type: "failed", error: { kind: "generic" } });
    expect(failed.step !== "done" && failed.busy).toBe(false);
  });

  test("a second submit while busy changes nothing (double-click guard)", () => {
    const busy = loginReducer(initialLoginState("a@b.c"), { type: "submit" });
    expect(loginReducer(busy, { type: "submit" })).toBe(busy);
  });

  test("submit on the terminal step is ignored", () => {
    const done = loginReducer(initialLoginState(), { type: "loginResolved", login: COMPLETE });
    expect(loginReducer(done, { type: "submit" })).toBe(done);
  });
});

describe("error branches", () => {
  test("a failure keeps the step and records the error", () => {
    const onCode = run([{ type: "submit" }, codeSent, { type: "submit" }]);
    const failed = loginReducer(onCode, { type: "failed", error: { kind: "invalidCode" } });
    expect(failed.step).toBe("code");
    expect(failed.step !== "done" && failed.error?.kind).toBe("invalidCode");
    // The pending id survives, so the user can retype the code.
    expect(failed.step === "code" && failed.pendingId).toBe("p1");
  });

  test("typing clears a previous error on the email step", () => {
    const failed = loginReducer(initialLoginState(), {
      type: "failed",
      error: { kind: "emailRequired" },
    });
    const typed = loginReducer(failed, { type: "editEmail", email: "a" });
    expect(typed.step === "email" && typed.error).toBeNull();
  });

  test("advancing a step clears the previous error", () => {
    const failed = run([
      { type: "submit" },
      { type: "failed", error: { kind: "rateLimited", retryAfter: 30 } },
    ]);
    const advanced = loginReducer(failed, codeSent);
    expect(advanced.step !== "done" && advanced.error).toBeNull();
  });

  test("switching the MFA mode clears the error", () => {
    const onMfa = loginReducer(initialLoginState(), { type: "loginResolved", login: NEEDS_MFA });
    const failed = loginReducer(onMfa, { type: "failed", error: { kind: "invalidCode" } });
    const switched = loginReducer(failed, { type: "setMfaMode", mode: "recovery" });
    expect(switched.step !== "done" && switched.error).toBeNull();
  });

  test("a failure arriving after the login already completed is ignored", () => {
    const done = loginReducer(initialLoginState(), { type: "loginResolved", login: COMPLETE });
    expect(loginReducer(done, { type: "failed", error: { kind: "network" } })).toBe(done);
  });
});

describe("events on the wrong step are ignored, not crashes", () => {
  const done = loginReducer(initialLoginState(), { type: "loginResolved", login: COMPLETE });
  const onCode = run([{ type: "submit" }, codeSent]);

  test.each([
    ["editEmail on the code step", onCode, { type: "editEmail", email: "x" } as LoginEvent],
    ["changeEmail on the email step", initialLoginState(), { type: "changeEmail" } as LoginEvent],
    [
      "setMfaMode outside the MFA step",
      onCode,
      { type: "setMfaMode", mode: "recovery" } as LoginEvent,
    ],
    ["codeSent after completion", done, codeSent],
    [
      "loginResolved after completion",
      done,
      { type: "loginResolved", login: NEEDS_MFA } as LoginEvent,
    ],
  ])("%s", (_name, state: LoginState, event: LoginEvent) => {
    expect(loginReducer(state, event)).toBe(state);
  });
});

describe("mfa_required without a handle", () => {
  test("falls through to done rather than stranding the user on an unusable step", () => {
    // The server always sends `mfa_token` with `mfa_required` (S-05.a). If it
    // somehow does not, an MFA step with nothing to redeem is a dead end; the
    // completion path at least surfaces the missing-token failure downstream.
    const state = loginReducer(initialLoginState(), {
      type: "loginResolved",
      login: { mfa_required: true },
    });
    expect(state.step).toBe("done");
  });
});

describe("classifyLoginError (S-04 uniformity)", () => {
  test("invalid_code and a bare 401 collapse into ONE class", () => {
    expect(classifyLoginError(new ApiError("invalid_code", "nope", 400)).kind).toBe("invalidCode");
    expect(classifyLoginError(new ApiError("unauthorized", "nope", 401)).kind).toBe("invalidCode");
  });

  test("429 carries the Retry-After through", () => {
    const classified = classifyLoginError(
      new ApiError("rate_limited", "slow down", 429, { retryAfter: 42 }),
    );
    expect(classified).toEqual({ kind: "rateLimited", retryAfter: 42 });
  });

  test("a 429 whose code is something else is still throttling", () => {
    expect(classifyLoginError(new ApiError("too_many", "slow down", 429)).kind).toBe("rateLimited");
  });

  test("a NetworkError is never a rejection", () => {
    expect(classifyLoginError(new NetworkError("offline")).kind).toBe("network");
  });

  test("anything else is generic, including non-errors", () => {
    expect(classifyLoginError(new ApiError("boom", "x", 500)).kind).toBe("generic");
    expect(classifyLoginError("a string").kind).toBe("generic");
    expect(classifyLoginError(undefined).kind).toBe("generic");
  });
});

describe("resendAvailableAt", () => {
  test("defaults to the S-03 minimum when the server sent no Retry-After", () => {
    expect(resendAvailableAt(undefined, 1_000)).toBe(1_000 + RESEND_COOLDOWN_SECONDS * 1000);
  });

  test("honours a longer Retry-After", () => {
    expect(resendAvailableAt(300, 1_000)).toBe(301_000);
  });

  test("a zero or negative Retry-After falls back to the minimum, never to 'now'", () => {
    expect(resendAvailableAt(0, 1_000)).toBe(1_000 + RESEND_COOLDOWN_SECONDS * 1000);
    expect(resendAvailableAt(-5, 1_000)).toBe(1_000 + RESEND_COOLDOWN_SECONDS * 1000);
  });
});
