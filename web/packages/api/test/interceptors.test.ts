import { describe, expect, test } from "bun:test";
import { createClient, jsonBody } from "@pub/api/client";
import { ApiError, NetworkError, parseRetryAfter } from "@pub/api/errors";
import {
  type AuthLostReason,
  createAuthInterceptor,
  createRateLimitInterceptor,
  createStepUpInterceptor,
  mutationHeadersInterceptor,
  type StepUpSignal,
} from "@pub/api/interceptors";
import { createMemoryStorage, createTokenStorage, type TokenPair } from "@pub/api/storage";

/*
 * Interceptor behaviour, exercised through the real client with a fake fetch.
 *
 * These are the tests that protect the properties nothing else can: a page
 * that loads six things in parallel must cause ONE refresh (six would trip the
 * S-08 reuse detector and log the user out), and going offline must never look
 * like a denial.
 */

const BASE = "https://pub.test";

function jwt(expMs: number): string {
  const encode = (value: unknown): string =>
    btoa(JSON.stringify(value)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  return `${encode({ alg: "EdDSA" })}.${encode({ sub: "u1", sid: "s1", exp: expMs / 1000 })}.sig`;
}

function ok(data: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify({ status: "ok", data }), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

function errorResponse(status: number, code: string, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify({ status: "error", error: { code, message: code } }), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

type Harness = {
  readonly client: ReturnType<typeof createClient>;
  readonly storage: ReturnType<typeof createTokenStorage>;
  readonly requests: Request[];
  readonly authLost: AuthLostReason[];
  readonly stepUps: StepUpSignal[];
  readonly rateLimits: (number | undefined)[];
  refreshCalls: number;
  now: number;
  reset(): void;
  isDenied(): boolean;
  renew(): Promise<boolean>;
};

type HarnessOptions = {
  /** Answers requests in order of arrival; the last entry repeats. */
  readonly responses: readonly ((request: Request) => Response)[];
  /** What `POST /auth/refresh` does. Defaults to handing out a fresh long-lived pair. */
  readonly refresh?: (token: string, call: number) => Promise<TokenPair>;
  readonly initialPair?: TokenPair | null;
  readonly nowMs?: number;
};

function harness(options: HarnessOptions): Harness {
  const storage = createTokenStorage(createMemoryStorage());
  const requests: Request[] = [];
  const authLost: AuthLostReason[] = [];
  const stepUps: StepUpSignal[] = [];
  const rateLimits: (number | undefined)[] = [];
  const state = { refreshCalls: 0, now: options.nowMs ?? 1_000_000 };

  if (options.initialPair !== null) {
    storage.write(
      options.initialPair ?? { accessToken: jwt(state.now + 600_000), refreshToken: "r0" },
    );
  }

  const auth = createAuthInterceptor({
    storage,
    now: () => state.now,
    onAuthLost: (reason) => authLost.push(reason),
    refresh: async (token) => {
      state.refreshCalls += 1;
      const call = state.refreshCalls;
      if (options.refresh !== undefined) return options.refresh(token, call);
      return { accessToken: jwt(state.now + 900_000), refreshToken: `r${call}` };
    },
  });

  const client = createClient({
    baseUrl: BASE,
    interceptors: [
      mutationHeadersInterceptor,
      createRateLimitInterceptor((seconds) => rateLimits.push(seconds)),
      createStepUpInterceptor((signal) => stepUps.push(signal)),
      auth.intercept,
    ],
    fetchImpl: async (request) => {
      requests.push(request);
      const index = Math.min(requests.length - 1, options.responses.length - 1);
      const responder = options.responses[index];
      if (responder === undefined) throw new Error("no responder");
      return responder(request);
    },
  });

  return {
    client,
    storage,
    requests,
    authLost,
    stepUps,
    rateLimits,
    get refreshCalls() {
      return state.refreshCalls;
    },
    get now() {
      return state.now;
    },
    set now(value: number) {
      state.now = value;
    },
    reset: auth.reset,
    isDenied: auth.isDenied,
    renew: auth.renew,
  };
}

describe("bearer injection", () => {
  test("attaches the stored access token", async () => {
    const h = harness({ responses: [() => ok("fine")] });
    await h.client.request("/sessions");
    expect(h.requests[0]?.headers.get("authorization")).toBe(
      `Bearer ${h.storage.read()?.accessToken}`,
    );
  });

  test("skipAuth requests carry no Authorization and never refresh", async () => {
    const h = harness({
      responses: [() => ok(null)],
      initialPair: { accessToken: jwt(0), refreshToken: "r0" }, // long expired
    });
    await h.client.request("/auth/otp/request", { method: "POST" }, { skipAuth: true });
    expect(h.requests[0]?.headers.get("authorization")).toBeNull();
    expect(h.refreshCalls).toBe(0);
  });

  test("an anonymous 401 does not attempt a refresh and does not report a lost session", async () => {
    const h = harness({
      responses: [() => errorResponse(401, "unauthorized")],
      initialPair: null,
    });
    await expect(h.client.request("/sessions")).rejects.toBeInstanceOf(ApiError);
    expect(h.refreshCalls).toBe(0);
    expect(h.authLost).toEqual([]);
  });
});

describe("proactive refresh", () => {
  test("refreshes before the request when the access token is inside the skew window", async () => {
    const now = 5_000_000;
    const h = harness({
      nowMs: now,
      // 30 s of life left, default skew is 60 s.
      initialPair: { accessToken: jwt(now + 30_000), refreshToken: "r0" },
      responses: [() => ok("fine")],
    });

    await h.client.request("/sessions");

    expect(h.refreshCalls).toBe(1);
    // Exactly one wire request: the refresh runs on its own bare client.
    expect(h.requests).toHaveLength(1);
    expect(h.requests[0]?.headers.get("authorization")).toBe(
      `Bearer ${h.storage.read()?.accessToken}`,
    );
    expect(h.storage.read()?.refreshToken).toBe("r1");
  });

  test("a comfortably fresh token is used as-is", async () => {
    const now = 5_000_000;
    const h = harness({
      nowMs: now,
      initialPair: { accessToken: jwt(now + 600_000), refreshToken: "r0" },
      responses: [() => ok("fine")],
    });
    await h.client.request("/sessions");
    expect(h.refreshCalls).toBe(0);
  });

  test("six parallel calls on an expiring token cause ONE refresh", async () => {
    const now = 5_000_000;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const h = harness({
      nowMs: now,
      initialPair: { accessToken: jwt(now + 1_000), refreshToken: "r0" },
      responses: [() => ok("fine")],
      refresh: async (_token, call) => {
        await gate;
        return { accessToken: jwt(now + 900_000), refreshToken: `r${call}` };
      },
    });

    const inFlight = Promise.all(Array.from({ length: 6 }, () => h.client.request("/sessions")));
    release?.();
    await inFlight;

    // Six refreshes would present five rotated-out tokens and kill the family (S-08).
    expect(h.refreshCalls).toBe(1);
    expect(h.requests).toHaveLength(6);
  });
});

describe("reactive refresh on 401", () => {
  test("refreshes once and retries the request with the new token", async () => {
    const h = harness({
      responses: [() => errorResponse(401, "unauthorized"), () => ok("second time lucky")],
    });

    await expect(h.client.request<string>("/sessions")).resolves.toBe("second time lucky");
    expect(h.refreshCalls).toBe(1);
    expect(h.requests).toHaveLength(2);
    expect(h.requests[1]?.headers.get("authorization")).toBe(
      `Bearer ${h.storage.read()?.accessToken}`,
    );
  });

  test("the retry keeps the method, body, and mutation headers", async () => {
    const h = harness({
      responses: [() => errorResponse(401, "unauthorized"), () => ok({ id: "t1" })],
    });

    await h.client.request("/tokens", {
      method: "POST",
      body: JSON.stringify({ org_id: "o1", scopes: ["read"] }),
    });

    const retry = h.requests[1];
    expect(retry?.method).toBe("POST");
    expect(retry?.headers.get("x-pub-request")).toBe("1");
    expect(retry?.headers.get("content-type")).toBe("application/json");
    expect(await retry?.clone().text()).toBe(JSON.stringify({ org_id: "o1", scopes: ["read"] }));
  });

  test("three concurrent 401s share ONE refresh and all get retried", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const h = harness({
      responses: [
        () => errorResponse(401, "unauthorized"),
        () => errorResponse(401, "unauthorized"),
        () => errorResponse(401, "unauthorized"),
        () => ok("retried"),
      ],
      refresh: async (_token, call) => {
        await gate;
        return { accessToken: jwt(Date.now() + 900_000), refreshToken: `r${call}` };
      },
    });

    const inFlight = Promise.all([
      h.client.request<string>("/a"),
      h.client.request<string>("/b"),
      h.client.request<string>("/c"),
    ]);
    release?.();
    expect(await inFlight).toEqual(["retried", "retried", "retried"]);
    expect(h.refreshCalls).toBe(1);
    expect(h.requests).toHaveLength(6);
  });

  test("a 401 on the retry is surfaced instead of looping", async () => {
    const h = harness({ responses: [() => errorResponse(401, "unauthorized")] });
    await expect(h.client.request("/sessions")).rejects.toBeInstanceOf(ApiError);
    expect(h.refreshCalls).toBe(1);
    expect(h.requests).toHaveLength(2);
  });

  /*
   * `invalid_code` is a 401 about the code the user typed, not about the
   * credential this interceptor manages. Retrying it replays the same body, and
   * the server charges the S-03.a attempt budget atomically BEFORE comparing —
   * so a blind retry spends two of the five attempts per wrong digit, on three
   * flows: TOTP confirm, step-up, and the S-03.b email change.
   */
  test("a wrong code is surfaced without a refresh and without spending a second attempt", async () => {
    const h = harness({ responses: [() => errorResponse(401, "invalid_code")] });
    await expect(
      h.client.request("/me/email/verify", jsonBody("POST", { code: "00000000" })),
    ).rejects.toBeInstanceOf(ApiError);
    expect(h.refreshCalls).toBe(0);
    expect(h.requests).toHaveLength(1);
  });
});

describe("denial latch", () => {
  test("a refused refresh clears storage, reports once, and short-circuits later attempts", async () => {
    const h = harness({
      responses: [() => errorResponse(401, "unauthorized")],
      refresh: async () => {
        throw new ApiError("unauthorized", "session is gone", 401);
      },
    });

    await expect(h.client.request("/a")).rejects.toBeInstanceOf(ApiError);
    expect(h.authLost).toEqual(["refresh_denied"]);
    expect(h.storage.read()).toBeNull();
    expect(h.isDenied()).toBe(true);

    // A second call must not hammer the refresh endpoint.
    await expect(h.client.request("/b")).rejects.toBeInstanceOf(ApiError);
    expect(h.refreshCalls).toBe(1);
    expect(h.authLost).toEqual(["refresh_denied"]);
  });

  test("refresh_reused is reported distinctly — the whole family is dead (S-08)", async () => {
    const h = harness({
      responses: [() => errorResponse(401, "unauthorized")],
      refresh: async () => {
        throw new ApiError("refresh_reused", "token replayed", 401);
      },
    });
    await expect(h.client.request("/a")).rejects.toBeInstanceOf(ApiError);
    expect(h.authLost).toEqual(["refresh_reused"]);
  });

  test("reset() reopens the latch after a fresh sign-in", async () => {
    const h = harness({
      responses: [() => errorResponse(401, "unauthorized"), () => ok("back in")],
      refresh: async (_token, call) => {
        if (call === 1) throw new ApiError("unauthorized", "gone", 401);
        return { accessToken: jwt(Date.now() + 900_000), refreshToken: "r2" };
      },
    });

    await expect(h.client.request("/a")).rejects.toBeInstanceOf(ApiError);
    expect(h.isDenied()).toBe(true);

    h.storage.write({ accessToken: jwt(Date.now() + 900_000), refreshToken: "fresh" });
    h.reset();
    expect(h.isDenied()).toBe(false);
    await expect(h.client.request<string>("/b")).resolves.toBe("back in");
  });
});

/*
 * `renew()` exists for one situation: the caller was just granted a membership,
 * which by S-09.a does NOT revoke the session, so the access token keeps an
 * `orgs` claim that predates the grant. It must share the single-flight promise
 * and the denial latch with the automatic refresh — a second, independent
 * refresh call is exactly what trips the S-08 reuse detector.
 */
describe("explicit renew", () => {
  test("rotates the pair on demand and reports success", async () => {
    const h = harness({ responses: [() => ok("fine")] });
    const before = h.storage.read();
    expect(await h.renew()).toBe(true);
    expect(h.refreshCalls).toBe(1);
    expect(h.storage.read()?.refreshToken).toBe("r1");
    expect(h.storage.read()?.accessToken).not.toBe(before?.accessToken);
    // The next ordinary request rides the NEW token, with no second refresh.
    await h.client.request("/anything");
    expect(h.requests[0]?.headers.get("authorization")).toBe(
      `Bearer ${h.storage.read()?.accessToken}`,
    );
    expect(h.refreshCalls).toBe(1);
  });

  test("shares one flight with a concurrent automatic refresh", async () => {
    // The refresh is held open until both callers are waiting on it, which is
    // the only way to observe that they queue on ONE promise rather than
    // firing two rotations at a server that treats the second as reuse.
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const h = harness({
      responses: [() => errorResponse(401, "unauthorized"), () => ok("retried")],
      refresh: async (_token, call) => {
        await gate;
        return { accessToken: jwt(2_000_000), refreshToken: `r${call}` };
      },
    });
    const renewing = h.renew();
    const requesting = h.client.request<string>("/thing");
    // Let the request reach its 401 and join the in-flight rotation.
    await new Promise((resolve) => setTimeout(resolve, 0));
    release?.();
    expect(await renewing).toBe(true);
    expect(await requesting).toBe("retried");
    expect(h.refreshCalls).toBe(1);
  });

  test("a refused renewal reports the lost session once and then short-circuits", async () => {
    const h = harness({
      responses: [() => ok("unused")],
      refresh: () => Promise.reject(new ApiError("unauthorized", "no", 401)),
    });
    expect(await h.renew()).toBe(false);
    expect(h.authLost).toEqual(["refresh_denied"]);
    expect(h.storage.read()).toBeNull();
    expect(await h.renew()).toBe(false);
    expect(h.refreshCalls).toBe(1);
    expect(h.authLost).toEqual(["refresh_denied"]);
  });

  test("offline REJECTS rather than reporting a denial — the session is intact", async () => {
    const h = harness({
      responses: [() => ok("unused")],
      refresh: () => Promise.reject(new NetworkError("offline")),
    });
    await expect(h.renew()).rejects.toBeInstanceOf(NetworkError);
    expect(h.authLost).toEqual([]);
    expect(h.isDenied()).toBe(false);
    expect(h.storage.read()?.refreshToken).toBe("r0");
  });
});

describe("network is not denial", () => {
  test("a NetworkError during a reactive refresh keeps the session and stays quiet", async () => {
    const h = harness({
      responses: [() => errorResponse(401, "unauthorized")],
      refresh: async () => {
        throw new NetworkError("offline");
      },
    });

    const failure = await h.client.request("/a").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(NetworkError);
    expect(failure).not.toBeInstanceOf(ApiError);
    // The three properties that make "a tunnel" different from "a logout":
    expect(h.authLost).toEqual([]);
    expect(h.storage.read()).not.toBeNull();
    expect(h.isDenied()).toBe(false);
  });

  test("a NetworkError during a proactive refresh behaves the same and can recover", async () => {
    const now = 7_000_000;
    const h = harness({
      nowMs: now,
      initialPair: { accessToken: jwt(now + 1_000), refreshToken: "r0" },
      responses: [() => ok("recovered")],
      refresh: async (_token, call) => {
        if (call === 1) throw new NetworkError("offline");
        return { accessToken: jwt(now + 900_000), refreshToken: "r2" };
      },
    });

    await expect(h.client.request("/a")).rejects.toBeInstanceOf(NetworkError);
    expect(h.authLost).toEqual([]);
    // Connectivity returns; the latch never closed, so the next call succeeds.
    await expect(h.client.request<string>("/a")).resolves.toBe("recovered");
    expect(h.refreshCalls).toBe(2);
  });

  test("a transport failure on the ORIGINAL request never triggers a refresh", async () => {
    const storage = createTokenStorage(createMemoryStorage());
    storage.write({ accessToken: jwt(Date.now() + 900_000), refreshToken: "r0" });
    let refreshCalls = 0;
    const auth = createAuthInterceptor({
      storage,
      onAuthLost: () => undefined,
      refresh: async () => {
        refreshCalls += 1;
        return { accessToken: "x", refreshToken: "y" };
      },
    });
    const client = createClient({
      baseUrl: BASE,
      interceptors: [auth.intercept],
      fetchImpl: async () => {
        throw new TypeError("fetch failed");
      },
    });

    await expect(client.request("/a")).rejects.toBeInstanceOf(NetworkError);
    expect(refreshCalls).toBe(0);
    expect(storage.read()).not.toBeNull();
  });
});

describe("step-up", () => {
  test("the distinct 403 reaches the controller and still throws for the caller", async () => {
    const h = harness({
      responses: [() => errorResponse(403, "step_up_required")],
    });

    const failure = await h.client
      .request("/tokens", { method: "POST", body: "{}" })
      .catch((error: unknown) => error);

    expect(h.stepUps).toHaveLength(1);
    expect(h.stepUps[0]?.method).toBe("POST");
    expect(h.stepUps[0]?.url).toBe(`${BASE}/tokens`);
    expect((failure as ApiError).code).toBe("step_up_required");
    expect((failure as ApiError).status).toBe(403);
  });

  test("an ordinary 403 is left alone", async () => {
    const h = harness({ responses: [() => errorResponse(403, "forbidden")] });
    await expect(h.client.request("/orgs")).rejects.toBeInstanceOf(ApiError);
    expect(h.stepUps).toEqual([]);
  });

  test("peeking at the body does not consume it — the caller still gets the message", async () => {
    const h = harness({ responses: [() => errorResponse(403, "step_up_required")] });
    const failure = await h.client.request("/tokens").catch((error: unknown) => error);
    expect((failure as ApiError).message).toBe("step_up_required");
  });
});

describe("Retry-After", () => {
  test("delta-seconds land on the ApiError and on the rate-limit listener", async () => {
    const h = harness({
      responses: [() => errorResponse(429, "rate_limited", { "retry-after": "42" })],
    });
    const failure = await h.client.request("/auth/otp/request").catch((error: unknown) => error);
    expect((failure as ApiError).retryAfter).toBe(42);
    expect(h.rateLimits).toEqual([42]);
  });

  test("an HTTP-date is converted to seconds from now", () => {
    const now = Date.parse("2026-08-07T10:00:00Z");
    expect(parseRetryAfter("Fri, 07 Aug 2026 10:01:30 GMT", now)).toBe(90);
  });

  test("a date in the past clamps to 0 rather than going negative", () => {
    const now = Date.parse("2026-08-07T10:00:00Z");
    expect(parseRetryAfter("Fri, 07 Aug 2026 09:00:00 GMT", now)).toBe(0);
  });

  test.each([
    ["absent", null],
    ["empty", "   "],
    ["nonsense", "soon"],
  ])("%s Retry-After yields undefined, never NaN", (_name, value) => {
    expect(parseRetryAfter(value)).toBeUndefined();
  });

  test("a 429 with no Retry-After still reaches the listener, with undefined", async () => {
    const h = harness({ responses: [() => errorResponse(429, "rate_limited")] });
    await h.client.request("/auth/otp/request").catch(() => undefined);
    expect(h.rateLimits).toEqual([undefined]);
  });
});

describe("mutation headers (S-12)", () => {
  test("POST with a body gets the custom header and a JSON content type", async () => {
    const h = harness({ responses: [() => ok(null)] });
    await h.client.request("/orgs", { method: "POST", body: "{}" });
    expect(h.requests[0]?.headers.get("x-pub-request")).toBe("1");
    expect(h.requests[0]?.headers.get("content-type")).toBe("application/json");
  });

  test("a bodiless mutation gets the header but NO content type", async () => {
    // The server accepts a missing content type on a bodiless mutation and
    // rejects a non-JSON one; sending a type with no body is noise.
    const h = harness({ responses: [() => new Response(null, { status: 204 })] });
    await h.client.request("/sessions/s1", { method: "DELETE" });
    expect(h.requests[0]?.headers.get("x-pub-request")).toBe("1");
    expect(h.requests[0]?.headers.get("content-type")).toBeNull();
  });

  test("GET carries neither", async () => {
    const h = harness({ responses: [() => ok([])] });
    await h.client.request("/tokens");
    expect(h.requests[0]?.headers.get("x-pub-request")).toBeNull();
    expect(h.requests[0]?.headers.get("content-type")).toBeNull();
  });

  test("an explicit content type is not overwritten", async () => {
    const h = harness({ responses: [() => ok(null)] });
    await h.client.request("/orgs", {
      method: "POST",
      body: "{}",
      headers: { "content-type": "application/json; charset=utf-8" },
    });
    expect(h.requests[0]?.headers.get("content-type")).toBe("application/json; charset=utf-8");
  });

  test("the browser's implicit text/plain on a string body is replaced with JSON", async () => {
    // Browser parity: `new Request(url, { body: "…" })` appends
    // `Content-Type: text/plain;charset=UTF-8` (Fetch, "extract a body") and
    // guard.rs answers 415 to it. Bun's Request does not add the header, so
    // this test states the browser's behaviour explicitly instead of relying
    // on the runtime to produce it.
    const h = harness({ responses: [() => ok(null)] });
    await h.client.request("/orgs", {
      method: "POST",
      body: "{}",
      headers: { "content-type": "text/plain;charset=UTF-8" },
    });
    expect(h.requests[0]?.headers.get("content-type")).toBe("application/json");
  });

  test("jsonBody declares the JSON type up front, so no implicit type can appear", async () => {
    const h = harness({ responses: [() => ok(null)] });
    await h.client.request("/orgs", jsonBody("POST", { name: "acme" }));
    expect(h.requests[0]?.headers.get("content-type")).toBe("application/json");
    expect(h.requests[0]?.headers.get("x-pub-request")).toBe("1");
  });
});
