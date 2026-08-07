import { type Interceptor, peekErrorCode, requestMeta } from "./client";
import { ApiError, ERROR_CODES, NetworkError, parseRetryAfter } from "./errors";
import { isAccessTokenExpiring } from "./jwt";
import type { TokenPair, TokenStorage } from "./storage";

/*
 * The interceptor chain (decision 14, docs/rules/web.md “Data & API”).
 *
 * Assembled outermost-first as:
 *   mutationHeaders → stepUp → auth(bearer + refresh) → fetch
 *
 * `auth` sits innermost of the three so its retry re-enters only the terminal
 * fetch: the mutation headers are already on the cloned request, and a retried
 * call cannot re-trigger the step-up probe for a 403 it already reported.
 */

/** Default proactive-refresh lead time: refresh once the access token is this close to `exp`. */
export const DEFAULT_REFRESH_SKEW_MS = 60_000;

/** Why the client considers the session gone (never fired for a NetworkError). */
export type AuthLostReason = "refresh_denied" | "refresh_reused" | "no_refresh_token";

export type AuthInterceptorOptions = {
  readonly storage: TokenStorage;
  /** Performs `POST /auth/refresh`; must reject with ApiError on denial, NetworkError offline. */
  readonly refresh: (refreshToken: string) => Promise<TokenPair>;
  /** Called once when the session is provably dead — the app clears its stores and routes to login. */
  readonly onAuthLost: (reason: AuthLostReason) => void;
  /** Lead time for the proactive refresh. */
  readonly skewMs?: number;
  /** Injectable clock for tests. */
  readonly now?: () => number;
};

export type AuthInterceptor = {
  readonly intercept: Interceptor;
  /** Clears the denial latch — call after a fresh sign-in stores a new pair. */
  reset(): void;
  /** Whether the latch is closed (further refresh attempts short-circuit). */
  isDenied(): boolean;
};

/**
 * Bearer injection + proactive and reactive refresh, with a denial latch.
 *
 * Three behaviors that are load-bearing and separately tested:
 *
 * 1. **Single flight.** Concurrent requests that all see an expiring token, or
 *    all get 401 at once, share ONE refresh promise. Without it a page with
 *    six parallel loads fires six refreshes, five of which present a
 *    rotated-out token and trip the S-08 reuse detector — logging the user out
 *    as a direct result of loading a page.
 * 2. **Denial latch.** Once the server has *refused* a refresh, every later
 *    attempt short-circuits until `reset()`. A dead session must cost one
 *    request, not one per click.
 * 3. **Network ≠ denial.** A `NetworkError` from the refresh call propagates
 *    untouched: the latch stays open, the stored tokens stay, and `onAuthLost`
 *    is NOT called. Going through a tunnel is not a logout.
 */
export function createAuthInterceptor(options: AuthInterceptorOptions): AuthInterceptor {
  const skewMs = options.skewMs ?? DEFAULT_REFRESH_SKEW_MS;
  const now = options.now ?? Date.now;
  let inflight: Promise<TokenPair | null> | null = null;
  let denied = false;

  /** Returns the new pair, or `null` when the session is provably gone. Throws on network failure. */
  const refreshOnce = (): Promise<TokenPair | null> => {
    if (denied) return Promise.resolve(null);
    if (inflight !== null) return inflight;

    const current = options.storage.read();
    if (current === null) {
      denied = true;
      options.onAuthLost("no_refresh_token");
      return Promise.resolve(null);
    }

    const run = async (): Promise<TokenPair | null> => {
      try {
        const next = await options.refresh(current.refreshToken);
        options.storage.write(next);
        return next;
      } catch (error) {
        if (error instanceof NetworkError) throw error;
        denied = true;
        options.storage.clear();
        options.onAuthLost(
          error instanceof ApiError && error.code === ERROR_CODES.refreshReused
            ? "refresh_reused"
            : "refresh_denied",
        );
        return null;
      } finally {
        inflight = null;
      }
    };

    inflight = run();
    return inflight;
  };

  const intercept: Interceptor = async (ctx, next) => {
    const meta = requestMeta(ctx);
    if (meta.skipAuth === true || meta.isRefresh === true) return next(ctx);

    let pair = options.storage.read();

    // Proactive: spend the round trip before the user's action, not during it.
    if (pair !== null && isAccessTokenExpiring(pair.accessToken, now(), skewMs)) {
      pair = (await refreshOnce()) ?? options.storage.read();
    }
    if (pair !== null) {
      ctx.request.headers.set("authorization", `Bearer ${pair.accessToken}`);
    }

    // Clone BEFORE the body is consumed so a retry has an intact request.
    const retryable = pair === null ? null : ctx.request.clone();
    const response = await next(ctx);
    if (response.status !== 401 || retryable === null) return response;

    // Reactive: one refresh, one retry. An anonymous 401 never reaches here.
    const refreshed = await refreshOnce();
    if (refreshed === null) return response;
    retryable.headers.set("authorization", `Bearer ${refreshed.accessToken}`);
    return next({ request: retryable, state: ctx.state });
  };

  return {
    intercept,
    reset(): void {
      denied = false;
    },
    isDenied(): boolean {
      return denied;
    },
  };
}

/**
 * The type the Fetch spec attaches to a string body on its own — never an
 * author's choice, so it does not count as "the caller picked a content type".
 */
const IMPLICIT_STRING_BODY_TYPE = "text/plain;charset=utf-8";

/**
 * S-12: every state-changing app-API request carries `X-Pub-Request: 1`, and a
 * body is always JSON. The header forces a CORS preflight; the server also
 * verifies `Origin`/`Sec-Fetch-Site` itself, so this is a layer, not the lock.
 *
 * Content-Type is set only when there IS a body — the server rejects a
 * non-JSON content type but accepts a bodiless mutation with none at all
 * (logout, revoke-all, DELETE), and sending one there is noise.
 *
 * The `text/plain;charset=UTF-8` case is deliberate, not defensive clutter: a
 * browser's `Request` constructor appends exactly that header to any string
 * body it was not given a type for, and `guard.rs` answers 415 to it. Treating
 * the implicit type as "unset" is what keeps a request built outside
 * `jsonBody` working in a browser; Bun does not add the header at all, so this
 * branch is only reachable in the environment that needs it.
 */
export const mutationHeadersInterceptor: Interceptor = async (ctx, next) => {
  const method = ctx.request.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
    ctx.request.headers.set("x-pub-request", "1");
    if (ctx.request.body !== null) {
      const declared = ctx.request.headers.get("content-type");
      const implicit =
        declared !== null &&
        declared.replaceAll(" ", "").toLowerCase() === IMPLICIT_STRING_BODY_TYPE;
      if (declared === null || implicit) {
        ctx.request.headers.set("content-type", "application/json");
      }
    }
  }
  return next(ctx);
};

/** What the step-up controller is handed when a call hits the S-06 gate. */
export type StepUpSignal = {
  /** The request that was refused, so the prompt can name the action if it wants to. */
  readonly method: string;
  readonly url: string;
};

/**
 * Surfaces the distinct `step_up_required` 403 (S-06.a) to a controller.
 *
 * The interceptor only *reports*; it never retries. The caller owns the retry
 * because only the caller knows whether the action is still wanted after the
 * user has typed a TOTP code (or cancelled).
 */
export function createStepUpInterceptor(notify: (signal: StepUpSignal) => void): Interceptor {
  return async (ctx, next) => {
    const response = await next(ctx);
    if (response.status !== 403) return response;
    if ((await peekErrorCode(response)) !== ERROR_CODES.stepUpRequired) return response;
    notify({ method: ctx.request.method.toUpperCase(), url: ctx.request.url });
    return response;
  };
}

/**
 * Reports throttling (429) to a listener before the error is thrown.
 *
 * Screens with a countdown (OTP resend) read `ApiError.retryAfter`; this exists
 * for the global toast, which must fire even when nobody catches the error.
 */
export function createRateLimitInterceptor(
  notify: (retryAfterSeconds: number | undefined) => void,
): Interceptor {
  return async (ctx, next) => {
    const response = await next(ctx);
    if (response.status === 429) notify(parseRetryAfter(response.headers.get("retry-after")));
    return response;
  };
}
