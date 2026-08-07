import { type AuthApi, createAuthApi } from "./auth";
import { type ApiClient, createClient, type FetchLike } from "./client";
import { ApiError } from "./errors";
import {
  type AuthLostReason,
  createAuthInterceptor,
  createRateLimitInterceptor,
  createStepUpInterceptor,
  mutationHeadersInterceptor,
  type StepUpSignal,
} from "./interceptors";
import { createOrgsApi, type OrgsApi } from "./orgs";
import { createSessionsApi, type SessionsApi } from "./sessions";
import { createTokenStorage, type TokenPair, type TokenStorage } from "./storage";
import { createTokensApi, type TokensApi } from "./tokens";
import type { LoginDto } from "./types";

/*
 * Assembles the whole client: storage, interceptor chain, and one typed module
 * per API area. The app creates exactly one of these at island start-up.
 *
 * The refresh call deliberately runs on a SEPARATE bare client carrying only
 * the mutation headers. Routing it through the auth interceptor would be a
 * cycle (refresh needs a client that needs refresh) and, worse, would let a
 * 401 on the refresh endpoint trigger another refresh.
 */

export const DEFAULT_BASE_URL = "/api/v1";

export type PubApiOptions = {
  /** API prefix. Same-origin `/api/v1` in the app; absolute in tests. */
  readonly baseUrl?: string;
  readonly fetchImpl?: FetchLike;
  /** Defaults to localStorage-backed storage (`pub_access` / `pub_refresh`). */
  readonly storage?: TokenStorage;
  /** The session is provably dead — clear stores, route to login. Never fires on a network error. */
  readonly onAuthLost?: (reason: AuthLostReason) => void;
  /** A call hit the S-06 gate; open the step-up prompt. */
  readonly onStepUpRequired?: (signal: StepUpSignal) => void;
  /** A call was throttled (S-24); `seconds` comes from `Retry-After`. */
  readonly onRateLimited?: (seconds: number | undefined) => void;
  readonly skewMs?: number;
  readonly now?: () => number;
};

export type PubApi = {
  readonly client: ApiClient;
  readonly storage: TokenStorage;
  readonly auth: AuthApi;
  readonly sessions: SessionsApi;
  readonly tokens: TokensApi;
  readonly orgs: OrgsApi;
  /** Clears the refresh denial latch after a fresh sign-in. */
  resetAuth(): void;
  /** Whether the latch is closed (a refresh has been refused). */
  isAuthDenied(): boolean;
};

/**
 * Extracts the token pair from a completed login.
 *
 * `null` for the `mfa_required` shape and for any response missing a half —
 * a half-stored pair is worse than none (the interceptor would refresh with
 * `undefined` on the very first call).
 */
export function loginTokenPair(login: LoginDto): TokenPair | null {
  if (login.mfa_required) return null;
  const { access_token: accessToken, refresh_token: refreshToken } = login;
  if (accessToken === undefined || refreshToken === undefined) return null;
  return { accessToken, refreshToken };
}

export function createPubApi(options: PubApiOptions = {}): PubApi {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const storage = options.storage ?? createTokenStorage();

  const refreshApi = createAuthApi(
    createClient({
      baseUrl,
      fetchImpl: options.fetchImpl,
      interceptors: [mutationHeadersInterceptor],
    }),
  );

  const authInterceptor = createAuthInterceptor({
    storage,
    now: options.now,
    skewMs: options.skewMs,
    onAuthLost: options.onAuthLost ?? ((): void => {}),
    refresh: async (refreshToken) => {
      const login = await refreshApi.refresh(refreshToken);
      const pair = loginTokenPair(login);
      if (pair === null) {
        // A refresh that answers `mfa_required` (or a half pair) is not a
        // usable session; treat it as a denial rather than storing junk.
        throw new ApiError("unauthorized", "refresh did not return a token pair", 401);
      }
      return pair;
    },
  });

  const interceptors = [
    mutationHeadersInterceptor,
    ...(options.onRateLimited === undefined
      ? []
      : [createRateLimitInterceptor(options.onRateLimited)]),
    ...(options.onStepUpRequired === undefined
      ? []
      : [createStepUpInterceptor(options.onStepUpRequired)]),
    authInterceptor.intercept,
  ];

  const client = createClient({ baseUrl, fetchImpl: options.fetchImpl, interceptors });

  return {
    client,
    storage,
    auth: createAuthApi(client),
    sessions: createSessionsApi(client),
    tokens: createTokensApi(client),
    orgs: createOrgsApi(client),
    resetAuth: authInterceptor.reset,
    isAuthDenied: authInterceptor.isDenied,
  };
}
