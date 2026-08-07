/*
 * The two failure classes are deliberately distinct (docs/rules/web.md):
 * an ApiError means the server received the request and said no; a
 * NetworkError means the request never completed. Interceptors and stores
 * must discriminate — a network failure must never log the user out.
 */

/** Error codes the client reacts to structurally (the rest are display-only). */
export const ERROR_CODES = {
  /** OTP/TOTP/recovery code rejected — surfaced as one uniform message (S-04). */
  invalidCode: "invalid_code",
  /** 429; `retryAfter` carries the parsed `Retry-After` seconds (S-24). */
  rateLimited: "rate_limited",
  /** 403; the session is no longer step-up-fresh — prompt, then retry (S-06). */
  stepUpRequired: "step_up_required",
  /** 401 on refresh; a rotated-out token was replayed — the family is dead (S-08). */
  refreshReused: "refresh_reused",
  /** 401; absent or invalid credentials. */
  unauthorized: "unauthorized",
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

export type ApiErrorOptions = {
  /** Seconds to wait before retrying, parsed from `Retry-After` (429/503). */
  readonly retryAfter?: number;
};

/** The server answered with an error envelope: `{ status: "error", error: { code, message } }`. */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly retryAfter: number | undefined;

  constructor(code: string, message: string, status: number, options?: ApiErrorOptions) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.retryAfter = options?.retryAfter;
  }
}

/** Transport-level failure (offline, DNS, aborted, CORS). Not a denial. */
export class NetworkError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "NetworkError";
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

export function isNetworkError(error: unknown): error is NetworkError {
  return error instanceof NetworkError;
}

/** True for the distinct 403 the UI answers with a step-up prompt (S-06.a). */
export function isStepUpRequired(error: unknown): boolean {
  return isApiError(error) && error.code === ERROR_CODES.stepUpRequired;
}

/** True for the throttled answer; `error.retryAfter` holds the cool-down in seconds. */
export function isRateLimited(error: unknown): boolean {
  return isApiError(error) && (error.code === ERROR_CODES.rateLimited || error.status === 429);
}

/**
 * Parses a `Retry-After` value into whole seconds from now.
 *
 * RFC 9110 allows both delta-seconds and an HTTP-date; the server sends
 * delta-seconds (S-24) but a proxy may rewrite it. Anything unparsable, empty,
 * or in the past yields `undefined` / `0` rather than `NaN` — the countdown UI
 * must never render "NaN s".
 */
export function parseRetryAfter(
  value: string | null | undefined,
  now = Date.now(),
): number | undefined {
  if (value === null || value === undefined) return undefined;
  const trimmed = value.trim();
  if (trimmed === "") return undefined;
  if (/^\d+$/.test(trimmed)) return Number.parseInt(trimmed, 10);
  const date = Date.parse(trimmed);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, Math.round((date - now) / 1000));
}
