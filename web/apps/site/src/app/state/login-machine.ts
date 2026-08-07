import { ApiError, ERROR_CODES, NetworkError } from "@pub/api/errors";
import type { LoginDto } from "@pub/api/types";

/*
 * The sign-in state machine, as a pure reducer.
 *
 * Sign-in is the screen with the most branches in the product (email → code →
 * optional second factor, with resend cool-downs, uniform failures, and an
 * OIDC entry point that can land on the second factor directly). Keeping the
 * transitions in a pure function means every branch is testable without a DOM,
 * and the component becomes "render the state, dispatch the event".
 *
 * Invariants the reducer enforces, all asserted in the tests:
 *   - an event that does not belong to the current step is ignored, never a
 *     crash and never a half-applied state;
 *   - `busy` is cleared by exactly one thing: an outcome (success or failure);
 *   - a failure never advances a step, and a step change always clears the
 *     previous error, so a stale "invalid code" can never sit under a new step.
 */

/** Uniform failure classes the sign-in screen renders (S-04: no "why"). */
export type LoginErrorKind =
  | "emailRequired"
  | "invalidCode"
  | "rateLimited"
  | "network"
  | "generic";

export type LoginError = {
  readonly kind: LoginErrorKind;
  /** Seconds from `Retry-After`, for the countdown (S-24). */
  readonly retryAfter?: number;
};

export type MfaMode = "totp" | "recovery";

export type LoginState =
  | {
      readonly step: "email";
      readonly email: string;
      readonly busy: boolean;
      readonly error: LoginError | null;
    }
  | {
      readonly step: "code";
      readonly email: string;
      readonly pendingId: string;
      /** Epoch ms before which resending is refused; honours `Retry-After`. */
      readonly resendAvailableAt: number;
      readonly busy: boolean;
      readonly error: LoginError | null;
    }
  | {
      readonly step: "mfa";
      readonly mfaToken: string;
      readonly mode: MfaMode;
      readonly busy: boolean;
      readonly error: LoginError | null;
    }
  | { readonly step: "done"; readonly login: LoginDto };

export type LoginEvent =
  | { readonly type: "editEmail"; readonly email: string }
  | { readonly type: "submit" }
  | {
      readonly type: "codeSent";
      readonly email: string;
      readonly pendingId: string;
      readonly resendAvailableAt: number;
    }
  | { readonly type: "loginResolved"; readonly login: LoginDto }
  | { readonly type: "failed"; readonly error: LoginError }
  | { readonly type: "changeEmail" }
  | { readonly type: "setMfaMode"; readonly mode: MfaMode };

/** Default resend cool-down when the server sends no `Retry-After` (S-03: ≥60 s). */
export const RESEND_COOLDOWN_SECONDS = 60;

export function initialLoginState(email = ""): LoginState {
  return { step: "email", email, busy: false, error: null };
}

export function loginReducer(state: LoginState, event: LoginEvent): LoginState {
  switch (event.type) {
    case "editEmail":
      // Typing clears the previous failure: the user is already fixing it.
      return state.step === "email" ? { ...state, email: event.email, error: null } : state;

    case "submit":
      return state.step === "done" || state.busy ? state : { ...state, busy: true, error: null };

    case "codeSent":
      // Reachable from "email" (first request) and from "code" (resend).
      if (state.step !== "email" && state.step !== "code") return state;
      return {
        step: "code",
        email: event.email,
        pendingId: event.pendingId,
        resendAvailableAt: event.resendAvailableAt,
        busy: false,
        error: null,
      };

    case "loginResolved": {
      if (state.step === "done") return state;
      const mfaToken = event.login.mfa_token;
      if (event.login.mfa_required && mfaToken !== undefined) {
        // Keep the mode across an MFA→MFA resolution (a recovery-code retry).
        return {
          step: "mfa",
          mfaToken,
          mode: state.step === "mfa" ? state.mode : "totp",
          busy: false,
          error: null,
        };
      }
      return { step: "done", login: event.login };
    }

    case "failed":
      return state.step === "done" ? state : { ...state, busy: false, error: event.error };

    case "changeEmail":
      return state.step === "code" ? initialLoginState(state.email) : state;

    case "setMfaMode":
      return state.step === "mfa" ? { ...state, mode: event.mode, error: null } : state;

    default:
      return state;
  }
}

/**
 * Maps a thrown error onto the uniform classes the screen renders.
 *
 * `invalid_code` and a plain 401 collapse into ONE message: telling the user
 * "wrong code" versus "unknown account" is the enumeration oracle S-04 exists
 * to prevent. A NetworkError is kept separate because it is actionable and,
 * critically, must not read as a rejection.
 */
export function classifyLoginError(error: unknown): LoginError {
  if (error instanceof NetworkError) return { kind: "network" };
  if (error instanceof ApiError) {
    if (error.status === 429 || error.code === ERROR_CODES.rateLimited) {
      return { kind: "rateLimited", retryAfter: error.retryAfter };
    }
    if (error.code === ERROR_CODES.invalidCode || error.status === 401) {
      return { kind: "invalidCode" };
    }
  }
  return { kind: "generic" };
}

/** Epoch ms at which a resend becomes available, honouring `Retry-After`. */
export function resendAvailableAt(retryAfterSeconds: number | undefined, now = Date.now()): number {
  const seconds =
    retryAfterSeconds === undefined || retryAfterSeconds <= 0
      ? RESEND_COOLDOWN_SECONDS
      : retryAfterSeconds;
  return now + seconds * 1000;
}
