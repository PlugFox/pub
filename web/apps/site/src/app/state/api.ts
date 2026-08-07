import { isStepUpRequired, NetworkError } from "@pub/api/errors";
import { createPubApi, loginTokenPair, type PubApi } from "@pub/api/pub-api";
import type { LoginDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { adoptLogin, clearSession, hydrateSession } from "./session-store";
import { promptStepUp, requestStepUp } from "./step-up-store";
import { pushToast } from "./toast-store";

/*
 * The single API instance for the island, with its callbacks wired into the
 * stores. This module is the only place that knows both halves, which keeps
 * `packages/api` framework-free and the stores free of HTTP.
 */

export const api: PubApi = createPubApi({
  onAuthLost: () => {
    // Reached only when the server REFUSED a refresh — a NetworkError never
    // gets here (see createAuthInterceptor). Being offline is not a logout.
    clearSession(api.storage);
    pushToast(t(app.sessionExpired), "warning");
  },
  onStepUpRequired: () => requestStepUp(),
  onRateLimited: (seconds) => {
    pushToast(t(app.rateLimited, { seconds: seconds ?? 60 }), "warning");
  },
});

hydrateSession(api.storage);

/** Adopts a completed login (tokens + profile) and clears the refresh denial latch. */
export function completeLogin(login: LoginDto): boolean {
  const pair = loginTokenPair(login);
  if (pair === null) return false;
  adoptLogin(login, pair, api.storage);
  api.resetAuth();
  return true;
}

/**
 * Ends the session: tells the server, then clears locally regardless.
 *
 * The local clear is unconditional on purpose — if the logout call fails the
 * user still expects to be signed out of this browser, and the session dies on
 * the server at the latest when the refresh token's idle timeout elapses.
 */
export async function signOut(): Promise<void> {
  try {
    await api.auth.logout();
  } catch {
    // Already-invalid session, or offline: local state is what matters here.
  }
  clearSession(api.storage);
  api.resetAuth();
}

/**
 * Runs `action`, and on the S-06 gate opens the step-up prompt and runs it once more.
 *
 * The retry is the CALLER's job (the interceptor cannot know whether the
 * action is still wanted), so every gated call is written as
 * `withStepUp(() => api.…)`. A cancelled prompt re-throws the original error,
 * which the screen renders as an ordinary failure.
 */
export async function withStepUp<T>(action: () => Promise<T>): Promise<T> {
  try {
    return await action();
  } catch (error) {
    if (!isStepUpRequired(error)) throw error;
    const satisfied = await promptStepUp();
    if (!satisfied) throw error;
    return action();
  }
}

/** Human-readable message for an arbitrary failure, used by the action toasts. */
export function describeError(error: unknown): string {
  return error instanceof NetworkError ? t(app.networkError) : t(app.genericError);
}
