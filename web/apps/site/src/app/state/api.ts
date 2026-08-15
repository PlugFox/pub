import { isStepUpRequired } from "@pub/api/errors";
import { createPubApi, loginTokenPair, type PubApi } from "@pub/api/pub-api";
import type { LoginDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { setUnreadCount } from "./notification-store";
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
 * Reads the authoritative unread count into the badge store.
 *
 * `limit: 1` because only the `unread` total is wanted — the field is the
 * whole inbox's count, not this page's, so the cheapest page answers it. The
 * failure is swallowed on purpose: a badge is an ornament, and a signed-in
 * reader must not meet an error toast because a count could not be fetched.
 */
export async function seedUnreadCount(): Promise<void> {
  try {
    const feed = await api.notifications.list({ limit: 1 });
    setUnreadCount(feed.unread);
  } catch {
    // Offline, or a session that just died: the badge stays at its last value.
  }
}

/**
 * Rotates the access token so a membership the caller just gained is in its
 * `orgs` claim.
 *
 * A membership GRANT deliberately leaves sessions alone (S-09.a): the token
 * that predates it carries no claim for the org and therefore fails closed, so
 * revoking would cost the user every device for no security gain. The cost is
 * that the grant is invisible to every claim-derived surface — the org's
 * private packages, its member list, the SSE audience — until the next
 * rotation. This is that rotation, and it belongs next to the actions that
 * create the situation: creating an organization, accepting an invitation.
 *
 * Best-effort by construction. A refused refresh has already signalled the
 * session loss through `onAuthLost`, and being offline must not turn "you
 * joined an org" into an error the user has to act on — the claim lands on the
 * next automatic refresh either way.
 */
export async function renewMemberships(): Promise<void> {
  try {
    await api.renewAuth();
  } catch {
    // Offline: the membership is durable on the server; the claim catches up.
  }
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

/*
 * `describeError` lives in `../error-message` (D18): the mapping is a pure
 * function of the error, it has real behaviour worth testing without a DOM,
 * and it must not be able to reach the stores. Re-exported here because every
 * screen already imports it from this module, and moving that import would
 * touch a dozen files to say nothing new.
 */
export { describeError } from "../error-message";
