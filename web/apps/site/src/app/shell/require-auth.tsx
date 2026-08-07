import { isApiError, isNetworkError } from "@pub/api/errors";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Button, buttonVariants } from "@pub/ui/button";
import { EmptyState } from "@pub/ui/empty-state";
import { Skeleton } from "@pub/ui/skeleton";
import { A, Navigate, revalidate, useLocation } from "@solidjs/router";
import { ErrorBoundary, type JSX, Show, Suspense } from "solid-js";
import { isAuthenticated } from "../state/session-store";
import { toRouterPath } from "../urls";

/*
 * Route guard.
 *
 * The client-side check is a ROUTING convenience, never a security boundary:
 * every protected byte comes from an API call the server authorizes on its
 * own. All this does is send an unauthenticated visitor to sign-in instead of
 * rendering a screen that would only produce 401s — and remember where they
 * were going, so the sign-in lands them back there.
 *
 * `return_to` is a path, never a full URL, and it is re-validated with
 * `safeReturnTo` before use: an open redirect on a sign-in page is a phishing
 * primitive.
 *
 * It is also a ROUTER path, not a browser path: `location.pathname` carries
 * the `/app` base and `navigate()` re-adds it, so the base is stripped once
 * here — otherwise signing in from `/app/tokens` lands on `/app/app/tokens`.
 */

export type RequireAuthProps = { readonly children: JSX.Element };

export function RequireAuth(props: RequireAuthProps): JSX.Element {
  const location = useLocation();
  const returnTo = (): string =>
    encodeURIComponent(`${toRouterPath(location.pathname)}${location.search}`);
  return (
    <Show when={isAuthenticated()} fallback={<Navigate href={`/login?return_to=${returnTo()}`} />}>
      {props.children}
    </Show>
  );
}

/**
 * Suspense + error boundary for one screen's data.
 *
 * Every screen loads through `createAsync`, so each needs both: a skeleton
 * while the request is in flight and a recoverable failure state when it is
 * refused. Reloading the document would drop the SPA's state, so the retry
 * re-runs the boundary instead.
 *
 * TWO statuses get their own branch, and neither offers a retry, because for
 * both of them retrying is guaranteed to fail:
 *
 *   - **404** means "unknown name, or one you may not read" under decision 05.
 *     The server refuses to distinguish them, and so does this; offering a
 *     "request access" path would tell a prober that the name exists.
 *   - **403** means the resource is real and the caller's role is not enough
 *     (decision 19 — org slugs are not secret, so the server says so out loud).
 *     Answering that with "Something went wrong. Try again." misfiles a
 *     permission boundary as a glitch and hands the user a button that reruns
 *     the same denial. This is the state an ordinary member reaches by opening
 *     an admin-only screen, so it is a normal outcome, not a failure.
 *
 * Everything else — 5xx, an unparseable body, a dropped connection — is the
 * generic, retryable branch.
 */
export function ScreenBoundary(props: { readonly children: JSX.Element }): JSX.Element {
  return (
    <ErrorBoundary
      fallback={(error: unknown, reset: () => void) => {
        if (isApiError(error) && error.status === 404) {
          return (
            <div class="flex flex-col items-start gap-4">
              <EmptyState
                class="w-full"
                title={t(app.resourceNotFoundTitle)}
                description={t(app.resourceNotFoundBody)}
              >
                <A href="/search" class={buttonVariants({ intent: "outline", size: "sm" })}>
                  {t(app.homeBrowse)}
                </A>
              </EmptyState>
            </div>
          );
        }
        if (isApiError(error) && error.status === 403) {
          return (
            <div class="flex flex-col items-start gap-4">
              <EmptyState
                class="w-full"
                title={t(app.resourceForbiddenTitle)}
                description={t(app.resourceForbiddenBody)}
              >
                <A href="/" class={buttonVariants({ intent: "outline", size: "sm" })}>
                  {t(app.navOverview)}
                </A>
              </EmptyState>
            </div>
          );
        }
        return (
          <div class="flex flex-col items-start gap-4">
            <Alert intent="danger">
              {isNetworkError(error) ? t(app.networkError) : t(app.genericError)}
            </Alert>
            <Button
              intent="outline"
              onClick={() => {
                // The query cache holds the rejection, so dropping it has to
                // happen before the boundary re-renders its children.
                void revalidate(undefined, true).then(reset, reset);
              }}
            >
              {t(app.retry)}
            </Button>
          </div>
        );
      }}
    >
      <Suspense
        fallback={
          <div class="flex flex-col gap-3">
            <Skeleton class="h-8 w-48" />
            <Skeleton class="h-4 w-72" />
            <Skeleton class="h-40 w-full" />
          </div>
        }
      >
        {props.children}
      </Suspense>
    </ErrorBoundary>
  );
}
