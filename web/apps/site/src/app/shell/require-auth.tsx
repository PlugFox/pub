import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Button } from "@pub/ui/button";
import { Skeleton } from "@pub/ui/skeleton";
import { Navigate, revalidate, useLocation } from "@solidjs/router";
import { ErrorBoundary, type JSX, Show, Suspense } from "solid-js";
import { isAuthenticated } from "../state/session-store";

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
 */

export type RequireAuthProps = { readonly children: JSX.Element };

export function RequireAuth(props: RequireAuthProps): JSX.Element {
  const location = useLocation();
  return (
    <Show
      when={isAuthenticated()}
      fallback={
        <Navigate
          href={`/login?return_to=${encodeURIComponent(`${location.pathname}${location.search}`)}`}
        />
      }
    >
      {props.children}
    </Show>
  );
}

/**
 * Suspense + error boundary for one screen's data.
 *
 * Every list screen loads through `createAsync`, so each needs both: a
 * skeleton while the request is in flight and a recoverable failure state when
 * it is refused. Reloading the document would drop the SPA's state, so the
 * retry re-runs the boundary instead.
 */
export function ScreenBoundary(props: { readonly children: JSX.Element }): JSX.Element {
  return (
    <ErrorBoundary
      fallback={(_error: unknown, reset: () => void) => (
        <div class="flex flex-col items-start gap-4">
          <Alert intent="danger">{t(app.genericError)}</Alert>
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
      )}
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
