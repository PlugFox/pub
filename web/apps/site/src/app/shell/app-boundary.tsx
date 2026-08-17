import { isNetworkError } from "@pub/api/errors";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Button } from "@pub/ui/button";
import { revalidate } from "@solidjs/router";
import { ErrorBoundary, type JSX } from "solid-js";

/*
 * The last-resort boundary (decision 40).
 *
 * `ScreenBoundary` wraps the router's children, which is every screen and
 * nothing else — so the chrome around them (the branding prime, the org
 * switcher, the user menu) threw into no boundary at all, and Solid's default
 * for an uncaught render error is an empty document. The one surface present on
 * every route had the worst failure mode in the app.
 *
 * IT SITS INSIDE THE ROUTER AND AROUND THE SHELL. Inside, because the fallback
 * uses `revalidate` and the router's context has to exist for that; around,
 * because a boundary rendered *by* the shell cannot catch the shell.
 *
 * THE FALLBACK DRAWS NO CHROME. The component that failed is the one that draws
 * the header and the navigation, so re-rendering it inside the fallback is how
 * a fallback throws in its own turn. Two actions with different guarantees:
 * retry drops the query cache and re-renders (which repairs a refused prime or
 * a 500 from one query), reload replaces the document (which repairs the rest).
 *
 * What it cannot catch is worth stating rather than implying: an error thrown
 * before the island mounts, or inside an event handler, is not a render error,
 * and Solid's boundary sees neither. Nested boundaries still win — a screen's
 * failure is handled by `ScreenBoundary`, and only what escapes arrives here.
 */

export function AppBoundary(props: { readonly children: JSX.Element }): JSX.Element {
  return (
    <ErrorBoundary
      fallback={(error: unknown, reset: () => void) => (
        <main class="mx-auto flex min-h-dvh w-full max-w-xl flex-col justify-center gap-6 px-6 py-12">
          <h1 class="text-2xl font-bold tracking-tight text-ink">{t(app.shellErrorTitle)}</h1>
          <Alert intent="danger">
            {isNetworkError(error) ? t(app.networkError) : t(app.genericError)}
          </Alert>
          <div class="flex flex-wrap gap-3">
            <Button
              intent="primary"
              onClick={() => {
                // The query cache holds the rejection, so dropping it has to
                // happen before the boundary re-renders its children.
                void revalidate(undefined, true).then(reset, reset);
              }}
            >
              {t(app.retry)}
            </Button>
            <Button intent="outline" onClick={() => window.location.reload()}>
              {t(app.shellErrorReload)}
            </Button>
          </div>
        </main>
      )}
    >
      {props.children}
    </ErrorBoundary>
  );
}
