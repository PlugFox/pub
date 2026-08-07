import { Route, Router } from "@solidjs/router";
import type { JSX } from "solid-js";
import { AccountScreen } from "./screens/account";
import { LoginScreen } from "./screens/login";
import { OidcCallbackScreen } from "./screens/oidc-callback";
import { OrgDetailScreen, OrgsScreen } from "./screens/orgs";
import {
  AdminScreen,
  AppNotFoundScreen,
  NotificationsScreen,
  OverviewScreen,
  PackagesScreen,
  SearchScreen,
} from "./screens/placeholders";
import { SessionsScreen } from "./screens/sessions";
import { TokensScreen } from "./screens/tokens";
import { AppShell } from "./shell/app-shell";
import { RequireAuth, ScreenBoundary } from "./shell/require-auth";

/*
 * The single client:only SolidJS island (decision 14), routed by
 * @solidjs/router in browser mode with `/app` as the base.
 *
 * Two route classes:
 *   - public: sign-in and the OIDC redirect landing. They must render for a
 *     visitor with no credential, so they sit outside the guard.
 *   - guarded: everything else, wrapped in `RequireAuth` (routing, not
 *     security — the server authorizes every byte) and in a boundary that
 *     owns the screen's loading and failure states.
 *
 * The catch-all is LAST and inside the shell, so an unknown `/app/*` path
 * lands on the app's own 404 with its navigation intact rather than on the
 * static site's 404.
 */

function Guarded(props: { readonly children: JSX.Element }): JSX.Element {
  return (
    <RequireAuth>
      <ScreenBoundary>{props.children}</ScreenBoundary>
    </RequireAuth>
  );
}

export function App(): JSX.Element {
  return (
    <Router base="/app" root={(props) => <AppShell>{props.children}</AppShell>}>
      <Route path="/login" component={LoginScreen} />
      <Route path="/auth/callback/:provider" component={OidcCallbackScreen} />

      <Route
        path="/"
        component={() => (
          <Guarded>
            <OverviewScreen />
          </Guarded>
        )}
      />
      <Route
        path="/packages"
        component={() => (
          <Guarded>
            <PackagesScreen />
          </Guarded>
        )}
      />
      <Route
        path="/search"
        component={() => (
          <Guarded>
            <SearchScreen />
          </Guarded>
        )}
      />
      <Route
        path="/orgs"
        component={() => (
          <Guarded>
            <OrgsScreen />
          </Guarded>
        )}
      />
      <Route
        path="/orgs/:slug"
        component={() => (
          <Guarded>
            <OrgDetailScreen />
          </Guarded>
        )}
      />
      <Route
        path="/tokens"
        component={() => (
          <Guarded>
            <TokensScreen />
          </Guarded>
        )}
      />
      <Route
        path="/sessions"
        component={() => (
          <Guarded>
            <SessionsScreen />
          </Guarded>
        )}
      />
      <Route
        path="/notifications"
        component={() => (
          <Guarded>
            <NotificationsScreen />
          </Guarded>
        )}
      />
      <Route
        path="/account"
        component={() => (
          <Guarded>
            <AccountScreen />
          </Guarded>
        )}
      />
      <Route
        path="/admin"
        component={() => (
          <Guarded>
            <AdminScreen />
          </Guarded>
        )}
      />

      <Route path="*" component={AppNotFoundScreen} />
    </Router>
  );
}
