import { Route, Router } from "@solidjs/router";
import { type Component, type JSX, lazy } from "solid-js";
import { AppShell } from "./shell/app-shell";
import { RequireAuth, ScreenBoundary } from "./shell/require-auth";

/*
 * The single client:only SolidJS island (decision 14), routed by
 * @solidjs/router in browser mode with `/app` as the base.
 *
 * ROUTE-LEVEL CODE SPLITTING. Every screen is a `lazy()` entry, so the initial
 * island payload is the shell, the router, and the auth stores — not the admin
 * settings form and the audit viewer, which most sessions never open. Solid's
 * `lazy` wants a module with a `default`, and the screens export named
 * symbols, so each entry adapts the namespace rather than the codebase
 * growing default exports (docs/rules/web.md allows them for lazy entries;
 * adapting here keeps every screen consistently named).
 *
 * THREE ROUTE CLASSES, and the middle one is the interesting one:
 *
 *   - **public credentials**: sign-in and the OIDC landing. They must render
 *     for a visitor with no credential.
 *   - **public registry**: home, search, package pages, org profiles.
 *     Anonymous read is the default (decision 05), and these are exactly the
 *     endpoints that honour it — a public instance is a showcase, and forcing
 *     a sign-in in front of a page the API serves anonymously would be the
 *     frontend inventing a policy the backend does not have. Member-only
 *     affordances inside them (the package Manage tab) are gated on the role
 *     the API reports, not on the route.
 *   - **guarded**: everything that is about the CALLER — their orgs, tokens,
 *     sessions, notifications, account — plus administration. The guard is
 *     routing, not security: the server authorizes every byte.
 *
 * The catch-all is LAST and inside the shell, so an unknown `/app/*` path
 * lands on the app's own 404 with its navigation intact.
 */

/** Wraps a lazily-imported named screen as the default export `lazy` expects. */
function screen<K extends string>(load: () => Promise<Record<K, Component>>, name: K): Component {
  return lazy(async () => ({ default: (await load())[name] }));
}

const LoginScreen = screen(() => import("./screens/login"), "LoginScreen");
const OidcCallbackScreen = screen(() => import("./screens/oidc-callback"), "OidcCallbackScreen");
const HomeScreen = screen(() => import("./screens/home"), "HomeScreen");
const SearchScreen = screen(() => import("./screens/search"), "SearchScreen");
const PackageDetailScreen = screen(() => import("./screens/package"), "PackageDetailScreen");
const VersionDetailScreen = screen(() => import("./screens/package"), "VersionDetailScreen");
const OrgsScreen = screen(() => import("./screens/orgs"), "OrgsScreen");
const OrgDetailScreen = screen(() => import("./screens/org-detail"), "OrgDetailScreen");
const OrgManageScreen = screen(() => import("./screens/org-manage"), "OrgManageScreen");
const TokensScreen = screen(() => import("./screens/tokens"), "TokensScreen");
const SessionsScreen = screen(() => import("./screens/sessions"), "SessionsScreen");
const NotificationsScreen = screen(() => import("./screens/notifications"), "NotificationsScreen");
const NotificationPreferencesScreen = screen(
  () => import("./screens/notifications"),
  "NotificationPreferencesScreen",
);
const AccountScreen = screen(() => import("./screens/account"), "AccountScreen");
const AdminScreen = screen(() => import("./screens/admin"), "AdminScreen");
const AppNotFoundScreen = screen(() => import("./screens/not-found"), "AppNotFoundScreen");

/** Public screen: no credential required, but still its own loading/error boundary. */
function Open(props: { readonly children: JSX.Element }): JSX.Element {
  return <ScreenBoundary>{props.children}</ScreenBoundary>;
}

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
          <Open>
            <HomeScreen />
          </Open>
        )}
      />
      <Route
        path="/search"
        component={() => (
          <Open>
            <SearchScreen />
          </Open>
        )}
      />
      <Route
        path="/packages/:name"
        component={() => (
          <Open>
            <PackageDetailScreen />
          </Open>
        )}
      />
      <Route
        path="/packages/:name/versions/:version"
        component={() => (
          <Open>
            <VersionDetailScreen />
          </Open>
        )}
      />
      <Route
        path="/packages/:name/:tab"
        component={() => (
          <Open>
            <PackageDetailScreen />
          </Open>
        )}
      />
      <Route
        path="/orgs/:slug"
        component={() => (
          <Open>
            <OrgDetailScreen />
          </Open>
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
        path="/orgs/:slug/manage"
        component={() => (
          <Guarded>
            <OrgManageScreen />
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
        path="/notifications/preferences"
        component={() => (
          <Guarded>
            <NotificationPreferencesScreen />
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
      <Route
        path="/admin/:tab"
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
