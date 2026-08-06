import { t, tp } from "@pub/i18n";
import { common } from "@pub/i18n/generated/common";
import { A, Route, Router } from "@solidjs/router";
import type { JSX } from "solid-js";

/*
 * The single client:only SolidJS island (decision 14). Placeholder routes
 * only — feature folders (auth, orgs, packages, tokens, admin) mount here in
 * later roadmap steps, with data code written exclusively as
 * createAsync/query/action for the mechanical Solid 2.0 upgrade.
 */

function Dashboard(): JSX.Element {
  return (
    <main class="mx-auto w-full max-w-2xl px-6 py-16">
      <h1 class="text-2xl font-semibold text-ink">{t(common.appDashboard)}</h1>
      <p class="mt-2 text-ink-muted">{tp(common.packagesCount, 0)}</p>
      <A href="/about" class="mt-6 inline-block text-accent underline">
        {t(common.appAbout)}
      </A>
    </main>
  );
}

function About(): JSX.Element {
  return (
    <main class="mx-auto w-full max-w-2xl px-6 py-16">
      <h1 class="text-2xl font-semibold text-ink">{t(common.appAbout)}</h1>
      <p class="mt-2 text-ink-muted">{t(common.tagline)}</p>
      <A href="/" class="mt-6 inline-block text-accent underline">
        {t(common.appDashboard)}
      </A>
    </main>
  );
}

export function App(): JSX.Element {
  return (
    <Router base="/app">
      <Route path="/" component={Dashboard} />
      <Route path="/about" component={About} />
    </Router>
  );
}
