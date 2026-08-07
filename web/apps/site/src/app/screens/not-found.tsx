import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { common } from "@pub/i18n/generated/common";
import { buttonVariants } from "@pub/ui/button";
import { A } from "@solidjs/router";
import type { JSX } from "solid-js";

/**
 * 404 inside the island — an unknown `/app/*` path the router could not match.
 *
 * Distinct from the static site's 404: the app shell stays, so the reader
 * keeps their navigation and their session instead of being dropped onto a
 * marketing page.
 */
export function AppNotFoundScreen(): JSX.Element {
  return (
    <section class="flex flex-col items-start gap-4 py-6">
      <p class="font-mono text-5xl font-bold text-ink-muted">404</p>
      <h1 class="text-2xl font-semibold text-ink">{t(app.notFoundTitle)}</h1>
      <p class="max-w-md text-ink-muted">{t(app.notFoundBody)}</p>
      <div class="flex flex-wrap gap-3">
        <A href="/" class={buttonVariants({ intent: "primary", size: "md" })}>
          {t(app.backToOverview)}
        </A>
        <a href="/" class={buttonVariants({ intent: "ghost", size: "md" })}>
          {t(common.navHome)}
        </a>
      </div>
    </section>
  );
}
