import type { PackageSummaryDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { buttonVariants } from "@pub/ui/button";
import { EmptyState } from "@pub/ui/empty-state";
import { A, createAsync } from "@solidjs/router";
import { For, type JSX, Show } from "solid-js";
import { formatNumber } from "../format";
import { PackageCard } from "../package-card";
import { homeQuery } from "../state/instance-store";
import { isAuthenticated } from "../state/session-store";

/*
 * The landing dashboard.
 *
 * ONE request (`GET /api/v1/home`) carries instance identity, counters, and
 * both rails, so this screen has one loading state instead of four.
 *
 * The counters are SCOPED TO THE CALLER (decision 11): a member sees their
 * orgs' private packages counted, a visitor does not. That is why the copy
 * says "visible to you" rather than presenting them as instance totals — the
 * number genuinely differs per reader, and a dashboard that hid that would be
 * quietly lying to whoever has fewer memberships.
 *
 * The payload also carries the branding an administrator set at runtime
 * (decision 17), which the shared `homeQuery` publishes to `instance-store`.
 * The query lives there rather than here because the shell primes it on mount:
 * the header has to show the instance's name on every screen, not only to
 * readers who entered through this one.
 */

function Rail(props: {
  readonly title: string;
  readonly items: readonly PackageSummaryDto[];
  readonly emptyTitle: string;
}): JSX.Element {
  return (
    <section class="flex flex-col gap-4">
      <h2 class="text-xl font-semibold text-ink">{props.title}</h2>
      <Show when={props.items.length > 0} fallback={<EmptyState title={props.emptyTitle} />}>
        <ul class="grid gap-4 lg:grid-cols-2">
          <For each={props.items}>
            {(item) => (
              <li>
                <PackageCard item={item} />
              </li>
            )}
          </For>
        </ul>
      </Show>
    </section>
  );
}

function Counter(props: { readonly label: string; readonly value: number }): JSX.Element {
  return (
    <div class="flex flex-col gap-1 rounded-xl border border-line bg-surface p-6">
      <dt class="text-sm text-ink-muted">{props.label}</dt>
      <dd class="text-3xl font-bold tracking-tight text-ink">{formatNumber(props.value)}</dd>
    </div>
  );
}

export function HomeScreen(): JSX.Element {
  const home = createAsync(() => homeQuery());

  return (
    <div class="flex flex-col gap-10">
      <header class="flex flex-col gap-3">
        <h1 class="text-3xl font-bold tracking-tight text-ink">
          {home()?.instance.name ?? t(app.overviewTitle)}
        </h1>
        <Show
          when={home()?.instance.tagline}
          fallback={<p class="max-w-2xl text-ink-muted">{t(app.homeTaglineFallback)}</p>}
        >
          {(tagline) => <p class="max-w-2xl text-lg text-ink-muted">{tagline()}</p>}
        </Show>
        <div class="flex flex-wrap gap-3 pt-1">
          <A href="/search" class={buttonVariants({ intent: "primary", size: "md" })}>
            {t(app.homeBrowse)}
          </A>
          <Show when={!isAuthenticated()}>
            <A href="/login" class={buttonVariants({ intent: "outline", size: "md" })}>
              {t(app.loginTitle)}
            </A>
          </Show>
        </div>
      </header>

      <section class="flex flex-col gap-3">
        <h2 class="text-sm font-medium text-ink-muted">{t(app.homeCountersTitle)}</h2>
        <dl class="grid gap-4 sm:grid-cols-3">
          <Counter label={t(app.homeCounterPackages)} value={home()?.counters.packages ?? 0} />
          <Counter label={t(app.homeCounterVersions)} value={home()?.counters.versions ?? 0} />
          <Counter label={t(app.homeCounterOrgs)} value={home()?.counters.orgs ?? 0} />
        </dl>
        <p class="text-xs text-ink-muted">{t(app.homeCountersScoped)}</p>
      </section>

      <Rail
        title={t(app.homeRecentTitle)}
        items={home()?.recently_updated ?? []}
        emptyTitle={t(app.homeRailEmpty)}
      />
      <Rail
        title={t(app.homePopularTitle)}
        items={home()?.most_downloaded ?? []}
        emptyTitle={t(app.homeRailEmpty)}
      />
    </div>
  );
}
