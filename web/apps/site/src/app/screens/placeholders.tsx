import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { common } from "@pub/i18n/generated/common";
import { Badge } from "@pub/ui/badge";
import { buttonVariants } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { A, useSearchParams } from "@solidjs/router";
import type { JSX } from "solid-js";
import { Show } from "solid-js";
import { currentUser } from "../state/session-store";

/*
 * Honest placeholders for the areas whose endpoints are still being built
 * (packages, search, notifications, admin).
 *
 * They render a "coming soon" card and NOTHING else — no sample rows, no
 * seeded charts, no greyed-out fake tables. A screen that shows plausible data
 * it did not fetch trains the reader to distrust every other screen, and it
 * hides the moment the real endpoint starts returning something different.
 */

type ComingSoonProps = {
  readonly title: string;
  readonly body: string;
  readonly children?: JSX.Element;
};

function ComingSoon(props: ComingSoonProps): JSX.Element {
  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-wrap items-center gap-3">
        <h1 class="text-3xl font-bold tracking-tight text-ink">{props.title}</h1>
        <Badge variant="warning">{t(app.comingSoon)}</Badge>
      </header>
      <Card>
        <CardContent class="flex flex-col gap-4 pt-6">
          <p class="max-w-2xl text-sm leading-relaxed text-ink-muted">{props.body}</p>
          {props.children}
        </CardContent>
      </Card>
    </section>
  );
}

export function OverviewScreen(): JSX.Element {
  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-col gap-2">
        <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.overviewTitle)}</h1>
        <Show when={currentUser()}>
          {(user) => (
            <p class="text-ink-muted">
              {t(app.overviewSignedInAs, {
                name: user().display_name === "" ? (user().email ?? "") : user().display_name,
              })}
            </p>
          )}
        </Show>
      </header>
      <Card>
        <CardHeader>
          <Badge variant="warning" class="self-start">
            {t(app.comingSoon)}
          </Badge>
        </CardHeader>
        <CardContent>
          <p class="max-w-2xl text-sm leading-relaxed text-ink-muted">{t(app.overviewTodo)}</p>
        </CardContent>
      </Card>
    </section>
  );
}

export function PackagesScreen(): JSX.Element {
  return <ComingSoon title={t(app.navPackages)} body={t(app.placeholderPackages)} />;
}

export function SearchScreen(): JSX.Element {
  const [params] = useSearchParams();
  const queryText = (): string => (typeof params.q === "string" ? params.q : "");
  return (
    <ComingSoon title={t(app.navSearch)} body={t(app.placeholderSearch)}>
      <Show when={queryText() !== ""}>
        <p class="text-sm text-ink">{t(app.placeholderSearchQuery, { query: queryText() })}</p>
      </Show>
    </ComingSoon>
  );
}

export function NotificationsScreen(): JSX.Element {
  return <ComingSoon title={t(app.navNotifications)} body={t(app.placeholderNotifications)} />;
}

export function AdminScreen(): JSX.Element {
  return <ComingSoon title={t(app.navAdmin)} body={t(app.placeholderAdmin)} />;
}

/** 404 inside the island — an unknown `/app/*` path the router could not match. */
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
