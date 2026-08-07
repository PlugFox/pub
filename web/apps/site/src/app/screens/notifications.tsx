import type { NotificationDto, NotificationPreferenceDto } from "@pub/api/types";
import { NOTIFICATION_CATEGORIES } from "@pub/api/types";
import { t, tp } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button, buttonVariants } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { cn } from "@pub/ui/cn";
import { EmptyState } from "@pub/ui/empty-state";
import { A, createAsync, query, revalidate, useSearchParams } from "@solidjs/router";
import { createEffect, createSignal, For, type JSX, Show } from "solid-js";
import { formatRelative } from "../format";
import { api, describeError } from "../state/api";
import { setUnreadCount } from "../state/notification-store";
import { streamStatus } from "../state/sse";
import { pushToast } from "../state/toast-store";

/*
 * The notification center (decision 20).
 *
 * Feed semantics worth stating where they are rendered:
 *
 *   - `unread` in every response is the TOTAL, not the count on this page, and
 *     it is what the header badge shows. Both mutations answer with the
 *     recomputed value, so the badge updates without a second request — the
 *     store is written from the response, never guessed.
 *   - Rows carry the ORIGINATING EVENT verbatim in `payload`, plus a
 *     server-rendered one-line `title`. The title is shown; the payload is
 *     used only to build a link to the package or org the event named, because
 *     "your package was published" with nowhere to go is a dead end.
 *   - `?unread=1` narrows the feed. It is URL state so "show me what I missed"
 *     is a link, and so the filter survives the reload after marking all read.
 *
 * Live updates arrive over SSE (`state/sse.ts`) and bump the badge; the feed
 * itself is only revalidated on an explicit action. A list that reorders under
 * the reader's cursor while they are reading it is worse than a stale one.
 */

const feedQuery = query(
  (unread: boolean) => api.notifications.list({ unread, limit: 30 }),
  "notifications",
);
const preferencesQuery = query(() => api.notifications.preferences(), "notification-prefs");

const CATEGORY_LABELS: Record<string, { readonly id: string; readonly en: string }> = {
  package: app.notifCategoryPackage,
  org: app.notifCategoryOrg,
  security: app.notifCategorySecurity,
};

/** The in-app destination an event points at, or `null` when it names nothing. */
function targetPath(notification: NotificationDto): string | null {
  const payload = notification.payload as Record<string, unknown>;
  const name = payload.name;
  if (typeof name === "string" && name !== "" && notification.category === "package") {
    return `/packages/${encodeURIComponent(name)}`;
  }
  return null;
}

function categoryVariant(category: string): "accent" | "warning" | "neutral" {
  if (category === "security") return "warning";
  if (category === "org") return "accent";
  return "neutral";
}

function Feed(props: { readonly unread: boolean }): JSX.Element {
  const feed = createAsync(() => feedQuery(props.unread));
  const [busy, setBusy] = createSignal(false);
  const rows = (): readonly NotificationDto[] => feed()?.items ?? [];

  // The feed's `unread` is authoritative; adopting it here keeps the header
  // badge honest even if the stream missed a frame.
  createEffect(() => {
    const count = feed()?.unread;
    if (count !== undefined) setUnreadCount(count);
  });

  const mark = async (ids: readonly string[] | "all"): Promise<void> => {
    if (busy()) return;
    setBusy(true);
    try {
      const result =
        ids === "all"
          ? await api.notifications.markAllRead()
          : await api.notifications.markRead(ids);
      setUnreadCount(result.unread);
      await revalidate("notifications");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="flex flex-col gap-4">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <p class="text-sm text-ink-muted">{tp(app.notifUnreadCount, feed()?.unread ?? 0)}</p>
        <Button
          intent="outline"
          size="sm"
          disabled={busy() || (feed()?.unread ?? 0) === 0}
          onClick={() => void mark("all")}
        >
          {t(app.notifMarkAllRead)}
        </Button>
      </div>

      <Show
        when={rows().length > 0}
        fallback={
          <EmptyState
            title={props.unread ? t(app.notifEmptyUnread) : t(app.notifEmpty)}
            description={t(app.notifEmptyBody)}
          />
        }
      >
        <ul class="flex flex-col gap-3">
          <For each={rows()}>
            {(notification) => {
              const unread = (): boolean =>
                notification.read_at === null || notification.read_at === undefined;
              const href = targetPath(notification);
              return (
                <li
                  class={cn(
                    "flex flex-wrap items-start gap-3 rounded-xl border p-4",
                    unread() ? "border-accent-soft bg-accent-soft/30" : "border-line bg-surface",
                  )}
                >
                  {/*
                    The unread state is carried by a text badge as well as by
                    the tint: colour alone is not a status a screen reader or a
                    colour-blind reader receives.
                  */}
                  <div class="flex min-w-0 flex-1 flex-col gap-1">
                    <div class="flex flex-wrap items-center gap-2">
                      <Show when={unread()}>
                        <Badge variant="accent">{t(app.notifUnread)}</Badge>
                      </Show>
                      <Badge variant={categoryVariant(notification.category)}>
                        {t(CATEGORY_LABELS[notification.category] ?? app.notifCategoryPackage)}
                      </Badge>
                      <span class="font-mono text-xs text-ink-muted">{notification.event}</span>
                    </div>
                    <p class="text-sm text-ink">{notification.title}</p>
                    <p class="text-xs text-ink-muted">{formatRelative(notification.created_at)}</p>
                  </div>
                  <div class="flex shrink-0 items-center gap-2">
                    <Show when={href}>
                      {(path) => (
                        <A href={path()} class={buttonVariants({ intent: "ghost", size: "sm" })}>
                          {t(app.notifOpen)}
                        </A>
                      )}
                    </Show>
                    <Show when={unread()}>
                      <Button
                        intent="ghost"
                        size="sm"
                        disabled={busy()}
                        onClick={() => void mark([notification.id])}
                      >
                        {t(app.notifMarkRead)}
                      </Button>
                    </Show>
                  </div>
                </li>
              );
            }}
          </For>
        </ul>
      </Show>

      <Show when={feed()?.has_more === true}>
        <p class="text-xs text-ink-muted">{t(app.notifTruncated)}</p>
      </Show>
    </div>
  );
}

export function NotificationsScreen(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const unreadOnly = (): boolean => params.unread === "1";

  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex flex-col gap-2">
          <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.navNotifications)}</h1>
          <p class="max-w-2xl text-ink-muted">{t(app.notifSubtitle)}</p>
        </div>
        <A
          href="/notifications/preferences"
          class={buttonVariants({ intent: "outline", size: "sm" })}
        >
          {t(app.notifPreferences)}
        </A>
      </header>

      {/*
        The stream is a hint channel; when it is not connected the feed is
        still correct, it just stops arriving on its own. Saying so beats a
        silent absence of updates.
      */}
      <Show when={streamStatus() === "reconnecting"}>
        <Alert intent="warning">{t(app.notifStreamReconnecting)}</Alert>
      </Show>

      <div class="flex gap-2">
        <Button
          intent={unreadOnly() ? "ghost" : "outline"}
          size="sm"
          aria-pressed={!unreadOnly()}
          onClick={() => setParams({ unread: undefined })}
        >
          {t(app.notifFilterAll)}
        </Button>
        <Button
          intent={unreadOnly() ? "outline" : "ghost"}
          size="sm"
          aria-pressed={unreadOnly()}
          onClick={() => setParams({ unread: "1" })}
        >
          {t(app.notifFilterUnread)}
        </Button>
      </div>

      <Feed unread={unreadOnly()} />
    </section>
  );
}

/**
 * Per-category delivery preferences.
 *
 * Three categories, not one switch per event type (decision 20): a preference
 * list curated per event name is a preference list nobody curates. `org` and
 * `security` reach a mailbox by default; `package` does not, because a publish
 * firehose in everybody's inbox is the fastest way to get the sender filtered
 * into a folder and the other two categories missed.
 */
export function NotificationPreferencesScreen(): JSX.Element {
  const preferences = createAsync(() => preferencesQuery());
  const [draft, setDraft] = createSignal<readonly NotificationPreferenceDto[] | null>(null);
  const [busy, setBusy] = createSignal(false);

  const rows = (): readonly NotificationPreferenceDto[] =>
    draft() ??
    preferences()?.preferences ??
    NOTIFICATION_CATEGORIES.map((category) => ({ category, in_app: true, email: false }));

  const update = (category: string, patch: Partial<NotificationPreferenceDto>): void => {
    setDraft(rows().map((row) => (row.category === category ? { ...row, ...patch } : row)));
  };

  const save = async (): Promise<void> => {
    if (busy()) return;
    setBusy(true);
    try {
      const result = await api.notifications.updatePreferences(rows());
      setDraft(result.preferences);
      pushToast(t(app.notifPrefsSaved), "success");
      await revalidate("notification-prefs");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-col gap-2">
        <A
          href="/notifications"
          class="w-fit rounded-sm text-sm text-ink-muted outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
        >
          ← {t(app.navNotifications)}
        </A>
        <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.notifPreferences)}</h1>
        <p class="max-w-2xl text-ink-muted">{t(app.notifPrefsSubtitle)}</p>
      </header>

      <Card>
        <CardHeader>
          <h2 class="text-lg font-semibold text-ink">{t(app.notifPrefsCategories)}</h2>
        </CardHeader>
        <CardContent class="flex flex-col gap-6">
          <For each={rows()}>
            {(preference) => (
              <fieldset class="flex flex-col gap-2 border-b border-line pb-5 last:border-b-0 last:pb-0">
                <legend class="text-sm font-medium text-ink">
                  {t(CATEGORY_LABELS[preference.category] ?? app.notifCategoryPackage)}
                </legend>
                <p class="text-xs text-ink-muted">
                  {preference.category === "security"
                    ? t(app.notifPrefsSecurityHint)
                    : preference.category === "org"
                      ? t(app.notifPrefsOrgHint)
                      : t(app.notifPrefsPackageHint)}
                </p>
                <div class="flex flex-wrap gap-6 pt-1">
                  <label class="flex cursor-pointer items-center gap-2 text-sm text-ink">
                    <input
                      type="checkbox"
                      checked={preference.in_app}
                      onChange={(event) =>
                        update(preference.category, { in_app: event.currentTarget.checked })
                      }
                      class="size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                    />
                    <span>{t(app.notifPrefsInApp)}</span>
                  </label>
                  <label class="flex cursor-pointer items-center gap-2 text-sm text-ink">
                    <input
                      type="checkbox"
                      checked={preference.email}
                      onChange={(event) =>
                        update(preference.category, { email: event.currentTarget.checked })
                      }
                      class="size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                    />
                    <span>{t(app.notifPrefsEmail)}</span>
                  </label>
                </div>
              </fieldset>
            )}
          </For>
          <Button class="self-start" disabled={busy()} onClick={() => void save()}>
            {t(app.save)}
          </Button>
        </CardContent>
      </Card>
    </section>
  );
}
