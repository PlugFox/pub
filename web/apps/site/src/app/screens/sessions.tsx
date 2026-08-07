import type { SessionDto } from "@pub/api/types";
import { t, tp } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { EmptyState } from "@pub/ui/empty-state";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { createAsync, query, revalidate } from "@solidjs/router";
import { createSignal, For, type JSX, Show } from "solid-js";
import { formatDateTime, shortenUserAgent } from "../format";
import { api, describeError, withStepUp } from "../state/api";
import { pushToast } from "../state/toast-store";

/*
 * Session list (S-10): every browser signed in to this account, with the
 * current one flagged so a user can tell "revoke this" from "revoke that".
 *
 * `revoke-all` is step-up-gated (S-06.a), so it goes through `withStepUp`:
 * the prompt opens, and the call is retried once the user has proved a fresh
 * second factor.
 */

const SESSIONS_KEY = "sessions";
const sessionsQuery = query(() => api.sessions.list(), SESSIONS_KEY);

export function SessionsScreen(): JSX.Element {
  const sessions = createAsync(() => sessionsQuery());
  const [busyId, setBusyId] = createSignal<string | null>(null);
  const [revokingAll, setRevokingAll] = createSignal(false);

  const rows = (): readonly SessionDto[] => sessions()?.items ?? [];
  const others = (): readonly SessionDto[] => rows().filter((row) => !row.current);

  const revokeOne = async (session: SessionDto): Promise<void> => {
    setBusyId(session.id);
    try {
      await api.sessions.revoke(session.id);
      pushToast(t(app.sessionsRevoked), "success");
      await revalidate(SESSIONS_KEY);
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusyId(null);
    }
  };

  const revokeAll = async (): Promise<void> => {
    setRevokingAll(true);
    try {
      const result = await withStepUp(() => api.sessions.revokeAll());
      pushToast(tp(app.sessionsRevokedAll, result.revoked), "success");
      await revalidate(SESSIONS_KEY);
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setRevokingAll(false);
    }
  };

  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex flex-col gap-2">
          <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.sessionsTitle)}</h1>
          <p class="text-ink-muted">{t(app.sessionsSubtitle)}</p>
        </div>
        <Show when={others().length > 0}>
          <Button intent="outline" disabled={revokingAll()} onClick={() => void revokeAll()}>
            {t(app.sessionsRevokeAll)}
          </Button>
        </Show>
      </header>

      <Show
        when={rows().length > 0}
        fallback={<EmptyState title={t(app.sessionsEmpty)} description={t(app.sessionsSubtitle)} />}
      >
        <Table label={t(app.sessionsTableLabel)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.sessionsDevice)}</TableHeaderCell>
              <TableHeaderCell>{t(app.sessionsIp)}</TableHeaderCell>
              <TableHeaderCell>{t(app.sessionsCreated)}</TableHeaderCell>
              <TableHeaderCell>{t(app.sessionsLastSeen)}</TableHeaderCell>
              <TableHeaderCell>
                <span class="sr-only">{t(app.revoke)}</span>
              </TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(session) => (
                <TableRow>
                  <TableCell>
                    <div class="flex items-center gap-2">
                      <span class="max-w-64 truncate">
                        {shortenUserAgent(session.user_agent) ?? t(app.unknownValue)}
                      </span>
                      <Show when={session.current}>
                        <Badge variant="accent">{t(app.sessionsCurrent)}</Badge>
                      </Show>
                    </div>
                  </TableCell>
                  <TableCell class="font-mono text-xs">
                    {session.ip ?? t(app.unknownValue)}
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatDateTime(session.created_at)}
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatDateTime(session.last_seen_at)}
                  </TableCell>
                  <TableCell class="text-right">
                    <Button
                      intent="ghost"
                      size="sm"
                      disabled={busyId() === session.id}
                      onClick={() => void revokeOne(session)}
                    >
                      {t(app.revoke)}
                    </Button>
                  </TableCell>
                </TableRow>
              )}
            </For>
          </TableBody>
        </Table>
      </Show>
    </section>
  );
}
