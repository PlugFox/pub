import type { AuditEventDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { EmptyState } from "@pub/ui/empty-state";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { createAsync, query, useSearchParams } from "@solidjs/router";
import { createMemo, For, type JSX, Show } from "solid-js";
import { formatDateTime } from "../format";
import { api } from "../state/api";
import { CursorNav } from "./admin-people";

/*
 * The audit log viewer (S-22/S-23).
 *
 * The log is APPEND-ONLY and the row id is a ULID, which is also the cursor —
 * so "newest first" and "page forward" are the same ordering and there is
 * nothing to sort. Filters are URL state: an investigation is something you
 * paste into a ticket.
 *
 * `action` is a PREFIX filter (`org.member.` matches every membership action),
 * which is the difference between one useful field and a dropdown that has to
 * enumerate every action the server will ever emit.
 *
 * `metadata` is rendered as formatted JSON rather than interpreted: it is
 * structured before/after context whose shape varies per action, it never
 * contains secrets (S-22), and inventing a renderer per action is how an audit
 * viewer starts hiding the field somebody needed.
 */

const auditQuery = query(
  (filters: {
    org: string;
    action: string;
    actor: string;
    from: string;
    until: string;
    cursor: string | null;
  }) =>
    api.admin.audit({
      org: filters.org === "" ? undefined : filters.org,
      action: filters.action === "" ? undefined : filters.action,
      actor: filters.actor === "" ? undefined : filters.actor,
      from: filters.from === "" ? undefined : new Date(filters.from).toISOString(),
      until: filters.until === "" ? undefined : new Date(filters.until).toISOString(),
      cursor: filters.cursor ?? undefined,
      limit: 30,
    }),
  "admin-audit",
);

function resultVariant(result: string): "success" | "danger" {
  return result === "success" ? "success" : "danger";
}

export function AdminAuditPanel(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const text = (key: string): string => (typeof params[key] === "string" ? params[key] : "");
  const filters = createMemo(() => ({
    org: text("org"),
    action: text("action"),
    actor: text("actor"),
    from: text("from"),
    until: text("until"),
    cursor: text("cursor") === "" ? null : text("cursor"),
  }));
  const page = createAsync(() => auditQuery(filters()));
  const rows = (): readonly AuditEventDto[] => page()?.items ?? [];

  // Every filter change drops the cursor: a page position from the wider set
  // means nothing in the narrower one.
  const setFilter = (key: string, value: string): void => {
    setParams({ [key]: value === "" ? undefined : value, cursor: undefined });
  };

  return (
    <div class="flex flex-col gap-4">
      <form
        class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3"
        onSubmit={(event) => event.preventDefault()}
      >
        <div class="grid gap-1.5">
          <Label for="audit-action">{t(app.adminAuditAction)}</Label>
          <Input
            id="audit-action"
            class="font-mono"
            value={filters().action}
            placeholder="org.member."
            onChange={(event) => setFilter("action", event.currentTarget.value.trim())}
          />
          <p class="text-xs text-ink-muted">{t(app.adminAuditActionHint)}</p>
        </div>
        <div class="grid gap-1.5">
          <Label for="audit-org">{t(app.adminAuditOrg)}</Label>
          <Input
            id="audit-org"
            class="font-mono"
            value={filters().org}
            onChange={(event) => setFilter("org", event.currentTarget.value.trim())}
          />
        </div>
        <div class="grid gap-1.5">
          <Label for="audit-actor">{t(app.adminAuditActor)}</Label>
          <Input
            id="audit-actor"
            class="font-mono"
            value={filters().actor}
            onChange={(event) => setFilter("actor", event.currentTarget.value.trim())}
          />
        </div>
        <div class="grid gap-1.5">
          <Label for="audit-from">{t(app.adminAuditFrom)}</Label>
          <Input
            id="audit-from"
            type="datetime-local"
            value={filters().from}
            onChange={(event) => setFilter("from", event.currentTarget.value)}
          />
        </div>
        <div class="grid gap-1.5">
          <Label for="audit-until">{t(app.adminAuditUntil)}</Label>
          <Input
            id="audit-until"
            type="datetime-local"
            value={filters().until}
            onChange={(event) => setFilter("until", event.currentTarget.value)}
          />
        </div>
        <div class="flex items-end">
          <Button
            intent="ghost"
            onClick={() =>
              setParams({
                org: undefined,
                action: undefined,
                actor: undefined,
                from: undefined,
                until: undefined,
                cursor: undefined,
              })
            }
          >
            {t(app.adminAuditClear)}
          </Button>
        </div>
      </form>

      <Show when={rows().length > 0} fallback={<EmptyState title={t(app.adminAuditEmpty)} />}>
        <Table label={t(app.adminAuditTitle)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.adminAuditWhen)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminAuditAction)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminAuditActor)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminAuditTarget)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminAuditResult)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminAuditContext)}</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(event) => (
                <TableRow>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatDateTime(event.created_at)}
                  </TableCell>
                  <TableCell class="font-mono text-xs">{event.action}</TableCell>
                  <TableCell class="font-mono text-xs text-ink-muted">
                    <div class="flex flex-col">
                      <span>{event.actor_kind}</span>
                      <span>{event.actor_id ?? "—"}</span>
                    </div>
                  </TableCell>
                  <TableCell class="font-mono text-xs text-ink-muted">
                    {event.target ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={resultVariant(event.result)}>{event.result}</Badge>
                  </TableCell>
                  <TableCell>
                    <details class="max-w-md">
                      <summary class="cursor-pointer rounded-sm text-xs text-accent outline-none focus-visible:ring-2 focus-visible:ring-accent">
                        {t(app.adminAuditShowContext)}
                      </summary>
                      <pre class="mt-2 overflow-x-auto rounded-md border border-line bg-canvas p-2 font-mono text-xs text-ink">
                        {JSON.stringify(event.metadata, null, 2)}
                      </pre>
                      <p class="pt-1 font-mono text-xs text-ink-muted">{event.ip ?? "—"}</p>
                    </details>
                  </TableCell>
                </TableRow>
              )}
            </For>
          </TableBody>
        </Table>
      </Show>

      <CursorNav
        cursor={filters().cursor}
        next={page()?.has_more === true ? (page()?.cursor ?? null) : null}
        onGo={(cursor) => setParams({ cursor: cursor ?? undefined })}
      />
    </div>
  );
}
