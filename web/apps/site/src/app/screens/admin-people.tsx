import type { AdminOrgDto, AdminUserDto, UserStatus } from "@pub/api/types";
import { USER_STATUSES } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { EmptyState } from "@pub/ui/empty-state";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { A, createAsync, query, revalidate, useSearchParams } from "@solidjs/router";
import { createMemo, createSignal, For, type JSX, Show } from "solid-js";
import { formatDate, formatNumber } from "../format";
import { api, describeError } from "../state/api";
import { pushToast } from "../state/toast-store";
import { orgPath } from "../urls";

/*
 * Admin: the accounts table and the organizations table.
 *
 * Both filter and paginate through the URL, so an admin can link a colleague
 * at "the suspended accounts on page two" instead of describing it. Cursors
 * here are plain keyset tokens (no ordering tag), so unlike search they do not
 * need a reset — but the FILTERS do: narrowing the set while holding a cursor
 * from the wider one is a page nobody asked for, so every filter change drops
 * the cursor.
 *
 * Suspension revokes the account's sessions (S-09) and is effective on the
 * account's very next request: the instance-admin flag and the account status
 * are read from the row, never from a token claim (decision 19's addendum).
 */

const usersQuery = query(
  (input: { q: string; status: string; cursor: string | null }) =>
    api.admin.users({
      q: input.q === "" ? undefined : input.q,
      status: input.status === "" ? undefined : (input.status as UserStatus),
      cursor: input.cursor ?? undefined,
      limit: 30,
    }),
  "admin-users",
);

const orgsQuery = query(
  (cursor: string | null) => api.admin.orgs({ cursor: cursor ?? undefined, limit: 30 }),
  "admin-orgs",
);

function statusVariant(status: string): "success" | "warning" | "neutral" {
  if (status === "active") return "success";
  if (status === "suspended") return "warning";
  return "neutral";
}

export function AdminUsersPanel(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const [draft, setDraft] = createSignal<string | null>(null);
  const filters = createMemo(() => ({
    q: typeof params.q === "string" ? params.q : "",
    status: typeof params.status === "string" ? params.status : "",
    cursor: typeof params.cursor === "string" && params.cursor !== "" ? params.cursor : null,
  }));
  const page = createAsync(() => usersQuery(filters()));
  const [busyId, setBusyId] = createSignal<string | null>(null);
  const rows = (): readonly AdminUserDto[] => page()?.items ?? [];

  const toggle = async (user: AdminUserDto): Promise<void> => {
    if (busyId() !== null) return;
    setBusyId(user.id);
    try {
      const suspended = user.status === "suspended";
      await (suspended ? api.admin.unsuspend(user.id) : api.admin.suspend(user.id));
      pushToast(suspended ? t(app.adminUserUnsuspended) : t(app.adminUserSuspended), "success");
      await revalidate("admin-users");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div class="flex flex-col gap-4">
      <form
        class="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          // A new filter invalidates the page position.
          setParams({ q: draft() ?? filters().q, cursor: undefined });
          setDraft(null);
        }}
      >
        <div class="grid min-w-56 flex-1 gap-1.5">
          <Label for="admin-user-q">{t(app.adminUserSearch)}</Label>
          <Input
            id="admin-user-q"
            type="search"
            value={draft() ?? filters().q}
            onInput={(event) => setDraft(event.currentTarget.value)}
          />
        </div>
        <div class="grid gap-1.5">
          <Label for="admin-user-status">{t(app.adminUserStatus)}</Label>
          <select
            id="admin-user-status"
            value={filters().status}
            onChange={(event) =>
              setParams({
                status: event.currentTarget.value === "" ? undefined : event.currentTarget.value,
                cursor: undefined,
              })
            }
            class="h-10 rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
          >
            <option value="">{t(app.adminAnyStatus)}</option>
            <For each={USER_STATUSES}>{(status) => <option value={status}>{status}</option>}</For>
          </select>
        </div>
        <Button type="submit">{t(app.adminApplyFilters)}</Button>
      </form>

      <Show when={rows().length > 0} fallback={<EmptyState title={t(app.adminUsersEmpty)} />}>
        <Table label={t(app.adminUsersTitle)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.accountDisplayName)}</TableHeaderCell>
              <TableHeaderCell>{t(app.accountEmail)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminUserStatus)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminUserCreated)}</TableHeaderCell>
              <TableHeaderCell>
                <span class="sr-only">{t(app.adminUserSuspend)}</span>
              </TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(user) => (
                <TableRow>
                  <TableCell>
                    <div class="flex flex-wrap items-center gap-2">
                      <span class="font-medium">{user.display_name}</span>
                      <Show when={user.instance_admin}>
                        <Badge variant="accent">{t(app.adminUserAdmin)}</Badge>
                      </Show>
                    </div>
                  </TableCell>
                  <TableCell class="font-mono text-xs text-ink-muted">
                    {user.email ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(user.status)}>{user.status}</Badge>
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatDate(user.created_at)}
                  </TableCell>
                  <TableCell class="text-right">
                    <Show when={user.status !== "deleted"}>
                      <Button
                        intent={user.status === "suspended" ? "outline" : "ghost"}
                        size="sm"
                        disabled={busyId() === user.id}
                        onClick={() => void toggle(user)}
                      >
                        {user.status === "suspended"
                          ? t(app.adminUserUnsuspend)
                          : t(app.adminUserSuspend)}
                      </Button>
                    </Show>
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

export function AdminOrgsPanel(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const cursor = (): string | null =>
    typeof params.cursor === "string" && params.cursor !== "" ? params.cursor : null;
  const page = createAsync(() => orgsQuery(cursor()));
  const rows = (): readonly AdminOrgDto[] => page()?.items ?? [];

  return (
    <div class="flex flex-col gap-4">
      <Show when={rows().length > 0} fallback={<EmptyState title={t(app.adminOrgsEmpty)} />}>
        <Table label={t(app.adminOrgsTitle)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.orgsNameField)}</TableHeaderCell>
              <TableHeaderCell>{t(app.orgsSlugField)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminOrgMembers)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminOrgPackages)}</TableHeaderCell>
              <TableHeaderCell>{t(app.adminOrgCreated)}</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(row) => (
                <TableRow>
                  <TableCell>
                    <div class="flex flex-wrap items-center gap-2">
                      <A
                        href={orgPath(row.org.slug)}
                        class="rounded-sm font-medium text-ink outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
                      >
                        {row.org.name}
                      </A>
                      <Show when={row.org.archived}>
                        <Badge variant="warning">{t(app.orgArchived)}</Badge>
                      </Show>
                    </div>
                  </TableCell>
                  <TableCell class="font-mono text-xs text-ink-muted">{row.org.slug}</TableCell>
                  <TableCell>{formatNumber(row.members)}</TableCell>
                  <TableCell>{formatNumber(row.packages)}</TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatDate(row.org.created_at)}
                  </TableCell>
                </TableRow>
              )}
            </For>
          </TableBody>
        </Table>
      </Show>

      <CursorNav
        cursor={cursor()}
        next={page()?.has_more === true ? (page()?.cursor ?? null) : null}
        onGo={(next) => setParams({ cursor: next ?? undefined })}
      />
    </div>
  );
}

/** Forward-only cursor controls, shared by the admin tables. */
export function CursorNav(props: {
  readonly cursor: string | null;
  readonly next: string | null;
  readonly onGo: (cursor: string | null) => void;
}): JSX.Element {
  return (
    <Show when={props.cursor !== null || props.next !== null}>
      <nav aria-label={t(app.searchPagination)} class="flex flex-wrap justify-center gap-3">
        <Show when={props.cursor !== null}>
          <Button intent="ghost" onClick={() => props.onGo(null)}>
            {t(app.searchFirstPage)}
          </Button>
        </Show>
        <Show when={props.next}>
          {(next) => (
            <Button intent="outline" onClick={() => props.onGo(next())}>
              {t(app.searchNextPage)}
            </Button>
          )}
        </Show>
      </nav>
    </Show>
  );
}
