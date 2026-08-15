import type { AdminOrgDto, AdminUserDto, UserStatus } from "@pub/api/types";
import { USER_STATUSES } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@pub/ui/dialog";
import { EmptyState } from "@pub/ui/empty-state";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { A, createAsync, query, revalidate, useSearchParams } from "@solidjs/router";
import { createMemo, createSignal, For, type JSX, Show } from "solid-js";
import { formatBytes, formatDate, formatNumber } from "../format";
import { adminSettingsQuery } from "../state/admin-queries";
import { api, describeError } from "../state/api";
import { pushToast } from "../state/toast-store";
import {
  QUOTA_MODES,
  type QuotaForm,
  type QuotaMode,
  quotaToForm,
  quotaToPatch,
  validateQuota,
} from "../storage-quota";
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
 *
 * THE ORG TABLE NOW WRITES. `PATCH /api/v1/admin/orgs/{id}` is the admin
 * plane's first write over an organization (decision 32) and it sets exactly
 * one thing: the storage-quota override (S-20.b). It lives here rather than on
 * the org's own settings screen for the reason the quota exists — that screen
 * is reachable by an org Admin, and a quota its subject can raise is not a
 * quota.
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

const ADMIN_ORGS_KEY = "admin-orgs";

const orgsQuery = query(
  (cursor: string | null) => api.admin.orgs({ cursor: cursor ?? undefined, limit: 30 }),
  ADMIN_ORGS_KEY,
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

/**
 * One org's quota, as two lines: what applies, and where it comes from.
 *
 * The three states of the override are all reachable and all read
 * differently — `(size, instance default)`, `(Unlimited, override)`,
 * `(size, override)` — because "unlimited" alone cannot tell an operator
 * whether this org opted out of a finite instance default or merely inherited
 * an instance that has none. That difference survives a later change to the
 * instance number, so it has to be visible before one is made.
 *
 * The first line is the SERVER's `effective_quota_bytes`, not a number this
 * screen derives. Resolving an override against the instance default is one
 * rule owned by `pub_registry::publish::effective_storage_quota`, and a client
 * copy of it could disagree with the code that actually refuses a publish.
 * Only the second line — inherited vs. overridden — is a question about the
 * stored value, which is why the override is still passed in.
 */
function QuotaCell(props: {
  readonly override: number | null | undefined;
  readonly effective: number | null | undefined;
}): JSX.Element {
  const inherited = (): boolean => props.override === null || props.override === undefined;
  const applies = (): string =>
    props.effective === null || props.effective === undefined
      ? t(app.adminOrgQuotaUnlimited)
      : formatBytes(props.effective);
  return (
    <div class="flex flex-col gap-0.5">
      <span class="font-medium whitespace-nowrap">{applies()}</span>
      <span class="text-xs text-ink-muted">
        {inherited() ? t(app.adminOrgQuotaInherited) : t(app.adminOrgQuotaOverride)}
      </span>
    </div>
  );
}

/**
 * The quota editor: three radios, and a byte field that only the third needs.
 *
 * Radios rather than a number field with magic values, because the states are
 * not points on one scale — `null` and `0` are different rows with different
 * futures, and typing `0` into a box labelled "bytes" is not how an operator
 * says "opt this org out of the instance default forever".
 *
 * The dialog is mounted keyed on the org, so reopening it on another row
 * starts from that row's stored value rather than from the last one's draft.
 */
function OrgQuotaDialog(props: {
  readonly org: AdminOrgDto;
  readonly instanceDefault: number | undefined;
  readonly onClose: () => void;
}): JSX.Element {
  const [form, setForm] = createSignal<QuotaForm>(quotaToForm(props.org.storage_quota_bytes));
  const [invalid, setInvalid] = createSignal(false);
  const [failure, setFailure] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const inheritedText = (): string =>
    props.instanceDefault === undefined
      ? "—"
      : props.instanceDefault > 0
        ? formatBytes(props.instanceDefault)
        : t(app.adminOrgQuotaUnlimited);

  const modeLabel = (mode: QuotaMode): string => {
    if (mode === "default") return t(app.adminOrgQuotaModeDefault, { value: inheritedText() });
    if (mode === "unlimited") return t(app.adminOrgQuotaModeUnlimited);
    return t(app.adminOrgQuotaModeLimit);
  };

  const echo = (): string => {
    const parsed = quotaToPatch(form());
    return parsed === null || parsed === 0 ? "" : formatBytes(parsed);
  };

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy()) return;
    if (validateQuota(form()) !== null) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    setFailure(null);
    setBusy(true);
    try {
      // The response carries what the override RESOLVES to, which is the
      // operator's actual question and the one number the list payload cannot
      // answer on its own. Reporting it beats echoing back what was typed.
      const saved = await api.admin.setOrgQuota(props.org.org.id, quotaToPatch(form()));
      const effective =
        saved.effective_quota_bytes === null || saved.effective_quota_bytes === undefined
          ? t(app.adminOrgQuotaUnlimited)
          : formatBytes(saved.effective_quota_bytes);
      pushToast(
        t(app.adminOrgQuotaSaved, { org: props.org.org.slug, quota: effective }),
        "success",
      );
      props.onClose();
      await revalidate(ADMIN_ORGS_KEY);
    } catch (error) {
      setFailure(describeError(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && props.onClose()}>
      <DialogContent>
        <DialogTitle>{t(app.adminOrgQuotaTitle, { org: props.org.org.name })}</DialogTitle>
        <DialogDescription>{t(app.adminOrgQuotaBody)}</DialogDescription>
        <form class="flex flex-col gap-5" onSubmit={(event) => void submit(event)}>
          <fieldset class="grid gap-2">
            <legend class="pb-1 text-sm font-medium text-ink">{t(app.adminOrgQuotaLegend)}</legend>
            <For each={QUOTA_MODES}>
              {(mode) => (
                <label class="flex cursor-pointer items-start gap-2 text-sm text-ink">
                  <input
                    type="radio"
                    name="org-quota-mode"
                    value={mode}
                    checked={form().mode === mode}
                    onChange={() => {
                      setForm({ ...form(), mode });
                      setInvalid(false);
                    }}
                    class="mt-0.5 size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                  />
                  <span>{modeLabel(mode)}</span>
                </label>
              )}
            </For>
          </fieldset>

          <Show when={form().mode === "limit"}>
            <div class="grid gap-1.5">
              <Label for="org-quota-bytes">{t(app.adminOrgQuotaBytes)}</Label>
              <Input
                id="org-quota-bytes"
                type="number"
                min={1}
                value={form().bytes}
                aria-invalid={invalid()}
                aria-describedby={invalid() ? "org-quota-bytes-error" : undefined}
                onInput={(event) => {
                  setForm({ ...form(), bytes: event.currentTarget.value });
                  setInvalid(false);
                }}
              />
              <Show when={echo()}>
                {(size) => <p class="text-xs font-medium text-ink">{size()}</p>}
              </Show>
              <Show when={invalid()}>
                <p id="org-quota-bytes-error" class="text-xs text-danger-ink">
                  {t(app.adminOrgQuotaBytesError)}
                </p>
              </Show>
            </div>
          </Show>

          <Show when={failure()}>{(message) => <Alert intent="danger">{message()}</Alert>}</Show>

          <div class="flex justify-end gap-3">
            <Button intent="ghost" onClick={() => props.onClose()}>
              {t(app.cancel)}
            </Button>
            <Button type="submit" disabled={busy()}>
              {t(app.save)}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function AdminOrgsPanel(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const cursor = (): string | null =>
    typeof params.cursor === "string" && params.cursor !== "" ? params.cursor : null;
  const page = createAsync(() => orgsQuery(cursor()));
  // The list payload resolves each org's effective quota server-side, so the
  // TABLE needs nothing else. The settings document is still loaded for the
  // EDITOR: its "follow the instance default" choice has to name the number
  // that default currently is, and no per-org payload can carry an
  // instance-wide setting. Same admin plane, same session, one extra GET.
  const settings = createAsync(() => adminSettingsQuery());
  const rows = (): readonly AdminOrgDto[] => page()?.items ?? [];
  const instanceDefault = (): number | undefined => settings()?.registry.storage_quota_bytes;
  // Deliberately NOT waiting on the settings document: it only refines one
  // radio label in a dialog nobody has opened yet, and holding the whole table
  // until a second request lands would make the org list as slow — and as
  // fragile — as the slower of the two.
  const loading = (): boolean => page() === undefined;
  const [editing, setEditing] = createSignal<AdminOrgDto | null>(null);

  return (
    <div class="flex flex-col gap-4">
      {/*
        The panel's async state, announced rather than mimed. D33 records the
        opposite pattern — `aria-hidden` skeletons with no live region — and
        this table had a second bug of the same family: while the first page
        was in flight it rendered "No organizations", which is a statement, not
        a spinner. The region is mounted for the panel's whole life and only
        its text changes, because a live region inserted together with its
        content is the classic way to get no announcement at all.
      */}
      <p role="status" class="sr-only">
        {loading() ? t(app.adminOrgsLoading) : t(app.adminOrgsLoaded)}
      </p>

      <Show
        when={!loading()}
        fallback={<p class="py-6 text-center text-sm text-ink-muted">{t(app.adminOrgsLoading)}</p>}
      >
        <Show when={rows().length > 0} fallback={<EmptyState title={t(app.adminOrgsEmpty)} />}>
          <Table label={t(app.adminOrgsTitle)}>
            <TableHead>
              <TableRow>
                <TableHeaderCell>{t(app.orgsNameField)}</TableHeaderCell>
                <TableHeaderCell>{t(app.orgsSlugField)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminOrgMembers)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminOrgPackages)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminOrgQuota)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminOrgCreated)}</TableHeaderCell>
                <TableHeaderCell>
                  <span class="sr-only">{t(app.adminOrgQuotaEdit)}</span>
                </TableHeaderCell>
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
                    <TableCell>
                      <QuotaCell
                        override={row.storage_quota_bytes}
                        effective={row.effective_quota_bytes}
                      />
                    </TableCell>
                    <TableCell class="whitespace-nowrap text-ink-muted">
                      {formatDate(row.org.created_at)}
                    </TableCell>
                    <TableCell class="text-right">
                      <Button intent="ghost" size="sm" onClick={() => setEditing(row)}>
                        {t(app.adminOrgQuotaEdit)}
                      </Button>
                    </TableCell>
                  </TableRow>
                )}
              </For>
            </TableBody>
          </Table>
        </Show>
      </Show>

      {/* Keyed, so a second row's dialog starts from that row's stored value. */}
      <Show when={editing()} keyed>
        {(org) => (
          <OrgQuotaDialog
            org={org}
            instanceDefault={instanceDefault()}
            onClose={() => setEditing(null)}
          />
        )}
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
