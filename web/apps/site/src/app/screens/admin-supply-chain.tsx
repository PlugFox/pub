import type { QuarantineDto, ShadowingDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { EmptyState } from "@pub/ui/empty-state";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { createAsync, query, revalidate, useSearchParams } from "@solidjs/router";
import { createSignal, For, type JSX, Show } from "solid-js";
import { CursorNav, nextCursor } from "../cursor-nav";
import { formatNumber, formatRelative } from "../format";
import { api, describeError } from "../state/api";
import { pushToast } from "../state/toast-store";

/*
 * The two supply-chain registers (S-17.b / S-19.b, decision 33).
 *
 * The dashboard already shows the newest twenty rows of each — that is the
 * ALARM, and it is where an operator learns something is wrong. This is the
 * REGISTER: the whole of it, paged, sliceable, and with the one write either
 * of them has.
 *
 * Two properties are worth stating because a reader will reasonably assume
 * otherwise:
 *
 *   - **Acknowledging changes nothing about resolution.** The local package
 *     won before the alarm and wins after it (decision 01, S-17.a). The button
 *     clears a notification, and the next upstream sighting raises it again as
 *     a new incident with a fresh start date.
 *   - **Quarantine has no button at all, deliberately.** Those rows are
 *     evidence written *after* the bytes were already refused, so nothing here
 *     could change what the proxy serves — and a row an admin session could
 *     clear is a row an attacker holding one could clear. Retention deletes
 *     them on a window (S-23.b); an operator never does.
 */

const QUARANTINE_KEY = "admin-quarantine";
const SHADOWING_KEY = "admin-shadowing";

const quarantineQuery = query(
  (cursor: string | null) => api.admin.quarantine({ cursor: cursor ?? undefined, limit: 30 }),
  QUARANTINE_KEY,
);

const shadowingQuery = query(
  (input: { active: boolean | undefined; cursor: string | null }) =>
    api.admin.shadowing({ active: input.active, cursor: input.cursor ?? undefined, limit: 30 }),
  SHADOWING_KEY,
);

/** The `active` filter as three states; anything unrecognized is "the whole register". */
function readActive(raw: unknown): boolean | undefined {
  if (raw === "active") return true;
  if (raw === "acknowledged") return false;
  return undefined;
}

export function AdminSupplyChainPanel(): JSX.Element {
  return (
    <div class="flex flex-col gap-10">
      <ShadowingRegister />
      <QuarantineRegister />
    </div>
  );
}

function ShadowingRegister(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const active = (): boolean | undefined => readActive(params.shadowing);
  const cursor = (): string | null =>
    typeof params.shadowingCursor === "string" && params.shadowingCursor !== ""
      ? params.shadowingCursor
      : null;
  const page = createAsync(() => shadowingQuery({ active: active(), cursor: cursor() }));
  const rows = (): readonly ShadowingDto[] => page()?.items ?? [];
  const loading = (): boolean => page() === undefined;
  const [busy, setBusy] = createSignal<string | null>(null);

  const acknowledge = async (alarm: ShadowingDto): Promise<void> => {
    const key = `${alarm.format}/${alarm.name}`;
    if (busy() !== null) return;
    setBusy(key);
    try {
      const result = await api.admin.acknowledgeShadowing(alarm.format, alarm.name);
      // `false` is not a failure: somebody else cleared it, or a stale page was
      // clicked. Saying so is better than a success toast for a no-op.
      pushToast(
        result.acknowledged
          ? t(app.adminShadowingAcknowledged)
          : t(app.adminShadowingAlreadyAcknowledged),
        result.acknowledged ? "success" : "warning",
      );
      await revalidate(SHADOWING_KEY);
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(null);
    }
  };

  const filters: readonly {
    readonly value: string;
    readonly label: { readonly id: string; readonly en: string };
  }[] = [
    { value: "active", label: app.adminShadowingFilterActive },
    { value: "acknowledged", label: app.adminShadowingFilterAcknowledged },
    { value: "all", label: app.adminShadowingFilterAll },
  ];
  const current = (): string =>
    params.shadowing === "acknowledged"
      ? "acknowledged"
      : params.shadowing === "active"
        ? "active"
        : "all";

  return (
    <section class="flex flex-col gap-4">
      <header class="flex flex-col gap-2">
        <h2 class="text-lg font-semibold text-ink">{t(app.adminShadowingTitle)}</h2>
        <Alert intent="warning">{t(app.adminShadowingBody)}</Alert>
      </header>

      {/*
        Mounted for the panel's whole life with only its text changing — a live
        region inserted together with its content announces nothing (D33).
      */}
      <p role="status" class="sr-only">
        {loading() ? t(app.adminRegisterLoading) : t(app.adminRegisterLoaded)}
      </p>

      <div class="flex flex-wrap gap-2">
        <For each={filters}>
          {(filter) => (
            <Button
              intent={current() === filter.value ? "outline" : "ghost"}
              aria-pressed={current() === filter.value}
              onClick={() =>
                setParams({
                  shadowing: filter.value === "all" ? undefined : filter.value,
                  // The cursor belongs to the slice it was issued for: keeping it
                  // across a filter change resumes a walk over a different set.
                  shadowingCursor: undefined,
                })
              }
            >
              {t(filter.label)}
            </Button>
          )}
        </For>
      </div>

      <Show
        when={!loading()}
        fallback={
          <p class="py-6 text-center text-sm text-ink-muted">{t(app.adminRegisterLoading)}</p>
        }
      >
        <Show
          when={rows().length > 0}
          fallback={
            <EmptyState
              title={t(app.adminShadowingEmpty)}
              description={t(app.adminShadowingEmptyBody)}
            />
          }
        >
          <Table label={t(app.adminShadowingTitle)}>
            <TableHead>
              <TableRow>
                <TableHeaderCell>{t(app.adminShadowingName)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminShadowingUpstream)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminShadowingSeen)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminShadowingActive)}</TableHeaderCell>
                <TableHeaderCell>
                  <span class="sr-only">{t(app.adminShadowingAcknowledge)}</span>
                </TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <For each={rows()}>
                {(alarm) => (
                  <TableRow>
                    <TableCell class="font-mono text-xs">{alarm.name}</TableCell>
                    <TableCell class="font-mono text-xs text-ink-muted">
                      <div class="flex flex-col">
                        <span>{alarm.upstream}</span>
                        <Show when={alarm.upstream_version}>
                          {(version) => <span class="text-ink-muted">{version()}</span>}
                        </Show>
                      </div>
                    </TableCell>
                    <TableCell class="whitespace-nowrap text-ink-muted">
                      {formatRelative(alarm.last_seen_at)}
                    </TableCell>
                    <TableCell>
                      <Badge variant={alarm.active ? "warning" : "neutral"}>
                        {formatNumber(alarm.observations)}
                      </Badge>
                    </TableCell>
                    <TableCell class="text-right">
                      <Show when={alarm.active}>
                        <Button
                          intent="outline"
                          disabled={busy() !== null}
                          onClick={() => void acknowledge(alarm)}
                        >
                          {t(app.adminShadowingAcknowledge)}
                        </Button>
                      </Show>
                    </TableCell>
                  </TableRow>
                )}
              </For>
            </TableBody>
          </Table>
        </Show>
      </Show>

      <CursorNav
        cursor={cursor()}
        next={nextCursor(page())}
        onGo={(next) => setParams({ shadowingCursor: next ?? undefined })}
      />
    </section>
  );
}

function QuarantineRegister(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const cursor = (): string | null =>
    typeof params.quarantineCursor === "string" && params.quarantineCursor !== ""
      ? params.quarantineCursor
      : null;
  const page = createAsync(() => quarantineQuery(cursor()));
  const rows = (): readonly QuarantineDto[] => page()?.items ?? [];
  const loading = (): boolean => page() === undefined;

  return (
    <section class="flex flex-col gap-4">
      <header class="flex flex-col gap-2">
        <h2 class="text-lg font-semibold text-ink">{t(app.adminQuarantineTitle)}</h2>
        <Alert intent="danger">{t(app.adminQuarantineBody)}</Alert>
      </header>

      <p role="status" class="sr-only">
        {loading() ? t(app.adminRegisterLoading) : t(app.adminRegisterLoaded)}
      </p>

      <Show
        when={!loading()}
        fallback={
          <p class="py-6 text-center text-sm text-ink-muted">{t(app.adminRegisterLoading)}</p>
        }
      >
        <Show
          when={rows().length > 0}
          fallback={
            <EmptyState
              title={t(app.adminQuarantineEmpty)}
              description={t(app.adminQuarantineEmptyBody)}
            />
          }
        >
          <Table label={t(app.adminQuarantineTitle)}>
            <TableHead>
              <TableRow>
                <TableHeaderCell>{t(app.pkgVersion)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminQuarantineExpected)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminQuarantineActual)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminShadowingActive)}</TableHeaderCell>
                <TableHeaderCell>{t(app.adminShadowingSeen)}</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <For each={rows()}>
                {(entry) => (
                  <TableRow>
                    <TableCell class="font-mono text-xs">
                      {entry.name}@{entry.version}
                    </TableCell>
                    {/*
                      Both hashes are clipped: the pair is what makes a mismatch
                      readable at a glance, and 64 hex characters each would make
                      the row unreadable on any screen an operator has.
                    */}
                    <TableCell class="font-mono text-xs text-ink-muted">
                      {entry.expected_sha256.slice(0, 16)}…
                    </TableCell>
                    <TableCell class="font-mono text-xs text-ink-muted">
                      {entry.actual_sha256.slice(0, 16)}…
                    </TableCell>
                    <TableCell>
                      <Badge variant="danger">{formatNumber(entry.occurrences)}</Badge>
                    </TableCell>
                    <TableCell class="whitespace-nowrap text-ink-muted">
                      {formatRelative(entry.last_seen_at)}
                    </TableCell>
                  </TableRow>
                )}
              </For>
            </TableBody>
          </Table>
        </Show>
      </Show>

      <CursorNav
        cursor={cursor()}
        next={nextCursor(page())}
        onGo={(next) => setParams({ quarantineCursor: next ?? undefined })}
      />
    </section>
  );
}
