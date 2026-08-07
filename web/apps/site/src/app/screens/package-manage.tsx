import type { OrgMembershipDto, PackageDetailDto, VersionSummaryDto } from "@pub/api/types";
import { PACKAGE_VISIBILITIES, roleAtLeast } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@pub/ui/dialog";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { createAsync, query, revalidate } from "@solidjs/router";
import { createSignal, For, type JSX, Show } from "solid-js";
import { formatDate, formatDateTime } from "../format";
import { api, describeError, withStepUp } from "../state/api";
import { pushToast } from "../state/toast-store";

/*
 * Package management for org members (decisions 06 and 19).
 *
 * Four operations with three different gates, and the gates are the design:
 *
 *   - **Options** (visibility / discontinued / unlisted / replaced-by) — Write+
 *     in the owning org, no step-up. They are reversible.
 *   - **Retract / unretract** — Write+ AND step-up (S-06). Retraction is not a
 *     delete: the version stays downloadable so existing lockfiles keep
 *     resolving, and it is only excluded from NEW resolutions. Unretract has a
 *     window; past it the server answers 409 and the only way forward is a new
 *     version. The UI says so before the click, not after the error.
 *   - **Hard delete** — Admin+, step-up, AND a typed confirmation of
 *     `name@version` plus a reason. The bytes are unrecoverable and the number
 *     is burned forever (S-18 tombstone), so the confirmation is a real speed
 *     bump rather than an "are you sure".
 *   - **Transfer** — Owner of BOTH orgs, step-up, typed package name.
 *
 * Every gated call goes through `withStepUp`, which opens the shared prompt on
 * `step_up_required` and retries once — the interceptor cannot retry, because
 * only the caller knows whether the action is still wanted.
 */

const versionsQuery = query(
  (name: string) => api.packages.versions(name, { limit: 50 }),
  "manage-versions",
);
const orgsQuery = query(() => api.orgs.list(), "manage-orgs");

function OptionsCard(props: { readonly detail: PackageDetailDto }): JSX.Element {
  const [visibility, setVisibility] = createSignal(props.detail.visibility);
  const [discontinued, setDiscontinued] = createSignal(props.detail.discontinued);
  const [unlisted, setUnlisted] = createSignal(props.detail.unlisted);
  const [replacedBy, setReplacedBy] = createSignal(props.detail.replaced_by ?? "");
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy()) return;
    setBusy(true);
    try {
      await api.packages.setOptions(props.detail.name, {
        visibility: visibility(),
        discontinued: discontinued(),
        unlisted: unlisted(),
        // `""` clears the replacement — the server documents that explicitly,
        // so an emptied field is a clear rather than a no-op.
        replaced_by: replacedBy().trim(),
      });
      pushToast(t(app.manageOptionsSaved), "success");
      await revalidate("package-detail");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <h2 class="text-lg font-semibold text-ink">{t(app.manageOptionsTitle)}</h2>
        <p class="text-sm text-ink-muted">{t(app.manageOptionsBody)}</p>
      </CardHeader>
      <CardContent>
        <form class="flex flex-col gap-5" onSubmit={(event) => void submit(event)}>
          <div class="grid gap-1.5">
            <Label for="manage-visibility">{t(app.manageVisibility)}</Label>
            <select
              id="manage-visibility"
              value={visibility()}
              onChange={(event) => setVisibility(event.currentTarget.value)}
              class="h-10 w-full max-w-xs rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
            >
              <For each={PACKAGE_VISIBILITIES}>
                {(value) => (
                  <option value={value}>
                    {value === "public"
                      ? t(app.manageVisibilityPublic)
                      : t(app.manageVisibilityPrivate)}
                  </option>
                )}
              </For>
            </select>
          </div>

          <label class="flex cursor-pointer items-start gap-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={unlisted()}
              onChange={(event) => setUnlisted(event.currentTarget.checked)}
              class="mt-0.5 size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
            />
            <span class="flex flex-col gap-0.5">
              <span class="font-medium">{t(app.manageUnlisted)}</span>
              <span class="text-xs text-ink-muted">{t(app.manageUnlistedHint)}</span>
            </span>
          </label>

          <label class="flex cursor-pointer items-start gap-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={discontinued()}
              onChange={(event) => setDiscontinued(event.currentTarget.checked)}
              class="mt-0.5 size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
            />
            <span class="flex flex-col gap-0.5">
              <span class="font-medium">{t(app.manageDiscontinued)}</span>
              <span class="text-xs text-ink-muted">{t(app.manageDiscontinuedHint)}</span>
            </span>
          </label>

          <div class="grid gap-1.5">
            <Label for="manage-replaced">{t(app.manageReplacedBy)}</Label>
            <Input
              id="manage-replaced"
              class="max-w-xs font-mono"
              value={replacedBy()}
              disabled={!discontinued()}
              onInput={(event) => setReplacedBy(event.currentTarget.value)}
            />
            <p class="text-xs text-ink-muted">{t(app.manageReplacedByHint)}</p>
          </div>

          <Button type="submit" class="self-start" disabled={busy()}>
            {t(app.save)}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function RetractionCard(props: { readonly detail: PackageDetailDto }): JSX.Element {
  const page = createAsync(() => versionsQuery(props.detail.name));
  const [busy, setBusy] = createSignal<string | null>(null);
  const rows = (): readonly VersionSummaryDto[] => page()?.items ?? [];

  const run = async (version: string, retract: boolean): Promise<void> => {
    if (busy() !== null) return;
    setBusy(version);
    try {
      const result = await withStepUp(() =>
        retract
          ? api.packages.retract(props.detail.name, version)
          : api.packages.unretract(props.detail.name, version),
      );
      pushToast(
        result.retracted
          ? t(app.manageRetracted, { version })
          : t(app.manageUnretracted, { version }),
        "success",
      );
      await revalidate("manage-versions");
      await revalidate("package-versions");
      await revalidate("package-detail");
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card>
      <CardHeader>
        <h2 class="text-lg font-semibold text-ink">{t(app.manageRetractTitle)}</h2>
        <p class="text-sm text-ink-muted">{t(app.manageRetractBody)}</p>
      </CardHeader>
      <CardContent class="flex flex-col gap-4">
        <Alert intent="info">{t(app.manageRetractWindow)}</Alert>
        <Show when={rows().length > 0} fallback={<p class="text-sm text-ink-muted">—</p>}>
          <Table label={t(app.manageRetractTable)}>
            <TableHead>
              <TableRow>
                <TableHeaderCell>{t(app.pkgVersion)}</TableHeaderCell>
                <TableHeaderCell>{t(app.pkgPublished)}</TableHeaderCell>
                <TableHeaderCell>{t(app.manageRetractedAt)}</TableHeaderCell>
                <TableHeaderCell>
                  <span class="sr-only">{t(app.manageRetractAction)}</span>
                </TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <For each={rows()}>
                {(version) => (
                  <TableRow>
                    <TableCell>
                      <div class="flex flex-wrap items-center gap-2">
                        <span class="font-mono">{version.version}</span>
                        <Show when={version.retracted}>
                          <Badge variant="danger">{t(app.pkgRetracted)}</Badge>
                        </Show>
                      </div>
                    </TableCell>
                    <TableCell class="whitespace-nowrap text-ink-muted">
                      {formatDate(version.published_at)}
                    </TableCell>
                    <TableCell class="whitespace-nowrap text-ink-muted">
                      {version.retracted_at === null || version.retracted_at === undefined
                        ? "—"
                        : formatDateTime(version.retracted_at)}
                    </TableCell>
                    <TableCell class="text-right">
                      <Button
                        intent={version.retracted ? "outline" : "ghost"}
                        size="sm"
                        disabled={busy() === version.version}
                        onClick={() => void run(version.version, !version.retracted)}
                      >
                        {version.retracted ? t(app.manageUnretract) : t(app.manageRetract)}
                      </Button>
                    </TableCell>
                  </TableRow>
                )}
              </For>
            </TableBody>
          </Table>
        </Show>
      </CardContent>
    </Card>
  );
}

function HardDeleteCard(props: { readonly detail: PackageDetailDto }): JSX.Element {
  const page = createAsync(() => versionsQuery(props.detail.name));
  const [open, setOpen] = createSignal(false);
  const [version, setVersion] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [reason, setReason] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const expected = (): string => `${props.detail.name}@${version()}`;
  const ready = (): boolean =>
    version() !== "" && confirm() === expected() && reason().trim() !== "";

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy() || !ready()) return;
    setBusy(true);
    setError(null);
    try {
      const result = await withStepUp(() =>
        api.packages.hardDelete(props.detail.name, version(), {
          confirm: expected(),
          reason: reason().trim(),
        }),
      );
      pushToast(t(app.manageDeleted, { version: result.version }), "success");
      setOpen(false);
      await revalidate("manage-versions");
      await revalidate("package-versions");
      await revalidate("package-detail");
    } catch (failure) {
      setError(describeError(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card class="border-danger-soft">
      <CardHeader>
        <h2 class="text-lg font-semibold text-ink">{t(app.manageDeleteTitle)}</h2>
        <p class="text-sm text-ink-muted">{t(app.manageDeleteBody)}</p>
      </CardHeader>
      <CardContent>
        <Dialog open={open()} onOpenChange={setOpen}>
          <Button
            intent="danger"
            onClick={() => {
              setVersion(page()?.items[0]?.version ?? "");
              setConfirm("");
              setReason("");
              setError(null);
              setOpen(true);
            }}
          >
            {t(app.manageDeleteAction)}
          </Button>
          <DialogContent>
            <DialogTitle>{t(app.manageDeleteTitle)}</DialogTitle>
            <DialogDescription>{t(app.manageDeleteWarning)}</DialogDescription>
            <form class="flex flex-col gap-5" onSubmit={(event) => void submit(event)}>
              <div class="grid gap-1.5">
                <Label for="delete-version">{t(app.pkgVersion)}</Label>
                <select
                  id="delete-version"
                  value={version()}
                  onChange={(event) => setVersion(event.currentTarget.value)}
                  class="h-10 w-full rounded-md border border-line bg-surface px-3 font-mono text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
                >
                  <For each={page()?.items ?? []}>
                    {(item) => <option value={item.version}>{item.version}</option>}
                  </For>
                </select>
              </div>
              <div class="grid gap-1.5">
                <Label for="delete-confirm">{t(app.manageDeleteConfirmLabel)}</Label>
                <Input
                  id="delete-confirm"
                  class="font-mono"
                  value={confirm()}
                  placeholder={expected()}
                  aria-invalid={confirm() !== "" && confirm() !== expected()}
                  onInput={(event) => setConfirm(event.currentTarget.value)}
                />
                <p class="text-xs text-ink-muted">
                  {t(app.manageDeleteConfirmHint, { expected: expected() })}
                </p>
              </div>
              <div class="grid gap-1.5">
                <Label for="delete-reason">{t(app.manageDeleteReason)}</Label>
                <Input
                  id="delete-reason"
                  value={reason()}
                  onInput={(event) => setReason(event.currentTarget.value)}
                />
                <p class="text-xs text-ink-muted">{t(app.manageDeleteReasonHint)}</p>
              </div>
              <Show when={error()}>{(message) => <Alert intent="danger">{message()}</Alert>}</Show>
              <div class="flex justify-end gap-3">
                <Button intent="ghost" onClick={() => setOpen(false)}>
                  {t(app.cancel)}
                </Button>
                <Button type="submit" intent="danger" disabled={busy() || !ready()}>
                  {t(app.manageDeleteAction)}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}

function TransferCard(props: { readonly detail: PackageDetailDto }): JSX.Element {
  const orgs = createAsync(() => orgsQuery());
  const [open, setOpen] = createSignal(false);
  const [target, setTarget] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  // Only orgs the caller OWNS can receive a transfer, and the current owner is
  // not a target — offering either would be a button whose only outcome is a
  // 403 or a 400.
  const targets = (): readonly OrgMembershipDto[] =>
    (orgs()?.items ?? []).filter(
      (item) => roleAtLeast(item.role, "owner") && item.org.slug !== props.detail.org,
    );
  const ready = (): boolean => target() !== "" && confirm() === props.detail.name;

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy() || !ready()) return;
    setBusy(true);
    setError(null);
    try {
      const result = await withStepUp(() =>
        api.packages.transfer(props.detail.name, {
          target_org: target(),
          confirm: props.detail.name,
        }),
      );
      pushToast(t(app.manageTransferred, { org: result.org }), "success");
      setOpen(false);
      await revalidate("package-detail");
    } catch (failure) {
      setError(describeError(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <h2 class="text-lg font-semibold text-ink">{t(app.manageTransferTitle)}</h2>
        <p class="text-sm text-ink-muted">{t(app.manageTransferBody)}</p>
      </CardHeader>
      <CardContent>
        <Show
          when={targets().length > 0}
          fallback={<p class="text-sm text-ink-muted">{t(app.manageTransferNoTargets)}</p>}
        >
          <Dialog open={open()} onOpenChange={setOpen}>
            <Button
              intent="outline"
              onClick={() => {
                setTarget(targets()[0]?.org.slug ?? "");
                setConfirm("");
                setError(null);
                setOpen(true);
              }}
            >
              {t(app.manageTransferAction)}
            </Button>
            <DialogContent>
              <DialogTitle>{t(app.manageTransferTitle)}</DialogTitle>
              <DialogDescription>{t(app.manageTransferWarning)}</DialogDescription>
              <form class="flex flex-col gap-5" onSubmit={(event) => void submit(event)}>
                <div class="grid gap-1.5">
                  <Label for="transfer-target">{t(app.manageTransferTarget)}</Label>
                  <select
                    id="transfer-target"
                    value={target()}
                    onChange={(event) => setTarget(event.currentTarget.value)}
                    class="h-10 w-full rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
                  >
                    <For each={targets()}>
                      {(item) => <option value={item.org.slug}>{item.org.name}</option>}
                    </For>
                  </select>
                </div>
                <div class="grid gap-1.5">
                  <Label for="transfer-confirm">{t(app.manageTransferConfirmLabel)}</Label>
                  <Input
                    id="transfer-confirm"
                    class="font-mono"
                    value={confirm()}
                    placeholder={props.detail.name}
                    aria-invalid={confirm() !== "" && confirm() !== props.detail.name}
                    onInput={(event) => setConfirm(event.currentTarget.value)}
                  />
                </div>
                <Show when={error()}>
                  {(message) => <Alert intent="danger">{message()}</Alert>}
                </Show>
                <div class="flex justify-end gap-3">
                  <Button intent="ghost" onClick={() => setOpen(false)}>
                    {t(app.cancel)}
                  </Button>
                  <Button type="submit" disabled={busy() || !ready()}>
                    {t(app.manageTransferAction)}
                  </Button>
                </div>
              </form>
            </DialogContent>
          </Dialog>
        </Show>
      </CardContent>
    </Card>
  );
}

export type PackageManageTabProps = {
  readonly detail: PackageDetailDto;
  /** The caller's role in the owning org; decides which cards appear. */
  readonly role: string | null;
};

export function PackageManageTab(props: PackageManageTabProps): JSX.Element {
  return (
    <div class="flex flex-col gap-6">
      <Alert intent="info">{t(app.manageIntro)}</Alert>
      <OptionsCard detail={props.detail} />
      <RetractionCard detail={props.detail} />
      <Show when={roleAtLeast(props.role, "admin")}>
        <HardDeleteCard detail={props.detail} />
      </Show>
      <Show when={roleAtLeast(props.role, "owner")}>
        <TransferCard detail={props.detail} />
      </Show>
    </div>
  );
}
