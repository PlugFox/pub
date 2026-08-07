import { scopesNeedStepUp } from "@pub/api/tokens";
import {
  type OrgMembershipDto,
  TOKEN_SCOPES,
  type TokenCreatedDto,
  type TokenDto,
  type TokenScope,
} from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { CopyButton } from "@pub/ui/copy-button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@pub/ui/dialog";
import { EmptyState } from "@pub/ui/empty-state";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { createAsync, query, revalidate } from "@solidjs/router";
import { createMemo, createSignal, For, type JSX, Show } from "solid-js";
import { formatDate, formatDateTime } from "../format";
import { api, describeError, withStepUp } from "../state/api";
import { pushToast } from "../state/toast-store";
import { registryBase } from "../urls";

/*
 * CLI/API tokens (S-13).
 *
 * Two things here are not cosmetic:
 *
 *   - the show-once panel is the ONLY time the secret exists in the UI — the
 *     server keeps a SHA-256 and a first-eight hint, so a user who closes it
 *     without copying has to mint a new token;
 *   - the `dart pub token add <base>` line is rendered with the *real* base
 *     for the selected org, because a token pasted against the wrong base is
 *     the single most common self-inflicted failure with a private registry.
 */

const TOKENS_KEY = "tokens";
const tokensQuery = query(() => api.tokens.list(), TOKENS_KEY);
const orgsQuery = query(() => api.orgs.list(), "tokens-orgs");

const SCOPE_LABELS: Record<TokenScope, { readonly id: string; readonly en: string }> = {
  read: app.tokensScopeRead,
  publish: app.tokensScopePublish,
  retract: app.tokensScopeRetract,
  admin: app.tokensScopeAdmin,
};

function CreateTokenDialog(props: {
  readonly orgs: readonly OrgMembershipDto[];
  readonly onCreated: (created: TokenCreatedDto) => void;
}): JSX.Element {
  const [open, setOpen] = createSignal(false);
  const [label, setLabel] = createSignal("");
  const [orgId, setOrgId] = createSignal("");
  const [scopes, setScopes] = createSignal<readonly TokenScope[]>(["read"]);
  const [expiresDays, setExpiresDays] = createSignal(90);
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const reset = (): void => {
    setLabel("");
    setOrgId(props.orgs[0]?.org.id ?? "");
    setScopes(["read"]);
    setExpiresDays(90);
    setError(null);
    setBusy(false);
  };

  const toggleScope = (scope: TokenScope): void => {
    setScopes((current) =>
      current.includes(scope) ? current.filter((item) => item !== scope) : [...current, scope],
    );
  };

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy()) return;
    if (orgId() === "") {
      setError(t(app.tokensOrgRequired));
      return;
    }
    if (scopes().length === 0) {
      setError(t(app.tokensScopesRequired));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await withStepUp(() =>
        api.tokens.create({
          label: label().trim() === "" ? undefined : label().trim(),
          org_id: orgId(),
          scopes: scopes(),
          expires_days: expiresDays() > 0 ? expiresDays() : undefined,
        }),
      );
      setOpen(false);
      props.onCreated(created);
    } catch (failure) {
      setError(describeError(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open()} onOpenChange={setOpen}>
      {/*
        Reset happens HERE, on the control that opens the dialog, not in
        `onOpenChange`: Kobalte only calls that callback for state changes it
        drives itself, so a programmatic `setOpen(true)` would never have run
        it — and the dialog would open with `orgId` still "", refusing its own
        submit with "choose an organization" while showing an organization.
      */}
      <Button
        onClick={() => {
          reset();
          setOpen(true);
        }}
      >
        {t(app.tokensNew)}
      </Button>
      <DialogContent>
        <DialogTitle>{t(app.tokensCreateTitle)}</DialogTitle>
        <DialogDescription>{t(app.tokensSubtitle)}</DialogDescription>
        <form class="flex flex-col gap-5" onSubmit={(event) => void submit(event)}>
          <div class="grid gap-1.5">
            <Label for="token-label">{t(app.tokensLabelField)}</Label>
            <Input
              id="token-label"
              value={label()}
              placeholder={t(app.tokensLabelPlaceholder)}
              onInput={(event) => setLabel(event.currentTarget.value)}
            />
          </div>

          <div class="grid gap-1.5">
            <Label for="token-org">{t(app.tokensOrg)}</Label>
            <select
              id="token-org"
              value={orgId()}
              onChange={(event) => setOrgId(event.currentTarget.value)}
              class="h-10 w-full rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
            >
              <For each={props.orgs}>
                {(membership) => <option value={membership.org.id}>{membership.org.name}</option>}
              </For>
            </select>
          </div>

          <fieldset class="grid gap-2">
            <legend class="pb-1 text-sm font-medium text-ink">{t(app.tokensScopesField)}</legend>
            <For each={TOKEN_SCOPES}>
              {(scope) => (
                <label class="flex cursor-pointer items-center gap-2 text-sm text-ink">
                  <input
                    type="checkbox"
                    checked={scopes().includes(scope)}
                    onChange={() => toggleScope(scope)}
                    // The native checkbox keeps its own control rendering
                    // (`accent-accent`); only the focus ring is replaced, so
                    // it matches every other control in the dialog.
                    class="size-4 accent-accent outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                  />
                  <span>{t(SCOPE_LABELS[scope])}</span>
                </label>
              )}
            </For>
          </fieldset>

          <Show when={scopesNeedStepUp(scopes())}>
            <Alert intent="warning">{t(app.tokensStepUpNotice)}</Alert>
          </Show>

          <div class="grid gap-1.5">
            <Label for="token-expiry">{t(app.tokensExpiryField)}</Label>
            <Input
              id="token-expiry"
              type="number"
              min={1}
              max={3650}
              value={String(expiresDays())}
              onInput={(event) => setExpiresDays(Number(event.currentTarget.value))}
            />
          </div>

          <Show when={error()}>{(message) => <Alert intent="danger">{message()}</Alert>}</Show>

          <div class="flex justify-end gap-3">
            <Button intent="ghost" onClick={() => setOpen(false)}>
              {t(app.cancel)}
            </Button>
            <Button type="submit" disabled={busy()}>
              {t(app.create)}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function SecretPanel(props: {
  readonly created: TokenCreatedDto;
  readonly base: string;
  readonly onDismiss: () => void;
}): JSX.Element {
  const command = (): string => `dart pub token add ${props.base}`;
  return (
    <Card class="border-warning-soft bg-warning-soft/40">
      <CardHeader>
        <h2 class="text-lg font-semibold text-ink">{t(app.tokensSecretTitle)}</h2>
        <p class="text-sm text-warning-ink">{t(app.tokensSecretBody)}</p>
      </CardHeader>
      <CardContent class="flex flex-col gap-5">
        <div class="flex flex-wrap items-center gap-3">
          <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-surface px-3 py-2 font-mono text-sm text-ink">
            {props.created.secret}
          </code>
          <CopyButton value={props.created.secret} />
        </div>
        <div class="flex flex-col gap-2">
          <p class="text-sm text-ink-muted">{t(app.tokensSecretCli)}</p>
          <div class="flex flex-wrap items-center gap-3">
            <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-surface px-3 py-2 font-mono text-sm text-ink">
              {command()}
            </code>
            <CopyButton value={command()} />
          </div>
        </div>
        <Button intent="outline" class="self-start" onClick={props.onDismiss}>
          {t(app.securityRecoveryDone)}
        </Button>
      </CardContent>
    </Card>
  );
}

export function TokensScreen(): JSX.Element {
  const tokens = createAsync(() => tokensQuery());
  const orgs = createAsync(() => orgsQuery());
  const [created, setCreated] = createSignal<TokenCreatedDto | null>(null);
  const [pendingRevoke, setPendingRevoke] = createSignal<TokenDto | null>(null);
  const [busy, setBusy] = createSignal(false);

  const rows = (): readonly TokenDto[] => tokens()?.items ?? [];
  const orgList = (): readonly OrgMembershipDto[] => orgs()?.items ?? [];
  const orgName = (id: string): string =>
    orgList().find((membership) => membership.org.id === id)?.org.name ?? id;
  const createdBase = createMemo(() => {
    const value = created();
    if (value === null) return "";
    const slug = orgList().find((m) => m.org.id === value.token.org_id)?.org.slug;
    return slug === undefined
      ? `${window.location.origin}/pub`
      : registryBase(slug, window.location.origin);
  });

  const confirmRevoke = async (): Promise<void> => {
    const token = pendingRevoke();
    if (token === null || busy()) return;
    setBusy(true);
    try {
      await api.tokens.revoke(token.id);
      pushToast(t(app.tokensRevoked), "success");
      setPendingRevoke(null);
      await revalidate(TOKENS_KEY);
    } catch (error) {
      pushToast(describeError(error), "danger");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex flex-col gap-2">
          <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.tokensTitle)}</h1>
          <p class="max-w-2xl text-ink-muted">{t(app.tokensSubtitle)}</p>
        </div>
        <CreateTokenDialog
          orgs={orgList()}
          onCreated={(value) => {
            setCreated(value);
            pushToast(t(app.tokensCreated), "success");
            void revalidate(TOKENS_KEY);
          }}
        />
      </header>

      <Show when={created()}>
        {(value) => (
          <SecretPanel created={value()} base={createdBase()} onDismiss={() => setCreated(null)} />
        )}
      </Show>

      <Show
        when={rows().length > 0}
        fallback={<EmptyState title={t(app.tokensEmpty)} description={t(app.tokensEmptyBody)} />}
      >
        <Table label={t(app.tokensTableLabel)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.tokensHint)}</TableHeaderCell>
              <TableHeaderCell>{t(app.tokensScopes)}</TableHeaderCell>
              <TableHeaderCell>{t(app.tokensOrg)}</TableHeaderCell>
              <TableHeaderCell>{t(app.tokensExpires)}</TableHeaderCell>
              <TableHeaderCell>{t(app.tokensLastUsed)}</TableHeaderCell>
              <TableHeaderCell>
                <span class="sr-only">{t(app.revoke)}</span>
              </TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(token) => (
                <TableRow>
                  <TableCell>
                    <div class="flex flex-col">
                      <span class="font-medium">{token.name}</span>
                      <span class="font-mono text-xs text-ink-muted">{token.display_hint}…</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div class="flex flex-wrap gap-1">
                      <For each={token.scopes}>
                        {(scope) => (
                          <Badge
                            variant={
                              scope === "admin" || scope === "publish" ? "warning" : "neutral"
                            }
                            class="font-mono"
                          >
                            {scope}
                          </Badge>
                        )}
                      </For>
                    </div>
                  </TableCell>
                  <TableCell class="whitespace-nowrap">{orgName(token.org_id)}</TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {token.expires_at === null ? t(app.tokensNever) : formatDate(token.expires_at)}
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {token.last_used_at === null
                      ? t(app.tokensNever)
                      : formatDateTime(token.last_used_at)}
                  </TableCell>
                  <TableCell class="text-right">
                    <Button intent="ghost" size="sm" onClick={() => setPendingRevoke(token)}>
                      {t(app.revoke)}
                    </Button>
                  </TableCell>
                </TableRow>
              )}
            </For>
          </TableBody>
        </Table>
      </Show>

      <Dialog
        open={pendingRevoke() !== null}
        onOpenChange={(open) => !open && setPendingRevoke(null)}
      >
        <DialogContent>
          <DialogTitle>{t(app.tokensRevokeTitle)}</DialogTitle>
          <DialogDescription>
            {t(app.tokensRevokeBody, { name: pendingRevoke()?.name ?? "" })}
          </DialogDescription>
          <div class="flex justify-end gap-3">
            <Button intent="ghost" onClick={() => setPendingRevoke(null)}>
              {t(app.cancel)}
            </Button>
            <Button intent="danger" disabled={busy()} onClick={() => void confirmRevoke()}>
              {t(app.revoke)}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  );
}
