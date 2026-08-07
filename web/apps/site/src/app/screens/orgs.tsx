import type { OrgMembershipDto } from "@pub/api/types";
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
import { A, createAsync, query, revalidate, useParams } from "@solidjs/router";
import { createSignal, For, type JSX, Show } from "solid-js";
import { api, describeError } from "../state/api";
import { pushToast } from "../state/toast-store";
import { registryBase } from "../urls";

/*
 * Organizations: the list the caller belongs to (with their role), creation,
 * and a placeholder detail screen.
 *
 * The slug is shown as the registry base rather than as a slug, because that
 * is what it IS (decision 01: `/o/{slug}/pub` is `PUB_HOSTED_URL`) and it is
 * the value a user actually needs to copy into a `dart pub token add` or a
 * `pubspec.yaml`. It is also immutable (decision 19), which the create dialog
 * says out loud before the field is filled in rather than after.
 */

const ORGS_KEY = "orgs";
const orgsQuery = query(() => api.orgs.list(), ORGS_KEY);

const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function roleVariant(role: string): "accent" | "neutral" {
  return role === "owner" || role === "admin" ? "accent" : "neutral";
}

function CreateOrgDialog(): JSX.Element {
  const [open, setOpen] = createSignal(false);
  const [name, setName] = createSignal("");
  const [slug, setSlug] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event): Promise<void> => {
    event.preventDefault();
    if (busy()) return;
    if (name().trim() === "") {
      setError(t(app.orgsNameRequired));
      return;
    }
    if (!SLUG_PATTERN.test(slug().trim())) {
      setError(t(app.orgsSlugRequired));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.orgs.create({ name: name().trim(), slug: slug().trim() });
      pushToast(t(app.orgsCreated), "success");
      setOpen(false);
      setName("");
      setSlug("");
      await revalidate(ORGS_KEY);
    } catch (failure) {
      setError(describeError(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open()} onOpenChange={setOpen}>
      {/* Clear the previous attempt's error before reopening — see tokens.tsx. */}
      <Button
        onClick={() => {
          setError(null);
          setOpen(true);
        }}
      >
        {t(app.orgsNew)}
      </Button>
      <DialogContent>
        <DialogTitle>{t(app.orgsCreateTitle)}</DialogTitle>
        <DialogDescription>{t(app.orgsSubtitle)}</DialogDescription>
        <form class="flex flex-col gap-5" onSubmit={(event) => void submit(event)}>
          <div class="grid gap-1.5">
            <Label for="org-name">{t(app.orgsNameField)}</Label>
            <Input
              id="org-name"
              value={name()}
              autofocus
              onInput={(event) => {
                setName(event.currentTarget.value);
                // Suggest a slug while the field is untouched; stop as soon as
                // the user edits it themselves.
                if (slug() === "" || slug() === suggestSlug(name())) {
                  setSlug(suggestSlug(event.currentTarget.value));
                }
              }}
            />
          </div>
          <div class="grid gap-1.5">
            <Label for="org-slug">{t(app.orgsSlugField)}</Label>
            <Input
              id="org-slug"
              value={slug()}
              class="font-mono"
              onInput={(event) => setSlug(event.currentTarget.value)}
            />
            <p class="text-xs text-ink-muted">{t(app.orgsSlugHint)}</p>
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

function suggestSlug(name: string): string {
  return name
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/g, "-")
    .replaceAll(/^-+|-+$/g, "");
}

export function OrgsScreen(): JSX.Element {
  const orgs = createAsync(() => orgsQuery());
  const rows = (): readonly OrgMembershipDto[] => orgs()?.items ?? [];

  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex flex-col gap-2">
          <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.orgsTitle)}</h1>
          <p class="max-w-2xl text-ink-muted">{t(app.orgsSubtitle)}</p>
        </div>
        <CreateOrgDialog />
      </header>

      <Show
        when={rows().length > 0}
        fallback={<EmptyState title={t(app.orgsEmpty)} description={t(app.orgsEmptyBody)} />}
      >
        <div class="grid gap-4 sm:grid-cols-2">
          <For each={rows()}>
            {(membership) => (
              <Card>
                <CardHeader>
                  <div class="flex items-start justify-between gap-3">
                    <A
                      href={`/orgs/${membership.org.slug}`}
                      class="rounded-md text-lg font-semibold text-ink outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {membership.org.name}
                    </A>
                    <Badge variant={roleVariant(membership.role)} aria-label={t(app.orgsRole)}>
                      {membership.role}
                    </Badge>
                  </div>
                  <Show when={membership.org.description !== ""}>
                    <p class="text-sm text-ink-muted">{membership.org.description}</p>
                  </Show>
                </CardHeader>
                <CardContent class="flex flex-col gap-2">
                  <p class="text-xs font-medium text-ink-muted">{t(app.orgsRegistryUrl)}</p>
                  <div class="flex items-center gap-2">
                    <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-xs text-ink">
                      {registryBase(membership.org.slug, window.location.origin)}
                    </code>
                    <CopyButton value={registryBase(membership.org.slug, window.location.origin)} />
                  </div>
                </CardContent>
              </Card>
            )}
          </For>
        </div>
      </Show>
    </section>
  );
}

/**
 * Single-organization screen.
 *
 * Deliberately a marked placeholder: members, invitations, packages, settings,
 * and the audit log all live behind management endpoints that are being built
 * right now. Rendering plausible-looking empty tables here would be worse than
 * saying so — it would read as "this org has no members".
 */
export function OrgDetailScreen(): JSX.Element {
  const params = useParams<{ slug: string }>();
  const orgs = createAsync(() => orgsQuery());
  const membership = (): OrgMembershipDto | undefined =>
    orgs()?.items.find((item) => item.org.slug === params.slug);

  return (
    <section class="flex flex-col gap-6">
      <header>
        <p class="text-sm text-ink-muted">{t(app.orgDetailTitle)}</p>
        <h1 class="text-3xl font-bold tracking-tight text-ink">
          {membership()?.org.name ?? params.slug}
        </h1>
      </header>

      <Card>
        <CardHeader>
          <div class="flex flex-wrap items-center gap-3">
            <Badge variant="warning">{t(app.comingSoon)}</Badge>
            <Show when={membership()}>
              {(item) => (
                <Badge variant={roleVariant(item().role)}>
                  {t(app.orgsRole)}: {item().role}
                </Badge>
              )}
            </Show>
          </div>
        </CardHeader>
        <CardContent class="flex flex-col gap-4">
          <p class="text-sm leading-relaxed text-ink-muted">{t(app.orgDetailTodo)}</p>
          <div class="flex flex-col gap-2">
            <p class="text-xs font-medium text-ink-muted">{t(app.orgsRegistryUrl)}</p>
            <div class="flex items-center gap-2">
              <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-xs text-ink">
                {registryBase(params.slug, window.location.origin)}
              </code>
              <CopyButton value={registryBase(params.slug, window.location.origin)} />
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
