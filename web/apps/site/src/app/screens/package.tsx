import type {
  OrgMembershipDto,
  PackageDetailDto,
  PackageSummaryDto,
  VersionSummaryDto,
} from "@pub/api/types";
import { roleAtLeast } from "@pub/api/types";
import { t, tp } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button } from "@pub/ui/button";
import { cn } from "@pub/ui/cn";
import { CopyButton } from "@pub/ui/copy-button";
import { EmptyState } from "@pub/ui/empty-state";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { A, createAsync, query, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { createMemo, For, type JSX, Show } from "solid-js";
import { CursorNav, nextCursor, readCursor } from "../cursor-nav";
import { formatBytes, formatDate, formatNumber, formatRelative } from "../format";
import { PackageCard, PackageFlags } from "../package-card";
import { PACKAGE_TABS, type PackageTab, packageTabPath, readPackageTab } from "../package-tabs";
import { Prose } from "../prose";
import { api } from "../state/api";
import { instancePublicUrl } from "../state/instance-store";
import { isAuthenticated } from "../state/session-store";
import { orgPath, packageVersionPath, pubspecSnippet, registryBase } from "../urls";
import { PackageManageTab } from "./package-manage";

/*
 * The package page.
 *
 * Tabs are routed (see `package-tabs.ts`), so every one of them is a URL a
 * reader can paste. The heavy tabs load their own data — the versions list and
 * the dependents list are cursor-paginated and have no business being fetched
 * because somebody opened the README.
 *
 * A 404 here means "unknown name OR a name this principal may not read"
 * (decision 05): the server refuses to distinguish them, and so does this
 * screen. There is deliberately no "request access" affordance — offering one
 * would tell an unauthenticated prober that the name exists.
 *
 * The retracted-latest explanation is the one flag that needs prose rather
 * than a badge: `latest_retracted` means the NEWEST version is retracted and
 * `latest_version` is therefore an older one, which is exactly the situation
 * where a reader would otherwise conclude the page is buggy.
 */

const detailQuery = query((name: string) => api.packages.detail(name), "package-detail");
const versionsQuery = query(
  (input: { name: string; cursor: string | null }) =>
    api.packages.versions(input.name, { cursor: input.cursor ?? undefined, limit: 50 }),
  "package-versions",
);
const dependentsQuery = query(
  (input: { name: string; cursor: string | null }) =>
    api.packages.dependents(input.name, { cursor: input.cursor ?? undefined, limit: 50 }),
  "package-dependents",
);
const versionQuery = query(
  (input: { name: string; version: string }) => api.packages.version(input.name, input.version),
  "package-version",
);
const membershipsQuery = query(() => api.orgs.list(), "package-orgs");

const TAB_LABELS: Record<PackageTab, { readonly id: string; readonly en: string }> = {
  readme: app.pkgTabReadme,
  changelog: app.pkgTabChangelog,
  versions: app.pkgTabVersions,
  dependents: app.pkgTabDependents,
  installing: app.pkgTabInstalling,
  manage: app.pkgTabManage,
};

/**
 * The caller's role in the owning org, or `null` when they are not a member.
 *
 * The membership list is only fetched for a signed-in reader: this screen is
 * anonymous-reachable, and `GET /orgs` would answer 401 for a visitor — one
 * pointless request per package page, plus a spurious refresh attempt.
 */
function useOrgRole(orgSlug: () => string | undefined): () => string | null {
  const memberships = createAsync(async () =>
    isAuthenticated() ? await membershipsQuery() : null,
  );
  return () => {
    const slug = orgSlug();
    if (slug === undefined) return null;
    const items: readonly OrgMembershipDto[] = memberships()?.items ?? [];
    return items.find((item) => item.org.slug === slug)?.role ?? null;
  };
}

/**
 * One routed tab.
 *
 * Deliberately NOT `role="tab"`. The ARIA tab pattern promises a tab list a
 * screen reader user navigates with arrow keys and panels that swap in place;
 * these are links that change the URL, and claiming the role without the
 * roving focus behaviour is worse than plain navigation semantics. So: a
 * labelled `<nav>` of links, with `aria-current="page"` marking the open one.
 */
function TabLink(props: {
  readonly name: string;
  readonly tab: PackageTab;
  readonly active: boolean;
}): JSX.Element {
  return (
    <A
      href={packageTabPath(props.name, props.tab)}
      aria-current={props.active ? "page" : undefined}
      class={cn(
        "-mb-px cursor-pointer border-b-2 px-4 py-2 text-sm font-medium outline-none",
        "transition-colors focus-visible:ring-2 focus-visible:ring-accent",
        props.active
          ? "border-accent text-ink"
          : "border-transparent text-ink-muted hover:text-ink",
      )}
    >
      {t(TAB_LABELS[props.tab])}
    </A>
  );
}

/**
 * The cursor of the open tab.
 *
 * ONE parameter for both paginated tabs, and that is safe for the reason a
 * shared parameter usually is not: the tab is part of the PATH, so only one
 * list is mounted at a time, and a tab link carries no query string — moving
 * between them drops the cursor rather than presenting the versions cursor to
 * the dependents endpoint (decision 40's slice rule; `search-query.ts` enforces
 * the same thing for `sort`).
 */
function useTabCursor(): [() => string | null, (cursor: string | null) => void] {
  const [params, setParams] = useSearchParams();
  return [() => readCursor(params.cursor), (cursor) => setParams({ cursor: cursor ?? undefined })];
}

function VersionsTab(props: { readonly name: string }): JSX.Element {
  const [cursor, goTo] = useTabCursor();
  const page = createAsync(() => versionsQuery({ name: props.name, cursor: cursor() }));
  const rows = (): readonly VersionSummaryDto[] => page()?.items ?? [];
  return (
    <div class="flex flex-col gap-4">
      <Show when={rows().length > 0} fallback={<EmptyState title={t(app.pkgVersionsEmpty)} />}>
        <Table label={t(app.pkgVersionsTable)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.pkgVersion)}</TableHeaderCell>
              <TableHeaderCell>{t(app.pkgPublished)}</TableHeaderCell>
              <TableHeaderCell>{t(app.pkgArchiveSize)}</TableHeaderCell>
              <TableHeaderCell>{t(app.pkgPublisher)}</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(version) => (
                <TableRow>
                  <TableCell>
                    <div class="flex flex-wrap items-center gap-2">
                      <A
                        href={packageVersionPath(props.name, version.version)}
                        class="rounded-sm font-mono font-medium text-ink outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
                      >
                        {version.version}
                      </A>
                      <Show when={version.retracted}>
                        <Badge variant="danger">{t(app.pkgRetracted)}</Badge>
                      </Show>
                    </div>
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatDate(version.published_at)}
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatBytes(version.archive_size)}
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {version.publisher?.display_name ?? "—"}
                  </TableCell>
                </TableRow>
              )}
            </For>
          </TableBody>
        </Table>
      </Show>
      {/*
        The pub protocol's listing is the machine view and keeps its own bounds
        (decision 32); this is the human one, and a person looking for the
        version they published last Tuesday is not going to read the JSON.
      */}
      <CursorNav cursor={cursor()} next={nextCursor(page())} onGo={goTo} />
    </div>
  );
}

function DependentsTab(props: { readonly name: string }): JSX.Element {
  const [cursor, goTo] = useTabCursor();
  const page = createAsync(() => dependentsQuery({ name: props.name, cursor: cursor() }));
  const rows = (): readonly PackageSummaryDto[] => page()?.items ?? [];
  return (
    <div class="flex flex-col gap-4">
      <Show
        when={rows().length > 0}
        fallback={
          <EmptyState
            title={t(app.pkgDependentsEmpty)}
            description={t(app.pkgDependentsEmptyBody)}
          />
        }
      >
        <ul class="flex flex-col gap-4">
          <For each={rows()}>
            {(item) => (
              <li>
                <PackageCard item={item} />
              </li>
            )}
          </For>
        </ul>
      </Show>
      <CursorNav cursor={cursor()} next={nextCursor(page())} onGo={goTo} />
    </div>
  );
}

function InstallingTab(props: { readonly detail: PackageDetailDto }): JSX.Element {
  const hosted = (): string => registryBase(props.detail.org, instancePublicUrl());
  const snippet = (): string =>
    pubspecSnippet(props.detail.name, props.detail.latest_version, hosted());
  const command = (): string => `dart pub token add ${hosted()}`;
  return (
    <div class="flex flex-col gap-8">
      <section class="flex flex-col gap-3">
        <h2 class="text-lg font-semibold text-ink">{t(app.pkgInstallPubspecTitle)}</h2>
        <p class="max-w-2xl text-sm text-ink-muted">{t(app.pkgInstallPubspecBody)}</p>
        <div class="flex flex-col gap-2">
          <pre class="overflow-x-auto rounded-lg border border-line bg-canvas p-4 font-mono text-sm text-ink">
            {snippet()}
          </pre>
          <CopyButton value={snippet()} class="self-start" />
        </div>
      </section>

      <section class="flex flex-col gap-3">
        <h2 class="text-lg font-semibold text-ink">{t(app.pkgInstallHostedTitle)}</h2>
        <p class="max-w-2xl text-sm text-ink-muted">{t(app.pkgInstallHostedBody)}</p>
        <div class="flex flex-wrap items-center gap-3">
          <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-sm text-ink">
            {hosted()}
          </code>
          <CopyButton value={hosted()} />
        </div>
      </section>

      <Show when={props.detail.visibility === "private"}>
        <section class="flex flex-col gap-3">
          <h2 class="text-lg font-semibold text-ink">{t(app.pkgInstallTokenTitle)}</h2>
          <p class="max-w-2xl text-sm text-ink-muted">{t(app.pkgInstallTokenBody)}</p>
          <div class="flex flex-wrap items-center gap-3">
            <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-sm text-ink">
              {command()}
            </code>
            <CopyButton value={command()} />
          </div>
        </section>
      </Show>
    </div>
  );
}

function DetailHeader(props: { readonly detail: PackageDetailDto }): JSX.Element {
  const hosted = (): string => registryBase(props.detail.org, instancePublicUrl());
  const dependencyLine = (): string =>
    pubspecSnippet(props.detail.name, props.detail.latest_version, hosted());
  return (
    <header class="flex flex-col gap-4">
      <div class="flex flex-wrap items-baseline gap-x-3 gap-y-2">
        <h1 class="text-3xl font-bold tracking-tight text-ink">{props.detail.name}</h1>
        <span class="font-mono text-lg text-ink-muted">{props.detail.latest_version}</span>
        <div class="flex flex-wrap items-center gap-1.5">
          <PackageFlags item={props.detail} />
        </div>
      </div>

      <Show when={props.detail.description !== ""}>
        <p class="max-w-3xl text-ink-muted">{props.detail.description}</p>
      </Show>

      <div class="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-ink-muted">
        <span>
          {t(app.pkgOrg)}{" "}
          <A
            href={orgPath(props.detail.org)}
            class="rounded-sm font-medium text-ink outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
          >
            {props.detail.org_name === "" ? props.detail.org : props.detail.org_name}
          </A>
        </span>
        <span>
          {t(app.pkgDownloads)}{" "}
          <span class="font-medium text-ink">{formatNumber(props.detail.downloads.total)}</span>
        </span>
        <span>
          {t(app.pkgUpdated)} {formatRelative(props.detail.updated_at)}
        </span>
        <span>
          {tp(app.pkgVersionCount, props.detail.versions_count, {
            count: formatNumber(props.detail.versions_count),
          })}
        </span>
      </div>

      {/* The exact line a reader came here to copy. */}
      <div class="flex flex-wrap items-center gap-3">
        <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-xs whitespace-pre text-ink">
          {dependencyLine()}
        </code>
        <CopyButton value={dependencyLine()} />
      </div>

      <Show when={props.detail.discontinued}>
        <Alert intent="warning">
          <span>
            {t(app.pkgDiscontinuedBody)}
            <Show when={props.detail.replaced_by}>
              {(replacement) => (
                <>
                  {" "}
                  <A
                    href={`/packages/${encodeURIComponent(replacement())}`}
                    class="rounded-sm font-medium underline outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {t(app.pkgReplacedBy, { name: replacement() })}
                  </A>
                </>
              )}
            </Show>
          </span>
        </Alert>
      </Show>

      <Show when={props.detail.latest_retracted}>
        {/*
          Not a duplicate of the badge: the badge says WHAT, this says what it
          means for the version above it, which is the part a reader gets wrong.
        */}
        <Alert intent="danger">{t(app.pkgLatestRetractedBody)}</Alert>
      </Show>

      <Show when={props.detail.unlisted}>
        <Alert intent="info">{t(app.pkgUnlistedBody)}</Alert>
      </Show>
    </header>
  );
}

export function PackageDetailScreen(): JSX.Element {
  const params = useParams<{ name: string; tab?: string }>();
  const detail = createAsync(() => detailQuery(params.name));
  const tab = createMemo(() => readPackageTab(params.tab));
  const role = useOrgRole(() => detail()?.org);
  const canManage = (): boolean => roleAtLeast(role(), "write");
  const visibleTabs = createMemo(() =>
    PACKAGE_TABS.filter((entry) => entry !== "manage" || canManage()),
  );

  return (
    <Show when={detail()}>
      {(loaded) => (
        <section class="flex flex-col gap-6">
          <DetailHeader detail={loaded()} />

          {/*
            Routed sections, not the Kobalte Tabs primitive: the primitive owns
            its own selection state, and here the URL owns it.
          */}
          <nav aria-label={t(app.pkgTabs)} class="border-b border-line">
            <ul class="flex overflow-x-auto">
              <For each={visibleTabs()}>
                {(entry) => (
                  <li class="shrink-0">
                    <TabLink name={loaded().name} tab={entry} active={tab() === entry} />
                  </li>
                )}
              </For>
            </ul>
          </nav>

          <div class="min-w-0">
            <Show when={tab() === "readme"}>
              <Prose
                html={loaded().readme_html}
                fallback={<EmptyState title={t(app.pkgNoReadme)} />}
              />
            </Show>
            <Show when={tab() === "changelog"}>
              <ChangelogTab name={loaded().name} version={loaded().latest_version} />
            </Show>
            <Show when={tab() === "versions"}>
              <VersionsTab name={loaded().name} />
            </Show>
            <Show when={tab() === "dependents"}>
              <DependentsTab name={loaded().name} />
            </Show>
            <Show when={tab() === "installing"}>
              <InstallingTab detail={loaded()} />
            </Show>
            <Show when={tab() === "manage" && canManage()}>
              <PackageManageTab detail={loaded()} role={role()} />
            </Show>
          </div>
        </section>
      )}
    </Show>
  );
}

/**
 * The changelog of the newest live version.
 *
 * It comes from the VERSION endpoint, not from the package detail: a changelog
 * belongs to a release, and the package payload only carries the README to
 * keep the first paint of the most-visited tab small.
 */
function ChangelogTab(props: { readonly name: string; readonly version: string }): JSX.Element {
  const version = createAsync(() => versionQuery({ name: props.name, version: props.version }));
  return (
    <Prose
      html={version()?.changelog_html}
      fallback={<EmptyState title={t(app.pkgNoChangelog)} />}
    />
  );
}

/**
 * One version's page — the deep link out of the versions tab.
 *
 * Reuses the same prose rendering and the same installing snippet, pinned to
 * this version rather than to the latest one: somebody who navigated here did
 * so because they care about this specific release.
 */
export function VersionDetailScreen(): JSX.Element {
  const params = useParams<{ name: string; version: string }>();
  const navigate = useNavigate();
  const version = createAsync(() => versionQuery({ name: params.name, version: params.version }));
  const hosted = createAsync(async () => {
    const detail = await detailQuery(params.name);
    return registryBase(detail.org, instancePublicUrl());
  });
  const snippet = (): string =>
    pubspecSnippet(params.name, params.version, hosted() ?? instancePublicUrl());

  return (
    <Show when={version()}>
      {(loaded) => (
        <section class="flex flex-col gap-6">
          <header class="flex flex-col gap-3">
            <A
              href={packageTabPath(params.name, "versions")}
              class="w-fit rounded-sm text-sm text-ink-muted outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
            >
              ← {params.name}
            </A>
            <div class="flex flex-wrap items-baseline gap-3">
              <h1 class="text-3xl font-bold tracking-tight text-ink">{params.name}</h1>
              <span class="font-mono text-lg text-ink-muted">{loaded().version}</span>
              <Show when={loaded().retracted}>
                <Badge variant="danger">{t(app.pkgRetracted)}</Badge>
              </Show>
            </div>
            <dl class="flex flex-wrap gap-x-6 gap-y-1 text-sm text-ink-muted">
              <div class="flex gap-1">
                <dt>{t(app.pkgPublished)}</dt>
                <dd class="text-ink">{formatDate(loaded().published_at)}</dd>
              </div>
              <div class="flex gap-1">
                <dt>{t(app.pkgArchiveSize)}</dt>
                <dd class="text-ink">{formatBytes(loaded().archive_size)}</dd>
              </div>
              <Show when={loaded().publisher}>
                {(publisher) => (
                  <div class="flex gap-1">
                    <dt>{t(app.pkgPublisher)}</dt>
                    <dd class="text-ink">{publisher().display_name}</dd>
                  </div>
                )}
              </Show>
            </dl>
            <div class="flex flex-wrap items-center gap-3">
              <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-xs text-ink">
                {loaded().archive_sha256}
              </code>
              <CopyButton value={loaded().archive_sha256} />
            </div>
            <Show when={loaded().retracted}>
              <Alert intent="danger">{t(app.pkgVersionRetractedBody)}</Alert>
            </Show>
          </header>

          <section class="flex flex-col gap-3">
            <h2 class="text-lg font-semibold text-ink">{t(app.pkgTabInstalling)}</h2>
            <div class="flex flex-col gap-2">
              <pre class="overflow-x-auto rounded-lg border border-line bg-canvas p-4 font-mono text-sm text-ink">
                {snippet()}
              </pre>
              <CopyButton value={snippet()} class="self-start" />
            </div>
          </section>

          <section class="flex flex-col gap-3">
            <h2 class="text-lg font-semibold text-ink">{t(app.pkgTabChangelog)}</h2>
            <Prose
              html={loaded().changelog_html}
              fallback={<EmptyState title={t(app.pkgNoChangelog)} />}
            />
          </section>

          <section class="flex flex-col gap-3">
            <h2 class="text-lg font-semibold text-ink">{t(app.pkgTabReadme)}</h2>
            <Prose
              html={loaded().readme_html}
              fallback={<EmptyState title={t(app.pkgNoReadme)} />}
            />
          </section>

          <Button
            intent="ghost"
            class="self-start"
            onClick={() => navigate(packageTabPath(params.name, "versions"))}
          >
            {t(app.pkgBackToVersions)}
          </Button>
        </section>
      )}
    </Show>
  );
}
