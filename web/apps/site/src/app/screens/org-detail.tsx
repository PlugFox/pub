import type { MemberDto, PackageSummaryDto } from "@pub/api/types";
import { roleAtLeast } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Badge } from "@pub/ui/badge";
import { buttonVariants } from "@pub/ui/button";
import { Card, CardContent, CardHeader } from "@pub/ui/card";
import { cn } from "@pub/ui/cn";
import { CopyButton } from "@pub/ui/copy-button";
import { EmptyState } from "@pub/ui/empty-state";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@pub/ui/table";
import { A, createAsync, query, useParams } from "@solidjs/router";
import { For, type JSX, Show } from "solid-js";
import { formatDate } from "../format";
import { PackageCard } from "../package-card";
import { api } from "../state/api";
import { instancePublicUrl } from "../state/instance-store";
import { isAuthenticated } from "../state/session-store";
import { registryBase } from "../urls";

/*
 * One organization: profile, registry base, packages, and — for members — the
 * member list.
 *
 * TWO REQUESTS, TWO AUDIENCES, and the split is the point:
 *
 *   - `GET /orgs/{slug}` is anonymous-reachable. Slugs are not secret (S-04.b)
 *     and the package list runs through the same visibility view search does,
 *     so a stranger sees the org's public, listed packages and nothing else.
 *   - `GET /orgs/{slug}/members` is **Admin+** (`Action::ManageMembers`) and
 *     answers 403 to everyone else. It is therefore fetched ONLY when the
 *     profile came back with a role of at least Admin, rather than
 *     fetched-and-caught: a 403 the UI expected is still a 403 in the server
 *     log and in the audit trail. Gating it on "has any role" instead — which
 *     is what this screen used to do — turned the whole org page into an error
 *     state for every Read and Write member, because one rejected query in a
 *     screen rejects the screen.
 *
 * Management (roles, invitations, danger zone) is Admin+ and lives on its own
 * surface; from here it is a link, so this screen stays the org's public face.
 */

const profileQuery = query((slug: string) => api.orgs.profile(slug, { limit: 30 }), "org-profile");
const membersQuery = query((slug: string) => api.orgs.members(slug), "org-members");

function roleVariant(role: string): "accent" | "neutral" {
  return role === "owner" || role === "admin" ? "accent" : "neutral";
}

function MembersCard(props: { readonly slug: string }): JSX.Element {
  const members = createAsync(() => membersQuery(props.slug));
  const rows = (): readonly MemberDto[] => members()?.items ?? [];
  return (
    <section class="flex flex-col gap-4">
      <h2 class="text-xl font-semibold text-ink">{t(app.orgMembersTitle)}</h2>
      <Show when={rows().length > 0} fallback={<EmptyState title={t(app.orgMembersEmpty)} />}>
        <Table label={t(app.orgMembersTitle)}>
          <TableHead>
            <TableRow>
              <TableHeaderCell>{t(app.orgMemberName)}</TableHeaderCell>
              <TableHeaderCell>{t(app.accountEmail)}</TableHeaderCell>
              <TableHeaderCell>{t(app.orgsRole)}</TableHeaderCell>
              <TableHeaderCell>{t(app.orgMemberSince)}</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <For each={rows()}>
              {(member) => (
                <TableRow>
                  <TableCell class="font-medium">{member.display_name}</TableCell>
                  <TableCell class="font-mono text-xs text-ink-muted">
                    {member.email ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={roleVariant(member.role)}>{member.role}</Badge>
                  </TableCell>
                  <TableCell class="whitespace-nowrap text-ink-muted">
                    {formatDate(member.created_at)}
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

export function OrgDetailScreen(): JSX.Element {
  const params = useParams<{ slug: string }>();
  const profile = createAsync(() => profileQuery(params.slug));
  const packages = (): readonly PackageSummaryDto[] => profile()?.packages.items ?? [];
  const base = (): string => registryBase(params.slug, instancePublicUrl());
  const role = (): string | null => profile()?.role ?? null;

  return (
    <Show when={profile()}>
      {(loaded) => (
        <section class="flex flex-col gap-8">
          <header class="flex flex-wrap items-start justify-between gap-4">
            <div class="flex flex-col gap-2">
              <div class="flex flex-wrap items-center gap-3">
                <h1 class="text-3xl font-bold tracking-tight text-ink">{loaded().org.name}</h1>
                <Show when={role()}>
                  {(value) => <Badge variant={roleVariant(value())}>{value()}</Badge>}
                </Show>
                <Show when={loaded().org.archived}>
                  <Badge variant="warning">{t(app.orgArchived)}</Badge>
                </Show>
              </div>
              <p class="font-mono text-sm text-ink-muted">{loaded().org.slug}</p>
              <Show when={loaded().org.description !== ""}>
                <p class="max-w-2xl text-ink-muted">{loaded().org.description}</p>
              </Show>
            </div>
            {/*
              Management is Admin+, and the links are hidden below that: the
              server refuses anyway, so a visible link would only ever produce
              a 403 for a Read member who cannot act on it. Neither points at
              `/admin` — instance administration is an ORTHOGONAL plane
              (decision 19's addendum), and an org Owner holds nothing there.
            */}
            <Show when={roleAtLeast(role(), "admin")}>
              <div class="flex flex-wrap gap-3">
                <A
                  href={`/orgs/${encodeURIComponent(params.slug)}/manage`}
                  class={buttonVariants({ intent: "outline", size: "sm" })}
                >
                  {t(app.orgManageLink)}
                </A>
                <A href="/tokens" class={cn(buttonVariants({ intent: "ghost", size: "sm" }))}>
                  {t(app.orgTokensLink)}
                </A>
              </div>
            </Show>
          </header>

          <Card>
            <CardHeader>
              <h2 class="text-base font-semibold text-ink">{t(app.orgsRegistryUrl)}</h2>
              <p class="text-sm text-ink-muted">{t(app.orgRegistryHint)}</p>
            </CardHeader>
            <CardContent class="flex flex-col gap-3">
              <div class="flex flex-wrap items-center gap-3">
                <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-xs text-ink">
                  {base()}
                </code>
                <CopyButton value={base()} />
              </div>
              <div class="flex flex-wrap items-center gap-3">
                <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-xs text-ink">
                  {`dart pub token add ${base()}`}
                </code>
                <CopyButton value={`dart pub token add ${base()}`} />
              </div>
              <p class="text-xs text-ink-muted">
                {t(app.orgUpstreamPolicy, { policy: loaded().org.upstream_policy })}
              </p>
            </CardContent>
          </Card>

          <section class="flex flex-col gap-4">
            <h2 class="text-xl font-semibold text-ink">{t(app.orgPackagesTitle)}</h2>
            <Show
              when={packages().length > 0}
              fallback={
                <EmptyState
                  title={t(app.orgPackagesEmpty)}
                  description={t(app.orgPackagesEmptyBody)}
                />
              }
            >
              <ul class="flex flex-col gap-4">
                <For each={packages()}>
                  {(item) => (
                    <li>
                      <PackageCard item={item} hideOrg />
                    </li>
                  )}
                </For>
              </ul>
            </Show>
            <Show when={loaded().packages.has_more === true}>
              <p class="text-xs text-ink-muted">{t(app.orgPackagesTruncated)}</p>
            </Show>
          </section>

          <Show when={isAuthenticated() && roleAtLeast(role(), "admin")}>
            <MembersCard slug={params.slug} />
          </Show>
        </section>
      )}
    </Show>
  );
}
