import type { PackageSummaryDto } from "@pub/api/types";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Badge } from "@pub/ui/badge";
import { A } from "@solidjs/router";
import { For, type JSX, Show } from "solid-js";
import { formatNumber, formatRelative } from "./format";
import { orgPath, packagePath } from "./urls";

/*
 * One package as a result row.
 *
 * Shared by search, the home rails, the org profile, and the dependents tab —
 * one card so a package looks the same wherever it appears, and so the flag
 * vocabulary (discontinued / unlisted / private / retracted-latest) is defined
 * exactly once.
 *
 * The flags are the part worth care: each one changes what a reader should DO
 * with the package, and three of the four are easy to misread as decoration.
 * `latest_retracted` in particular does not mean "this package is retracted"
 * — it means the newest version is, and `latest_version` is therefore an
 * older one than the version list's first row.
 */

export type PackageFlagsProps = { readonly item: PackageSummaryDto };

export function PackageFlags(props: PackageFlagsProps): JSX.Element {
  return (
    <>
      <Show when={props.item.visibility === "private"}>
        <Badge variant="neutral">{t(app.pkgFlagPrivate)}</Badge>
      </Show>
      <Show when={props.item.unlisted}>
        <Badge variant="neutral">{t(app.pkgFlagUnlisted)}</Badge>
      </Show>
      <Show when={props.item.discontinued}>
        <Badge variant="warning">{t(app.pkgFlagDiscontinued)}</Badge>
      </Show>
      <Show when={props.item.latest_retracted}>
        <Badge variant="danger">{t(app.pkgFlagLatestRetracted)}</Badge>
      </Show>
    </>
  );
}

export type PackageCardProps = {
  readonly item: PackageSummaryDto;
  /** Hide the org line where the whole list is one org's (the org profile). */
  readonly hideOrg?: boolean;
};

export function PackageCard(props: PackageCardProps): JSX.Element {
  return (
    <article class="flex flex-col gap-3 rounded-xl border border-line bg-surface p-6">
      <div class="flex flex-wrap items-baseline gap-x-3 gap-y-2">
        <h3 class="text-base font-semibold">
          <A
            href={packagePath(props.item.name)}
            class="rounded-md text-ink outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
          >
            {props.item.name}
          </A>
        </h3>
        <span class="font-mono text-sm text-ink-muted">{props.item.latest_version}</span>
        <div class="flex flex-wrap items-center gap-1.5">
          <PackageFlags item={props.item} />
        </div>
      </div>

      <Show when={props.item.description !== ""}>
        <p class="line-clamp-3 text-sm leading-relaxed text-ink-muted">{props.item.description}</p>
      </Show>

      <Show when={props.item.topics.length > 0}>
        <ul class="flex flex-wrap gap-1.5">
          <For each={props.item.topics.slice(0, 6)}>
            {(topic) => (
              <li>
                <Badge variant="accent" class="font-mono">
                  {topic}
                </Badge>
              </li>
            )}
          </For>
        </ul>
      </Show>

      <dl class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-muted">
        <Show when={props.hideOrg !== true}>
          <div class="flex items-center gap-1">
            <dt>{t(app.pkgOrg)}</dt>
            <dd>
              <A
                href={orgPath(props.item.org)}
                class="rounded-sm font-medium text-ink outline-none hover:text-accent focus-visible:ring-2 focus-visible:ring-accent"
              >
                {props.item.org}
              </A>
            </dd>
          </div>
        </Show>
        <div class="flex items-center gap-1">
          <dt>{t(app.pkgDownloads)}</dt>
          <dd class="font-medium text-ink">{formatNumber(props.item.downloads.total)}</dd>
        </div>
        <div class="flex items-center gap-1">
          <dt>{t(app.pkgUpdated)}</dt>
          <dd>{formatRelative(props.item.updated_at)}</dd>
        </div>
      </dl>
    </article>
  );
}
