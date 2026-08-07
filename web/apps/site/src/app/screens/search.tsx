import { isNetworkError } from "@pub/api/errors";
import { SEARCH_SORTS, type SearchSort } from "@pub/api/types";
import { t, tp } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Alert } from "@pub/ui/alert";
import { Badge } from "@pub/ui/badge";
import { Button, buttonVariants } from "@pub/ui/button";
import { cn } from "@pub/ui/cn";
import { EmptyState } from "@pub/ui/empty-state";
import { Input } from "@pub/ui/input";
import { Label } from "@pub/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@pub/ui/popover";
import { Skeleton } from "@pub/ui/skeleton";
import { createAsync, query, useSearchParams } from "@solidjs/router";
import { createMemo, createSignal, ErrorBoundary, For, type JSX, Show, Suspense } from "solid-js";
import { formatNumber } from "../format";
import { PackageCard } from "../package-card";
import {
  hasFilterTag,
  readSearchState,
  type SearchState,
  searchStateParams,
  toggleFilterTag,
  withCursor,
  withQuery,
  withSort,
} from "../search-query";
import { api } from "../state/api";

/*
 * Package search.
 *
 * The URL is the state (see `search-query.ts`): `?q=&sort=&cursor=`. Every
 * mutation goes through the transitions in that module, which is what enforces
 * the one rule this screen cannot get wrong — a cursor is bound to the sort it
 * was minted under, and presenting it under a different one is a 400, not a
 * reshuffled page (decision 11).
 *
 * Three server behaviours are surfaced rather than hidden:
 *
 *   - `unknown_filters` — the parser never fails, it collects what it did not
 *     understand and echoes it. Saying "these were ignored" is the difference
 *     between a typo and a mysteriously empty result set, and it also removes
 *     the oracle where a malformed filter and a filter matching nothing look
 *     the same;
 *   - `sort` — the ordering ACTUALLY applied. `relevance` degrades to
 *     `updated` without query text, so the control reflects the response, not
 *     the request;
 *   - `facets` — counts over the whole filtered set, not this page. The chips
 *     write into the query text rather than into a hidden second filter state,
 *     so the box, the URL, and the chips can never disagree.
 *
 * This screen deliberately runs its OWN boundary rather than the shell's: a
 * failed search must keep the query box on screen and editable, and the shell
 * boundary replaces the whole screen.
 */

const PAGE_SIZE = 20;

const searchQuery = query(
  (state: SearchState) =>
    api.packages.search({
      q: state.q === "" ? undefined : state.q,
      sort: state.sort,
      cursor: state.cursor ?? undefined,
      limit: PAGE_SIZE,
    }),
  "package-search",
);

const SORT_LABELS: Record<SearchSort, { readonly id: string; readonly en: string }> = {
  relevance: app.searchSortRelevance,
  updated: app.searchSortUpdated,
  name: app.searchSortName,
  downloads: app.searchSortDownloads,
};

/** One row of the syntax reference: the tag, and what it does. */
const SYNTAX: readonly { readonly tag: string; readonly help: { id: string; en: string } }[] = [
  { tag: "org:acme", help: app.searchSyntaxOrg },
  { tag: "topic:widgets", help: app.searchSyntaxTopic },
  { tag: "dependency:http", help: app.searchSyntaxDependency },
  { tag: "is:public", help: app.searchSyntaxIs },
  { tag: "format:pub", help: app.searchSyntaxFormat },
  { tag: "sort:downloads", help: app.searchSyntaxSort },
  { tag: "-is:discontinued", help: app.searchSyntaxNegate },
  { tag: '"exact phrase"', help: app.searchSyntaxPhrase },
];

function SyntaxHelp(): JSX.Element {
  return (
    <Popover>
      <PopoverTrigger
        aria-label={t(app.searchSyntaxTitle)}
        class={cn(buttonVariants({ intent: "ghost", size: "sm" }), "shrink-0")}
      >
        {t(app.searchSyntaxTrigger)}
      </PopoverTrigger>
      <PopoverContent title={t(app.searchSyntaxTitle)}>
        <p class="pb-3 text-xs text-ink-muted">{t(app.searchSyntaxIntro)}</p>
        <dl class="flex flex-col gap-2">
          <For each={SYNTAX}>
            {(entry) => (
              <div class="flex flex-col gap-0.5">
                <dt>
                  <code class="rounded-sm bg-accent-soft px-1.5 py-0.5 font-mono text-xs text-accent">
                    {entry.tag}
                  </code>
                </dt>
                <dd class="text-xs text-ink-muted">{t(entry.help)}</dd>
              </div>
            )}
          </For>
        </dl>
      </PopoverContent>
    </Popover>
  );
}

type ResultsProps = {
  readonly state: SearchState;
  readonly onNext: (cursor: string) => void;
  readonly onFirst: () => void;
};

function Results(props: ResultsProps): JSX.Element {
  const results = createAsync(() => searchQuery(props.state));

  return (
    <div class="flex flex-col gap-6">
      <div class="flex flex-wrap items-center gap-3">
        <p class="text-sm text-ink-muted">
          {tp(app.searchTotal, results()?.total ?? 0, {
            count: formatNumber(results()?.total ?? 0),
          })}
        </p>
        <Show when={results() !== undefined && results()?.sort !== props.state.sort}>
          {/*
            The effective ordering differs from the requested one — always
            because `relevance` has nothing to rank without query text. Saying
            so beats a sort control that silently lies.
          */}
          <Badge variant="neutral">
            {t(app.searchSortApplied, {
              sort: t(SORT_LABELS[(results()?.sort ?? "updated") as SearchSort]),
            })}
          </Badge>
        </Show>
      </div>

      <Show when={(results()?.unknown_filters.length ?? 0) > 0}>
        <Alert intent="warning">
          {t(app.searchIgnoredFilters, {
            filters: (results()?.unknown_filters ?? []).join(", "),
          })}
        </Alert>
      </Show>

      <Show when={(results()?.facets.orgs.length ?? 0) > 0}>
        <section class="flex flex-col gap-2">
          <h2 class="text-xs font-medium text-ink-muted">{t(app.searchFacetOrgs)}</h2>
          <ul class="flex flex-wrap gap-2">
            <For each={results()?.facets.orgs ?? []}>
              {(facet) => {
                const tag = (): string => `org:${facet.value}`;
                const active = (): boolean => hasFilterTag(props.state, tag());
                return (
                  <li>
                    <FacetChip
                      label={facet.value}
                      count={facet.count}
                      active={active()}
                      state={props.state}
                      tag={tag()}
                    />
                  </li>
                );
              }}
            </For>
          </ul>
        </section>
      </Show>

      <Show
        when={(results()?.items.length ?? 0) > 0}
        fallback={
          <EmptyState
            title={t(app.searchEmptyTitle)}
            description={props.state.q === "" ? t(app.searchEmptyBrowse) : t(app.searchEmptyBody)}
          />
        }
      >
        <ul class="flex flex-col gap-4">
          <For each={results()?.items ?? []}>
            {(item) => (
              <li>
                <PackageCard item={item} />
              </li>
            )}
          </For>
        </ul>
      </Show>

      {/*
        Cursor pagination is forward-only by construction, so there is no page
        number and no "previous": the honest controls are "next page" and
        "start over". Both live in the URL, so the browser's own back button
        walks the pages a reader visited.
      */}
      <Show when={props.state.cursor !== null || results()?.has_more === true}>
        <nav aria-label={t(app.searchPagination)} class="flex flex-wrap justify-center gap-3">
          <Show when={props.state.cursor !== null}>
            <Button intent="ghost" onClick={() => props.onFirst()}>
              {t(app.searchFirstPage)}
            </Button>
          </Show>
          <Show when={results()?.has_more === true && results()?.cursor}>
            {(cursor) => (
              <Button intent="outline" onClick={() => props.onNext(cursor())}>
                {t(app.searchNextPage)}
              </Button>
            )}
          </Show>
        </nav>
      </Show>
    </div>
  );
}

/** A facet chip is a toggle over one token of the query text — see `toggleFilterTag`. */
function FacetChip(props: {
  readonly label: string;
  readonly count: number;
  readonly active: boolean;
  readonly state: SearchState;
  readonly tag: string;
}): JSX.Element {
  const [, setParams] = useSearchParams();
  return (
    <button
      type="button"
      aria-pressed={props.active}
      onClick={() => setParams(searchStateParams(toggleFilterTag(props.state, props.tag)))}
      class={cn(
        "inline-flex cursor-pointer items-center gap-1.5 rounded-full border px-2.5 py-0.5",
        "text-xs font-medium transition-colors outline-none focus-visible:ring-2",
        "focus-visible:ring-accent",
        props.active
          ? "border-transparent bg-accent text-on-accent"
          : "border-line bg-canvas text-ink-muted hover:bg-line/40 hover:text-ink",
      )}
    >
      <span>{props.label}</span>
      <span class="font-mono">{formatNumber(props.count)}</span>
    </button>
  );
}

export function SearchScreen(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const state = createMemo(() => readSearchState(params));
  // The box is a draft: it only becomes URL state on submit, so typing does
  // not fire a request per keystroke and the back button steps between
  // searches rather than between characters.
  const [draft, setDraft] = createSignal<string | null>(null);
  const boxValue = (): string => draft() ?? state().q;

  const submit = (event: Event): void => {
    event.preventDefault();
    setParams(searchStateParams(withQuery(state(), boxValue().trim())));
    setDraft(null);
  };

  return (
    <section class="flex flex-col gap-6">
      <header class="flex flex-col gap-2">
        <h1 class="text-3xl font-bold tracking-tight text-ink">{t(app.searchTitle)}</h1>
        <p class="max-w-2xl text-ink-muted">{t(app.searchSubtitle)}</p>
      </header>

      <form class="flex flex-col gap-3" onSubmit={submit}>
        <div class="flex flex-wrap items-end gap-3">
          <div class="grid min-w-64 flex-1 gap-1.5">
            <Label for="search-q">{t(app.searchFieldLabel)}</Label>
            <Input
              id="search-q"
              type="search"
              name="q"
              value={boxValue()}
              placeholder={t(app.searchPlaceholder)}
              onInput={(event) => setDraft(event.currentTarget.value)}
            />
          </div>
          <div class="grid gap-1.5">
            <Label for="search-sort">{t(app.searchSortLabel)}</Label>
            <select
              id="search-sort"
              value={state().sort}
              onChange={(event) =>
                // Changing the ordering ALWAYS drops the cursor: presenting one
                // minted under another sort is `invalid_argument`.
                setParams(
                  searchStateParams(withSort(state(), event.currentTarget.value as SearchSort)),
                )
              }
              class="h-10 rounded-md border border-line bg-surface px-3 text-sm text-ink outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30"
            >
              <For each={SEARCH_SORTS}>
                {(sort) => <option value={sort}>{t(SORT_LABELS[sort])}</option>}
              </For>
            </select>
          </div>
          <Button type="submit">{t(app.searchSubmit)}</Button>
          <SyntaxHelp />
        </div>
      </form>

      <ErrorBoundary
        fallback={(error: unknown, reset: () => void) => (
          <div class="flex flex-col items-start gap-4">
            <Alert intent="danger">
              {isNetworkError(error) ? t(app.networkError) : t(app.searchFailed)}
            </Alert>
            <Button
              intent="outline"
              onClick={() => {
                // A cursor from a previous ordering is the one failure a retry
                // cannot fix on its own, so the retry also drops it.
                setParams(searchStateParams(withCursor(state(), null)));
                reset();
              }}
            >
              {t(app.retry)}
            </Button>
          </div>
        )}
      >
        <Suspense
          fallback={
            <div class="flex flex-col gap-4">
              <Skeleton class="h-4 w-32" />
              <Skeleton class="h-32 w-full" />
              <Skeleton class="h-32 w-full" />
            </div>
          }
        >
          <Results
            state={state()}
            onNext={(cursor) => setParams(searchStateParams(withCursor(state(), cursor)))}
            onFirst={() => setParams(searchStateParams(withCursor(state(), null)))}
          />
        </Suspense>
      </ErrorBoundary>
    </section>
  );
}
