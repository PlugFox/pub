import { SEARCH_SORTS, type SearchSort } from "@pub/api/types";

/*
 * Search URL state.
 *
 * The query, the ordering, and the page cursor live in the URL and nowhere
 * else: a results page must be linkable, shareable, and survive a reload and
 * the back button. Everything here is a pure function over the search params
 * so the round-trip can be tested without a router or a DOM.
 *
 * THE CURSOR RESET IS NOT COSMETIC. Search cursors are keyset and
 * ordering-bound (decision 11): the token carries a one-character sort tag,
 * and presenting it under a different `sort` is answered with 400
 * `invalid_argument`, not with a silently reshuffled page. So every transition
 * that changes what the ordering means — a new sort, new query text — drops
 * the cursor, and only "next page" keeps it. Building that into the state
 * transitions rather than into each call site is what stops the one screen
 * that forgets from 400-ing.
 */

export const DEFAULT_SORT: SearchSort = "relevance";

export type SearchState = {
  readonly q: string;
  readonly sort: SearchSort;
  /** Page cursor; `null` on the first page. Only valid under `sort`. */
  readonly cursor: string | null;
};

export const EMPTY_SEARCH: SearchState = { q: "", sort: DEFAULT_SORT, cursor: null };

/** Anything the router hands back for a query parameter. */
export type ParamValue = string | string[] | undefined;
export type SearchParamsLike = Record<string, ParamValue>;

/**
 * First value of a repeated parameter.
 *
 * `?q=a&q=b` is legal and the router surfaces it as an array; picking the
 * first is what a browser's own form submission does, and it keeps the state
 * a single value rather than an accidental list.
 */
function single(value: ParamValue): string {
  if (value === undefined) return "";
  return (Array.isArray(value) ? value[0] : value) ?? "";
}

function isSort(value: string): value is SearchSort {
  return (SEARCH_SORTS as readonly string[]).includes(value);
}

/**
 * Reads state out of URL params.
 *
 * An unrecognized `sort` degrades to the default rather than erroring: the
 * value is user-editable text in an address bar, and a 400 from a typo would
 * be a worse answer than the default ordering. The cursor is carried through
 * verbatim — it is opaque, and validating it here would only duplicate the
 * server's check badly.
 */
export function readSearchState(params: SearchParamsLike): SearchState {
  const rawSort = single(params.sort).trim();
  const cursor = single(params.cursor);
  return {
    q: single(params.q),
    sort: isSort(rawSort) ? rawSort : DEFAULT_SORT,
    cursor: cursor === "" ? null : cursor,
  };
}

/**
 * The params for a state, with defaults omitted.
 *
 * `undefined` means "remove this parameter" to `useSearchParams`, which is why
 * an empty query and the default sort are dropped: `/search` and
 * `/search?q=&sort=relevance` are the same page and should have one URL.
 */
export function searchStateParams(state: SearchState): Record<string, string | undefined> {
  return {
    q: state.q === "" ? undefined : state.q,
    sort: state.sort === DEFAULT_SORT ? undefined : state.sort,
    cursor: state.cursor ?? undefined,
  };
}

/** The canonical path+query for a state (used for links and tests). */
export function searchPath(state: SearchState, base = "/search"): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(searchStateParams(state))) {
    if (value !== undefined) search.set(key, value);
  }
  const encoded = search.toString();
  return encoded === "" ? base : `${base}?${encoded}`;
}

/** New query text — resets the cursor (the result set changed). */
export function withQuery(state: SearchState, q: string): SearchState {
  return { ...state, q, cursor: null };
}

/** New ordering — resets the cursor (a cursor is only valid under its own sort). */
export function withSort(state: SearchState, sort: SearchSort): SearchState {
  return { ...state, sort, cursor: null };
}

/** Next page under the SAME ordering. */
export function withCursor(state: SearchState, cursor: string | null): SearchState {
  return { ...state, cursor };
}

/**
 * Appends (or removes) a filter tag in the query text.
 *
 * Facet chips are a toggle over the same text box the user types in, not a
 * second, hidden filter state — so clicking `org:acme` writes `org:acme` into
 * `q`, and clicking it again removes exactly that token. Keeping one source of
 * truth is what makes the URL, the box, and the chips agree.
 */
export function toggleFilterTag(state: SearchState, tag: string): SearchState {
  const tokens = state.q.split(/\s+/).filter((token) => token !== "");
  const index = tokens.indexOf(tag);
  const next = index === -1 ? [...tokens, tag] : tokens.filter((_, at) => at !== index);
  return withQuery(state, next.join(" "));
}

/** Whether the query text already carries `tag` as a whole token. */
export function hasFilterTag(state: SearchState, tag: string): boolean {
  return state.q.split(/\s+/).includes(tag);
}
