import { describe, expect, test } from "bun:test";
import {
  DEFAULT_SORT,
  EMPTY_SEARCH,
  hasFilterTag,
  readSearchState,
  type SearchState,
  searchPath,
  searchStateParams,
  toggleFilterTag,
  withCursor,
  withQuery,
  withSort,
} from "../src/app/search-query";

/*
 * Search URL state.
 *
 * The cursor-reset rules get the most coverage because they are the ones a
 * server error hangs off: a search cursor is keyset AND ordering-bound
 * (decision 11), so presenting one under a different `sort` is answered with
 * 400 `invalid_argument`. Every transition that changes the ordering or the
 * result set must therefore drop it, and the round-trip tests exist so a URL
 * a user pasted cannot resurrect one.
 */

function state(overrides: Partial<SearchState> = {}): SearchState {
  return { ...EMPTY_SEARCH, ...overrides };
}

describe("readSearchState", () => {
  test("empty params give the empty state", () => {
    expect(readSearchState({})).toEqual(EMPTY_SEARCH);
  });

  test("reads query, sort, and cursor", () => {
    expect(readSearchState({ q: "bloc", sort: "downloads", cursor: "abc" })).toEqual({
      q: "bloc",
      sort: "downloads",
      cursor: "abc",
    });
  });

  test.each(["", "  ", "popular", "RELEVANCE", "1", "sort"])(
    "an unrecognized sort %p degrades to the default rather than erroring",
    (raw) => {
      expect(readSearchState({ sort: raw }).sort).toBe(DEFAULT_SORT);
    },
  );

  test("an empty cursor parameter is no cursor", () => {
    expect(readSearchState({ cursor: "" }).cursor).toBeNull();
  });

  test("a repeated parameter takes the first value, like a form submission", () => {
    expect(readSearchState({ q: ["first", "second"] }).q).toBe("first");
  });

  test("an empty repeated parameter does not become undefined", () => {
    expect(readSearchState({ q: [] }).q).toBe("");
  });
});

describe("searchStateParams", () => {
  test("drops defaults so /search and /search?sort=relevance are one URL", () => {
    expect(searchStateParams(EMPTY_SEARCH)).toEqual({
      q: undefined,
      sort: undefined,
      cursor: undefined,
    });
  });

  test("keeps every non-default value", () => {
    expect(searchStateParams(state({ q: "http", sort: "name", cursor: "c1" }))).toEqual({
      q: "http",
      sort: "name",
      cursor: "c1",
    });
  });
});

describe("URL round-trip", () => {
  const cases: readonly SearchState[] = [
    EMPTY_SEARCH,
    state({ q: "bloc" }),
    state({ sort: "updated" }),
    state({ q: "org:acme is:public", sort: "downloads", cursor: "eyJhIjoxfQ" }),
    state({ q: 'flutter "state management"', sort: "name" }),
    state({ q: "a+b&c=d", sort: "updated", cursor: "c/2+3=" }),
  ];

  test.each(cases.map((value) => [JSON.stringify(value), value] as const))(
    "%s survives a trip through the query string",
    (_label, original) => {
      const path = searchPath(original);
      const params = Object.fromEntries(new URL(path, "https://pub.test").searchParams);
      expect(readSearchState(params)).toEqual(original);
    },
  );

  test("the empty state has no query string at all", () => {
    expect(searchPath(EMPTY_SEARCH)).toBe("/search");
  });
});

describe("cursor lifecycle", () => {
  const paged = state({ q: "bloc", sort: "downloads", cursor: "page2" });

  test("changing the sort drops the cursor (the API 400s on a foreign one)", () => {
    expect(withSort(paged, "name").cursor).toBeNull();
  });

  test("re-selecting the SAME sort still drops the cursor", () => {
    // Cheap and safe: the alternative is a control that sometimes keeps a
    // cursor and sometimes does not, depending on what the user clicked last.
    expect(withSort(paged, "downloads").cursor).toBeNull();
  });

  test("changing the query drops the cursor", () => {
    expect(withQuery(paged, "http").cursor).toBeNull();
  });

  test("toggling a facet drops the cursor, because it edits the query", () => {
    expect(toggleFilterTag(paged, "org:acme").cursor).toBeNull();
  });

  test("only paging keeps the ordering and advances the cursor", () => {
    const next = withCursor(paged, "page3");
    expect(next.sort).toBe("downloads");
    expect(next.q).toBe("bloc");
    expect(next.cursor).toBe("page3");
  });

  test("going back to the first page clears the cursor", () => {
    expect(withCursor(paged, null).cursor).toBeNull();
  });

  test("a sort change is visible in the URL and the cursor is gone from it", () => {
    const path = searchPath(withSort(paged, "name"));
    expect(path).toContain("sort=name");
    expect(path).not.toContain("cursor");
  });
});

describe("filter tags", () => {
  test("adding a tag appends it to the query text", () => {
    expect(toggleFilterTag(state({ q: "bloc" }), "org:acme").q).toBe("bloc org:acme");
  });

  test("toggling the same tag again removes exactly it", () => {
    const on = toggleFilterTag(state({ q: "bloc" }), "org:acme");
    expect(toggleFilterTag(on, "org:acme").q).toBe("bloc");
  });

  test("removing a tag leaves other tags of the same family alone", () => {
    const both = state({ q: "org:acme org:other" });
    expect(toggleFilterTag(both, "org:acme").q).toBe("org:other");
  });

  test("adding a tag to an empty query does not leave leading whitespace", () => {
    expect(toggleFilterTag(EMPTY_SEARCH, "is:public").q).toBe("is:public");
  });

  test("runs of whitespace between tokens collapse", () => {
    expect(toggleFilterTag(state({ q: "a   b" }), "c").q).toBe("a b c");
  });

  test("hasFilterTag matches whole tokens only", () => {
    const current = state({ q: "org:acme-corp" });
    expect(hasFilterTag(current, "org:acme-corp")).toBe(true);
    expect(hasFilterTag(current, "org:acme")).toBe(false);
  });
});
