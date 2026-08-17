import { describe, expect, test } from "bun:test";
import { nextCursor, readCursor } from "../src/app/cursor-nav";

/*
 * The two pure rules behind the app's paginator (decision 40). The component
 * itself is JSX and is covered by the typecheck plus the screens that use it;
 * these are the decisions it makes about a server response and a URL.
 */

describe("nextCursor", () => {
  test("offers the next page only when the server says there is one", () => {
    expect(nextCursor({ has_more: true, cursor: "abc" })).toBe("abc");
    expect(nextCursor({ has_more: false, cursor: "abc" })).toBeNull();
  });

  test("a page still loading offers nothing", () => {
    // `createAsync` yields `undefined` before the first response; rendering a
    // "next page" button then would page from a cursor nobody has.
    expect(nextCursor(undefined)).toBeNull();
  });

  test("`has_more` without a cursor is the last page", () => {
    // Belt for a response that contradicts itself: the button would send
    // `cursor=undefined` and silently re-fetch page one.
    expect(nextCursor({ has_more: true, cursor: null })).toBeNull();
    expect(nextCursor({ has_more: true })).toBeNull();
  });
});

describe("readCursor", () => {
  test("an absent or empty parameter is the first page", () => {
    expect(readCursor(undefined)).toBeNull();
    expect(readCursor("")).toBeNull();
  });

  test("a repeated parameter takes its first value", () => {
    expect(readCursor(["one", "two"])).toBe("one");
  });

  test("an empty repeated parameter is still the first page", () => {
    expect(readCursor([])).toBeNull();
    expect(readCursor([""])).toBeNull();
  });

  test("the value is opaque and passes through unvalidated", () => {
    // Cursors are server-minted tokens; a client-side shape check would only
    // duplicate the server's, badly — a refusal is the server's answer to give.
    expect(readCursor("not:a:real:cursor")).toBe("not:a:real:cursor");
  });
});
