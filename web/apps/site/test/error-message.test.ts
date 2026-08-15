import { describe, expect, test } from "bun:test";
import { ApiError, NetworkError } from "@pub/api/errors";
import { describeError } from "../src/app/error-message";

/*
 * What a refusal says to the user (D18, decision 33).
 *
 * The property worth the most here is the NEGATIVE one: for the codes whose
 * server text is operator information or a deliberately uniform S-04 answer,
 * no part of that text may reach the rendered string. A test that only checked
 * the happy tier would let a future edit widen the table by one line and leak
 * a SQL fragment into a toast.
 */

const SERVER_SECRET = "relation pub_app.tokens does not exist";

describe("describeError", () => {
  test("a network failure is never reported as a refusal", () => {
    // The distinction `packages/api/errors.ts` exists to preserve: the request
    // did not complete, so the server said nothing and we must not invent it.
    const message = describeError(new NetworkError("fetch failed"));
    expect(message).not.toContain("fetch failed");
    expect(message.toLowerCase()).toContain("server");
  });

  test("a non-API throwable falls back to the generic message", () => {
    expect(describeError(new Error("boom"))).not.toContain("boom");
    expect(describeError(undefined)).toBeTruthy();
  });

  test("the silent tier never renders the server's own message", () => {
    for (const code of [
      "internal",
      "database_error",
      "blob_error",
      "kv_error",
      "config_invalid",
      "not_found",
      "unauthorized",
    ]) {
      const rendered = describeError(new ApiError(code, `${code}: ${SERVER_SECRET}`, 500));
      expect(rendered).not.toContain(SERVER_SECRET);
      expect(rendered).not.toContain("pub_app");
    }
  });

  test("the detailed tier shows the reason the screen promised to explain", () => {
    // These are the exact refusals D18 named: without the detail they are
    // indistinguishable from a bug.
    const window = describeError(
      new ApiError("invalid_argument", "invalid argument: 1.0.0 is past the unretract window", 400),
    );
    expect(window).toContain("past the unretract window");

    const owner = describeError(
      new ApiError("last_owner", "operation would leave org 0189 without an owner", 409),
    );
    expect(owner.toLowerCase()).toContain("owner");

    const slug = describeError(new ApiError("conflict", "conflict: slug acme is taken", 409));
    expect(slug).toContain("slug acme is taken");
  });

  test("the domain error's own class prefix is not shown twice", () => {
    // `Display` writes "conflict: …" and the headline already says as much, in
    // the reader's language.
    const rendered = describeError(new ApiError("conflict", "conflict: slug acme is taken", 409));
    expect(rendered).not.toContain("conflict:");
  });

  test("a detailed code with an empty message degrades to the headline alone", () => {
    const rendered = describeError(new ApiError("busy", "   ", 409));
    expect(rendered.endsWith(":")).toBe(false);
    expect(rendered.trim()).toBe(rendered);
  });

  test("an unbounded server message is clipped rather than pasted into the UI", () => {
    const rendered = describeError(new ApiError("invalid_argument", "x".repeat(5000), 400));
    expect(rendered.length).toBeLessThan(400);
  });

  test("an unknown code prints the code and not the message", () => {
    // A code this table has not been taught may well be a future silent one, so
    // the message stays unrendered — but the code itself is what a bug report
    // needs, and it is a closed vocabulary, not user text.
    const rendered = describeError(new ApiError("brand_new_code", SERVER_SECRET, 400));
    expect(rendered).toContain("brand_new_code");
    expect(rendered).not.toContain(SERVER_SECRET);
  });

  test("a rate limit renders its cool-down, with a default when the header was absent", () => {
    expect(
      describeError(new ApiError("rate_limited", "slow down", 429, { retryAfter: 30 })),
    ).toContain("30");
    expect(describeError(new ApiError("rate_limited", "slow down", 429))).toContain("60");
  });
});
