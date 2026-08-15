import { describe, expect, test } from "bun:test";
import {
  expiryIsSubmittable,
  mintNeedsStepUp,
  neverExpiresAllowed,
  parsePatterns,
} from "@pub/api/tokens";

/*
 * The token creation form's three rules (S-13.c, S-06.d, decision 33).
 *
 * All three exist because `expires_days: null` means "never" on the wire, and
 * "never" is a materially different credential from a 90-day one.
 */

describe("expiryIsSubmittable", () => {
  test("a non-finite lifetime cannot be submitted as a non-expiring token", () => {
    // THE defect this guard exists for, and it is the serializer's doing rather
    // than the form's: `1e999` is valid syntax in a numeric input, `Number`
    // makes it `Infinity`, and `JSON.stringify` renders that as `null` — the
    // wire spelling of "never". The user asked for a very long lifetime and
    // would have got a credential with none.
    expect(JSON.stringify({ expires_days: Number("1e999") })).toBe('{"expires_days":null}');
    expect(expiryIsSubmittable(Number("1e999"), false)).toBe(false);
    expect(expiryIsSubmittable(Number.NaN, false)).toBe(false);
  });

  test("a cleared field is zero, not never — and is still refused here", () => {
    // `Number("")` is 0, not NaN. The server refuses 0 outright (S-13.c) so an
    // old client computing zero cannot stumble into "never"; the form refuses
    // it too, one round trip earlier.
    expect(Number("")).toBe(0);
    expect(expiryIsSubmittable(Number(""), false)).toBe(false);
  });

  test("a real number is submittable, and the range stays the server's rule", () => {
    expect(expiryIsSubmittable(90, false)).toBe(true);
    // Out of range on purpose: the 1…3650 bound belongs to the server (S-13.c),
    // and a copy here could drift away from the one that enforces it.
    expect(expiryIsSubmittable(9999, false)).toBe(true);
  });

  test("with never-expires ticked the number is irrelevant", () => {
    expect(expiryIsSubmittable(Number.NaN, true)).toBe(true);
  });
});

describe("neverExpiresAllowed", () => {
  test("read and nothing else", () => {
    expect(neverExpiresAllowed(["read"])).toBe(true);
    for (const scopes of [["publish"], ["read", "publish"], ["retract"], ["admin"], []] as const) {
      expect(neverExpiresAllowed(scopes)).toBe(false);
    }
  });
});

describe("mintNeedsStepUp", () => {
  test("the lifetime gates independently of the scope (S-06.d)", () => {
    expect(mintNeedsStepUp(["read"], false)).toBe(false);
    expect(mintNeedsStepUp(["read"], true)).toBe(true);
    expect(mintNeedsStepUp(["publish"], false)).toBe(true);
    expect(mintNeedsStepUp(["retract"], false)).toBe(false);
  });
});

describe("parsePatterns", () => {
  test("commas and whitespace both separate, and empties disappear", () => {
    expect(parsePatterns("acme_*, shared_utils")).toEqual(["acme_*", "shared_utils"]);
    expect(parsePatterns("  acme_*   other  ")).toEqual(["acme_*", "other"]);
    expect(parsePatterns(",,  ,")).toEqual([]);
    expect(parsePatterns("")).toEqual([]);
  });

  test("nothing is rejected here — the grammar is the server's", () => {
    // A malformed pattern reaches the mint and comes back as a precise
    // `invalid_argument`, which the dialog now renders (D18). A second copy of
    // the grammar in TypeScript could disagree with the one that enforces it.
    expect(parsePatterns("acme-*, *nope")).toEqual(["acme-*", "*nope"]);
  });
});
