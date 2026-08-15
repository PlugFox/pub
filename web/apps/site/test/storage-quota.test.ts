import { describe, expect, test } from "bun:test";
import {
  parseQuotaBytes,
  quotaMode,
  quotaToForm,
  quotaToPatch,
  validateQuota,
} from "../src/app/storage-quota";

/*
 * The per-org storage quota (S-20.b, decision 32).
 *
 * The rule under test is not "a number in a box" — it is a three-state
 * override whose states are easy to collapse into two by accident:
 *
 *   null → follow the instance default
 *   0    → unlimited FOR THIS ORG, whatever the default is
 *   n>0  → n bytes
 *
 * `null` and `0` RESOLVE identically on an instance whose default is already
 * unlimited — the default a fresh instance ships with — so a surface that
 * collapsed them would look correct on every test instance and would surface
 * the day an operator sets an instance-wide quota and one org silently gains
 * a wall it was explicitly exempted from. That is why `quotaMode` and
 * `quotaToForm` below keep the two apart even though the number an operator
 * reads is the same today: the STORED states differ, and only the stored
 * state survives a later change to the instance number.
 *
 * THE EFFECTIVE-LIMIT RESOLUTION IS NOT TESTED HERE BECAUSE IT IS NOT HERE.
 * It lives in `pub_registry::publish::effective_storage_quota` and reaches
 * every screen as `effective_quota_bytes` on the payload; a TypeScript mirror
 * of it — which this file used to test, arm by arm — made that function's own
 * "the one place that rule is written" false, and two implementations of one
 * rule can disagree while both suites stay green. What remains below is the
 * part the server has no opinion about: parsing, labelling, and the editor's
 * pre-flight.
 */

describe("parseQuotaBytes", () => {
  test("accepts whole non-negative integers, including 0", () => {
    expect(parseQuotaBytes("0")).toBe(0);
    expect(parseQuotaBytes("1")).toBe(1);
    expect(parseQuotaBytes(" 1073741824 ")).toBe(1_073_741_824);
  });

  test.each(["-1", "1.5", "1e9", "", " ", "abc", "0x10", "1_000", "1 000"])(
    "%p is not a byte count",
    (raw) => {
      expect(parseQuotaBytes(raw)).toBeNull();
    },
  );

  test("refuses a value past 2^53 rather than rounding it", () => {
    // The server takes an i64; this runtime cannot carry one, and a rounded
    // number would store a wall nobody typed.
    expect(parseQuotaBytes("9007199254740993")).toBeNull();
    expect(parseQuotaBytes("9007199254740991")).toBe(Number.MAX_SAFE_INTEGER);
  });
});

describe("quotaMode", () => {
  test("null and undefined both mean 'follow the instance default'", () => {
    // The payload omits the key when there is no override, so `undefined`
    // reaches this function as often as `null` does.
    expect(quotaMode(null)).toBe("default");
    expect(quotaMode(undefined)).toBe("default");
  });

  test("0 is a stored override, not the absence of one", () => {
    expect(quotaMode(0)).toBe("unlimited");
  });

  test("a positive number is a limit", () => {
    expect(quotaMode(1)).toBe("limit");
    expect(quotaMode(10_737_418_240)).toBe("limit");
  });
});

describe("quotaToForm", () => {
  test("each stored state opens the editor on its own choice", () => {
    expect(quotaToForm(null)).toEqual({ mode: "default", bytes: "" });
    expect(quotaToForm(0)).toEqual({ mode: "unlimited", bytes: "" });
    expect(quotaToForm(2_048)).toEqual({ mode: "limit", bytes: "2048" });
  });
});

describe("validateQuota", () => {
  test("the two limitless choices need no number", () => {
    expect(validateQuota({ mode: "default", bytes: "" })).toBeNull();
    expect(validateQuota({ mode: "unlimited", bytes: "" })).toBeNull();
    // A stale draft left behind by switching choices is ignored, not refused.
    expect(validateQuota({ mode: "default", bytes: "nonsense" })).toBeNull();
  });

  test("a limit of 0 is refused — the dialog already has a word for unlimited", () => {
    // The wire would ACCEPT it (0 is unlimited there), which is exactly why it
    // is refused here: an operator typing 0 into a field labelled "bytes" is
    // asking for a wall, and silently granting the opposite is the trap
    // decision 32 refuses to build.
    expect(validateQuota({ mode: "limit", bytes: "0" })).toBe("bytes");
  });

  test.each(["-1", "", " ", "1.5", "abc"])("a limit of %p is refused", (bytes) => {
    expect(validateQuota({ mode: "limit", bytes })).toBe("bytes");
  });

  test("one byte is a legal limit", () => {
    expect(validateQuota({ mode: "limit", bytes: "1" })).toBeNull();
  });
});

describe("quotaToPatch", () => {
  test("all three states are expressible on the wire and distinguishable", () => {
    expect(quotaToPatch({ mode: "default", bytes: "" })).toBeNull();
    expect(quotaToPatch({ mode: "unlimited", bytes: "" })).toBe(0);
    expect(quotaToPatch({ mode: "limit", bytes: "4096" })).toBe(4_096);
  });

  test("clearing the override sends an explicit null, never an absent field", () => {
    // The server refuses `{}` rather than reading it as one of the three
    // states, so "follow the default again" has to be a value in the body.
    const body = { storage_quota_bytes: quotaToPatch({ mode: "default", bytes: "" }) };
    expect(JSON.stringify(body)).toBe('{"storage_quota_bytes":null}');
  });

  test("a stale byte draft does not leak into the two limitless choices", () => {
    expect(quotaToPatch({ mode: "default", bytes: "4096" })).toBeNull();
    expect(quotaToPatch({ mode: "unlimited", bytes: "4096" })).toBe(0);
  });
});
