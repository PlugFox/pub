import { describe, expect, test } from "bun:test";
import { accessTokenExpiry, decodeAccessClaims, isAccessTokenExpiring } from "@pub/api/jwt";

/**
 * Builds an unsigned-looking JWT (the signature is never read).
 *
 * The payload goes through TextEncoder before btoa: `btoa` is latin1-only, and
 * the server emits UTF-8 — which is exactly the case the decoder must handle.
 */
function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string => {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    const binary = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join("");
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  };
  return `${encode({ alg: "EdDSA", kid: "k1" })}.${encode(payload)}.c2ln`;
}

describe("decodeAccessClaims", () => {
  test("reads sub/sid/exp from a well-formed token", () => {
    const claims = decodeAccessClaims(jwt({ sub: "u1", sid: "s1", exp: 1_800_000_000 }));
    expect(claims).toEqual({ sub: "u1", sid: "s1", exp: 1_800_000_000 });
  });

  test("survives base64url payloads that need padding", () => {
    // Payload lengths hitting each of the three padding cases.
    for (const sub of ["a", "ab", "abc", "abcd"]) {
      expect(decodeAccessClaims(jwt({ sub }))?.sub).toBe(sub);
    }
  });

  test("decodes non-ASCII claim values (UTF-8, not latin1)", () => {
    expect(decodeAccessClaims(jwt({ sub: "Ада" }))?.sub).toBe("Ада");
  });

  test.each([
    ["empty string", ""],
    ["two segments", "aaa.bbb"],
    ["four segments", "a.b.c.d"],
    ["non-base64 payload", "aaa.!!!!.ccc"],
    ["payload that is not JSON", `aaa.${btoa("not json")}.ccc`],
    ["payload that is a JSON array", `aaa.${btoa("[1,2]")}.ccc`],
  ])("returns null for %s", (_name, token) => {
    expect(decodeAccessClaims(token)).toBeNull();
  });
});

describe("expiry", () => {
  test("exp is reported in milliseconds", () => {
    expect(accessTokenExpiry(jwt({ exp: 1700 }))).toBe(1_700_000);
  });

  test("a token without exp has no schedule information", () => {
    expect(accessTokenExpiry(jwt({ sub: "u1" }))).toBeNull();
    expect(accessTokenExpiry("garbage")).toBeNull();
  });

  test("isAccessTokenExpiring fires only inside the skew window", () => {
    const now = 1_000_000;
    const token = (deltaMs: number): string => jwt({ exp: (now + deltaMs) / 1000 });
    expect(isAccessTokenExpiring(token(120_000), now, 60_000)).toBe(false);
    expect(isAccessTokenExpiring(token(59_000), now, 60_000)).toBe(true);
    expect(isAccessTokenExpiring(token(-1), now, 60_000)).toBe(true);
  });

  test("an undecodable token is NOT treated as expiring", () => {
    // Otherwise every request would refresh; the reactive 401 path handles it.
    expect(isAccessTokenExpiring("garbage", Date.now(), 60_000)).toBe(false);
    expect(isAccessTokenExpiring(jwt({ sub: "u1" }), Date.now(), 60_000)).toBe(false);
  });
});
