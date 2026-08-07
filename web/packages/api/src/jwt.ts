/*
 * Access-token introspection — the claims the *client* is allowed to care about.
 *
 * The access token is an Ed25519 JWT (S-07) and the client NEVER verifies it:
 * verification is the server's job on every request, and a browser that
 * "trusted" a decoded claim would be trusting attacker-supplied JSON. The only
 * legitimate client use is scheduling — reading `exp` to refresh proactively so
 * a user action does not pay for a round trip that ends in 401.
 *
 * Everything here therefore fails soft: a malformed token yields `null`, and
 * `null` means "no schedule information", never "expired" (a wrong guess of
 * "expired" would refresh on every request; the reactive 401 path is the safety
 * net either way).
 */

export type AccessClaims = {
  /** User id. */
  readonly sub?: string;
  /** Session id — the revocation handle (S-09). */
  readonly sid?: string;
  /** Expiry, seconds since the epoch. */
  readonly exp?: number;
  /** Issued-at, seconds since the epoch. */
  readonly iat?: number;
};

function decodeBase64Url(segment: string): string | null {
  const padded = segment.replaceAll("-", "+").replaceAll("_", "/");
  const withPadding = padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), "=");
  try {
    const binary = atob(withPadding);
    const bytes = Uint8Array.from(binary, (char) => char.codePointAt(0) ?? 0);
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/** Decodes the payload without verifying the signature. `null` when unreadable. */
export function decodeAccessClaims(token: string): AccessClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const payload = parts[1];
  if (payload === undefined || payload === "") return null;
  const json = decodeBase64Url(payload);
  if (json === null) return null;
  try {
    const parsed: unknown = JSON.parse(json);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return parsed as AccessClaims;
  } catch {
    return null;
  }
}

/** `exp` in milliseconds, or `null` when the token carries no readable expiry. */
export function accessTokenExpiry(token: string): number | null {
  const exp = decodeAccessClaims(token)?.exp;
  return typeof exp === "number" && Number.isFinite(exp) ? exp * 1000 : null;
}

/**
 * Whether `token` expires within `skewMs` of `now` — the proactive-refresh trigger.
 *
 * An undecodable token is NOT treated as expiring: refreshing on every request
 * would be worse than letting the reactive 401 path handle it once.
 */
export function isAccessTokenExpiring(token: string, now: number, skewMs: number): boolean {
  const expiry = accessTokenExpiry(token);
  if (expiry === null) return false;
  return expiry - skewMs <= now;
}
