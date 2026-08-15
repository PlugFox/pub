import { type ApiClient, jsonBody } from "./client";
import {
  type ListDto,
  STEP_UP_SCOPES,
  type TokenCreateBody,
  type TokenCreatedDto,
  type TokenDto,
  type TokenScope,
} from "./types";

/*
 * CLI/API tokens (`/api/v1/tokens`) — the second credential plane (S-13).
 *
 * The plaintext secret exists exactly once, in the `create` response. There is
 * no endpoint that returns it again, so the show-once panel is not a UX
 * flourish: it is the only chance the user gets.
 */

export type TokensApi = ReturnType<typeof createTokensApi>;

/** Whether minting these scopes will hit the S-06 step-up gate. */
export function scopesNeedStepUp(scopes: readonly TokenScope[]): boolean {
  return scopes.some((scope) => STEP_UP_SCOPES.includes(scope));
}

/**
 * Whether this mint will hit a step-up gate at all.
 *
 * Two independent gates, and the second is about the LIFETIME rather than the
 * scope (S-06.d): a token with no expiry is the longest-lived credential the
 * server can produce, so minting one demands a fresh second factor even for
 * `read`. The UI asks this before it opens the dialog's notice, so a user is
 * told what will be required rather than meeting a prompt mid-submit.
 */
export function mintNeedsStepUp(scopes: readonly TokenScope[], neverExpires: boolean): boolean {
  return neverExpires || scopesNeedStepUp(scopes);
}

/**
 * Whether a non-expiring token may carry these scopes (S-13.c).
 *
 * Mirrored here only to keep the form from submitting a request the server
 * will refuse — the enforcement is the server's and stays there. `read` and
 * nothing else: a leaked read token costs the confidentiality of packages the
 * org already shows every member and is one request from revocation, while a
 * leaked `publish` token writes supply-chain artefacts under the org's name
 * with no expiry to bound the window.
 */
export function neverExpiresAllowed(scopes: readonly TokenScope[]): boolean {
  return scopes.length > 0 && scopes.every((scope) => scope === "read");
}

/**
 * Splits the pattern field into the list the API takes.
 *
 * Commas and whitespace both separate, because both are what people type. The
 * **grammar is deliberately not checked here**: `pub_core::token::validate_patterns`
 * owns it, the mint refuses anything it cannot satisfy with a precise
 * `invalid_argument`, and since D18 that sentence is what the dialog shows. A
 * second copy of the rule in TypeScript could disagree with the one that
 * enforces it while both looked right in their own tests — the mistake
 * `storage-quota.ts` documents at length.
 */
/**
 * Whether the expiry field can be submitted as written.
 *
 * **A non-finite number here changes what is being asked for.** `JSON.stringify`
 * renders both `Infinity` and `NaN` as `null`, and since decision 33 `null` is
 * the wire spelling of "never expires" — so a lifetime of `1e999`, which a
 * numeric input accepts as valid syntax, would silently request a non-expiring
 * token instead of an absurdly long one. For a write scope the server refuses
 * it; for `read` it is granted to a step-up-fresh session, which is a
 * materially longer-lived credential than the user typed.
 *
 * A *cleared* field is a different and safe case: `Number("")` is `0`, and the
 * server refuses `0` outright (S-13.c) precisely so an old client computing
 * zero cannot stumble into "never". This guard rejects it too, because a form
 * that explains the problem beats a round trip that does.
 *
 * Deliberately only a finiteness check plus that zero: the 1…3650 range is the
 * server's rule and stays there, so this cannot drift away from it.
 */
export function expiryIsSubmittable(raw: number, neverExpires: boolean): boolean {
  return neverExpires || (Number.isFinite(raw) && raw > 0);
}

export function parsePatterns(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((pattern) => pattern.trim())
    .filter((pattern) => pattern !== "");
}

export function createTokensApi(client: ApiClient) {
  return {
    list(): Promise<ListDto<TokenDto>> {
      return client.request<ListDto<TokenDto>>("/tokens");
    },

    /** S-06.a: `publish`/`admin` scopes are step-up-gated; `read`/`retract` are not. */
    create(body: TokenCreateBody): Promise<TokenCreatedDto> {
      return client.request<TokenCreatedDto>("/tokens", jsonBody("POST", body));
    },

    /** S-13: revocation is effective within 60 s (no server-side token caching beyond that). */
    revoke(id: string): Promise<undefined> {
      return client.request<undefined>(`/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
    },
  };
}
