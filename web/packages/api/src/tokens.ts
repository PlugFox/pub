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
