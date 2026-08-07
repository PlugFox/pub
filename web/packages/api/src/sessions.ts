import type { ApiClient } from "./client";
import type { ListDto, RevokedDto, SessionDto } from "./types";

/*
 * Session management (`/api/v1/sessions`) — the S-10 device list.
 *
 * `revokeAll` is step-up-gated (S-06.a): on a stale session it answers
 * `step_up_required` and the caller retries after the prompt is satisfied.
 */

export type SessionsApi = ReturnType<typeof createSessionsApi>;

export function createSessionsApi(client: ApiClient) {
  return {
    list(): Promise<ListDto<SessionDto>> {
      return client.request<ListDto<SessionDto>>("/sessions");
    },

    /** Revokes one session. Revoking the current one ends this browser's session too. */
    revoke(id: string): Promise<undefined> {
      return client.request<undefined>(`/sessions/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
    },

    /** S-06.a: step-up-gated. Returns how many sessions were revoked. */
    revokeAll(): Promise<RevokedDto> {
      return client.request<RevokedDto>("/sessions/revoke-all", { method: "POST" });
    },
  };
}
