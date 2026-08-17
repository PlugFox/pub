import { type ApiClient, jsonBody, throwIfError } from "./client";
import type { AccountDeletedDto, EmailChangeStartedDto, MeDto } from "./types";

/*
 * The caller's own account (`/api/v1/me`) — S-29 and decision 39.
 *
 * `me()` is the one read that answers what the access token deliberately does
 * not carry (S-07 keeps claims to `sub`/`sid`/org levels/timestamps), which is
 * why the account screen calls it instead of reading the cached login profile:
 * `totp_enabled` and `is_instance_admin` are facts about the account *now*, and
 * a token minted before an enrollment cannot know either.
 *
 * Four of the five calls here are step-up gated (S-06), so every caller wraps
 * them in `withStepUp`. `update()` is not: S-06's list is about escalation, and
 * a prompt to fix a typo in a display name is how a prompt becomes noise.
 */

export type AccountApi = ReturnType<typeof createAccountApi>;

export function createAccountApi(client: ApiClient) {
  return {
    /** The caller's account row plus whether a second factor is enrolled. */
    me(): Promise<MeDto> {
      return client.request<MeDto>("/me");
    },

    /** Renames the account. Not step-up gated. */
    update(displayName: string): Promise<MeDto> {
      return client.request<MeDto>("/me", jsonBody("PATCH", { display_name: displayName }));
    },

    /**
     * Starts an address change: a code goes to the **new** address and nothing
     * on the account moves yet (S-03.b). Step-up gated.
     *
     * A `conflict` here means the address already belongs to an account — the
     * one non-uniform answer on this surface, taken deliberately so the
     * instance never mails a code to a stranger's inbox on request.
     */
    startEmailChange(email: string): Promise<EmailChangeStartedDto> {
      return client.request<EmailChangeStartedDto>("/me/email", jsonBody("POST", { email }));
    },

    /**
     * Confirms the code and moves the address. Step-up gated.
     *
     * A wrong, expired or foreign code answers `invalid_code` with a **401**,
     * the same uniform answer `totp/confirm` and `step-up` give — it is not a
     * dead session, and the screen renders it as a wrong code.
     */
    confirmEmailChange(pendingId: string, code: string): Promise<MeDto> {
      return client.request<MeDto>(
        "/me/email/verify",
        jsonBody("POST", { pending_id: pendingId, code }),
      );
    },

    /**
     * Downloads the S-29.b export as one NDJSON blob. Step-up gated.
     *
     * Raw rather than enveloped: the body is a stream of records, so unwrapping
     * would try to parse a whole file as one JSON document. A refusal still
     * arrives as the ordinary envelope, and `throwIfError` turns it into an
     * `ApiError` instead of a file containing the refusal.
     */
    async export(): Promise<Blob> {
      const response = await throwIfError(await client.requestRaw("/me/export"));
      return response.blob();
    },

    /**
     * Deletes the account. Step-up gated, and `confirm` must repeat the
     * account's own address (S-06.b: the factor proves who, the confirmation
     * proves what). **Irreversible** — no grace period, no operator restore.
     */
    delete(confirm: string): Promise<AccountDeletedDto> {
      return client.request<AccountDeletedDto>("/me", jsonBody("DELETE", { confirm }));
    },
  };
}
