import { type ApiClient, jsonBody, type RequestMeta } from "./client";
import type {
  LoginDto,
  OidcStartDto,
  PendingDto,
  ProvidersDto,
  StepUpDto,
  TotpConfirmedDto,
  TotpEnrollDto,
} from "./types";

/*
 * Authentication surface (`/api/v1/auth/*`).
 *
 * Everything that establishes or repairs a credential runs with
 * `skipAuth: true`: attaching a stale bearer to the login or refresh call
 * would make the interceptor try to refresh in order to refresh.
 */

const ANONYMOUS: RequestMeta = { skipAuth: true };
const REFRESH: RequestMeta = { skipAuth: true, isRefresh: true };

export type AuthApi = ReturnType<typeof createAuthApi>;

export function createAuthApi(client: ApiClient) {
  return {
    /**
     * S-03: mails an 8-digit code and returns the opaque pending id the verify
     * step must present. The response is shape-identical for known, unknown,
     * and policy-rejected addresses (S-04) — the UI must not infer anything
     * from it beyond "we accepted the request".
     */
    requestOtp(email: string): Promise<PendingDto> {
      return client.request<PendingDto>(
        "/auth/otp/request",
        jsonBody("POST", { email }),
        ANONYMOUS,
      );
    },

    /** S-03: redeems the code against the pending record. May answer `mfa_required`. */
    verifyOtp(input: { pendingId: string; email: string; code: string }): Promise<LoginDto> {
      return client.request<LoginDto>(
        "/auth/otp/verify",
        jsonBody("POST", {
          pending_id: input.pendingId,
          email: input.email,
          code: input.code,
        }),
        ANONYMOUS,
      );
    },

    /** Configured OIDC providers, in config order. Empty list = email OTP only. */
    providers(): Promise<ProvidersDto> {
      return client.request<ProvidersDto>("/auth/providers", undefined, ANONYMOUS);
    },

    /**
     * S-01.a: starts an OIDC flow. The returned `flow_id` is the flow binder —
     * hold it in sessionStorage across the full-page redirect and present it at
     * the callback; `state` alone redeems nothing.
     */
    startOidc(provider: string): Promise<OidcStartDto> {
      return client.request<OidcStartDto>(
        `/auth/oidc/${encodeURIComponent(provider)}/start`,
        { method: "POST" },
        ANONYMOUS,
      );
    },

    /** S-01.a: exchanges the redirect's `code` + `state` against the stored flow record. */
    finishOidc(input: {
      provider: string;
      flowId: string;
      code: string;
      state: string;
    }): Promise<LoginDto> {
      return client.request<LoginDto>(
        `/auth/oidc/${encodeURIComponent(input.provider)}/callback`,
        jsonBody("POST", { flow_id: input.flowId, code: input.code, state: input.state }),
        ANONYMOUS,
      );
    },

    /** S-05: redeems the pending-MFA handle with a TOTP code or a recovery code. */
    verifyTotp(input: {
      mfaToken: string;
      code?: string;
      recoveryCode?: string;
    }): Promise<LoginDto> {
      return client.request<LoginDto>(
        "/auth/totp/verify",
        jsonBody("POST", {
          mfa_token: input.mfaToken,
          code: input.code,
          recovery_code: input.recoveryCode,
        }),
        ANONYMOUS,
      );
    },

    /** S-05.a: parks a sealed seed for 15 minutes; nothing is written until `confirmTotp`. */
    enrollTotp(): Promise<TotpEnrollDto> {
      return client.request<TotpEnrollDto>("/auth/totp/enroll", { method: "POST" });
    },

    /** S-05.a: proves the authenticator works, writes the credential, returns the 10 recovery codes ONCE. */
    confirmTotp(code: string): Promise<TotpConfirmedDto> {
      return client.request<TotpConfirmedDto>("/auth/totp/confirm", jsonBody("POST", { code }));
    },

    /** S-06: disabling 2FA is step-up-gated — expect `step_up_required` on a stale session. */
    disableTotp(): Promise<undefined> {
      return client.request<undefined>("/auth/totp", { method: "DELETE" });
    },

    /** S-06.a: marks the session step-up-fresh until the returned instant. */
    stepUp(input: { code?: string; recoveryCode?: string }): Promise<StepUpDto> {
      return client.request<StepUpDto>(
        "/auth/step-up",
        jsonBody("POST", { code: input.code, recovery_code: input.recoveryCode }),
      );
    },

    /** S-08: rotates the refresh token. Reuse of a rotated-out token kills the family. */
    refresh(refreshToken: string): Promise<LoginDto> {
      return client.request<LoginDto>(
        "/auth/refresh",
        jsonBody("POST", { refresh_token: refreshToken }),
        REFRESH,
      );
    },

    /** S-09: revokes the current session server-side. The caller still clears local storage. */
    logout(): Promise<undefined> {
      return client.request<undefined>("/auth/logout", { method: "POST" });
    },
  };
}
