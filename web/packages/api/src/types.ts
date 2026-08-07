/*
 * Hand-written wire types for the app API.
 *
 * REGENERATE FROM OPENAPI once the app API stabilizes: the server annotates
 * every DTO with utoipa (`server/crates/api/src/dto.rs`) and emits OpenAPI
 * 3.1; decision 14 fixes `openapi-typescript` as the generator. Until then
 * these mirror the committed auth/session/token/org surface by hand — when a
 * field here disagrees with `dto.rs`, `dto.rs` wins.
 *
 * Conventions carried over from the server: ids travel as strings, timestamps
 * as RFC 3339 strings, role levels as names (decision 19), and every optional
 * field is `#[serde(skip_serializing_if = "Option::is_none")]` — hence
 * `field?: T` rather than `field: T | null` unless the server sends `null`.
 */

/** Cursor-paginated list envelope (docs/rules/api.md: cursor pagination only). */
export type ListDto<T> = {
  readonly items: readonly T[];
  readonly cursor: string | null;
  readonly has_more: boolean;
};

// --- auth ---

export type UserDto = {
  readonly id: string;
  readonly email: string | null;
  readonly email_verified: boolean;
  readonly display_name: string;
  readonly created_at: string;
};

/**
 * A sign-in step or a refresh.
 *
 * Two shapes behind one schema: `mfa_required: true` carries only `mfa_token`
 * (redeem at `POST /auth/totp/verify`, S-05); `false` carries the full pair.
 */
export type LoginDto = {
  readonly mfa_required: boolean;
  readonly mfa_token?: string;
  readonly access_token?: string;
  readonly refresh_token?: string;
  readonly session_id?: string;
  readonly user?: UserDto;
};

export type PendingDto = { readonly pending_id: string };

export type ProviderDto = { readonly id: string; readonly display_name: string };
export type ProvidersDto = { readonly providers: readonly ProviderDto[] };

export type OidcStartDto = { readonly authorize_url: string; readonly flow_id: string };

export type TotpEnrollDto = { readonly secret: string; readonly otpauth_url: string };
export type TotpConfirmedDto = { readonly recovery_codes: readonly string[] };

export type StepUpDto = { readonly valid_until: string };

// --- sessions (S-10) ---

export type SessionDto = {
  readonly id: string;
  readonly created_at: string;
  readonly last_seen_at: string;
  readonly ip: string | null;
  readonly user_agent: string | null;
  readonly current: boolean;
};

export type RevokedDto = { readonly revoked: number };

// --- CLI/API tokens (S-13) ---

export const TOKEN_SCOPES = ["read", "publish", "retract", "admin"] as const;
export type TokenScope = (typeof TOKEN_SCOPES)[number];

/** Scopes whose minting is step-up-gated (S-06.a). */
export const STEP_UP_SCOPES: readonly TokenScope[] = ["publish", "admin"];

export type TokenDto = {
  readonly id: string;
  readonly org_id: string;
  readonly name: string;
  /** First 8 characters of the secret — the only part ever retrievable (S-13). */
  readonly display_hint: string;
  readonly scopes: readonly string[];
  readonly created_at: string;
  readonly expires_at: string | null;
  readonly last_used_at: string | null;
};

/** `POST /tokens`: metadata plus the show-once secret. */
export type TokenCreatedDto = { readonly secret: string; readonly token: TokenDto };

export type TokenCreateBody = {
  readonly label?: string;
  readonly org_id: string;
  readonly scopes: readonly TokenScope[];
  readonly expires_days?: number;
};

// --- orgs (decision 19) ---

export const ORG_ROLES = ["read", "write", "admin", "owner"] as const;
export type OrgRole = (typeof ORG_ROLES)[number];

export type OrgDto = {
  readonly id: string;
  readonly name: string;
  /** Also the virtual registry base (`/o/{slug}/pub`) — immutable (decision 19). */
  readonly slug: string;
  readonly description: string;
  readonly upstream_policy: string;
  readonly archived: boolean;
  readonly created_at: string;
};

export type OrgMembershipDto = { readonly org: OrgDto; readonly role: string };

export type OrgCreateBody = { readonly name: string; readonly slug: string };
