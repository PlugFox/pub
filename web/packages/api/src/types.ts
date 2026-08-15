/*
 * Wire types for the app API.
 *
 * The DTOs are NOT hand-written any more: they are aliases into
 * `src/generated/openapi.ts`, which `bun run gen:api` derives from
 * `openapi.json` — the utoipa document the server emits at
 * `GET /api/openapi.json`. When a field here disagrees with the server, the
 * fix is to refresh the document and regenerate, never to edit a type.
 *
 * What stays hand-written, and why:
 *
 *   - `ListDto<T>`: utoipa monomorphizes the envelope (`ListDto_TokenDto`,
 *     `ListDto_MemberDto`, …), so the generated document has no generic to
 *     alias. The shape is normative in docs/rules/api.md and identical in
 *     every instantiation, so one generic here beats a dozen aliases.
 *   - The value-level vocabularies (`TOKEN_SCOPES`, `ORG_ROLES`,
 *     `SEARCH_SORTS`, …): the server types these fields as plain `string`
 *     because the wire carries names, not an enum (decision 19). The unions
 *     are ours — they drive `<For>` loops and exhaustive labels — and every
 *     one of them is *widened* back to `string` where a response is read, so
 *     a server that grows a value renders it rather than crashing.
 *   - Query-parameter option bags: utoipa emits every `IntoParams` field as
 *     `in: path` (the derive defaults `parameter_in` when the handler takes
 *     them from the query string), so the generated `parameters` entries are
 *     unusable for the listing routes. The area modules therefore declare
 *     their own option types; the response types are generated and correct.
 */

import type { components } from "./generated/openapi";

type Schemas = components["schemas"];

/** Cursor-paginated list envelope (docs/rules/api.md: cursor pagination only). */
export type ListDto<T> = {
  readonly items: readonly T[];
  readonly cursor?: string | null;
  readonly has_more: boolean;
};

// --- auth ---

export type UserDto = Schemas["UserDto"];
export type LoginDto = Schemas["LoginDto"];
export type PendingDto = Schemas["PendingDto"];
export type ProviderDto = Schemas["ProviderDto"];
export type ProvidersDto = Schemas["ProvidersDto"];
export type OidcStartDto = Schemas["OidcStartDto"];
export type TotpEnrollDto = Schemas["TotpEnrollDto"];
export type TotpConfirmedDto = Schemas["TotpConfirmedDto"];
export type StepUpDto = Schemas["StepUpDto"];

// --- sessions (S-10) ---

export type SessionDto = Schemas["SessionDto"];
export type RevokedDto = Schemas["RevokedDto"];

// --- CLI/API tokens (S-13) ---

export const TOKEN_SCOPES = ["read", "publish", "retract", "admin"] as const;
export type TokenScope = (typeof TOKEN_SCOPES)[number];

/** Scopes whose minting is step-up-gated (S-06.a). */
export const STEP_UP_SCOPES: readonly TokenScope[] = ["publish", "admin"];

export type TokenDto = Schemas["TokenDto"];
export type TokenCreatedDto = Schemas["TokenCreatedDto"];
export type TokenCreateBody = Omit<Schemas["TokenCreateBody"], "scopes"> & {
  readonly scopes: readonly TokenScope[];
};

// --- orgs (decision 19) ---

export const ORG_ROLES = ["read", "write", "admin", "owner"] as const;
export type OrgRole = (typeof ORG_ROLES)[number];

export type OrgDto = Schemas["OrgDto"];
export type OrgMembershipDto = Schemas["OrgMembershipDto"];
export type OrgProfileDto = Schemas["OrgProfileDto"];
export type OrgCreateBody = Schemas["OrgCreateBody"];
export type OrgUpdateBody = Schemas["OrgUpdateBody"];
export type OrgDeleteBody = Schemas["OrgDeleteBody"];
export type OrgDeletedDto = Schemas["OrgDeletedDto"];
export type MemberDto = Schemas["MemberDto"];
export type MemberAddBody = Schemas["MemberAddBody"];
export type MembershipChangedDto = Schemas["MembershipChangedDto"];
export type InvitationDto = Schemas["InvitationDto"];
export type InvitationCreatedDto = Schemas["InvitationCreatedDto"];

/** `read` < `write` < `admin` < `owner` — the client-side mirror of decision 19's ladder. */
const ROLE_RANK: Record<string, number> = { read: 50, write: 100, admin: 200, owner: 250 };

/**
 * Numeric rank of a role name; unknown or absent names rank 0.
 *
 * A DISPLAY decision only, like `roleAtLeast` below: comparisons built on it
 * hide affordances the server would refuse anyway, so an unknown future role
 * ranking 0 costs a hidden control, never an escalation.
 */
export function roleRank(role: string | null | undefined): number {
  if (role === null || role === undefined) return 0;
  return ROLE_RANK[role] ?? 0;
}

/**
 * Whether `role` is at least `required`.
 *
 * A DISPLAY decision only: it hides management affordances the server would
 * refuse anyway. Every authorization decision is the server's `authorize()`
 * chokepoint, so an unknown future role name ranking 0 here costs a hidden
 * button, never an escalation.
 */
export function roleAtLeast(role: string | null | undefined, required: OrgRole): boolean {
  return roleRank(role) >= ROLE_RANK[required];
}

// --- packages: read model (decision 11) ---

export const SEARCH_SORTS = ["relevance", "updated", "name", "downloads"] as const;
export type SearchSort = (typeof SEARCH_SORTS)[number];

export type DownloadsDto = Schemas["DownloadsDto"];
export type PackageSummaryDto = Schemas["PackageSummaryDto"];
export type PackageDetailDto = Schemas["PackageDetailDto"];
export type PackageLinksDto = Schemas["PackageLinksDto"];
export type VersionSummaryDto = Schemas["VersionSummaryDto"];
export type VersionDetailDto = Schemas["VersionDetailDto"];
export type PublisherDto = Schemas["PublisherDto"];
export type SearchResultsDto = Schemas["SearchResultsDto"];
export type FacetDto = Schemas["FacetDto"];

// --- packages: management (decisions 06/19) ---

export const PACKAGE_VISIBILITIES = ["public", "private"] as const;
export type PackageVisibility = (typeof PACKAGE_VISIBILITIES)[number];

export type PackageOptionsBody = Schemas["PackageOptionsBody"];
export type PackageOptionsDto = Schemas["PackageOptionsDto"];
export type VersionRetractedDto = Schemas["VersionRetractedDto"];
export type HardDeleteBody = Schemas["HardDeleteBody"];
export type HardDeletedDto = Schemas["HardDeletedDto"];
export type PackageTransferBody = Schemas["PackageTransferBody"];
export type PackageTransferredDto = Schemas["PackageTransferredDto"];

// --- home / landing (decision 17 branding) ---

export type HomeDto = Schemas["HomeDto"];
export type InstanceDto = Schemas["InstanceDto"];
export type CountersDto = Schemas["CountersDto"];

// --- notifications & realtime (decision 20) ---

export const NOTIFICATION_CATEGORIES = ["package", "org", "security"] as const;
export type NotificationCategory = (typeof NOTIFICATION_CATEGORIES)[number];

export type NotificationDto = Schemas["NotificationDto"];
export type NotificationFeedDto = Schemas["NotificationFeedDto"];
export type NotificationsReadDto = Schemas["NotificationsReadDto"];
export type NotificationPreferenceDto = Schemas["NotificationPreferenceDto"];
export type NotificationPreferencesDto = Schemas["NotificationPreferencesDto"];

/** One frame of `GET /api/v1/events` (the SSE `data:` document). */
export type StreamEventDto = Schemas["StreamEventDto"];

// --- instance administration ---

export type AdminSettingsDto = Schemas["AdminSettingsDto"];
export type AdminSettingsPatchBody = Schemas["AdminSettingsPatchBody"];
export type BrandingSettingsDto = Schemas["BrandingSettingsDto"];
export type RateLimitSettingsDto = Schemas["RateLimitSettingsDto"];
export type RegistrationSettingsDto = Schemas["RegistrationSettingsDto"];
export type SmtpSettingsDto = Schemas["SmtpSettingsDto"];
export type SmtpSettingsPatchDto = Schemas["SmtpSettingsPatchDto"];
export type UpstreamSettingsDto = Schemas["UpstreamSettingsDto"];
export type RegistrySettingsDto = Schemas["RegistrySettingsDto"];
export type SmtpTestResultDto = Schemas["SmtpTestResultDto"];
export type AdminUserDto = Schemas["AdminUserDto"];
export type AdminOrgDto = Schemas["AdminOrgDto"];
export type AdminOrgQuotaDto = Schemas["AdminOrgQuotaDto"];
export type AdminStatsDto = Schemas["AdminStatsDto"];
export type AuditEventDto = Schemas["AuditEventDto"];
export type JobRunDto = Schemas["JobRunDto"];
export type JobStateDto = Schemas["JobStateDto"];
export type ShadowingDto = Schemas["ShadowingDto"];
export type QuarantineDto = Schemas["QuarantineDto"];

export const REGISTRATION_MODES = ["open", "invite", "closed"] as const;
export type RegistrationMode = (typeof REGISTRATION_MODES)[number];

export const SMTP_SECURITY_MODES = ["tls", "starttls", "none"] as const;
export type SmtpSecurityMode = (typeof SMTP_SECURITY_MODES)[number];

export const UPSTREAM_POLICIES = ["allow", "block"] as const;
export type UpstreamPolicy = (typeof UPSTREAM_POLICIES)[number];

export const USER_STATUSES = ["active", "suspended", "deleted"] as const;
export type UserStatus = (typeof USER_STATUSES)[number];
