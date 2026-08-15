import { type ApiClient, jsonBody } from "./client";
import type {
  AdminOrgDto,
  AdminOrgQuotaDto,
  AdminSettingsDto,
  AdminSettingsPatchBody,
  AdminStatsDto,
  AdminUserDto,
  AuditEventDto,
  JobRunDto,
  ListDto,
  SmtpTestResultDto,
  UserStatus,
} from "./types";

/*
 * Instance administration (`/api/v1/admin/*`).
 *
 * This is the second, ORTHOGONAL authorization plane (decision 19's addendum):
 * membership of it is `users.is_instance_admin`, read from the row on every
 * request and never carried in a token claim, so a demotion bites on the very
 * next call. Nothing here is reachable by holding an org role, however high.
 *
 * Two shapes the UI has to respect:
 *
 *   - `PATCH /admin/settings` replaces each SECTION wholesale. Sending
 *     `{ branding: { name } }` without the other branding fields clears them,
 *     so the settings form always submits a full section built from the loaded
 *     values.
 *   - Secrets are write-only (S-26). `SmtpSettingsDto` carries `password_set`
 *     and never a password; omitting `password` on a write keeps the stored
 *     one and `""` clears it. The form therefore has a "set password"
 *     affordance rather than a value-bearing field.
 */

export type AuditFilters = {
  /** Org id (not slug — the audit rows store ids). */
  readonly org?: string;
  /** Dot-namespaced action PREFIX, e.g. `org.member.`. */
  readonly action?: string;
  readonly actor?: string;
  readonly actorKind?: "user" | "token";
  /** RFC 3339, inclusive. */
  readonly from?: string;
  /** RFC 3339, exclusive. */
  readonly until?: string;
  readonly cursor?: string;
  readonly limit?: number;
};

export type UserFilters = {
  /** Case-insensitive substring of the email or display name. */
  readonly q?: string;
  readonly status?: UserStatus;
  readonly admins?: boolean;
  readonly cursor?: string;
  readonly limit?: number;
};

function queryString(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") continue;
    search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded === "" ? "" : `?${encoded}`;
}

export type AdminApi = ReturnType<typeof createAdminApi>;

export function createAdminApi(client: ApiClient) {
  return {
    settings(): Promise<AdminSettingsDto> {
      return client.request<AdminSettingsDto>("/admin/settings");
    },

    /** Each present section replaces the stored one wholesale. */
    updateSettings(body: AdminSettingsPatchBody): Promise<AdminSettingsDto> {
      return client.request<AdminSettingsDto>("/admin/settings", jsonBody("PATCH", body));
    },

    /**
     * Sends a probe message to the caller's own verified address.
     *
     * There is no recipient parameter, and a refused delivery is a `200` with
     * `delivered: false` — an SMTP misconfiguration is a diagnosis to render,
     * not an error to throw. Only transport-level failures reject.
     */
    testSmtp(): Promise<SmtpTestResultDto> {
      return client.request<SmtpTestResultDto>("/admin/settings/smtp/test", { method: "POST" });
    },

    users(filters: UserFilters = {}): Promise<ListDto<AdminUserDto>> {
      return client.request<ListDto<AdminUserDto>>(`/admin/users${queryString({ ...filters })}`);
    },

    /** S-09: suspension revokes the account's sessions; the count is not returned. */
    suspend(id: string): Promise<AdminUserDto> {
      return client.request<AdminUserDto>(`/admin/users/${encodeURIComponent(id)}/suspend`, {
        method: "POST",
      });
    },

    unsuspend(id: string): Promise<AdminUserDto> {
      return client.request<AdminUserDto>(`/admin/users/${encodeURIComponent(id)}/unsuspend`, {
        method: "POST",
      });
    },

    orgs(
      options: { readonly cursor?: string; readonly limit?: number } = {},
    ): Promise<ListDto<AdminOrgDto>> {
      return client.request<ListDto<AdminOrgDto>>(`/admin/orgs${queryString({ ...options })}`);
    },

    /**
     * Sets or clears one org's storage-quota override (S-20.b) — the admin
     * plane's only write over an org.
     *
     * `quota` is sent VERBATIM, including `null`: the server distinguishes an
     * explicit `null` ("clear the override, follow the instance default")
     * from an absent field, which it refuses with a 400 rather than reading as
     * one of the three states. `0` means unlimited for this org, whatever the
     * instance default is; a positive number is bytes.
     *
     * It is deliberately NOT reachable through `PATCH /api/v1/orgs/{slug}`,
     * which an org Admin can call — a quota its subject can raise is not a
     * quota.
     */
    setOrgQuota(id: string, quota: number | null): Promise<AdminOrgQuotaDto> {
      return client.request<AdminOrgQuotaDto>(
        `/admin/orgs/${encodeURIComponent(id)}`,
        jsonBody("PATCH", { storage_quota_bytes: quota }),
      );
    },

    /** Append-only audit log, newest first; the row id is also the cursor (S-22/S-23). */
    audit(filters: AuditFilters = {}): Promise<ListDto<AuditEventDto>> {
      return client.request<ListDto<AuditEventDto>>(
        `/admin/audit${queryString({
          org: filters.org,
          action: filters.action,
          actor: filters.actor,
          actor_kind: filters.actorKind,
          from: filters.from,
          until: filters.until,
          cursor: filters.cursor,
          limit: filters.limit,
        })}`,
      );
    },

    stats(): Promise<AdminStatsDto> {
      return client.request<AdminStatsDto>("/admin/stats");
    },

    /** 409 when the job already holds the cluster-wide leader lock. */
    runJob(job: string): Promise<JobRunDto> {
      return client.request<JobRunDto>(`/admin/jobs/${encodeURIComponent(job)}/run`, {
        method: "POST",
      });
    },
  };
}
