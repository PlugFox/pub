/*
 * The per-org storage quota editor (S-20.b, decision 32) — presentation and
 * validation only.
 *
 * THE EFFECTIVE-LIMIT RULE IS NOT HERE, AND MUST NOT COME BACK. Resolving an
 * override plus an instance default into the limit an org is measured against
 * is owned by one server function,
 * `pub_registry::publish::effective_storage_quota`, whose doc comment claims
 * to be "the one place that rule is written". A TypeScript copy made that
 * false, and the copy could disagree with the server that enforces it while
 * both looked correct in their own tests. Every payload that shows a quota now
 * carries `effective_quota_bytes` resolved server-side —
 * `GET /api/v1/admin/orgs` and `PATCH /api/v1/admin/orgs/{id}` alike — so the
 * screen renders a number rather than deriving one.
 *
 * What stays here is what the server has no opinion about: which of the three
 * states a stored override is in (for labelling), the editor's form shape, and
 * the pre-flight that keeps a typed `0` out of the "limit" field.
 *
 * The three states themselves, for the reader:
 *
 *   - a **positive** override is that many bytes;
 *   - an override of **0** is "unlimited for this org", whatever the instance
 *     default is — it stops following the default rather than inheriting it;
 *   - **no** override (`null`) follows `registry.storage_quota_bytes`, which
 *     is itself `0 = unlimited`.
 *
 * NOTHING EXPRESSES "this org may store nothing". `0` means unlimited in both
 * places on purpose (decision 32): giving it a second, opposite meaning on one
 * of the two surfaces is a trap an operator finds by typing it. An admin who
 * wants an org to stop publishing archives the org.
 */

/** The three states of the override, as the editor names them. */
export const QUOTA_MODES = ["default", "unlimited", "limit"] as const;
export type QuotaMode = (typeof QUOTA_MODES)[number];

/** The editable shape of the per-org quota dialog. */
export type QuotaForm = {
  readonly mode: QuotaMode;
  /** Bytes, as typed. Read only when `mode` is `"limit"`. */
  readonly bytes: string;
};

/**
 * Whole non-negative integer, or `null`.
 *
 * The upper bound is `Number.MAX_SAFE_INTEGER` rather than the server's
 * `u64`/`i64`: a quota beyond 2^53 bytes cannot round-trip through JSON in
 * this runtime, and sending a silently rounded number would store a wall the
 * operator did not type.
 */
export function parseQuotaBytes(raw: string): number | null {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const value = Number.parseInt(trimmed, 10);
  return Number.isSafeInteger(value) ? value : null;
}

/** Which of the three states a stored override is in. */
export function quotaMode(override: number | null | undefined): QuotaMode {
  if (override === null || override === undefined) return "default";
  return override > 0 ? "limit" : "unlimited";
}

/** Builds the editor state from the stored override. */
export function quotaToForm(override: number | null | undefined): QuotaForm {
  const mode = quotaMode(override);
  return { mode, bytes: mode === "limit" ? String(override) : "" };
}

/**
 * Pre-flight for the dialog; `null` means valid.
 *
 * A `limit` of `0` is REFUSED rather than quietly accepted as unlimited. The
 * wire would take it — `0` is unlimited there — but a form with a dedicated
 * "unlimited" choice must not have a second, less obvious way to reach the
 * same state: an operator who typed `0` into a field labelled "bytes" was
 * asking for a wall, not for its removal.
 */
export function validateQuota(form: QuotaForm): "bytes" | null {
  if (form.mode !== "limit") return null;
  const bytes = parseQuotaBytes(form.bytes);
  return bytes !== null && bytes >= 1 ? null : "bytes";
}

/**
 * The value `PATCH /api/v1/admin/orgs/{id}` carries. Call only on a form that
 * validated.
 *
 * `null` clears the override; `0` is this org's own unlimited. The field is
 * always PRESENT in the body — the server refuses an empty patch rather than
 * reading an absent field as one of the three states, so an omitted key is a
 * 400 and not a silent no-op.
 */
export function quotaToPatch(form: QuotaForm): number | null {
  if (form.mode === "default") return null;
  if (form.mode === "unlimited") return 0;
  return parseQuotaBytes(form.bytes);
}
