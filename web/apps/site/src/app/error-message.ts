import { type ApiError, isApiError, isNetworkError } from "@pub/api/errors";
import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";

/*
 * What a refusal says to the user (D18, [decision 16]).
 *
 * The server answers every refusal with `{ error: { code, message } }` where
 * the code is a stable closed vocabulary (`core/src/error.rs`) and the message
 * is a sentence written for a human. Until now the island threw both away and
 * rendered one generic string, so "you are past the unretract window", "you
 * cannot remove the last owner" and "that slug is taken" were indistinguishable
 * from a bug — including on the screens whose own copy promises to explain
 * exactly those cases.
 *
 * THE CHOICE IS MADE BY THE CODE, NEVER BY THE MESSAGE TEXT. Matching on
 * message strings is the one thing decision 16 forbids outright: the text is
 * not a contract, it is prose that gets rewritten, and a UI keyed on it breaks
 * silently the day somebody improves a sentence.
 *
 * Three tiers:
 *
 *   1. SILENT — the code is rendered, the message is NEVER shown. Two separate
 *      reasons, both binding. `internal` / `database_error` / `blob_error` /
 *      `kv_error` / `config_invalid` carry backend text (SQL fragments, key
 *      names, bucket paths): operator information, not user information. And
 *      `not_found` / `unauthorized` are answers S-04 deliberately makes
 *      uniform — a `not_found` whose message says WHAT was not found is an
 *      enumeration oracle rendered in the UI.
 *   2. DETAILED — the message IS the information, so it follows a localized
 *      headline. These are the refusals a user can act on.
 *   3. STRUCTURAL — codes the client answers with a prompt, a countdown or a
 *      sign-out. They are handled by the interceptors and the stores long
 *      before this module sees them; the mapping here is the fallback for the
 *      cases that reach a toast anyway.
 *
 * The detail is the server's ENGLISH sentence under a localized headline. That
 * is a deliberate trade, recorded in decision 33 rather than left to a screen:
 * the alternative is translating server prose, which means matching on it. It
 * is reversible in this one function if the API ever emits structured detail.
 *
 * [decision 16]: ../../../../../docs/decisions.md#16--error-handling
 */

/** Message descriptors are `{ id, en }` pairs from the generated i18n modules. */
type Message = { readonly id: string; readonly en: string };

/**
 * Codes whose server message is never rendered, and what is shown instead.
 *
 * A code in this table is a promise: no server text under it reaches the user.
 */
const SILENT: Record<string, Message> = {
  not_found: app.errorNotFound,
  unauthorized: app.errorUnauthorized,
  internal: app.errorServer,
  database_error: app.errorServer,
  blob_error: app.errorServer,
  kv_error: app.errorServer,
  config_invalid: app.errorServer,
  unimplemented: app.errorUnimplemented,
};

/** Codes whose server message carries the reason, shown after a localized headline. */
const DETAILED: Record<string, Message> = {
  invalid_argument: app.errorInvalid,
  conflict: app.errorConflict,
  forbidden: app.errorForbidden,
  expired: app.errorExpired,
  busy: app.errorBusy,
  last_owner: app.errorLastOwner,
};

/** Codes the client answers structurally; here only as a fallback rendering. */
const STRUCTURAL: Record<string, Message> = {
  invalid_code: app.errorInvalidCode,
  step_up_required: app.errorStepUpRequired,
  refresh_reused: app.errorRefreshReused,
};

/** Longest server detail rendered; anything past this is clipped. */
const MAX_DETAIL = 300;

/**
 * The sentence to show for an arbitrary failure.
 *
 * A `NetworkError` is never a refusal — the request did not complete — and
 * keeps its own message, which is the distinction `packages/api/errors.ts`
 * exists to preserve.
 */
export function describeError(error: unknown): string {
  if (isNetworkError(error)) return t(app.networkError);
  if (!isApiError(error)) return t(app.genericError);
  return describeApiError(error);
}

function describeApiError(error: ApiError): string {
  const silent = SILENT[error.code];
  if (silent !== undefined) return t(silent);

  const structural = STRUCTURAL[error.code];
  if (structural !== undefined) return t(structural);

  if (error.code === "rate_limited") {
    return t(app.rateLimited, { seconds: error.retryAfter ?? 60 });
  }

  const detailed = DETAILED[error.code];
  const detail = cleanDetail(error.message);
  if (detailed !== undefined) {
    return detail === null ? t(detailed) : `${t(detailed)}: ${detail}`;
  }

  /*
   * An unrecognized code is a code this table has not been taught yet — which
   * may well be a future SILENT one. The safe default for an unclassified
   * message is not to print it; the code itself is short, stable, and the one
   * thing a bug report needs.
   */
  return `${t(app.genericError)} (${clip(error.code, 40)})`;
}

/**
 * The server sentence, or `null` when there is nothing worth showing.
 *
 * The domain error's `Display` prefixes its own class — "conflict: slug taken",
 * "invalid argument: …" — and the headline already says that, so the prefix is
 * dropped rather than shown twice in two languages.
 */
function cleanDetail(message: string): string | null {
  const trimmed = message.trim();
  if (trimmed === "") return null;
  const colon = trimmed.indexOf(": ");
  const body = colon > 0 && colon <= 24 ? trimmed.slice(colon + 2).trim() : trimmed;
  return body === "" ? null : clip(body, MAX_DETAIL);
}

function clip(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}
