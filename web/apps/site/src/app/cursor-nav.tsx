import { t } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";
import { Button } from "@pub/ui/button";
import { type JSX, Show } from "solid-js";

/*
 * The app's one paginator (decision 40).
 *
 * FORWARD-ONLY, because every list behind it is keyset-paginated: the server
 * hands back a cursor for the next page and there is no token for the previous
 * one. "First page" is the way back, and it is the only one that is always
 * correct — a numbered pager over a keyset walk would have to invent offsets
 * the API does not have.
 *
 * A CURSOR BELONGS TO THE SLICE THAT MINTED IT. The caller keeps it in the URL
 * and drops it whenever the slice changes — a different sort, a different tab,
 * a different filter. That rule lives with the caller rather than here because
 * only the caller knows what its slice is; what this component guarantees is
 * that it renders nothing at all when there is neither a page to go back to nor
 * one to go forward to, so a short list has no chrome.
 */

export type CursorNavProps = {
  /** The cursor the current page was loaded with; `null` on the first page. */
  readonly cursor: string | null;
  /** The cursor of the next page, or `null` when this is the last one. */
  readonly next: string | null;
  readonly onGo: (cursor: string | null) => void;
};

export function CursorNav(props: CursorNavProps): JSX.Element {
  return (
    <Show when={props.cursor !== null || props.next !== null}>
      <nav aria-label={t(app.paginationLabel)} class="flex flex-wrap justify-center gap-3">
        <Show when={props.cursor !== null}>
          <Button intent="ghost" onClick={() => props.onGo(null)}>
            {t(app.paginationFirst)}
          </Button>
        </Show>
        <Show when={props.next}>
          {(next) => (
            <Button intent="outline" onClick={() => props.onGo(next())}>
              {t(app.paginationNext)}
            </Button>
          )}
        </Show>
      </nav>
    </Show>
  );
}

/**
 * The `next` argument for a page response: the server's cursor, but only when
 * it says there is more.
 *
 * The server's contract is that `cursor` is `Some` exactly when `has_more` is
 * true, so the two readings agree — this reads `has_more` because that is the
 * field [`rules/api.md`] documents as the "there is more" signal, and it keeps
 * one expression in one place instead of a copy per list.
 */
export function nextCursor(
  page: { readonly has_more?: boolean; readonly cursor?: string | null } | undefined,
): string | null {
  if (page?.has_more !== true) return null;
  return page.cursor ?? null;
}

/**
 * The cursor a URL carries, or `null` for "first page".
 *
 * `?cursor=a&cursor=b` is legal and the router surfaces it as an array; the
 * first value is what a browser's own form submission would send, and an empty
 * string is the shape a cleared parameter leaves behind — both mean the first
 * page rather than a cursor the server would refuse. The value itself is opaque
 * and is passed through unvalidated: checking it here would only duplicate the
 * server's check badly.
 */
export function readCursor(value: string | string[] | undefined): string | null {
  const first = value === undefined ? "" : ((Array.isArray(value) ? value[0] : value) ?? "");
  return first === "" ? null : first;
}
