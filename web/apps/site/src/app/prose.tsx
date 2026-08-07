import { cn } from "@pub/ui/cn";
import { type JSX, Show, splitProps } from "solid-js";

/*
 * Renders documentation HTML produced by the SERVER.
 *
 * This is the one place in the app that assigns `innerHTML`, and the contract
 * that makes it safe is entirely server-side (S-11,
 * `server/crates/registry/src/markdown.rs`):
 *
 *   - README/CHANGELOG are rendered from CommonMark ONCE, at publish time,
 *     onto the immutable version row — never at read time, so an attacker's
 *     markdown is not re-run on every page view;
 *   - comrak runs with `unsafe_ = false`, so raw HTML in the source is escaped
 *     rather than passed through;
 *   - ammonia then sanitizes the output against an allowlist, forces
 *     `rel="nofollow ugc noopener"` on links, permits only http/https/mailto
 *     schemes, and denies relative URLs so an `src` cannot be resolved against
 *     our own origin.
 *
 * Consequences for this component, all deliberate:
 *
 *   - `html` accepts ONLY those two server fields (`readme_html`,
 *     `changelog_html`). Nothing user-typed, nothing interpolated, no
 *     translated string — the i18n runtime has its own no-innerHTML rule.
 *   - `null`/`undefined` renders the `fallback` slot rather than an empty box,
 *     because "this version shipped without a README" is information.
 *   - Styling lives in `styles/prose.css` (`.pub-prose`): the incoming markup
 *     carries no classes, so descendant selectors are the only lever, and
 *     `@apply` keeps them on the token scale.
 */

export type ProseProps = Omit<JSX.HTMLAttributes<HTMLDivElement>, "innerHTML" | "children"> & {
  /** Sanitized HTML from the server. `null`/`undefined` shows `fallback`. */
  readonly html: string | null | undefined;
  /** Shown when there is no document. */
  readonly fallback?: JSX.Element;
};

export function Prose(props: ProseProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class", "html", "fallback"]);
  const html = (): string | null => {
    const value = local.html;
    return value === null || value === undefined || value.trim() === "" ? null : value;
  };
  return (
    <Show when={html()} fallback={local.fallback}>
      {(value) => (
        <div
          {...rest}
          class={cn("pub-prose max-w-none", local.class)}
          // Safe by the server-side contract documented above; see S-11.
          innerHTML={value()}
        />
      )}
    </Show>
  );
}
