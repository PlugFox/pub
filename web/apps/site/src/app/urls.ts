/*
 * URL helpers shared by the island's screens.
 *
 * Both functions here are small and both are load-bearing: one decides where a
 * sign-in sends the user (an open redirect on a login page is a phishing
 * primitive), the other renders the string a user pastes into `dart pub token
 * add` (getting it wrong is the most common self-inflicted failure with a
 * private registry). They live outside any screen so there is exactly one
 * implementation of each, and so they can be tested without a DOM.
 */

/**
 * The router's base (decision 14: the island owns everything under `/app`).
 *
 * Kept next to the path helpers because it is the one value that has to agree
 * between the `<Router base>` and every place that converts a BROWSER path
 * into a ROUTER path.
 */
export const APP_BASE = "/app";

/**
 * Strips the router base off a browser pathname.
 *
 * `useLocation().pathname` reports the address-bar path, base included
 * (`/app/tokens`), while `navigate()` and `<A href>` take router-relative
 * paths (`/tokens`) and re-add the base themselves. Round-tripping one through
 * the other — which is exactly what a `return_to` does — therefore has to drop
 * the base once, or the redirect after sign-in lands on `/app/app/tokens`.
 */
export function toRouterPath(pathname: string, base: string = APP_BASE): string {
  if (pathname === base) return "/";
  return pathname.startsWith(`${base}/`) ? pathname.slice(base.length) : pathname;
}

/**
 * Narrows a `return_to` value to a same-origin absolute path.
 *
 * Anything that could leave the origin collapses to "/": a scheme
 * (`https://evil.example`), a protocol-relative path (`//evil.example`, which
 * a browser resolves as an absolute URL), a backslash (some parsers treat it
 * as a separator), and anything not rooted at "/". Control characters go too —
 * browsers strip tabs and newlines from URLs before parsing, so `/\tevil` and
 * `/%09evil` can disagree about what the path is.
 */
export function safeReturnTo(raw: string | null | undefined): string {
  if (raw === null || raw === undefined) return "/";
  if (!raw.startsWith("/")) return "/";
  if (raw.startsWith("//")) return "/";
  if (raw.includes("\\")) return "/";
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point.
  if (/[\u0000-\u001f\u007f]/.test(raw)) return "/";
  return raw;
}

/**
 * The org's virtual registry base — `PUB_HOSTED_URL` for the pub client
 * (decision 01: `/o/{slug}/pub`, with the format segment reserved).
 */
export function registryBase(slug: string, origin: string): string {
  return `${origin}/o/${slug}/pub`;
}

/**
 * The `pubspec.yaml` block that installs a package from this instance.
 *
 * `hosted:` with an explicit `url:` is not optional here and not a nicety: a
 * bare `hosted: ^1.0.0` resolves against `PUB_HOSTED_URL`, so a snippet
 * without the URL works on the author's machine (where the env var is set) and
 * silently reaches for pub.dev on a teammate's. Two spaces of indentation and
 * the caret constraint match what `dart pub add` writes, so the snippet can be
 * pasted next to lines the tool produced without reformatting the file.
 *
 * The version is rendered as a caret range because that is what `pub add`
 * picks; a pinned version is the exception a user types themselves.
 */
export function pubspecSnippet(name: string, version: string, hostedUrl: string): string {
  return [
    "dependencies:",
    `  ${name}:`,
    `    hosted: ${hostedUrl}`,
    `    version: ^${version}`,
  ].join("\n");
}

/** In-app path of a package page; `tab` deep-links one of its tabs. */
export function packagePath(name: string, tab?: string): string {
  const base = `/packages/${encodeURIComponent(name)}`;
  return tab === undefined || tab === "readme" ? base : `${base}/${tab}`;
}

/** In-app path of one version's page. */
export function packageVersionPath(name: string, version: string): string {
  return `/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`;
}

/** In-app path of an organization page. */
export function orgPath(slug: string): string {
  return `/orgs/${encodeURIComponent(slug)}`;
}
