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
