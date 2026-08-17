/*
 * Precache manifest computation (decision 41) — the pure half of `build-sw.ts`.
 *
 * Every chunk name in the Astro build is a content hash (`App.B3adkQxQ.js`), so
 * no committed file can name the assets a document needs; the manifest has to
 * be read out of the emitted build. That is what makes this worth testing on
 * its own: a generator that quietly produced an empty list would give a green
 * build and the blank offline page this whole item exists to fix.
 *
 * WHAT IS COLLECTED, and what deliberately is not:
 *
 *   - every `/_astro/…` reference in the document — module scripts, the
 *     stylesheet, `modulepreload` hints and the preloaded font subset. Astro
 *     emits all of them under that one prefix (`assetsInlineLimit: 0` keeps
 *     bundled scripts out of the HTML), so one prefix is the whole surface;
 *   - the transitive **static** import closure of every JavaScript file in it.
 *     `import("./screen.js")` is NOT followed: route-level code splitting is
 *     the point of the app's `lazy()` entries, and precaching the admin audit
 *     viewer would undo it. Lazily-loaded chunks are picked up at runtime by
 *     the worker's cache-first rule instead.
 *
 * The reader is injected so the tests can describe a build as a plain object
 * rather than writing one to disk.
 */

/** A document to precache: the URL it is served at, and its file in the build. */
export type PrecacheDocument = {
  readonly url: string;
  readonly file: string;
};

/** The slice of the emitted build this module reads; paths are build-relative. */
export type DistReader = {
  exists(file: string): boolean;
  /** File contents, or `null` when absent or unreadable as text. */
  read(file: string): string | null;
};

/** Anything Astro emits under this prefix carries a content hash in its name. */
const ASSET_PREFIX = "/_astro/";

/** A reference to a hashed asset, in any attribute of any tag. */
const ASSET_REFERENCE = /["'(](\/_astro\/[A-Za-z0-9._-]+)["')]/g;

/**
 * Static imports in Rollup's minified output: `from"./chunk.js"` covers
 * `import … from`, `export … from` and `export * from`; the bare form is a
 * side-effect import. Neither can match `import("./chunk.js")`, because a
 * dynamic import is followed by `(` and never by a quote.
 */
const STATIC_IMPORT = /(?:from|import)\s*["']\.\/([A-Za-z0-9._-]+\.js)["']/g;

/** Raised when the build is not the shape a manifest can be computed from. */
export class PrecacheError extends Error {}

/**
 * The precache manifest for `documents`, plus `extras`, sorted and deduplicated.
 *
 * Throws rather than returning a short list: a missing document, or one that
 * references no assets, means the build changed shape — and that failure has to
 * reach the person who changed it instead of shipping a worker that caches a
 * page without its stylesheet.
 */
export function collectPrecache(
  reader: DistReader,
  documents: readonly PrecacheDocument[],
  extras: readonly string[] = [],
): string[] {
  const manifest = new Set<string>(extras);

  for (const document of documents) {
    const html = reader.read(document.file);
    if (html === null) {
      throw new PrecacheError(`precache document is missing from the build: ${document.file}`);
    }

    const assets = closureOf(reader, referencedAssets(html));
    if (assets.size === 0) {
      throw new PrecacheError(
        `${document.file} references no ${ASSET_PREFIX} asset — the build layout changed`,
      );
    }

    manifest.add(document.url);
    for (const asset of assets) manifest.add(asset);
  }

  return [...manifest].sort();
}

/** Every hashed asset URL named directly by one document. */
function referencedAssets(html: string): string[] {
  return [...html.matchAll(ASSET_REFERENCE)].map((match) => match[1]);
}

/**
 * The transitive static-import closure of `roots`.
 *
 * A reference to a file that is not in the build is dropped rather than fatal:
 * the reference pattern reads attributes and inline island payloads alike, and
 * a string that merely looks like an asset URL must not fail a good build. A
 * *missing* real dependency surfaces as the empty-closure refusal above.
 */
function closureOf(reader: DistReader, roots: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const pending = [...roots];

  while (pending.length > 0) {
    const url = pending.pop();
    if (url === undefined || seen.has(url)) continue;

    const file = url.slice(1);
    if (!reader.exists(file)) continue;
    seen.add(url);

    if (!url.endsWith(".js")) continue;
    const source = reader.read(file);
    if (source === null) continue;
    for (const match of source.matchAll(STATIC_IMPORT)) {
      pending.push(`${ASSET_PREFIX}${match[1]}`);
    }
  }

  return seen;
}
