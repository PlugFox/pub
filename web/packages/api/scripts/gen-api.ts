/*
 * API type codegen (decision 14). Run via `bun run gen:api` from `web/`.
 *
 * Input:  packages/api/openapi.json — the server's utoipa-generated OpenAPI
 *         3.1 document, refreshed with
 *           cargo run -p pubd &
 *           curl -o web/packages/api/openapi.json http://127.0.0.1:8080/api/openapi.json
 *         The document is checked in so a frontend build never needs a running
 *         backend, and so a contract change shows up as a reviewable diff.
 * Output: packages/api/src/generated/openapi.ts — committed, Biome-excluded,
 *         never hand-edited. `src/types.ts` re-exports the useful aliases;
 *         screens import those, never this file.
 *
 * WHY THE BINARY IS SPAWNED FROM THIS PACKAGE'S OWN node_modules: openapi-typescript
 * embeds the TypeScript compiler API, and the repo typechecks with TS 7 native
 * (docs/rules/web.md), whose JS API does not expose `ts.factory`. `packages/api`
 * therefore pins a nested `typescript@5` **for the generator only** — the root
 * `tsc` that `bun run check` uses stays TS 7. Running the CLI from the package
 * root is what makes it resolve the nested copy.
 */
import { join } from "node:path";

const PKG_ROOT = join(import.meta.dir, "..");
const DOCUMENT = join(PKG_ROOT, "openapi.json");
const OUTPUT = join(PKG_ROOT, "src", "generated", "openapi.ts");
const BINARY = join(PKG_ROOT, "node_modules", ".bin", "openapi-typescript");
/** Normalized copy fed to the generator; never committed. */
const NORMALIZED = join(PKG_ROOT, "node_modules", ".cache-openapi.json");

const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"] as const;

type Operation = { operationId?: string };
type PathItem = Partial<Record<(typeof METHODS)[number], Operation>>;

/**
 * Makes `operationId` unique.
 *
 * utoipa derives the id from the handler's function NAME, and several modules
 * legitimately export a `list` / `create` / `revoke` — while the pub-protocol
 * routes are registered twice, once per virtual base (decision 01). OpenAPI
 * requires the id to be unique across the document, and openapi-typescript
 * turns each one into a key of its `operations` interface, so duplicates
 * become "Duplicate identifier" type errors in the generated module.
 *
 * Rather than silently letting the last one win, collisions are disambiguated
 * with a slug of the method and path (`list` → `list_get_api_v1_orgs`) and
 * reported, so the drift stays visible in the regeneration log. The fix
 * belongs upstream in the utoipa annotations; this keeps the frontend building
 * until it lands. Only `operations` keys are affected — nothing the app
 * imports (`components["schemas"]`) depends on the id.
 */
function dedupeOperationIds(document: { paths?: Record<string, PathItem> }): string[] {
  const seen = new Set<string>();
  const renamed: string[] = [];
  for (const [path, item] of Object.entries(document.paths ?? {})) {
    for (const method of METHODS) {
      const operation = item[method];
      const id = operation?.operationId;
      if (operation === undefined || id === undefined) continue;
      if (!seen.has(id)) {
        seen.add(id);
        continue;
      }
      const suffix = `${method}_${path}`.replaceAll(/[^a-zA-Z0-9]+/g, "_").replaceAll(/^_|_$/g, "");
      operation.operationId = `${id}_${suffix}`;
      seen.add(operation.operationId);
      renamed.push(`${id} → ${operation.operationId}`);
    }
  }
  return renamed;
}

const BANNER = `/*
 * AUTO-GENERATED from packages/api/openapi.json — DO NOT EDIT.
 *
 * Regenerate:
 *   1. refresh the document from a running server (optional — only when the
 *      backend contract moved):
 *        cargo run -p pubd            # SQLite + fs blob + memory KV defaults
 *        curl -o web/packages/api/openapi.json \\
 *             http://127.0.0.1:8080/api/openapi.json
 *   2. from web/:  bun run gen:api
 *
 * Consume the aliases in ../types.ts, not this module: the public surface of
 * @pub/api is the typed per-area modules (auth, orgs, packages, admin, …).
 */
`;

const document = (await Bun.file(DOCUMENT).json()) as { paths?: Record<string, PathItem> };
const renamed = dedupeOperationIds(document);
if (renamed.length > 0) {
  console.warn(
    `gen-api: ${renamed.length} duplicate operationId(s) disambiguated — fix the utoipa\n` +
      `         annotations upstream:\n           ${renamed.join("\n           ")}`,
  );
}
await Bun.write(NORMALIZED, JSON.stringify(document));

const generated = Bun.spawnSync([BINARY, NORMALIZED, "-o", OUTPUT], {
  cwd: PKG_ROOT,
  stdout: "inherit",
  stderr: "inherit",
});
if (generated.exitCode !== 0) {
  console.error("gen-api: openapi-typescript failed");
  process.exit(generated.exitCode ?? 1);
}

const body = await Bun.file(OUTPUT).text();
await Bun.write(OUTPUT, `${BANNER}${body}`);
console.log(`gen-api: ${OUTPUT.slice(PKG_ROOT.length + 1)} — ${body.split("\n").length} lines`);
