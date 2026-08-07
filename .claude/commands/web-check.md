---
description: Run web pre-commit checks (typecheck, biome, contrast gate, build, tests)
allowed-tools: Bash
---

Run the full web validation pipeline and report results.

Execute in order, stop on first failure:

1. `cd web && bun run check` — workspace typechecks (tsc ×5), Biome, and the WCAG-AA contrast gate over the token palette.
2. `cd web && bun run build` — production Astro build.
3. `cd web && bun test` — the web test suite.

If a step fails: show the failing output (tail only), identify the root cause, propose a fix. For pure formatting, you may run `bun run fix` but show the diff before applying.

If all pass: report `web-check: OK` with a one-line summary (test count, bundle size from the Astro output).

If generated artifacts are stale, regenerate first: `bun run i18n:gen` after YAML message edits, `bun run gen:api` after `packages/api/openapi.json` changes. Generated files are committed — include them in the same commit.
