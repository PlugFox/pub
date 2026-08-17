# Frontend Conventions (`web/`)

**Any UI work starts with [`web/DESIGN.md`](../../web/DESIGN.md)** — the visual source of truth (mood, tokens, type scale, radii/elevation, component specs, agent checklist).

Bun workspaces; TypeScript 7 strict; Biome (2-space, 100 cols, double quotes) for lint+format — no ESLint/Prettier.

## TypeScript

- `strict`, `verbatimModuleSyntax`, `erasableSyntaxOnly`, `noUncheckedSideEffectImports`, `moduleResolution: "bundler"`.
- No `enum`, no namespaces — `as const` objects + unions. No `any` (Biome error).
- Typecheck with native `tsc` (TS7); tools that embed their own TS engine (astro check) may lag — that's expected until TS 7.1.

## Structure

- kebab-case filenames; named exports only (default exports only where a framework requires them: Astro pages, lazy route entries).
- Features never import other features; shared code goes to `packages/*` or `src/shared/`.
- Pages/routes are thin — no business logic. Max 3 directory nesting levels. No barrel files.

## Components (`packages/ui`)

- Simple components: Tailwind + CVA variants (exported separately). Interactive primitives: thin Kobalte wrappers with **subpath imports** (`@kobalte/core/dialog`).
- `splitProps`, never destructure props (Solid reactivity). Mandatory `class` prop merged via `cn()` (clsx + tailwind-merge). No margins on component roots. Build only what a screen actually needs.
- Every component gets a showcase entry in the ui-kit page (variants, sizes, states, both themes).

## Styling

- Tailwind 4 CSS-first. Design tokens live ONLY in `packages/tokens/theme.css` (OKLCH custom properties on `:root` / `[data-theme="dark"]`, mapped in a non-inline `@theme` block). No arbitrary values, no `!important`, no hex colors in components.
- Dark mode keys off `data-theme` (`@custom-variant dark`); the anti-FOUC inline script in the base layout is the only inline script (CSP nonce).

## i18n (`packages/i18n`)

- Every user-facing string is an i18n message. YAML per namespace; every key carries `en` + mandatory `desc` (context for translators/LLMs). `bun run i18n:gen` regenerates typed modules — generated code is committed and Biome-excluded, never hand-edited.
- 10 locales (en ru fr it de es pt ja ko zh-Hans); English is the bundled fallback; plurals via `Intl.PluralRules`; rich text only through the whitelist parser — no `innerHTML`.

## Data & API

- All HTTP goes through `packages/api` (interceptor-chain client; `ApiError` vs `NetworkError` are distinct — network failures never log the user out).
- Solid data code uses `createAsync`/`query`/`action` (solid-router) — no `createResource` in new code (Solid 2.0 migration surface).

## Tests

- `bun test` for pure logic (i18n, interceptors, utils) — corner cases first-class; component tests via vitest browser mode (headless Chromium, playwright provider) where behavior warrants it: `bun run test:browser` from `web/`.
- Browser tests live in `packages/ui/test/browser/*.vitest.{ts,tsx}` — the `.vitest.` suffix keeps them out of `bun test`'s `*.test.*`/`*.spec.*` globs, and vitest's `include` only matches that suffix. Never name a file so both runners pick it up.
- End-to-end specs live in `apps/site/test/e2e/*.e2e.ts` and run against the **production** build via `astro preview` (`just web-e2e`, or `bun run test:e2e` from `web/`) — the service worker registers under `import.meta.env.PROD` only. Same naming contract as above: `*.e2e.ts`, never `*.spec.ts`. Opt-in, not part of `just web-check`.
- The service worker is authored in `apps/site/src/sw/` and typechecked by `apps/site/tsconfig.sw.json` (lib `WebWorker`, no DOM — the two cannot share a program). Its routing table is a pure function in `policy.ts` so `bun test` can cover it; `sw.ts` is bundled to `dist/sw.js` by `scripts/build-sw.ts`, which also generates the precache manifest. Never hand-write `public/sw.js`.
