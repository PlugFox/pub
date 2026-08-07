---
name: tailwind-styling
description: Apply Tailwind v4 correctly in pub's web/ — semantic token utilities from packages/tokens/theme.css, CVA for kit components vs inline utilities for screens, no arbitrary values / !important / hex, contrast-gated tokens. Use when writing a class string, adding a token, or reviewing Tailwind diffs.
---

# Tailwind Styling (pub web)

**Source:** adapted from foxic `client/tailwind-styling`, re-grounded in pub's
[web/DESIGN.md](../../../../web/DESIGN.md) and
[docs/rules/web.md](../../../../docs/rules/web.md) (both normative — this skill
summarizes, they decide), cross-checked with [Tailwind CSS v4 docs](https://tailwindcss.com/docs/theme)
and [CVA docs](https://cva.style/docs).

## Setup facts (don't fight them)

- Tailwind 4, **CSS-first** via `@tailwindcss/vite` in `apps/site/astro.config.ts`.
  There is **no `tailwind.config.js`** — all configuration lives in CSS.
- Entry: `apps/site/src/styles/global.css` imports fonts → `tailwindcss` →
  `@pub/tokens/theme.css` → `prose.css`, then registers the workspace package
  with `@source "../../../../packages/ui/src"`. A new workspace package with
  class names needs its own `@source` line, or its utilities silently vanish.
- Tokens live **only** in
  [packages/tokens/theme.css](../../../../web/packages/tokens/theme.css), three layers:
  1. raw `--pub-*` OKLCH custom properties on `:root` (light) + `[data-theme="dark"]` override block;
  2. a semantic `@theme` block mapping `--color-*`/`--radius-*`/`--font-*` onto them →
     utilities like `bg-canvas`, `text-ink`, `border-line`, `bg-accent-soft`;
  3. `@custom-variant dark` keyed off `data-theme` (never `prefers-color-scheme` in CSS),
     plus named Kobalte state variants `selected:` / `expanded:` / `highlighted:`.
- The `@theme` block is **deliberately not `@theme inline`**, although current
  Tailwind docs recommend `inline` for `var()` references: non-inline utilities
  compile to `var(--color-x)` which resolves *at the consuming element*, and that
  is exactly what makes the `[data-theme="dark"]` palette flip work. Do not "fix" this.
- **Radii are overridden** (SaaS-soft, one notch rounder than stock):
  `rounded-sm` 6px · `rounded-md` 8px · `rounded-lg` 12px · `rounded-xl` 16px ·
  `rounded-2xl` 24px. Don't assume Tailwind default sizes when eyeballing specs.

## Decision: CVA vs inline utilities

- **Reusable component in `packages/ui`** → CVA recipe, exported separately
  (`buttonVariants`, …) so links/other tags can reuse it. See
  `packages/ui/src/button.tsx` for the canonical skeleton (cva + `splitProps` +
  `cn()` merge of the `class` prop).
- **One-off layout in a screen** (`apps/site/src/app/screens/`) → inline utilities.
  Don't extract prematurely.
- No third option: no local "styles" helpers, no `@apply` for component classes.
  The one sanctioned `@apply` site is `apps/site/src/styles/prose.css`, which
  styles server-rendered README/CHANGELOG HTML that carries no classes.
- `cn()` = `twMerge(clsx(...))` from `packages/ui/src/cn.ts`. Every component
  merges its incoming `class` prop through it, or caller overrides are silently lost.

## Hard bans (DESIGN.md §7 — grep your diff)

- No arbitrary values (`w-[13px]`, `text-[15px]`, `data-[selected]:…`) — extend
  the token scale or use the named variants instead. No `[` in class strings.
- No `!important`. The global reduced-motion reset wins by being *unlayered*,
  not by `!important` — that trick is already spent in `global.css`; never add
  per-component `motion-safe:`/`motion-reduce:` variants.
- No hex colors, no raw `oklch()`, no `--pub-*` references in components —
  semantic utilities only. Raw Tailwind palette classes (`text-red-500`,
  `bg-gray-50`) are equally banned; the palette namespace is the token set.
- No `dark:` overrides for plain colors — tokens flip automatically via layer 1.
  `dark:` is only for genuinely structural differences.
- No margins on component roots — parents own spacing via `gap-*`/padding.
  (One sanctioned exception: `MenuSeparator` carries `my-1`, documented in DESIGN.md §6.)

## Adding a token

1. Add the `--pub-*` value to **both** theme blocks in `theme.css` (light `:root`
   and `[data-theme="dark"]`) — same token set, no new names in only one theme.
2. Map it in the `@theme` block.
3. If it carries text (or is text on something), add the pair to `TEXT_PAIRS` in
   [packages/tokens/scripts/contrast-check.ts](../../../../web/packages/tokens/scripts/contrast-check.ts)
   — the WCAG AA ≥ 4.5:1 gate runs on every `bun run check`, in both themes.
4. Update the token table in `web/DESIGN.md` in the same commit (sync note at its top).

## States

- Focus ring contract: `focus-visible:ring-2 focus-visible:ring-accent`
  (+ `ring-offset-2 ring-offset-canvas` on filled controls). `focus-visible`, not `focus`.
- Kobalte primitives report state via data attributes — use the named variants
  (`selected:`, `expanded:`, `highlighted:`), plus native `disabled:`/`aria-disabled:`
  and `aria-invalid` for inputs. Never mirror state into JS for styling.

## Spacing

4 px grid, whole Tailwind steps only. Rhythm anchors (DESIGN.md §4): `gap-2`
icon↔text, `gap-3` button rows, `p-6` card slots, `gap-5` between form fields,
`px-6` page padding. Gap over margin inside flex/grid.

## Before committing

Run the DESIGN.md §9 checklist: `bun run check && bun run build && bun test`
green (check includes the contrast gate), both themes eyeballed on `/ui-kit`,
diff grepped for `#`-hex / `oklch(` / `--pub-` / `[` inside class strings.

## Related

- [design-anti-patterns](../design-anti-patterns/SKILL.md) — gradients, cardocalypse, contrast.
- [typography-scale](../typography-scale/SKILL.md) — type roles, mono rules.
- [web/DESIGN.md](../../../../web/DESIGN.md) — the visual source of truth (tokens, elevation, component specs).
- [docs/rules/web.md](../../../../docs/rules/web.md) — component conventions (CVA, Kobalte, splitProps).
- [packages/tokens/theme.css](../../../../web/packages/tokens/theme.css) — machine truth for tokens.
