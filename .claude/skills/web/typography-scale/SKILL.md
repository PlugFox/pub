---
name: typography-scale
description: Apply pub's fixed type scale — discrete Tailwind steps with breakpoint jumps, never clamp()/fluid sizing; Inter Variable for UI, JetBrains Mono one step smaller for code/versions/hashes. Use when adding text or headings, or when "responsive typography" is suggested.
---

# Typography Scale (pub web)

**Source:** adapted from foxic `client/typography-scale` (itself from
[impeccable.style](https://impeccable.style/) `/typeset`), re-grounded in
[web/DESIGN.md](../../../../web/DESIGN.md) §3 — the normative table. This skill
mirrors it; when they disagree, DESIGN.md wins.

## Core rule

**Fixed steps, no `clamp()`, no viewport units for text — anywhere,** including
the hero. Pub is stricter than the usual "fluid is OK on marketing" advice:
responsive jumps use breakpoint variants (`text-4xl sm:text-5xl`), never fluid
interpolation. The landing is welcoming and generous (pub is a product SaaS, not
an austere dev-tool), but it gets there with whitespace and breakpoint steps.

## The scale (mirror of DESIGN.md §3 — sync when it changes)

| Role | Utility | Size | Extras |
|---|---|---|---|
| Hero display | `text-4xl sm:text-5xl` | 36 → 48 px | `font-bold tracking-tight` |
| Page title (h1) | `text-3xl` | 30 px | `font-bold tracking-tight` |
| Section (h2) | `text-xl`…`text-3xl` | 20–30 px | `font-semibold`; `tracking-tight` from 2xl up |
| Card/list title (h3) | `text-base`–`text-lg` | 16–18 px | `font-semibold` |
| Body large (hero subline) | `text-lg` | 18 px | `leading-relaxed`, usually `text-ink-muted` |
| Body | `text-base` | 16 px | default |
| Secondary / UI | `text-sm` | 14 px | buttons, inputs, table cells |
| Caption / badge | `text-xs` | 12 px | `font-medium` in badges |

Anything above `text-5xl` is wrong everywhere; above `text-3xl` is wrong outside
the hero.

## Fonts — the pairing is decided, don't re-decide it

- **Inter Variable** (all UI text) and **JetBrains Mono** (code, versions,
  sha256 digests, CLI commands, token displays) — both **self-hosted** via
  fontsource files, `@font-face` rules hand-copied into
  `apps/site/src/styles/fonts.css` for exactly four subsets (latin, latin-ext,
  cyrillic, cyrillic-ext) with fontsource `unicode-range` values. No CDN
  requests, ever; the critical Inter latin woff2 is preloaded in the base layout.
- **CJK is a documented fallback contract:** ja/ko/zh-Hans render through the
  system stacks baked into `--pub-font-sans` — we ship no CJK font files.
- Adding a font file, weight, or subset requires updating `fonts.css`, the
  preload, and the bundle-size report (DESIGN.md §7 Don't). When bumping
  fontsource packages, re-diff the unicode-ranges against the shipped index.css.

## Mono rules (DESIGN.md §3)

- `font-mono text-sm` — mono runs **one visual step smaller** than surrounding
  prose (`text-xs` inside badges).
- Use for: version numbers, hashes, package names in code context, CLI
  commands, URLs presented as configuration. Never for headings, body prose, or
  navigation. Badge callers add `font-mono` themselves for version chips.

## Rules of thumb

- **Body floor is `text-sm` / 14 px.** `text-xs` is for captions and badges
  only, always with `font-medium` — never thin weights at small sizes.
- **Weight steps must be visible:** 400 → 600 (`font-semibold`) or 500 → 700,
  not 400 → 500 at the same size.
- **Muted text is `text-ink-muted`,** never a raw palette grey — the token pair
  is contrast-gated in both themes.
- **`tabular-nums`** wherever numbers align in columns (tables, version lists,
  counts). Proportional numerals are for prose only.
- Two families on one screen is the maximum; a third face is a bug.

## i18n note

10 locales; ru runs ~30% longer than en, de longer still, and CJK falls back to
system fonts with different metrics. Don't pick sizes/line-heights that barely
fit the English string. Every user-facing string is a YAML key with a `desc` in
`packages/i18n/messages/` → `bun run i18n:gen` (see docs/rules/web.md).

## Related

- [design-anti-patterns](../design-anti-patterns/SKILL.md) — low-contrast and font-sprawl traps.
- [tailwind-styling](../tailwind-styling/SKILL.md) — tokens, bans, CVA.
- [web/DESIGN.md](../../../../web/DESIGN.md) §3 — the canonical scale, families, and CJK contract.
- [docs/rules/web.md](../../../../docs/rules/web.md) — i18n flow and component conventions.
