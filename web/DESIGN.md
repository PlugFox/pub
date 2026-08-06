# Pub — Design System

The visual source of truth for everything under `web/`. Component conventions
(CVA, Kobalte, `cn()`, splitProps) live in [docs/rules/web.md](../docs/rules/web.md);
this document decides how things **look** and why. The live gallery is
[`/ui-kit`](apps/site/src/pages/ui-kit.astro) — every component, every state,
both themes.

> **Sync note:** the token tables below mirror
> [`packages/tokens/theme.css`](packages/tokens/theme.css) — that file is the
> machine truth (the contrast gate parses it, not this document). When you
> change a token there, update the table here in the same commit.

## 1. Mood

Pub is a **product SaaS**, not an austere IDE-styled dev-tool. The landing and
docs are welcoming and generous with whitespace — a friendly marketing surface
that happens to sell infrastructure. The app area (`/app`) may be denser than
the landing (tables, lists, monospace metadata), but it shares the same warmth:
same tokens, same soft radii, same accent.

- **Accent:** indigo/violet family (OKLCH hue ≈ 282–285). One accent; no
  secondary brand color.
- **Fonts:** Inter (variable) for UI text, JetBrains Mono for code, versions,
  and hashes. Cyrillic is first-class; CJK falls back to system fonts (§3).
- **Theme:** system default; light and dark are both first-class. Every visual
  decision is made twice — check `/ui-kit` in both before shipping.
- **Restraint:** subtle accent-tinted gradients are allowed on hero/marketing
  surfaces only. The app's data UI is flat: solid surfaces, hairline borders.

## 2. Color tokens

Three-layer system in `packages/tokens/theme.css`: raw `--pub-*` OKLCH values
(light on `:root`, dark on `[data-theme="dark"]`) → semantic `@theme` mapping →
Tailwind utilities (`bg-canvas`, `text-ink`, `border-line`, …). Components use
utilities only — never `--pub-*` variables, never hex, never raw `oklch()`.

Every pair listed in
[`packages/tokens/scripts/contrast-check.ts`](packages/tokens/scripts/contrast-check.ts)
is asserted ≥ 4.5:1 (WCAG AA normal text) in both themes on every `bun run
check`. Adding a token that carries text? Add its pair to the script in the
same commit.

### Neutrals & accent

| Token | Role | Light | Dark |
|---|---|---|---|
| `canvas` | page background | `oklch(0.982 0.005 285)` | `oklch(0.16 0.015 285)` |
| `surface` | cards, headers, raised blocks | `oklch(1 0 0)` | `oklch(0.21 0.018 285)` |
| `ink` | primary text | `oklch(0.24 0.02 285)` | `oklch(0.93 0.008 285)` |
| `ink-muted` | secondary text | `oklch(0.47 0.022 285)` | `oklch(0.71 0.02 285)` |
| `line` | borders, separators | `oklch(0.9 0.008 285)` | `oklch(0.31 0.02 285)` |
| `accent` | interactive fill, links | `oklch(0.5 0.19 282)` | `oklch(0.74 0.13 285)` |
| `accent-strong` | hover/active fill | `oklch(0.43 0.2 282)` | `oklch(0.79 0.115 285)` |
| `on-accent` | text on accent fill | `oklch(0.99 0.005 282)` | `oklch(0.18 0.03 285)` |
| `accent-soft` | tinted chips, hovers, hero | `oklch(0.95 0.03 282)` | `oklch(0.28 0.05 285)` |

### Status colors

Each status hue ships four roles: `x` (solid fill — buttons and strong
indicators only), `on-x` (text on the solid fill), `x-soft` (tinted background
for badges/alerts), `x-ink` (text that passes AA on `x-soft`, `canvas`, and
`surface`).

| Token | Light | Dark |
|---|---|---|
| `success` / `on-success` | `oklch(0.52 0.13 152)` / `oklch(0.98 0.01 152)` | `oklch(0.72 0.13 152)` / `oklch(0.18 0.04 152)` |
| `success-soft` / `success-ink` | `oklch(0.95 0.04 152)` / `oklch(0.42 0.1 152)` | `oklch(0.27 0.045 152)` / `oklch(0.8 0.13 152)` |
| `warning` / `on-warning` | `oklch(0.76 0.15 75)` / `oklch(0.28 0.05 75)` | `oklch(0.78 0.13 80)` / `oklch(0.2 0.045 80)` |
| `warning-soft` / `warning-ink` | `oklch(0.95 0.055 85)` / `oklch(0.44 0.09 70)` | `oklch(0.28 0.04 80)` / `oklch(0.82 0.12 85)` |
| `danger` / `on-danger` | `oklch(0.5 0.19 27)` / `oklch(0.99 0.005 27)` | `oklch(0.68 0.15 25)` / `oklch(0.16 0.03 25)` |
| `danger-soft` / `danger-ink` | `oklch(0.94 0.035 25)` / `oklch(0.45 0.16 27)` | `oklch(0.27 0.06 25)` / `oklch(0.78 0.11 25)` |

Usage rules:

- Soft tints (`*-soft` + `*-ink`) for badges, alerts, row highlights.
- Solid fills for buttons (`danger` intent) and small strong indicators (dots).
- `warning` solid always takes `on-warning` (dark text) — amber cannot carry
  white text at AA.
- Never mix roles across hues (no `success-ink` on `danger-soft`).

## 3. Typography

### Families

- **Inter Variable** (self-hosted via `@fontsource-variable/inter`; latin,
  latin-ext, cyrillic, cyrillic-ext subsets; wght 100–900) — all UI text.
- **JetBrains Mono** (self-hosted via `@fontsource/jetbrains-mono`; same four
  subsets; weight 400) — code, package versions, hashes, CLI commands, token
  displays.
- No CDN requests, ever. `@font-face` rules live in
  [`apps/site/src/styles/fonts.css`](apps/site/src/styles/fonts.css) with
  fontsource's `unicode-range` values; the critical Inter latin woff2 is
  preloaded in the base layout.

**CJK fallback (documented contract):** ja / ko / zh-Hans render through the
system stacks in `--pub-font-sans` — "Hiragino Kaku Gothic ProN", "Hiragino
Sans", "Yu Gothic UI", Meiryo (ja); "Apple SD Gothic Neo", "Malgun Gothic"
(ko); "PingFang SC", "Microsoft YaHei" (zh-Hans) — followed by generic
`sans-serif` and emoji fonts. We do not ship CJK font files; system rendering
is the accepted, tested behavior for those locales.

### Type scale

Fixed steps, no `clamp()`. Responsive jumps use breakpoint variants
(`text-4xl sm:text-5xl`), never fluid sizing.

| Role | Utility | Size | Weight / extras |
|---|---|---|---|
| Hero display | `text-4xl sm:text-5xl` | 36 → 48 px | `font-bold tracking-tight` |
| Page title (h1) | `text-3xl` | 30 px | `font-bold tracking-tight` |
| Section (h2) | `text-xl`…`text-3xl` | 20–30 px | `font-semibold`; `tracking-tight` from 2xl up |
| Card/list title (h3) | `text-base`–`text-lg` | 16–18 px | `font-semibold` |
| Body large (hero subline) | `text-lg` | 18 px | `leading-relaxed`, usually `text-ink-muted` |
| Body | `text-base` | 16 px | default |
| Secondary / UI | `text-sm` | 14 px | buttons, inputs, table cells |
| Caption / badge | `text-xs` | 12 px | `font-medium` in badges |

### Mono rules

- `font-mono text-sm` (or `text-xs` in badges) — mono runs one visual step
  smaller than surrounding prose.
- Use for: version numbers, sha256 digests, token values, package names in
  code context, CLI commands, URLs presented as configuration.
- Never for headings, body prose, or navigation.

## 4. Spacing — 4 px grid

Tailwind's default scale is the grid; use whole steps only (arbitrary values
are banned). Rhythm anchors:

- Component internals: `gap-1.5` (label↔input), `gap-2` (icon↔text),
  `gap-3` (button rows), `p-6` (card slots).
- Between form fields: `gap-5`. Between showcase/content sections: `gap-10`.
- Page padding: `px-6`; landing section rhythm `py-20`–`py-24`; app/tool pages
  `py-12`.
- Spacing belongs to parents (`gap-*`, container padding). Component roots
  never carry margins.

## 5. Radii & elevation

Radius tokens override Tailwind's scale (one notch softer than default — the
SaaS look; a terminal tool would use half of these):

| Utility | Value | Use |
|---|---|---|
| `rounded-sm` | 6 px | tiny chips |
| `rounded-md` | 8 px | inputs, tooltip panel, small controls |
| `rounded-lg` | 12 px | buttons, icon wells, code chips |
| `rounded-xl` | 16 px | cards, dialogs, showcase frames |
| `rounded-2xl` | 24 px | hero/marketing surfaces |
| `rounded-full` | pill | badges, ThemeToggle |

Elevation has exactly three levels:

1. **Flat** — `bg-canvas`, no border. The page itself.
2. **Static surface** — `bg-surface` + `border border-line`, **no shadow**.
   Cards, inputs, headers. Shadows on static content are noise.
3. **Transient surface** — appears above content, so it earns a shadow:
   `shadow-md` (tooltip, dropdown) or `shadow-lg` (dialog), always with
   `border border-line` (light) which doubles as the edge in dark mode.

**Gradients:** subtle accent-tinted only (`from-accent-soft/70` fading to
`canvas`), and only on hero/marketing surfaces. Never inside the app's data UI
— no gradient table headers, no gradient cards, no gradient buttons.

## 6. Component specs (`packages/ui`)

Common contract for all components: CVA recipe exported separately
(`buttonVariants`, …), `class` prop merged via `cn()`, `splitProps` for props,
no margins on roots, focus ring `focus-visible:ring-2 focus-visible:ring-accent`
(+ `ring-offset` on filled controls). Interactive primitives wrap Kobalte via
subpath imports. Every component has a `/ui-kit` registry entry.

- **Button** — intents `primary` (accent fill), `ghost` (transparent,
  `hover:bg-line/40`), `outline` (surface + line border, accent on hover),
  `danger` (danger fill, destructive confirmation actions only); sizes `sm`
  h-8, `md` h-10, `lg` h-12 (hero CTAs). `rounded-lg`, `font-medium`,
  no shadow. Links reuse `buttonVariants` on `<a>`.
- **Input & Label** — `rounded-md`, `bg-surface`, `border-line`; focus =
  accent border + soft accent ring; invalid state keys off `aria-invalid`
  (danger border/ring); sizes `sm` h-8 / `md` h-10. Label: `text-sm
  font-medium`, pairs via `for`/`id`, dims via `peer-disabled`.
- **Card** — elevation level 2 static: `rounded-xl border border-line
  bg-surface`, no shadow. Slots: `CardHeader` (p-6, gap-1.5),
  `CardContent` (p-6 pt-0), `CardFooter` (p-6 pt-0, flex gap-3).
- **Badge** — pill (`rounded-full`), `text-xs font-medium`, soft tints only:
  `neutral` (line border + canvas), `accent`, `success`, `warning`, `danger`
  (each `*-soft` bg + `*-ink`/`accent` text). Version numbers inside get
  `font-mono` from the caller.
- **Skeleton** — `animate-pulse rounded-md bg-line/60`, `aria-hidden`; caller
  sizes it to the content it replaces.
- **Separator** — hairline `bg-line`, horizontal/vertical, always decorative
  (`aria-hidden`). Semantic separation = real `<hr>` or a heading.
- **Dialog** (Kobalte) — overlay `bg-ink/40`; panel `max-w-md rounded-xl
  border bg-surface p-6 shadow-lg`; `DialogTitle` `text-lg font-semibold`;
  `DialogDescription` `text-sm text-ink-muted`; built-in close button
  (i18n `common.close`). Actions right-aligned, primary/danger last.
- **Tooltip** (Kobalte) — inverted surface: `bg-ink text-canvas` (an
  AA-checked pair in both themes), `rounded-md px-3 py-1.5 text-xs
  shadow-md`, 300 ms open delay, arrow included. Content is a short hint —
  never interactive controls.
- **ThemeToggle** — ghost pill (`rounded-full`, 32 px square) cycling
  light → dark → system; persists `pub_theme`; stamps `data-theme` (contract
  shared with the anti-FOUC script).

## 7. Do / Don't

**Do**

- Use semantic token utilities (`text-ink-muted`, `bg-surface`) everywhere.
- Merge every `class` prop through `cn()`; export CVA recipes.
- Keep focus visible: every interactive element has the accent focus ring.
- Add a `/ui-kit` entry, variants export, and (if it has logic) tests with any
  new component.
- Route every user-facing string through i18n with a `desc`.

**Don't**

- ❌ No hex colors, raw `oklch()`, or `--pub-*` references in components —
  tokens only via utilities.
- ❌ No arbitrary Tailwind values (`w-[13px]`, `text-[15px]`) and no
  `!important` — extend the token scale instead if genuinely needed.
- ❌ No margins on component roots — parents own spacing via `gap`/padding.
- ❌ No new inline scripts. The anti-FOUC theme script in the base layout is
  the ONLY authored inline script (CSP hash/nonce). Astro's island bootstrap
  scripts are framework-emitted and hashed server-side; never add
  `is:inline`, inline event handlers, or `javascript:` URLs.
- ❌ No shadows on static surfaces; no gradients outside hero/marketing.
- ❌ No `dark:` overrides for plain colors — the tokens flip automatically.
  Reach for `dark:` only when the design genuinely differs structurally.
- ❌ No new font files or weights without updating fonts.css subsets, the
  preload, and the bundle-size report.

## 8. Responsive strategy

Mobile-first with Tailwind's stock breakpoints (`sm` 640, `md` 768, `lg` 1024,
`xl` 1280). Fixed type steps at breakpoints — no `clamp()`, no viewport units
for text.

- Containers: landing `max-w-6xl`; tool pages `max-w-5xl`; prose/content
  `max-w-2xl`–`max-w-3xl`; all with `px-6`.
- Grids collapse: 4-col feature grid → `sm:grid-cols-2` → single column.
- The app area may keep denser layouts (tables scroll horizontally inside
  their own container rather than reflowing).
- Touch targets ≥ 32 px (`sm` controls); default controls 40 px (`md`).

## 9. Agent Guide — pre-commit visual checklist

Before committing any UI change, an AI contributor must verify:

1. **Gate:** `bun install && bun run check && bun run build && bun test` — all
   green. `check` includes the WCAG contrast gate over `theme.css`.
2. **Both themes:** open `/ui-kit` (and any touched screen) in light AND dark
   via the ThemeToggle. No unreadable pairs, no invisible borders.
3. **Tokens only:** grep your diff for `#`-hex, `oklch(`, `--pub-`, `[` inside
   class strings — all four should be absent from component code.
4. **New tokens:** added to `theme.css` (both themes) + mapped in `@theme` +
   contrast pair added to `contrast-check.ts` + table updated here.
5. **New component:** CVA recipe exported, `class` via `cn()`, `splitProps`,
   no root margins, focus ring, `/ui-kit` registry entry with all
   variants/sizes/states, subpath export in `packages/ui/package.json`,
   tests for anything with logic.
6. **Strings:** every new user-facing string is a YAML key with `desc`;
   `bun run i18n:gen` ran; ru translated (others may carry the `__todo__`
   marker). Internal tool pages (`/ui-kit`) are the only English-only surface.
7. **CSP:** built HTML contains no new inline scripts beyond the anti-FOUC
   script and Astro's island bootstraps; the service-worker registration stays
   an external bundled script.
8. **No external requests:** grep `dist/` for `https://` — only inert
   href/text occurrences allowed; no fonts, styles, or scripts from CDNs.
9. **Size:** compare `dist/` total and largest `_astro/*.js`/`*.css` chunks
   against the previous build; justify any notable growth in the PR/report.
