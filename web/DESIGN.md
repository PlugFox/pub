# Pub — Design System

The visual source of truth for everything under `web/`. Component conventions
(CVA, Kobalte, `cn()`, splitProps) live in [docs/rules/web.md](../docs/rules/web.md);
this document decides how things **look** and why. The live gallery is
[`/ui-kit`](apps/site/src/pages/ui-kit.astro) — every component, every state,
every theme.

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

- **Palette "Patina":** warm graphite neutrals (OKLCH hue 60–85 at whisper
  chroma) with a desaturated teal accent (hue ≈ 195). One accent; no
  secondary brand color. The alternate directions explored (iris, nocturne)
  live in [`packages/tokens/candidates/`](packages/tokens/candidates/) as
  future-theme material.
- **Fonts:** Inter (variable) for UI text, JetBrains Mono for code, versions,
  and hashes. Cyrillic is first-class; CJK falls back to system fonts (§3).
- **Themes are a registry, not a binary.** Three themes ship today — `light`
  (the `:root` palette and SSR default), `dark` (warm charcoal), and `amoled`
  (true-black for OLED screens) — and the model is open: a theme is a named
  `[data-theme="…"]` block in `theme.css` over the same token set (the full
  registration checklist lives in that file's header). The picker persists
  `system` or an explicit theme name; `system` resolves to light/dark by OS
  preference — amoled is only ever an explicit choice. Every visual decision
  is checked in **every registered theme** on `/ui-kit` before shipping.
- **Seed-theme seam (future):** a Material-You-style theme derived from one
  seed color slots in by *generating* the same raw token set at runtime and
  stamping it under a new `data-theme` name — the `--pub-*` token names are
  the generation contract, and a generated set must pass the same contrast
  pairs the static gate asserts. Documented in `theme.css`; not implemented.
- **Restraint:** subtle accent-tinted gradients are allowed on hero/marketing
  surfaces only. The app's data UI is flat: solid surfaces, hairline borders.

## 2. Color tokens

Three-layer system in `packages/tokens/theme.css`: raw `--pub-*` OKLCH values
(light on `:root`, every other registered theme as a named
`[data-theme="…"]` override block) → semantic `@theme` mapping → Tailwind
utilities (`bg-canvas`, `text-ink`, `border-line`, …). Components use
utilities only — never `--pub-*` variables, never hex, never raw `oklch()`.

Every pair listed in
[`packages/tokens/scripts/contrast-check.ts`](packages/tokens/scripts/contrast-check.ts)
is asserted ≥ 4.5:1 (WCAG AA normal text) in **every registered theme** on
every `bun run check` — the gate discovers the `[data-theme]` blocks by
parsing `theme.css`, so registering a theme automatically puts it under the
gate. Adding a token that carries text? Add its pair to the script in the
same commit.

### Neutrals & accent

| Token | Role | Light | Dark | AMOLED |
|---|---|---|---|---|
| `canvas` | page background | `oklch(0.978 0.004 85)` | `oklch(0.19 0.008 75)` | `oklch(0 0 0)` |
| `surface` | cards, headers, raised blocks | `oklch(0.995 0.002 85)` | `oklch(0.235 0.01 75)` | `oklch(0.15 0.006 75)` |
| `ink` | primary text | `oklch(0.245 0.012 60)` | `oklch(0.93 0.006 85)` | `oklch(0.93 0.006 85)` |
| `ink-muted` | secondary text | `oklch(0.47 0.015 60)` | `oklch(0.71 0.015 80)` | `oklch(0.72 0.015 80)` |
| `line` | borders, separators | `oklch(0.9 0.007 75)` | `oklch(0.33 0.012 75)` | `oklch(0.28 0.01 75)` |
| `accent` | interactive fill, links | `oklch(0.5 0.1 195)` | `oklch(0.75 0.1 195)` | `oklch(0.75 0.1 195)` |
| `accent-strong` | hover/active fill | `oklch(0.43 0.1 195)` | `oklch(0.8 0.09 195)` | `oklch(0.8 0.09 195)` |
| `on-accent` | text on accent fill | `oklch(0.985 0.005 195)` | `oklch(0.17 0.03 195)` | `oklch(0.15 0.03 195)` |
| `accent-soft` | tinted chips, hovers, hero | `oklch(0.95 0.032 190)` | `oklch(0.28 0.045 195)` | `oklch(0.24 0.04 195)` |
| `qr-surface` | QR well background | `oklch(1 0 0)` | `oklch(1 0 0)` | `oklch(1 0 0)` |
| `qr-ink` | QR modules | `oklch(0.15 0 0)` | `oklch(0.15 0 0)` | `oklch(0.15 0 0)` |

AMOLED is a **darkness variant of dark, not a second brand**: pure-black
canvas (an OLED switches those pixels off), surfaces barely lifted above it,
and the same accent/status families as dark — only `on-*` fills and soft
tints shift slightly so the pairs keep AA margins on black.

`qr-surface`/`qr-ink` are the **one pair that deliberately does not flip**: a QR
reader expects dark modules on a light field, and an inverted code is
unscannable on most phone cameras. Every theme carries identical values so the
contrast gate still checks the pair in each.

### Status colors

Each status hue ships four roles: `x` (solid fill — buttons and strong
indicators only), `on-x` (text on the solid fill), `x-soft` (tinted background
for badges/alerts), `x-ink` (text that passes AA on `x-soft`, `canvas`, and
`surface`).

| Token | Light | Dark | AMOLED |
|---|---|---|---|
| `success` / `on-success` | `oklch(0.52 0.13 150)` / `oklch(0.98 0.01 150)` | `oklch(0.72 0.13 150)` / `oklch(0.18 0.04 150)` | `oklch(0.72 0.13 150)` / `oklch(0.16 0.04 150)` |
| `success-soft` / `success-ink` | `oklch(0.95 0.04 150)` / `oklch(0.42 0.1 150)` | `oklch(0.27 0.045 150)` / `oklch(0.8 0.13 150)` | `oklch(0.23 0.04 150)` / `oklch(0.8 0.13 150)` |
| `warning` / `on-warning` | `oklch(0.76 0.15 75)` / `oklch(0.28 0.05 75)` | `oklch(0.78 0.13 80)` / `oklch(0.2 0.045 80)` | `oklch(0.78 0.13 80)` / `oklch(0.18 0.045 80)` |
| `warning-soft` / `warning-ink` | `oklch(0.95 0.055 85)` / `oklch(0.44 0.09 70)` | `oklch(0.28 0.04 80)` / `oklch(0.82 0.12 85)` | `oklch(0.24 0.035 80)` / `oklch(0.82 0.12 85)` |
| `danger` / `on-danger` | `oklch(0.51 0.18 30)` / `oklch(0.99 0.005 30)` | `oklch(0.68 0.15 28)` / `oklch(0.16 0.03 28)` | `oklch(0.68 0.15 28)` / `oklch(0.14 0.03 28)` |
| `danger-soft` / `danger-ink` | `oklch(0.94 0.035 28)` / `oklch(0.45 0.16 30)` | `oklch(0.27 0.055 28)` / `oklch(0.78 0.11 28)` | `oklch(0.23 0.05 28)` / `oklch(0.78 0.11 28)` |

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
| `rounded-full` | pill | badges, ThemePicker |

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
- **ThemePicker** — ghost pill trigger (`rounded-full`, 32 px square) opening
  a Menu of radio items: **system** plus one entry per registered theme
  (light, dark, amoled). Persists `pub_theme` ("system" or a theme name;
  unknown counts as system); stamps the *resolved* `data-theme` (contract
  shared with the anti-FOUC script); follows OS changes live while in
  system mode. The registry itself (`THEMES`, `resolveTheme`) is the pure
  module `@pub/ui/theme` — DOM-free and unit-tested.
- **Alert** — inline, layout-owned status block: `rounded-lg border p-4
  text-sm`, soft tints only (same palette rules as Badge). `danger` renders
  `role="alert"` (assertive), the rest `role="status"` (polite). Not a toast —
  an Alert stays until its condition changes. `AlertTitle` is an optional bold
  first line.
- **Spinner** — indeterminate busy indicator for actions of unknown duration
  (`sm` 16 / `md` 20 / `lg` 32 px), `animate-spin`, `currentColor`, wrapper is
  `role="status"` with a default `common.loading` name. Loading *content* of a
  known shape uses Skeleton instead.
- **Table** — the app's dense surface. Renders its own `overflow-x-auto`
  scroll container as a named, focusable `<section>` (§8: tables scroll, they
  do not reflow; a scroll region a keyboard cannot reach is a WCAG 2.1.1
  failure). Slots `TableHead` (canvas, bottom hairline) / `TableBody`
  (`divide-y`) / `TableRow` / `TableHeaderCell` (`text-ink-muted`,
  `scope="col"`) / `TableCell`; `px-4 py-3` cells, `text-sm`.
- **Tabs** (Kobalte) — underline skin: list is a bottom hairline, triggers are
  `text-ink-muted` going `text-ink` when `selected`, and an accent
  `TabsIndicator` slides under the active one. Kobalte owns roving focus and
  arrow-key navigation.
- **Menu** (Kobalte dropdown) — transient surface: `rounded-lg border bg-surface
  p-1 shadow-md`, items `rounded-md px-3 py-2 text-sm` highlighting to
  `bg-accent-soft text-accent`. `MenuLabel` is a muted `text-xs` heading,
  `MenuSeparator` a hairline that carries its own `my-1` — the **one
  sanctioned root margin** in the kit, because a separator's whole job is the
  gap around it and `MenuContent` cannot use `gap-*` without also spacing the
  items it deliberately packs. Single-choice groups (theme picker, sort
  order) use `MenuRadioGroup`/`MenuRadioItem` — Kobalte wires
  `menuitemradio` + `aria-checked`, and the checked item shows a check glyph
  in a fixed-width slot so labels stay aligned. Content is actions —
  never a form.
- **Popover** (Kobalte) — transient surface: `w-80 max-w-sm rounded-lg border
  bg-surface p-4 shadow-md`, arrow, a `text-sm font-semibold` title row and a
  built-in close button (i18n `common.close`). The line against Tooltip is
  behavioural, not visual, and it decides which one a screen may use: a
  Tooltip opens on hover, is never focusable, and holds a short hint; a
  Popover opens on **click**, takes focus, closes on Escape, and may hold
  headings, links, code, and copyable text. Reference documentation (the
  search-syntax help) is a Popover; an icon's one-line explanation is a
  Tooltip.
- **Toast** — transient message, `rounded-lg border p-4 shadow-md`, same four
  intents as Alert, with a close button. `ToastRegion` is the fixed
  bottom-right stack: `aria-live="polite"`, `pointer-events-none` on the
  region so it never blocks the page. The queue is app state, not UI state —
  `packages/ui` stays stateless.
- **EmptyState** — a *hole* in the layout, so a dashed outline on the canvas
  rather than a Card: `rounded-xl border border-dashed px-6 py-12 text-center`,
  title + optional description + an action slot. Always offer the action that
  fills it.
- **CopyButton** — outline `sm` Button that writes `value` to the clipboard and
  swaps its own label to `common.copied` for two seconds (`aria-live="polite"`).
  A denied or unavailable clipboard fails silently: the value is always
  rendered next to the button.
- **QrCode** — SVG QR from the dependency-free encoder in
  [`qr-encode.ts`](packages/ui/src/qr-encode.ts) (byte mode, level M, versions
  1–9). One `<path>` of module sub-paths, `currentColor` on transparent, so
  callers place it in a `bg-qr-surface text-qr-ink` well. `fallback` renders
  when the payload exceeds capacity — 2FA enrollment degrades to manual secret
  entry rather than to a blank box.

### App-owned surfaces (not in the kit)

One visual surface deliberately lives in `apps/site` rather than in
`packages/ui`, and it is documented here because it is still a design
decision:

- **Prose** (`apps/site/src/app/prose.tsx`, styled by
  [`styles/prose.css`](apps/site/src/styles/prose.css)) — the container for
  README/CHANGELOG HTML the **server** rendered and sanitized (S-11). It is the
  only place in the product that assigns `innerHTML`, and it accepts nothing
  but those two fields. Two consequences shape it: the incoming markup carries
  no classes, so the styling is descendant selectors rather than a class
  string — written with `@apply` of semantic utilities so no token leaks and
  no `[` appears in a class attribute (§7); and because a package cannot
  import the app's Tailwind entry, the stylesheet belongs to the app, which is
  what keeps it out of the kit. Type scale, radii, and colours are the same
  tokens as everywhere else; long tables and code blocks scroll inside their
  own box (§8) rather than widening the page.

**Kobalte state variants.** Primitives report state through data attributes;
`theme.css` names them so component class strings stay free of arbitrary-value
syntax: `selected:` (`[data-selected]`), `expanded:`, `highlighted:`. Disabled
state keys off the native `aria-disabled:`/`disabled:` variants.

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
  Reach for `dark:` only when the design genuinely differs structurally
  (it matches the whole dark family: dark and amoled).
- ❌ No new font files or weights without updating fonts.css subsets, the
  preload, and the bundle-size report.

## 7a. Motion

Motion in this product is decorative without exception: the Skeleton pulse,
the Spinner rotation, `transition-colors` on interactive surfaces, and the
sliding Tabs indicator. None of it encodes state a user could not read from the
static frame, so `prefers-reduced-motion: reduce` switches **all** of it off in
one place — [`apps/site/src/styles/global.css`](apps/site/src/styles/global.css)
sets `animation: none; transition: none` on every element.

Two consequences worth knowing before adding a component:

- The block is **unlayered** on purpose. Tailwind 4 emits utilities inside
  `@layer utilities`, and an unlayered rule outranks every layered one whatever
  its specificity — that is what lets it beat `animate-spin` without the
  `!important` §7 bans.
- Because the reset is global, a component never writes `motion-safe:` /
  `motion-reduce:` variants. If a future animation *does* carry meaning (a
  progress bar, a diff highlight), it must opt back in explicitly and say why.

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
   **Motion:** any new animation is covered by the global reduced-motion reset
   (§7a) — do not add per-component `motion-*` variants.
2. **Every theme:** open `/ui-kit` (and any touched screen) in every
   registered theme (light, dark, amoled) via the ThemePicker menu. No
   unreadable pairs, no invisible borders — watch hairlines especially on
   amoled's black canvas.
3. **Tokens only:** grep your diff for `#`-hex, `oklch(`, `--pub-`, `[` inside
   class strings — all four should be absent from component code.
4. **New tokens:** added to `theme.css` (every theme block) + mapped in
   `@theme` + contrast pair added to `contrast-check.ts` + table updated here.
   **New themes:** follow the registry checklist in `theme.css`'s header.
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
