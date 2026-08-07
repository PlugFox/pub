---
name: design-anti-patterns
description: Avoid the default "AI-generated" look in pub UI — no multi-hue gradients (accent-soft hero tints only), no nested/shadowed cards, no low-contrast grey-on-grey, no emoji-only states, no clamp(). Use before styling a new screen or reviewing a UI diff — enumerate the reflex defaults you will NOT use.
---

# Design Anti-Patterns (pub web)

**Source:** adapted from foxic `client/design-anti-patterns` (itself from
[impeccable.style](https://impeccable.style/) — "Gallery of Shame" + Paul
Bakaus's anti-attractor procedure), aligned with pub's
[web/DESIGN.md](../../../../web/DESIGN.md) (normative).

## The procedure

Before writing a single class, **enumerate the reflex defaults you will not
use.** LLMs and templates snap to the same narrow aesthetic; naming the trap
avoids it.

## The 6 traps, pub edition

1. **Multi-hue AI gradients.** Pub's accent *is* indigo/violet — which makes
   `from-purple-500 to-blue-500` slop extra easy to reach for. The rule
   (DESIGN.md §5): gradients are **subtle accent tints only**
   (`from-accent-soft/70` fading to `canvas`), **hero/marketing surfaces only**.
   Never in the app's data UI — no gradient table headers, cards, or buttons,
   and no `bg-clip-text` gradient text anywhere.
2. **Inter Everywhere.** Pub *did* pick Inter — deliberately, paired with
   JetBrains Mono for versions/hashes/code (DESIGN.md §3). The trap here is
   drift: a third face, mono in headings/nav, or decorative display fonts. The
   pairing is decided; spend the craft on hierarchy and spacing instead.
3. **Cardocalypse.** Pub's Card is `rounded-xl border border-line bg-surface` —
   **no shadow** (static surfaces never carry one; DESIGN.md §5's three-level
   elevation ladder). Never nest a card inside a card — reach for a heading,
   Separator, or whitespace. Shadows belong only to transient surfaces:
   `shadow-md` (tooltip, dropdown, popover, toast), `shadow-lg` (dialog).
4. **Template layouts.** Pub genuinely has a marketing surface (product SaaS,
   welcoming landing) — so the trap is subtler: keep the hero/3-col/testimonial
   clichés from leaking into `/app`, which is density + focus (tables, lists,
   monospace metadata). Same tokens and warmth on both, different information
   density.
5. **Low contrast.** Muted text is `text-ink-muted`, never `text-gray-400` —
   raw palette classes are banned outright (tokens only), and every
   ink-on-surface pair is machine-checked at WCAG AA ≥ 4.5:1 in both themes by
   [contrast-check.ts](../../../../web/packages/tokens/scripts/contrast-check.ts)
   on `bun run check`. A new text-bearing token without a `TEXT_PAIRS` entry is
   an unchecked pair — add it in the same commit. Don't prove contrast by eye.
6. **Emoji / icon-only states.** Every empty/error/loading state needs words.
   Pub ships the vocabulary: `EmptyState` (dashed outline, title + optional
   description + action slot — **always offer the action that fills the
   hole**), `Alert` for inline status, `Skeleton` for known-shape loading,
   `Spinner` (with its `common.loading` name) for unknown-duration actions.
   There is no icon set yet — components inline their own `currentColor` SVGs;
   never drop an emoji into production UI, and never rely on color or icon
   alone to carry a status.

## Deterministic checks (grep the diff before committing)

- `from-\w+-\d+.*to-\w+-\d+` — multi-hue gradient. Outside a hero with
  accent-soft tints, remove.
- `#`-hex, `oklch(`, `--pub-`, or `[` inside class strings — token-system
  violations (DESIGN.md §9.3).
- `red-|blue-|green-|gray-|neutral-|purple-` palette classes — banned; map to
  `danger`/`accent`/`success`/`ink-muted` tokens.
- Nested `rounded-xl`/`rounded-2xl` blocks, or `shadow-` on anything static —
  cardocalypse / elevation violation.
- `clamp(` — fixed scale everywhere, breakpoint jumps only (see
  [typography-scale](../typography-scale/SKILL.md)).
- `bg-clip-text` with a gradient — AI-gradient-text smell; solid color.
- `dark:` on a plain color utility — tokens flip themselves; `dark:` is for
  structural differences only.
- Emoji-only children of `EmptyState`/`Alert` — add copy and an action.

## When reviewing someone else's UI

Ask, in order:

1. Any gradient? If yes — hero/marketing surface, single accent tint?
2. Any nested cards or shadows on static surfaces?
3. Are all text colors token utilities, and are new pairs in the contrast gate?
4. Do empty/error/loading states exist, have copy, and (for EmptyState) an action?
5. Was it checked in **both** themes on `/ui-kit` and the touched screen?
6. Does it look like every other AI-generated SaaS dashboard? If yes, reject.

## Related

- [tailwind-styling](../tailwind-styling/SKILL.md) — the token system and hard bans.
- [typography-scale](../typography-scale/SKILL.md) — fixed scale, mono discipline.
- [web/DESIGN.md](../../../../web/DESIGN.md) — mood, elevation ladder, component specs, pre-commit checklist (§9).
- [docs/rules/web.md](../../../../docs/rules/web.md) — component conventions.
