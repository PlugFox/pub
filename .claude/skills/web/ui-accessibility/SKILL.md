---
name: ui-accessibility
description: Ship accessible UI in the Pub frontend — semantic HTML, correct ARIA, keyboard-only flows, Kobalte focus management, the machine-enforced contrast gate, reduced-motion, and the known a11y debt to fix when touching a screen. Use when adding an interactive component, a dialog/menu/popover, a custom control, or reviewing a UI change for a11y.
---

# UI Accessibility (Pub web)

**Source:** ported from foxic `client/ui-accessibility`; grounded in [WCAG 2.2](https://www.w3.org/TR/WCAG22/), [Kobalte docs](https://kobalte.dev/docs/core/overview/introduction), and the [WAI-ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/patterns/). Pub-specific rules defer to [web/DESIGN.md](../../../../web/DESIGN.md) (normative for how things look and behave).

## Principle: semantic HTML first, ARIA second

If a native element does the job, use it. `<button>` not `<div onClick>`. `<a href>` not `<span role="link">`. ARIA is a patch for when semantics aren't enough — not a default.

## Hard rules (enforced in this repo)

- **Every interactive element is a real button / link / input.** Click-bound divs are banned.
- **Every form field has a label** — `Label` from `@pub/ui/label` pairs via `for`/`id`. A `placeholder` is not a label.
- **Every image has `alt`.** Decorative → `alt=""` (the landing logo does this). Functional → descriptive text.
- **Focus ring on every interactive element:** `focus-visible:ring-2 focus-visible:ring-accent` (+ `ring-offset` on filled controls) — DESIGN.md §6. Never `outline-none` without that replacement.
- **Contrast is machine-checked, not eyeballed.** Every text-carrying token pair listed in [contrast-check.ts](../../../../web/packages/tokens/scripts/contrast-check.ts) is asserted ≥ 4.5:1 in **both themes** on every `bun run check`. Adding a token that carries text? Add its pair to the script in the same commit.
- **Touch targets ≥ 32 px** (`sm` controls); default controls are 40 px (`md`) — DESIGN.md §8.
- **Scrollable content is keyboard-reachable.** `Table` renders its own named, focusable scroll region (`<section tabindex="0" aria-label=…>` around `overflow-x-auto`) — a scroll region a keyboard cannot reach is a WCAG 2.1.1 failure. Never wrap wide content in a bare `overflow-x-auto` div; reuse the Table pattern or give the container `tabindex="0"` + an accessible name.

## Keyboard

Every flow must be completable with keyboard only:

- `Tab` / `Shift+Tab` — focus moves in visual order.
- `Enter` / `Space` activate the focused button; `Enter` only for links and form submit.
- `Escape` closes Dialog, Menu, Popover (Kobalte does this — don't disable it).
- Arrow keys inside Menu, Tabs (Kobalte owns roving focus).
- **Focus trap + focus return** in Dialog — Kobalte handles both when you use the `@pub/ui/dialog` wrapper with its trigger; don't bypass with `document.querySelector`.

Test: unplug the mouse and complete the flow. If you can't, it's broken.

## ARIA patterns (use `packages/ui` first)

Interactive primitives are thin Kobalte wrappers (subpath imports) in [packages/ui/src/](../../../../web/packages/ui/src/): Dialog, Menu, Popover, Tabs, Tooltip. **Use these** — rolling your own `role="menu"` is a bug. The kit also fixes the live-region semantics; keep them intact:

- **Alert** — `danger` renders `role="alert"` (assertive); every other intent `role="status"` (polite).
- **ToastRegion** — `aria-live="polite"`, `pointer-events-none` on the region.
- **CopyButton** — `aria-live="polite"` on the button; the label swap to `common.copied` *is* the confirmation.
- **Spinner** — `role="status"` with a default `common.loading` name.
- **Skeleton / Separator** — `aria-hidden`; semantic separation is a real `<hr>` or a heading.

If you must add ARIA manually:

- `aria-label` for icon-only buttons, always through i18n: `<button aria-label={t(common.close)}>`. Never let an `aria-label` *replace* meaningful visible text (see debt list below).
- `aria-hidden="true"` on decorative icons inside labelled buttons (else the label is read twice).
- `aria-invalid` drives the Input danger styles — always pair it with `aria-describedby` pointing at the error text.
- Never `tabindex` > 0. Use `0` for focusable custom elements, `-1` to remove from tab order.

## Screen-reader-only text

```tsx
<button class="…">
  <svg aria-hidden="true" class="size-4" …/>
  <span class="sr-only">{t(tokens.revoke)}</span>
</button>
```

Tailwind ships `sr-only`. Use it for any icon-only control or status text; the string still goes through i18n with a `desc`.

## Motion

All motion in this product is decorative, and `prefers-reduced-motion: reduce` kills **all** of it in one unlayered block in [global.css](../../../../web/apps/site/src/styles/global.css) (`animation: none; transition: none`). Consequences (DESIGN.md §7a):

- Never write `motion-safe:` / `motion-reduce:` variants in components — the global reset covers you.
- If a future animation genuinely carries meaning (progress bar, diff highlight), it must opt back in explicitly and document why.

## Color + state

- **Never color-only to convey state.** Error red also gets an icon and text; status Badges keep their visible text.
- **Both themes, every time.** Check the touched screen and `/ui-kit` in light AND dark via the ThemeToggle before shipping.
- `disabled` removes an element from tab order; use `aria-disabled` when it should stay focusable but non-actionable. Kobalte state styling keys off the `aria-disabled:`/`disabled:` variants.

## Known debt — fix when you touch the screen

Verified gaps from [roadmap D33](../../../../docs/roadmap.md); if your change touches one of these areas, fixing the gap is part of the change:

- [ ] **Route change is silent** — no focus management or announcement when the SPA navigates. Moving focus to the new screen's heading (or an `aria-live` announcement) is the fix.
- [ ] **`EmptyState` titles are paragraphs**, so the 404/403 screens built on it have no heading at all. Every screen needs a real `<h1>`/`<h2>`.
- [ ] **Nine admin fields set `aria-invalid` with no `aria-describedby`** — the error text exists but is not programmatically linked.
- [ ] **Suspense fallbacks are `aria-hidden` skeletons with no live region** — a screen-reader user gets silence while content loads.
- [ ] **A `Badge` `aria-label` replaces the visible role value with the word "Role"** — an `aria-label` must never say less than the visible text.

## Testing

- **Keyboard-only walkthrough** of the touched flow — mandatory before commit.
- **Real browser** via the claude-in-chrome MCP (`mcp__claude-in-chrome__*`): open the touched screen, both themes, exercise the flow.
- `@playwright/test` is a dev dependency but there is **no test suite yet** — when one lands, an axe-core pass per route belongs in it; don't invent commands that don't exist today.
- **VoiceOver (macOS)** walkthrough for any new complex component before PR.

## Deterministic checks (grep the diff)

- `onClick` on `<div`/`<span` — wrong element.
- `outline-none` without a `focus-visible:ring-` replacement — invisible focus.
- `aria-label=""` — broken.
- `tabindex` with N > 0 — tab order hack.
- `aria-invalid` without a nearby `aria-describedby` — unlinked error.
- New `overflow-x-auto`/`overflow-auto` container without `tabindex="0"` + accessible name — unreachable scroll region.

## Related

- [ui-critique](../ui-critique/SKILL.md) — full usability pass; includes a11y.
- [web/DESIGN.md](../../../../web/DESIGN.md) — component specs, motion policy, pre-commit checklist (normative).
- [docs/rules/web.md](../../../../docs/rules/web.md) — component/code conventions (normative).
- [docs/roadmap.md](../../../../docs/roadmap.md) — D33 a11y debt inventory.
- Component sources: [web/packages/ui/src/](../../../../web/packages/ui/src/); showcase: [ui-kit-page.tsx](../../../../web/apps/site/src/ui-kit/ui-kit-page.tsx).
