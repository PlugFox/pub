---
name: ui-critique
description: Review a Pub screen or component against Nielsen's 10 heuristics, cognitive load, and mandatory empty/loading/error state coverage; produce P0–P3 severity findings. Use when the user asks to "review", "critique", or "audit" a UI change, or before shipping a non-trivial screen.
---

# UI Critique (Pub web)

**Source:** ported from foxic `client/ui-critique`; adapted from [impeccable.style](https://impeccable.style/) (`/critique` + `/audit` + `/harden`) and [Nielsen Norman Group — 10 Usability Heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/). Visual rules defer to [web/DESIGN.md](../../../../web/DESIGN.md).

Screens under review live in [apps/site/src/app/screens/](../../../../web/apps/site/src/app/screens/) (SPA) and [apps/site/src/pages/](../../../../web/apps/site/src/pages/) (static Astro).

## Checklist

Run every pass. Record findings with severity.

### 1. State coverage (hard requirement — P0 if missing)

Every data-driven view must handle **all five** states. The kit maps them directly:

- **Empty** — `EmptyState`: title + one-line description + the action that fills it (its spec *requires* offering that action). No results in `search.tsx`, no orgs in `orgs.tsx`, no tokens in `tokens.tsx` — each must tell the user what to do next, not just that nothing is here.
- **Loading** — `Skeleton` sized to the content it replaces, for content regions. `Spinner` only for discrete actions of unknown duration (a submitting button), never for page content.
- **Error** — `Alert` (`danger` intent): what went wrong in human language, what to do (retry), and keep `ApiError` vs `NetworkError` distinct — a network failure is "check your connection", not "forbidden". Never raw error objects in copy.
- **Partial / stale** — cached data while refetching; a stopped SSE stream must surface, not silently stale (see roadmap D32: the SSE stream never restarts after a rate-limited stop — that class of bug).
- **Full** — the happy path.

First-run flows specifically: greet, explain, set up something useful on the first click. Don't drop the user into an empty dashboard.

### 2. Nielsen's 10 heuristics

1. **Visibility of system status.** Every async op shows progress; every click responds within 100 ms. Transient confirmations are Toasts; persistent conditions are Alerts (an Alert stays until its condition changes).
2. **Match with the real world.** Every user-facing string goes through `packages/i18n` (YAML + mandatory `desc`, `bun run i18n:gen`) — never hardcoded; 10 locales, English fallback. No jargon like "null" in copy. Versions/hashes render in mono per DESIGN.md §3.
3. **User control and freedom.** Cancel buttons on dialogs; destructive ops get a `danger`-intent confirmation, reversible ops don't get "are you sure?". Show-once surfaces (the token panel in `tokens.tsx`) must say clearly that the value won't be shown again — the user can't undo closing it.
4. **Consistency and standards.** Same action, same label everywhere. Dialog actions right-aligned, primary/danger last (DESIGN.md §6). Use `packages/ui` components — never a one-off restyle in a screen.
5. **Error prevention.** Validate before submit; disable the primary button when the form is invalid and show why in helper text.
6. **Recognition rather than recall.** Field hints visible; no "remember the code from the previous step" (2FA enrollment renders the manual secret next to the QR for exactly this reason).
7. **Flexibility and efficiency.** Keyboard completes every flow (see [ui-accessibility](../ui-accessibility/SKILL.md)); bulk actions for lists ≥ 20 items; tables get search/filter as they grow.
8. **Aesthetic and minimalist design.** Every pixel earns its place — DESIGN.md §7 Do/Don't is the rulebook (tokens only, no shadows on static surfaces, no gradients outside marketing).
9. **Recognize, diagnose, recover from errors.** Inline validation at field level (`aria-invalid` + linked description); a single retry on network failures; error codes for support where the server provides them.
10. **Help and documentation.** Contextual hints, not a buried help center. `Tooltip` for a non-obvious icon (hover, short hint); `Popover` for reference content like search syntax (click, focusable, may hold links/code).

### 3. Cognitive load

- How many decisions does the user face on this screen? > 7 → redesign.
- One primary action per screen; everything else is `ghost`/`outline`.
- Read the screen aloud in one sentence. If you can't, the hierarchy is wrong.

### 4. Keyboard + focus

- Tab order matches visual order; focus ring visible on every interactive element (accent ring — DESIGN.md §6).
- Escape closes dialogs/menus/popovers; Enter submits the default form.
- Every screen has a real heading; route changes move focus or announce (both are known debt — roadmap D33; flag as P0 on touched screens).

### 5. Perf + feel

- Time-to-interactive on the main view < 500 ms perceived; use `<Suspense>` boundaries with Skeleton fallbacks.
- No layout shift: reserve space for async content with skeletons sized to the real content.
- Transitions ≤ 200 ms; motion is decorative-only in this product and dies under reduced-motion globally (DESIGN.md §7a) — no bouncy springs, ever.
- Bundle awareness: compare `dist/` sizes after `bun run build` (DESIGN.md §9.9); the eager island is already ~79 KB gzip (roadmap D34) — new eager imports need justification.

## Severity

- **P0** — broken functionality, data loss risk, accessibility blocker, missing state coverage. Fix before merge.
- **P1** — usability defect, design-system inconsistency, low contrast. Fix this PR or file a follow-up.
- **P2** — polish issue (alignment, minor copy). Batch these.
- **P3** — nitpick. Note, don't block.

## Deliverable

A numbered list grouped by severity. For each finding: where (file:line or screen name), what's wrong, what to do. Verify visually in the real browser (both themes via the ThemeToggle) using the claude-in-chrome MCP before writing findings from code alone.

## Related

- [ui-accessibility](../ui-accessibility/SKILL.md) — the dedicated a11y pass + known-debt checklist.
- [web/DESIGN.md](../../../../web/DESIGN.md) — component specs, Do/Don't, pre-commit visual checklist (normative).
- [docs/rules/web.md](../../../../docs/rules/web.md) — code conventions (normative).
- [docs/roadmap.md](../../../../docs/roadmap.md) — D32/D33/D34: known frontend defects worth flagging when adjacent.
