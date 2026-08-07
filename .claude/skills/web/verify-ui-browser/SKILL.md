---
name: verify-ui-browser
description: Drive the Pub web UI in real Chrome via the claude-in-chrome MCP to verify a UI change end-to-end — golden path plus at least one edge case, both themes, mobile viewport. Use after any change that affects rendered UI, a form, a dialog, navigation, or user-visible behavior.
---

# Verify UI in the Browser (Pub web)

**Source:** ported from foxic `client/verify-ui-playwright`; rewritten for the claude-in-chrome MCP — Pub verifies UI in the user's real Chrome, not a Playwright-driven browser.

Typecheck and build do not substitute for exercising the UI. If behavior changed, walk it in a browser — then run the [DESIGN.md §9 pre-commit visual checklist](../../../../web/DESIGN.md) before committing.

## When to run

| Change | Needed |
|---|---|
| New component, screen, dialog, form, flow | **yes** |
| Navigation / routing / auth guards | **yes** |
| API integration or data shape | **yes** |
| CSS / Tailwind tweak, copy-only i18n change | visual check is enough; `/web-check` may suffice |
| Backend-only change with no UI surface | no |

## Procedure

### 0. Gate first

Run `/web-check` (`cd web && bun run check && bun run build && bun test`). No point clicking around a broken build.

### 1. Serve the UI — pick the mode the flow needs

**Static pages** (landing, `/ui-kit`, pure visual/theme checks):

```bash
cd web/apps/site && bun run dev   # http://localhost:4321
```

There is no API proxy in `astro.config.ts` — the island's same-origin `/api/v1` calls have no backend here, so API-backed screens show their error/empty states. Fine for layout and theme checks; wrong for flow verification.

**Full stack** (any flow that talks to the API):

```bash
cd web && bun run build
rm -rf ../server/crates/api/embedded/* && cp -R apps/site/dist/* ../server/crates/api/embedded/
cd ../server && cargo run -p pubd   # http://localhost:8080
```

Defaults need no containers: SQLite (`data/pub.sqlite3`), filesystem blobs, in-memory KV. Debug builds serve `embedded/` from disk at request time (`rust-embed` without `debug-embed`), so re-copying a fresh dist does not require recompiling. `embedded/` holds a committed placeholder — restore it before committing: `git checkout -- server/crates/api/embedded`.

**Auth caveat:** sign-in is email OTP (+ optional OIDC). Without `smtp.host` the server uses the in-memory mailer — OTP mail is recorded, never delivered, and not logged. For authenticated flows, point `smtp.*` at a local mail catcher (e.g. Mailpit) and read the code there. On an empty instance the first registered account becomes the instance admin ([docs/decisions.md](../../../../docs/decisions.md)).

### 2. Drive via MCP

Use the `mcp__claude-in-chrome__*` tools, in this order:

1. `tabs_context_mcp` (`createIfEmpty: true`) — always first. Then `tabs_create_mcp` for a fresh tab owned by this task; close it with `tabs_close_mcp` when done. Don't hijack a tab the user is using.
2. `navigate` → the affected page.
3. `read_page` → accessibility tree (`filter: "interactive"` when hunting for controls). Confirm the expected state **before** interacting. `computer {action: "screenshot"}` when pixels matter — spacing, theme, focus rings; `zoom` for small controls.
4. `computer` clicks/typing (or `form_input` for inputs/selects) → walk the flow. Prefer `ref` ids from `read_page`/`find` over guessed coordinates; consult a screenshot before coordinate clicks.
5. `read_console_messages` — **always pass `pattern` or `onlyErrors: true`**; unfiltered output drowns the signal. Any uncaught error = blocker.
6. `read_network_requests` with `urlPattern: "/api/"` → verify method, path, and status match the contract.
7. Multi-step flow worth showing the user? `gif_creator`: `start_recording` → screenshot → walk the flow → screenshot → `stop_recording` → `export {download: true}`.

Cautions: avoid elements that open native dialogs (file pickers, print, `beforeunload`) — they stall automation; use `file_upload` for uploads.

### 3. Both themes and the mobile viewport

- Theme: use the ThemeToggle (app-shell user menu; also on `/ui-kit`), or `localStorage.setItem("pub_theme", "dark")` + reload — the anti-FOUC script stamps `data-theme` on `<html>` from that key. Look for unreadable pairs and invisible borders in **both** themes on every touched screen.
- Mobile: `resize_window` to ~390×844. Nav must collapse, tables scroll horizontally inside their own container, touch targets hold ≥32px ([DESIGN.md §8](../../../../web/DESIGN.md)).

### 4. Cover both paths

- **Golden path**: the feature works with valid input.
- **At least one edge case**: empty state, validation error, permission gap (member vs org admin vs instance admin), network failure, long content, package that exists only upstream.

Example, search screen: golden — type a query → `GET /api/v1/packages?q=…` → 200 → results and facets render, URL carries the state. Edge — a query with no matches → empty state, not a crash; console clean.

## What counts as verified

- Expected state confirmed in the `read_page` a11y tree (not only a screenshot).
- Zero uncaught errors in `read_console_messages`.
- `/api/` requests match the contract (method, path, status).
- Both themes and the mobile width sane on the touched screens.
- The edge case produced the intended error/empty UI, not a crash.

## Reporting

One line per path walked, and whether it passed:

```
UI verified (http://localhost:8080):
- Search "http" (golden): OK — GET /api/v1/packages?q=http → 200, results + facets render.
- Search no-match (edge): OK — empty state shown, no crash.
- Themes: light/dark OK on /app/search. Mobile 390px: table scrolls, no page overflow.
- Console: clean. Network: as expected.
```

If anything failed, show the console/network/screenshot excerpt and stop — don't mark the task done.

## Related

- [playwright-patterns](../playwright-patterns/SKILL.md) — patterns for the future automated E2E suite.
- [web/DESIGN.md](../../../../web/DESIGN.md) — §9 agent pre-commit visual checklist.
- [docs/rules/web.md](../../../../docs/rules/web.md) — frontend conventions.
- [/web-check](../../../commands/web-check.md) — the validation gate to run first.
