---
name: add-app-screen
description: Add a new screen to the pub SolidJS app island — screen file, lazy Route in App.tsx, guard class, createAsync + query data flow, i18n messages, prerendered shell path. Use when the user asks for a new page, screen, or route under /app.
---

# Add App Screen (pub web)

Source: ported from foxic `.claude/skills/client/add-feature-module`, renamed — pub has no `features/` layer; the unit of frontend work is a **screen** in the single SolidJS island.

**Read first**:

- [docs/rules/web.md](../../../../docs/rules/web.md) — structure, data rules (`createResource` is banned), i18n.
- [apps/site/src/app/App.tsx](../../../../web/apps/site/src/app/App.tsx) — the router; its header comment explains the three route classes.
- One real screen, e.g. [screens/tokens.tsx](../../../../web/apps/site/src/app/screens/tokens.tsx) — the full idiom: query + createAsync, dialogs, revalidate, toasts.
- [docs/rules/api.md](../../../../docs/rules/api.md) if the screen needs new endpoints.

## Anatomy

One screen = one file in `web/apps/site/src/app/screens/{name}.tsx` with a **named export** (`WidgetsScreen`); a file may export several related screens (see `package.tsx`, `notifications.tsx`). No business logic in routes; shared state helpers live in `src/app/state/` (`api.ts` exposes `api`, `describeError`, `withStepUp`; `toast-store.ts` exposes `pushToast`).

### Data: module-level `query`, `createAsync` in the component, `revalidate` after mutation

```tsx
import { createAsync, query, revalidate } from "@solidjs/router";
import { api, describeError } from "../state/api";
import { pushToast } from "../state/toast-store";

const WIDGETS_KEY = "widgets";
const widgetsQuery = query(() => api.widgets.list(), WIDGETS_KEY);

export function WidgetsScreen(): JSX.Element {
  const widgets = createAsync(() => widgetsQuery());
  const rows = (): readonly WidgetDto[] => widgets()?.items ?? [];

  const remove = async (id: string): Promise<void> => {
    try {
      await api.widgets.remove(id);
      pushToast(t(app.widgetsRemoved), "success");
      await revalidate(WIDGETS_KEY);
    } catch (error) {
      pushToast(describeError(error), "danger");
    }
  };
  // ... <Show>/<For> over rows(), EmptyState fallback, Dialog for confirmations
}
```

- **Never `createResource`** (Solid 2.0 migration surface — docs/rules/web.md).
- Loading/error UI is NOT the screen's job: `ScreenBoundary` (in `src/app/shell/require-auth.tsx`) wraps every routed screen with a Suspense skeleton and an ErrorBoundary that special-cases 404/403 and offers retry for the rest. Let errors from `createAsync` throw into it; handle only mutation errors locally (toast).
- Sensitive mutations (token create, etc.) wrap the call in `withStepUp(() => ...)`.
- DTO types come from `@pub/api/types`, generated from the committed `packages/api/openapi.json` (`bun run gen:api`) — never hand-write response shapes.

## Route wiring in App.tsx

1. Lazy entry via the `screen()` adapter (screens keep named exports; `lazy` gets its default):

```tsx
const WidgetsScreen = screen(() => import("./screens/widgets"), "WidgetsScreen");
```

2. Pick the guard class — the router's header comment is normative:
   - **public credentials** (`/login`, OIDC callback): bare `<Route component={...} />`.
   - **open** (public registry reads — home, search, packages, org profiles): wrap in `<Open>` (ScreenBoundary only). Anonymous read is the default (decision 05); don't invent a frontend-only auth policy.
   - **guarded** (about the caller: orgs, tokens, sessions, account, admin): wrap in `<Guarded>` (RequireAuth + ScreenBoundary). The guard is routing convenience, never security — the server authorizes every byte.
3. Keep the catch-all `<Route path="*">` LAST.
4. If the screen belongs in the sidebar, add a nav link in `src/app/shell/app-shell.tsx` with an `app.navX` message.

## Prerendered shell path

If the route introduces a **new static first segment** (e.g. `/app/widgets`), add `"widgets"` to `getStaticPaths()` in [pages/app/[...rest].astro](../../../../web/apps/site/src/pages/app/%5B...rest%5D.astro). Parameterised paths (`/app/orgs/{slug}`) need nothing — the server falls back to the same shell for unknown `/app/*` paths.

## i18n

Every user-facing string is a message in `packages/i18n/messages/app.yaml` (`en` + mandatory `desc`, add `ru` too), then `bun run i18n:gen`. The i18n-coverage test fails on referenced-but-missing keys AND on generated-but-unused `app` keys — add keys and their usages in the same change. See the `add-i18n-string` skill.

## After writing

1. `bun run i18n:gen` if messages changed; commit generated files.
2. `/web-check` — typecheck, Biome, contrast gate, build, tests must be green.
3. Walk the screen live in the browser via the claude-in-chrome MCP tools (`mcp__claude-in-chrome__*`): loading skeleton, empty state, error branch, the happy path.

## Related

- [add-solid-component](../add-solid-component/SKILL.md) — when the screen needs a new shared component.
- [add-i18n-string](../add-i18n-string/SKILL.md) — message workflow.
- [docs/rules/web.md](../../../../docs/rules/web.md) · [docs/rules/api.md](../../../../docs/rules/api.md) · [docs/decisions.md](../../../../docs/decisions.md) · [web/DESIGN.md](../../../../web/DESIGN.md)
