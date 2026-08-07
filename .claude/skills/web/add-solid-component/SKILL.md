---
name: add-solid-component
description: Create or modify a SolidJS component in the pub web workspace following project rules — splitProps (never destructure), CVA recipe exported separately, cn() class merge, Kobalte subpath imports, no root margins, mandatory ui-kit showcase entry. Use when the user asks to add, create, or modify a component, dialog, button, form, or any .tsx file under web/.
---

# Add SolidJS Component (pub web)

Source: ported from foxic `.claude/skills/client/add-solid-component`, adapted to pub's `web/` Bun workspace (`packages/ui` + `apps/site`).

**Read first**:

- [docs/rules/web.md](../../../../docs/rules/web.md) — normative frontend conventions (Components section especially).
- [web/DESIGN.md](../../../../web/DESIGN.md) — visual source of truth: tokens, type scale, component specs, agent checklist.

Check [web/packages/ui/src/](../../../../web/packages/ui/src/) first — ~21 components exist (button, input, dialog, menu, table, tabs, toast, tooltip, …). Reuse before building; "build only what a screen actually needs".

## Hard rules

- **Never destructure props** — breaks Solid reactivity. Use `splitProps(props, [...])` and `props.field`.
- **Control flow**: `<Show>`, `<For>`, `<Switch>/<Match>` — never `array.map()` in JSX.
- **CVA recipe exported separately** from the component (`buttonVariants` next to `Button`) so other call sites can reuse it (`<A class={buttonVariants({ intent: "outline" })}>`).
- **Mandatory `class` prop**, merged via `cn()` from [packages/ui/src/cn.ts](../../../../web/packages/ui/src/cn.ts) (`twMerge(clsx(...))`). Always `cn(recipe(...), local.class)` — caller classes win.
- **No margins on component roots** — spacing belongs to the parent layout (gap/grid).
- **Interactive primitives** (dialog, menu, popover, tooltip, tabs, toast) are thin Kobalte wrappers with **subpath imports**: `import * as DialogPrimitive from "@kobalte/core/dialog"` — never the package root. See [dialog.tsx](../../../../web/packages/ui/src/dialog.tsx) for the pattern (Kobalte does focus/aria; the wrapper does the skin).
- **Styling**: Tailwind 4 CSS-first, design tokens only (from `packages/tokens/theme.css` — `text-ink`, `bg-surface`, `border-line`, `bg-accent`, …). No arbitrary values, no hex colors, no `!important`.
- **No hardcoded user-facing text** — even `aria-label`s go through `t()` with descriptors from `@pub/i18n/generated/*` (the i18n-coverage test scans `packages/ui/src` too). See the `add-i18n-string` skill.
- **TS**: strict, no `any`, no `enum` (`as const` + unions), kebab-case filenames, named exports only.

## Skeleton (mirrors button.tsx)

```tsx
import { cva, type VariantProps } from "class-variance-authority";
import { type JSX, splitProps } from "solid-js";
import { cn } from "./cn";

/** Recipe exported separately so other call sites can reuse the classes. */
export const calloutVariants = cva("flex items-start gap-3 rounded-lg border p-4 text-sm", {
  variants: {
    intent: {
      neutral: "border-line bg-surface text-ink",
      danger: "border-danger-soft bg-danger-soft text-danger-ink",
    },
  },
  defaultVariants: { intent: "neutral" },
});

export type CalloutProps = JSX.HTMLAttributes<HTMLDivElement> &
  VariantProps<typeof calloutVariants>;

export function Callout(props: CalloutProps): JSX.Element {
  // splitProps, never destructuring — destructuring breaks Solid reactivity.
  const [local, rest] = splitProps(props, ["class", "intent"]);
  return <div {...rest} class={cn(calloutVariants({ intent: local.intent }), local.class)} />;
}
```

## Placement and wiring (shared component)

A new component in `packages/ui` is not done until all four exist:

1. `web/packages/ui/src/{name}.tsx` — the component, one file, named exports.
2. Subpath export in [packages/ui/package.json](../../../../web/packages/ui/package.json) `exports` map: `"./callout": "./src/callout.tsx"` (consumed as `@pub/ui/callout`).
3. Showcase entry in [apps/site/src/ui-kit/ui-kit-page.tsx](../../../../web/apps/site/src/ui-kit/ui-kit-page.tsx) — add one `ShowcaseEntry` (`name`, `note`, `render`) to the `registry` showing **all variants, sizes, and states**; check both themes via the page's ThemeToggle.
4. Variants test in [packages/ui/test/variants.test.ts](../../../../web/packages/ui/test/variants.test.ts) (`bun:test`) asserting the recipe: defaults, each variant's distinguishing classes, and any invariants (e.g. badges never use solid status fills).

Screen-specific pieces (a dialog only one screen uses) stay as local components inside that screen file under `apps/site/src/app/screens/` — pub has no `features/` layer.

## After writing

1. `/web-check` — typecheck ×5, Biome, WCAG contrast gate, build, `bun test` must all pass.
2. If the component has behavior (not just looks), verify it live in the browser via the claude-in-chrome MCP tools (`mcp__claude-in-chrome__*`), e.g. on the `/ui-kit` page. (`@playwright/test` is a dev dep but there is no test suite yet.)

## Related

- [add-app-screen](../add-app-screen/SKILL.md) — where components get used.
- [add-i18n-string](../add-i18n-string/SKILL.md) — for any user-facing text.
- [docs/rules/web.md](../../../../docs/rules/web.md) · [web/DESIGN.md](../../../../web/DESIGN.md) · [docs/decisions.md](../../../../docs/decisions.md)
