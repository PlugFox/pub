---
name: add-i18n-string
description: Add a user-facing string to pub's i18n YAML (en + mandatory desc), regenerate typed modules with bun run i18n:gen, and consume it via t()/tp() descriptors. Use when adding a label, button text, error message, placeholder, aria-label, or fixing a hardcoded string in web/.
---

# Add i18n String (pub web)

Source: ported from foxic `.claude/skills/client/add-i18n-string`, adapted to pub's descriptor-based codegen flow (`packages/i18n`).

**Hard rule** ([docs/rules/web.md](../../../../docs/rules/web.md)): every user-facing string is an i18n message — buttons, labels, tooltips, `aria-label`, `placeholder`, toasts, empty states. This applies inside `packages/ui` components too.

## Files and shape

Messages live in [web/packages/i18n/messages/](../../../../web/packages/i18n/messages/), one YAML per namespace:

- `common.yaml` — shared chrome (layout, navigation, theme, language).
- `landing.yaml` — the marketing/landing pages.
- `app.yaml` — everything in the SolidJS island under `/app`.

Keys are **flat camelCase** (`[a-z][A-Za-z0-9]*` — the generator rejects anything else), prefixed by screen/area: `tokensTitle`, `navOverview`, `searchPlaceholder`. Each entry:

```yaml
tokensRevokeTitle:
  en: Revoke token
  ru: Отозвать токен
  desc: Title of the confirmation dialog before revoking a CLI/API token.
```

- `en` — source of truth (string, or CLDR plural-form map that must include `other`).
- `desc` — **mandatory, non-empty**: context for translators and LLMs (what/where/constraints). The generator hard-fails without it.
- Per-locale translations are optional keys (`ru fr it de es pt ja ko zh-Hans`). **Always add `ru`** — en and ru are the genuinely maintained pair, and the coverage test fails if a `ru` value is byte-identical to `en` (deliberate exceptions are whitelisted in the test).

Interpolation is `{name}` placeholders; a missing param renders the placeholder literally (visible, greppable). Plurals get `{count}` for free:

```yaml
searchResultCount:
  en:
    one: "{count} package"
    other: "{count} packages"
  ru:
    one: "{count} пакет"
    few: "{count} пакета"
    many: "{count} пакетов"
    other: "{count} пакета"
  desc: Result count above the search results; {count} is the total.
```

## Generate

```
cd web && bun run i18n:gen
```

Regenerates two committed outputs (never hand-edit either):

- `packages/i18n/src/generated/{namespace}.ts` — typed `as const` descriptor modules (`{ id, en }` per key, `desc` as JSDoc).
- `apps/site/public/locales/{locale}/{namespace}.json` — lazy-loaded dictionaries; locales missing a translation fall back to English and carry a `__todo__` marker entry.

Commit the YAML and the generated files together.

## Usage

```tsx
import { t, tp } from "@pub/i18n";
import { app } from "@pub/i18n/generated/app";

<h1>{t(app.tokensTitle)}</h1>                          // simple
<p>{t(app.tokensRevokeBody, { name: token.name })}</p> // interpolation
<span>{tp(app.searchResultCount, total)}</span>        // plural via Intl.PluralRules
<Input placeholder={t(app.searchPlaceholder)} />       // attributes too
```

`t()`/`tp()` take the **descriptor object**, not a string key — typos are type errors. `aria-label`, `placeholder`, `title`, `alt` all go through `t()`. Rich text only via the whitelist parser — never `innerHTML`.

## Coverage test keeps you honest

[apps/site/test/i18n-coverage.test.ts](../../../../web/apps/site/test/i18n-coverage.test.ts) scans `apps/site/src` and `packages/ui/src` and fails on:

- a reference to a key the generator no longer produces (rename half-landed → `t()` of `undefined`);
- a generated `app` key that **nobody uses** (dead weight for nine translators) — add the key and its call site in the same change;
- a locale JSON missing any key, or `en`/`ru` carrying the `__todo__` marker;
- a `ru` value identical to `en` outside the whitelist.

## Checklist

- Key added to the right namespace YAML with `en` + `desc` + `ru`.
- `bun run i18n:gen` run; generated modules and locale JSONs committed.
- No leftover hardcoded text (grep the touched files for quoted English).
- `cd web && bun test` — coverage and runtime tests green; then `/web-check`.

## Related

- [add-app-screen](../add-app-screen/SKILL.md) · [add-solid-component](../add-solid-component/SKILL.md) — where messages get consumed.
- [docs/rules/web.md](../../../../docs/rules/web.md) — i18n section (10 locales, English bundled fallback).
- [packages/i18n/src/runtime.ts](../../../../web/packages/i18n/src/runtime.ts) · [packages/i18n/scripts/i18n-gen.ts](../../../../web/packages/i18n/scripts/i18n-gen.ts)
