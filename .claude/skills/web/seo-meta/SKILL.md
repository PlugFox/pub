---
name: seo-meta
description: SEO/meta for Pub's static Astro pages — title/description via BaseLayout, robots scope, and the groundwork for Open Graph, canonical, JSON-LD, sitemap, and hreflang as the per-locale docs pages land. Use when adding a public page, improving shareability, or on SEO/meta-tag/social-preview questions.
---

# SEO / Meta (Pub web)

**Source:** ported from foxic `client/seo-meta`; adapted from [aaron-he-zhu/seo-geo-claude-skills](https://skills.sh/aaron-he-zhu/seo-geo-claude-skills/meta-tags-optimizer), [addyosmani/web-quality-skills — seo](https://skills.sh/addyosmani/web-quality-skills/seo), and [Google Search Central docs](https://developers.google.com/search/docs).

## Scope — what is actually indexable

Pub is an Astro SSG site with a client-only SPA island under `/app` (decision 14). SEO applies **only to the static pages**:

- **Indexable today:** the landing (`/`). The 404 page exists but returns 404.
- **Planned indexable:** per-locale routes and a docs section (decisions 08/14) — configured in `astro.config.mjs` (10 locales, `prefixDefaultLocale: false`) but **not built yet**: roadmap D35 records that every built page is `lang="en"` today.
- **Never indexable:** `/app/*` (client-rendered app — crawlers see an empty shell) and `/ui-kit` (internal, English-only). Both are `Disallow`ed in [public/robots.txt](../../../../web/apps/site/public/robots.txt).
- Package pages live under `/app` and are therefore invisible to crawlers **by design today**. Making package pages indexable (pub.dev-style) would need SSG/SSR pages outside the island — that is a decision-level change: propose in [docs/decisions.md](../../../../docs/decisions.md) first, don't sneak it in.

## Current state (read before adding anything)

[base-layout.astro](../../../../web/apps/site/src/layouts/base-layout.astro) sets: `<title>`, optional `<meta name="description">`, SVG icon, webmanifest, Inter preload, `lang` from `Astro.currentLocale`. **Not present yet:** Open Graph, Twitter cards, canonical, JSON-LD, sitemap, hreflang, and no `Sitemap:` line in robots.txt.

## Per-page requirements (when extending)

Head tags belong in the layout, not sprinkled per page — extend `BaseLayout`'s `Props` (Astro frontmatter, **not** `@solidjs/meta`; the island never manages `<head>`):

```astro
<title>{title}</title>
<meta name="description" content={description} />
<link rel="canonical" href={canonicalUrl} />
<meta property="og:type" content="website" />
<meta property="og:title" content={title} />
<meta property="og:description" content={description} />
<meta property="og:image" content={ogImageUrl} />
<meta name="twitter:card" content="summary_large_image" />
```

Rules:

- **Title:** 50–60 chars, keyword first, brand last (`… — Pub`). Unique per page — grep the built `dist/` for duplicate `<title>` values.
- **Description:** 140–160 chars, one actionable sentence, unique per page. No keyword stuffing.
- **OG image:** 1200×630, < 300 KB, text readable at 200 px wide. Must be a self-hosted asset — the site makes no external requests (DESIGN.md §9.8).
- Pages are prerendered, so meta is in the initial HTML for free — one real SEO advantage of the SSG side; keep new public pages static, don't island-ify them.

## The absolute-URL problem (surface before implementing)

Canonical, `og:url`, `og:image`, and sitemap entries need an absolute base URL. Astro's `site` config is **unset**, and Pub is self-hosted/white-label (decision 17) — the server advertises the deployment's public base URL at runtime, but the static site is built once. Baking a domain at build time is only correct for a single flagship instance. This is a genuinely open choice: **stop and discuss** (per CLAUDE.md) before wiring `site` + canonical + sitemap.

## Structured data (JSON-LD)

When landing/docs mature: `SoftwareApplication` (the registry product), `Organization` + `WebSite` (home), `BreadcrumbList` and `FAQPage` (docs). Build with `JSON.stringify`, validate with the [Rich Results Test](https://search.google.com/test/rich-results).

CSP note: a `<script type="application/ld+json">` block is a non-executable data block, so CSP `script-src` does not gate it — but DESIGN.md §9.7 greps built HTML for inline scripts; teach that check to allow `ld+json` in the same commit that introduces it.

## Robots + sitemap

- robots.txt today: `Allow: /`, `Disallow: /app`, `Disallow: /ui-kit`. Add a `Sitemap:` line only when a sitemap actually ships (blocked on the base-URL decision above).
- `Disallow` prevents crawling, not indexing of already-known URLs. For real de-indexing of `/app/*`, add `X-Robots-Tag: noindex` on the server responses that serve the app shell (the embedded-asset service) — a server-side change, coordinate with `docs/rules/api.md`.

## hreflang (when D35 per-locale routes land)

English is unprefixed (`prefixDefaultLocale: false`), other locales get path prefixes. Every localized page then lists all variants plus `x-default` → the English URL:

```html
<link rel="alternate" hreflang="en" href="…/docs/getting-started" />
<link rel="alternate" hreflang="ru" href="…/ru/docs/getting-started" />
<link rel="alternate" hreflang="x-default" href="…/docs/getting-started" />
```

All 10 locale codes come from the Astro config / decision 08 (`zh-Hans` is a valid hreflang value). Generate the list from the config, don't hand-maintain a third copy of the locale list (roadmap D30 already counts three).

## AEO / generative search

Landing and future docs: clean semantic HTML (`<article>`, `<section>`, one `<h1>`), Q&A-style headings that mirror likely questions, FAQ schema on docs. The landing already uses semantic sectioning — keep it that way.

## Core Web Vitals

LCP < 2.5 s, INP < 200 ms, CLS < 0.1. There is no Lighthouse/CI budget yet (roadmap D36) — the working proxy is DESIGN.md §9.9: compare `dist/` totals per build and justify growth. The landing currently ships ~23 KB gzip of JS for one theme toggle (D34); don't grow that for meta work — meta is zero-JS.

## Deterministic checks

- `bun run build`, then grep `dist/` for duplicate `<title>` content across pages.
- Once OG ships: `grep -rL 'og:title' dist/` to find public pages missing it.
- Grep `dist/` for `https://` — external asset URLs (fonts, OG images on CDNs) are banned (DESIGN.md §9.8).

## Common mistakes

- Same `<title>` on every route (the `/app/*` shell pages legitimately share one — they're noindex; public pages must not).
- Canonical/OG pointing at a build-time domain that isn't this deployment (the self-hosted trap above).
- "noindex shipped to prod" — blocking crawlers for staging and forgetting to re-enable.
- JSON-LD built with template literals instead of `JSON.stringify` — escaping bugs.

## Related

- [ui-accessibility](../ui-accessibility/SKILL.md) — semantic HTML helps both SEO and a11y.
- [web/DESIGN.md](../../../../web/DESIGN.md) — CSP/inline-script and no-external-request rules that constrain meta work.
- [docs/decisions.md](../../../../docs/decisions.md) — 08 (locales), 14 (frontend shape), 17 (white-label branding).
- [docs/roadmap.md](../../../../docs/roadmap.md) — D34/D35/D36: bundle, missing locale routes/docs, missing CI gates.
