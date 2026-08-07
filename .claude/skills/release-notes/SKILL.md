---
name: release-notes
description: Maintain CHANGELOG.md — when a change is user-visible, how entries are tagged and structured, and why there is no version-bump step. Use when finishing user-visible work, when the user asks to update the changelog, or asks about versions/releases.
---

# Release Notes (Pub)

Source: adapted from foxic's `bump-version` skill. Pub has **no version-bump flow** — do not edit versions in `Cargo.toml` or `package.json` as a release step. Release engineering is [decision 18](../../../docs/decisions.md#18--ops-release-model-image-registry-reference-orchestrator-tbd) (status: tbd); per the roadmap's Phase 1 the version will derive from the **git tag** injected as a build arg, with no CI commits to master. Until that lands, the release discipline is the changelog.

## The rule

**Every user-visible change gets a `CHANGELOG.md` entry in the same commit** (CLAUDE.md; AGENTS.md mandatory rule 6: component tag + file links). No tags, no bumps, no release branches — just the entry.

## What counts as user-visible

Yes: new/changed endpoints or wire shapes, screens and UI behavior, config keys and their defaults, DB schema (migrations), anything the `dart pub` client observes, security behavior, jobs/ops behavior, docker/compose changes, notable docs (tagged `(docs)`).

No: pure refactors with no observable change, test-only changes, comment fixes. When in doubt, ask: could an operator, a package consumer, or a browser user notice? If yes, it goes in.

## Format (as the file itself declares)

[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/); SemVer per component — the server crate and the web package are versioned independently (independently *tagged*, once decision 18 settles). Verified structure of the existing file:

- **Sections are dated, newest first**: `## YYYY-MM-DD — <short thesis of the slice>`.
- A section may open with short **prose paragraphs** explaining the headline mechanisms (bolded lead sentences) before the lists — mechanism over adjectives, no marketing language (AGENTS.md rule 8).
- Subsections in use: `### Added`, `### Fixed`, `### Changed`, `### Notes` (Notes holds verification results, known gaps, deliberate non-fixes).
- **Every bullet starts with its component tag**: `(server)`, `(web)`, `(infra)`, `(docs)`.
- Entries **link to the files and docs they touch** — relative markdown links like `[assets.rs](server/crates/api/src/assets.rs)`, `[decision 11](docs/decisions.md#11--search-behind-a-trait)`, `[S-12](docs/security.md#2-sessions--web-plane)`.

## Mapping from conventional commits

| Commit | Changelog |
|---|---|
| `feat(server)` / `fix(server)` | `(server)` bullet under Added / Fixed |
| `feat(web)` / `fix(web)` | `(web)` bullet under Added / Fixed |
| `chore(infra)`, docker/CI changes | `(infra)` |
| `docs: …` worth recording | `(docs)` |
| `refactor`, `test`, `chore` with no observable change | usually no entry |

A behavior change to an existing surface goes under **Changed**; a deliberate limitation or a verification result goes under **Notes**.

## Procedure

1. Decide user-visibility (above). If not user-visible, stop — no entry.
2. Find or start today's dated section at the top of `CHANGELOG.md`.
3. Write tagged bullets under the right subsection, linking touched files and the governing decision/S-xx where one applies.
4. Commit the entry together with the change it describes.
5. Do **not** tag, bump, or push versions — when the user asks for "a release", point at decision 18's pending status instead of inventing a flow.

## Related

- [commit-message](../commit-message/SKILL.md) — scopes mirror the changelog tags
- [verify-changes](../verify-changes/SKILL.md) — green checks before the entry is "done"
- [CHANGELOG.md](../../../CHANGELOG.md) · [docs/decisions.md](../../../docs/decisions.md) · [docs/roadmap.md](../../../docs/roadmap.md) · [AGENTS.md](../../../AGENTS.md)
