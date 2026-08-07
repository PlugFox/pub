---
name: commit-message
description: Write a git commit message for Pub following Conventional Commits with the repo's scopes (server/web/infra/docs). Use when the user asks to commit, create a commit, or write a commit message.
---

# Commit Message (Pub)

Source: ported from foxic's `commit-message` skill, adapted to pub's scopes and CHANGELOG rule.

Follow [Conventional Commits](https://www.conventionalcommits.org/) with the scopes used in this repo (see `git log` for live examples).

## Format

```
<type>(<scope>): <subject>

<body — optional, wraps at 72 chars>
```

## Types

`feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `perf`, `build`, `ci`.

## Scopes

Component-level, matching the CHANGELOG tags: `server`, `web`, `infra`, `docs`. Real examples from history:

- `feat(server): app API — search, read model, management, admin, SSE, notifications`
- `feat(web): registry screens, generated API types, and the first live end-to-end pass`
- `chore(infra): …` for docker/CI; bare `docs: …` is also used for documentation-only commits.

## Rules

- **Subject**: imperative mood, lowercase, no trailing period, ≤72 chars.
- **Language**: English only in commits (even though we chat in Russian).
- **One logical change per commit.** If the diff spans unrelated areas, split it.
- **Body** (optional): explain the *why*, not the *what* — the diff shows the what.
- **Breaking changes**: `!` after scope (`feat(server)!: …`) plus a `BREAKING CHANGE:` footer.
- **Generated files travel with their source**: regenerated i18n modules (`bun run i18n:gen`) and `packages/api/src/generated/openapi.ts` (`bun run gen:api`) belong in the same commit as the YAML / `openapi.json` change that caused them.
- **Paired migrations travel together**: a schema change commits both `db-sqlite` and `db-postgres` migration files with the same `NNNN`.

## Before committing

1. `git status` / `git diff --staged` — only relevant files staged.
2. Never stage `.env*`, secrets, `node_modules/`, or `target/` artifacts.
3. **User-visible change ⇒ `CHANGELOG.md` entry in the same commit** (CLAUDE.md rule; format in the [release-notes](../release-notes/SKILL.md) skill).
4. The touched side should be green: `/server-check` for `server/`, `/web-check` for `web/`. If it has not run and the change is non-trivial, say so before committing.

## Co-author trailer

Add the `Co-Authored-By: Claude …` trailer only on commits you (the agent) create at the user's request; do not add it to commits the user writes themselves.

## Related

- [verify-changes](../verify-changes/SKILL.md) — run checks before committing
- [release-notes](../release-notes/SKILL.md) — CHANGELOG entry format
- [CLAUDE.md](../../../CLAUDE.md) · [AGENTS.md](../../../AGENTS.md) (mandatory rules list)
