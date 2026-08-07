# pub

Self-hosted, open-source package registry for Dart & Flutter — a private pub.dev with corporate-grade security. One binary for a laptop, a replicated cluster for an enterprise. *(Default product name: **Pub**; instances can rebrand via white-label settings.)*

**Status: pre-release.** The server, the embedded web app, and the operator docs exist and are verified against the real `dart pub` client; no release tag has been cut yet. State of the project and the plan forward: [docs/roadmap.md](docs/roadmap.md).

## Documentation

| Document | Contents |
|----------|----------|
| [docs/product.md](docs/product.md) | Vision, competitive landscape, feature triage (v1 / v1.1 / later) |
| [docs/architecture.md](docs/architecture.md) | Workspaces, traits, data model, request planes, proxy pipeline, testing |
| [docs/decisions.md](docs/decisions.md) | Architecture decision log with rationale |
| [docs/security.md](docs/security.md) | Normative security requirements (S-01…S-33) |
| [docs/protocol.md](docs/protocol.md) | Hosted Pub Repository Spec v2 — sharp edges we must honor |
| [docs/roadmap.md](docs/roadmap.md) | State of the project, tech debt, and the plan forward |
| [docs/ops/README.md](docs/ops/README.md) | Operator guide: install (Docker / compose / source), reverse proxy, backup & restore, upgrade, security runbook, token scanning |

## Shape of the thing

- **Backend**: Rust — axum, sqlx (SQLite *or* PostgreSQL), object_store (filesystem *or* S3), in-memory *or* Redis KV — all compiled in, selected by config; stateless app tier, Redis required only for multi-instance.
- **Frontend**: TypeScript 7, Bun, Astro (SSG landing/docs, 10 locales, light/dark) + SolidJS app island, Kobalte, PWA; embedded into the server binary.
- **Registry**: Hosted Pub Repository Spec v2, per-org virtual URLs (`/o/<org>/pub`), pub.dev read-through proxy + mirror mode, dependency-confusion protection, orgs/RBAC/tokens/audit, SSE live events + notification center, webhooks, statistics. Multi-format core: pub first, npm/cargo designed-for later.

## License

[MIT](LICENSE)
