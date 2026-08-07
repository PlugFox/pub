---
name: docker-multi-stage
description: Evolve pub's single-image multi-stage Docker build (web → cargo deps → binary → alpine runtime) — cache mounts, layer ordering, multi-arch for the GHCR release, SBOM. Use when editing docker/Dockerfile, docker-compose.yml, .dockerignore, or when asked to shrink the image or speed up the build.
---

# Docker Multi-Stage (Pub)

**Source:** adapted from foxic's `docker-multi-stage` skill (itself derived from [github/awesome-copilot — multi-stage-dockerfile](https://skills.sh/github/awesome-copilot/multi-stage-dockerfile) and [sickn33 — docker-expert](https://skills.sh/sickn33/antigravity-awesome-skills/docker-expert)); refreshed against [docs.docker.com](https://docs.docker.com/build/) 2026-08.

Pub already has a working production image. This skill is about **evolving** [docker/Dockerfile](../../../docker/Dockerfile), not writing one from scratch. Read the file first — its comments carry the reasoning.

## The build you are evolving

One image, one binary, frontend embedded (decision 04 in [docs/decisions.md](../../../docs/decisions.md)). Build **from the repo root**: `docker build -f docker/Dockerfile -t pub .`

| Stage | Base | Job |
|-------|------|-----|
| `web-build` | `oven/bun:1-alpine` | `bun install && bun run build` → `web/apps/site/dist` |
| `server-manifests` | `alpine:3` | strips `server/` to `Cargo.toml`/`Cargo.lock` only |
| `server-build` | `rust:1-alpine` | dummy-main dependency build, then real build of `pubd` with the dist embedded |
| `runtime` | `alpine:3` | CA certs, non-root uid 1000, `/data` home, `HEALTHCHECK` on `/healthz` |

## Invariants — do not break these when editing

- **Repo-root build context.** The Dockerfile copies both `server/` and `web/`; [.dockerignore](../../../.dockerignore) at the root keeps the context small. Don't move the context into `docker/`.
- **The `server-manifests` helper stage is the cache key.** `COPY --from` of a manifests-only tree produces a layer whose checksum changes only when a `Cargo.toml`/`Cargo.lock` changes — source edits never invalidate the dependency-compile layer. This works with plain layer caching (including registry cache in CI), unlike cache mounts. Keep it even if you add cache mounts.
- **Stub cleanup + `touch` after the dummy build.** The `rm -rf` of stub `src/` dirs and `find crates -name '*.rs' -exec touch {} +` defeat cargo's mtime fingerprints. Removing either can silently ship a do-nothing binary built from stubs. The Dockerfile comments explain both; never "simplify" them away.
- **musl end to end.** `rust:1-alpine` (not `-slim`) because the runtime is `alpine:3`: the Alpine toolchain targets musl and the binary runs without glibc shims. Switching either side alone breaks the pairing.
- **Embedded frontend swap.** `server/crates/api/embedded/` holds a git-committed placeholder; the image always replaces it with the real dist before `cargo build`. Ordering matters: dist copy → binary build.
- **No `SQLX_OFFLINE`, no DB at build time.** Pub uses runtime sqlx queries by design ([docs/rules/rust.md](../../../docs/rules/rust.md)); there is no `.sqlx` cache and no `cargo sqlx prepare`. Any guidance mentioning them is stale foxic residue.
- **Runtime stays non-root** (`USER pub`, uid 1000, `/data` writable for SQLite + fs blobs) with the busybox-wget healthcheck — `/healthz` is always on (decision 23).

## Speeding it up: cache mounts

The manifests trick caches the *layer*; BuildKit cache mounts additionally cache cargo's registry across builds even when manifests change. Add to **both** `cargo build` RUNs in `server-build`:

```dockerfile
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release
```

Caveats:

- A cache mount on `target/` is also possible but then the binary lives inside the mount — you must `cp` it out in the same `RUN`, and it largely duplicates what the manifests stage already gives you. Registry mount first; measure before adding a target mount.
- Cache mounts are **local to the builder**. On ephemeral CI runners they are empty unless you configure a cache backend (`cache-from`/`cache-to`, e.g. `type=gha`). The manifests-stage layer trick keeps working there regardless — that is why it stays.
- For `web-build`: `--mount=type=cache,target=/root/.bun/install/cache` before `bun install`. Move to `bun install --frozen-lockfile` once the scaffold's lockfile settles, in sync with `.github/workflows/web-ci.yml` (tracked as a comment in the Dockerfile).

## Multi-arch for the GHCR release (decision 18, roadmap)

The release milestone in [docs/roadmap.md](../../../docs/roadmap.md) calls for multi-arch images on GHCR, version derived from the git tag and injected as a **build arg** — never a CI commit to master (decision 18). When wiring the workflow:

- Target `linux/amd64,linux/arm64` via `docker buildx build --platform …`.
- **Do not QEMU-emulate the cargo build** — emulated Rust compilation is brutally slow. Prefer per-arch native runners (`ubuntu-latest` + `ubuntu-*-arm`), each building and pushing its own digest, then merge with `docker buildx imagetools create -t ghcr.io/…/pub:X.Y.Z <digest-amd64> <digest-arm64>`. Cross-compilation (`FROM --platform=$BUILDPLATFORM` + `TARGETARCH` → musl cross target) is the alternative if arm runners are unavailable; it complicates the alpine toolchain pairing above, so treat it as plan B.
- The version build arg must reach the binary so the release job can `docker run` the image and assert `/healthz` reports the expected version (roadmap exit criterion).
- Add a plain `docker build` job to PR CI so the image cannot rot between releases.

## SBOM + provenance

For published images, generate attestations at build time:

```sh
docker buildx build --sbom=true --provenance=mode=max --push -t ghcr.io/…/pub:X.Y.Z -f docker/Dockerfile .
```

- Inspect: `docker buildx imagetools inspect <img> --format '{{ json .SBOM.SPDX }}'`.
- By default only the final stage is scanned — fine here (runtime = alpine + one binary). Scanning build stages needs `ARG BUILDKIT_SBOM_SCAN_STAGE`; not worth the noise for pub.
- `docker scout cves <image>` before publishing; the alpine runtime keeps the surface tiny.

## docker-compose.yml

[docker/docker-compose.yml](../../../docker/docker-compose.yml) is **optional** infrastructure — the default dev loop needs no containers (SQLite + fs blob + in-memory KV). Profiles: `pg` (Postgres 17), `s3` (MinIO), `redis` (Valkey 8), `full` (app + all). See [docker/README.md](../../../docker/README.md) for one-liners. Keep:

- Named volumes for data, not bind mounts (macOS permission issues).
- `depends_on` with `condition: service_healthy` for the `full`-profile app.
- `$$` escaping inside container-side healthcheck commands so compose does not interpolate.
- `PUB_*`/`__` env names in the app service in sync with `server/crates/config`.
- Every variable defaulted so a zero-config `up` works; overrides go in `docker/.env`, never edits to the committed file.

## Common mistakes

- Copying manifests and source in one `COPY` — kills the dependency cache. The manifests stage exists precisely to prevent this; new crates are picked up automatically (both the manifests stage and the dummy-build loop `find` every `Cargo.toml` under `crates/`).
- Secrets via `ARG` — visible in `docker history`. Use `RUN --mount=type=secret,id=…` if a build ever needs one (none does today).
- Forgetting a new crate's `src/` stub pattern: the dummy-build loop writes both `main.rs` and `lib.rs` for every crate found — if you restructure it, keep both, or bin-only/lib-only crates fail the dependency build.
- Editing the healthcheck to curl — curl is not in the runtime image; busybox `wget` is, deliberately.
- `EXPOSE` is documentation, not a firewall — still publish with `-p` or compose `ports:`.

## Related

- [docker/README.md](../../../docker/README.md) — profiles, one-liners, env overrides.
- [docs/decisions.md](../../../docs/decisions.md) — 04 (single binary, embedded frontend), 18 (release model, GHCR), 23 (`/healthz` always on).
- [docs/roadmap.md](../../../docs/roadmap.md) — release-engineering milestone this skill's multi-arch/SBOM sections feed.
- `/db-up` slash command starts the compose profiles; `/server-check` and `/web-check` validate the code the image ships.
