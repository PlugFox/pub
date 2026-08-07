# syntax=docker/dockerfile:1
# Single-image multi-stage build (decision 04: one binary with the frontend embedded).
# Build from the REPO ROOT:  docker build -f docker/Dockerfile .
#
# Stages:
#   1. web-build         — Bun builds the Astro site (web/apps/site/dist).
#   2. server-manifests  — helper: strips server/ down to Cargo manifests only, so the
#                          dependency-compile layer is cached independently of source edits.
#   3. server-build      — Rust compiles pubd with the web dist embedded.
#   4. runtime           — minimal Alpine image, non-root, just the binary.

# ---------------------------------------------------------------------------
# Stage 1 — frontend build.
# ---------------------------------------------------------------------------
FROM oven/bun:1-alpine AS web-build
WORKDIR /app/web
# Whole Bun workspace (node_modules / dist are excluded by the root .dockerignore).
COPY web/ ./
# Plain install while the scaffold's lockfile churns; move to --frozen-lockfile later
# (keep in sync with .github/workflows/web-ci.yml).
RUN bun install
RUN bun run build
# Production output: /app/web/apps/site/dist

# ---------------------------------------------------------------------------
# Stage 2 — manifests-only copy of the server tree (dependency-cache helper).
# Everything except Cargo.toml / Cargo.lock is deleted, so the COPY --from below
# produces a layer whose checksum changes only when manifests change. Source-only
# edits therefore never invalidate the (expensive) dependency-compile layer.
# ---------------------------------------------------------------------------
FROM alpine:3 AS server-manifests
COPY server/ /server/
RUN find /server -type f ! -name 'Cargo.toml' ! -name 'Cargo.lock' -delete \
 && find /server -type d -empty -delete

# ---------------------------------------------------------------------------
# Stage 3 — server build.
# rust:1-alpine (not rust:1-slim) on purpose: the runtime stage is alpine:3, and the
# Alpine toolchain targets musl, producing a (statically linked) binary that runs on
# plain Alpine with no glibc shims. A rust:1-slim (glibc) binary would not.
# build-base provides gcc/musl-dev needed as linker and for any C-backed crates
# (e.g. ring); pkgconfig helps -sys crates find libraries.
# ---------------------------------------------------------------------------
FROM rust:1-alpine AS server-build
RUN apk add --no-cache build-base pkgconfig
WORKDIR /app/server

# 3a. Dummy-main dependency build: manifests + stub sources → compile all dependencies.
# This layer is the cache workhorse; it only rebuilds when a Cargo.toml/lock changes.
COPY --from=server-manifests /server/ ./
RUN for manifest in $(find crates -name Cargo.toml); do \
      dir=$(dirname "$manifest"); \
      mkdir -p "$dir/src"; \
      echo 'fn main() {}' > "$dir/src/main.rs"; \
      : > "$dir/src/lib.rs"; \
    done \
 && cargo build --release

# 3b. Real sources. First drop the stub src/ dirs so no dummy file survives next to the
# real tree (a leftover stub main.rs would add a spurious bin target to lib-only crates).
# touch(1) then defeats cargo's mtime-based fingerprints — COPY preserves context mtimes,
# which may be older than the dummy build's artifacts; without the touch cargo could keep
# the stub-built crates and ship a do-nothing binary.
RUN find crates -type d -name src -prune -exec rm -rf {} +
COPY server/ ./
RUN find crates -name '*.rs' -exec touch {} +

# 3c. Replace the committed placeholder with the real frontend build, then compile pubd.
# server/crates/api/embedded/ holds a placeholder index.html in git; the image always
# embeds the real dist.
RUN rm -rf crates/api/embedded && mkdir -p crates/api/embedded
COPY --from=web-build /app/web/apps/site/dist/ crates/api/embedded/
# Release version (decision 18): git tag → --build-arg PUB_VERSION → compile-time env →
# pub_core::version::VERSION → /healthz and `pubd --version`. Declared *after* the
# dependency build on purpose: a version change must never invalidate the (expensive)
# dependency-compile layer above. Unset/empty (local builds, PR CI) the binary falls back
# to the crate version marked `+dev`.
ARG PUB_VERSION=""
ENV PUB_VERSION=${PUB_VERSION}
RUN cargo build --release --bin pubd

# ---------------------------------------------------------------------------
# Stage 4 — runtime.
# alpine:3 + CA certs (outbound TLS: pub.dev proxy, S3, SMTP, OIDC). Non-root user
# uid 1000 with /data as home — the writable default location for SQLite + fs blobs.
# ---------------------------------------------------------------------------
FROM alpine:3 AS runtime
# OCI labels: `source` links the GHCR package to the repository; `version` carries the
# release version (empty on untagged local builds — the binary itself reports `+dev`).
ARG PUB_VERSION=""
LABEL org.opencontainers.image.title="Pub" \
      org.opencontainers.image.description="Self-hosted pub package registry" \
      org.opencontainers.image.source="https://github.com/plugfox/pub" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${PUB_VERSION}"
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 1000 -h /data pub
WORKDIR /data
COPY --from=server-build --chown=1000:1000 /app/server/target/release/pubd /usr/local/bin/pubd

# Config via PUB_* env (nested separator __); TOML/CLI also supported by the binary.
ENV PUB_SERVER__LISTEN=0.0.0.0:8080
EXPOSE 8080
USER pub

# /healthz is always on (decision 23); busybox wget ships with Alpine.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/pubd"]
