# Canonical task runner for pub. `just` lists recipes; recipes mirror the
# validation pipelines documented in CLAUDE.md — keep the two in sync.

set working-directory := '.'

default:
    @just --list

# --- validation ------------------------------------------------------------

# Full server validation pipeline (fmt, clippy, tests)
#
# The optional backend legs (postgres, redis, s3) run when their PUB_TEST_*_URL / _ENDPOINT is
# exported and are skipped **out loud** otherwise — decision 35: a leg that did not run and a
# leg that passed used to be the same green. `just db-up full` plus the three exports below
# turns every leg on; CI exports them beside its service containers and sets no opt-out, so a
# backend that fails to start is a red build there.
server-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cd server
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    skipped=()
    if [ -z "${PUB_TEST_POSTGRES_URL:-}" ]; then
        export PUB_TEST_NO_POSTGRES=1
        skipped+=("postgres (just db-up pg; export PUB_TEST_POSTGRES_URL=postgres://pub:pub_dev_password@127.0.0.1:5432/pub)")
    fi
    if [ -z "${PUB_TEST_REDIS_URL:-}" ]; then
        export PUB_TEST_NO_REDIS=1
        skipped+=("redis (just db-up redis; export PUB_TEST_REDIS_URL=redis://127.0.0.1:6379)")
    fi
    if [ -z "${PUB_TEST_S3_ENDPOINT:-}" ]; then
        export PUB_TEST_NO_S3=1
        skipped+=("s3 (just db-up s3; export PUB_TEST_S3_ENDPOINT=http://127.0.0.1:9000)")
    fi
    if [ -z "${PUB_TEST_CLUSTER_URL:-}" ]; then
        export PUB_TEST_NO_CLUSTER=1
        skipped+=("cluster (just cluster-up; export PUB_TEST_CLUSTER_URL=http://localhost:18080)")
    fi
    for leg in ${skipped[@]+"${skipped[@]}"}; do
        printf '  \033[33mSKIPPED BACKEND LEG\033[0m %s\n' "$leg"
    done
    cargo test --workspace

# Full web validation pipeline (typecheck+lint+contrast, build, tests)
web-check:
    cd web && bun run check
    cd web && bun run build
    cd web && bun test

# Offline PWA end-to-end run against a real browser (decision 41).
# Opt-in like `cluster-check`, not part of `web-check`: it needs Playwright's
# browser binaries and serves the production build over `astro preview`.
web-e2e:
    cd web && bun run build
    cd web && bun run test:e2e

# Everything — both sides
check: server-check web-check

# Server tests only, via nextest (faster; no doctests — use server-check for those)
server-test:
    cd server && cargo nextest run --workspace

# --- dev loop --------------------------------------------------------------

# Run the server on the zero-container defaults (SQLite + fs blobs + memory KV)
serve:
    cd server && cargo run -p pubd

# Astro dev server for static pages/theme work (no API behind it)
web-dev:
    cd web && bun run --filter @pub/site dev

# Format everything in place
fmt:
    cd server && cargo fmt
    cd web && bun run fix
    taplo format server/Cargo.toml server/crates/*/Cargo.toml

# Regenerate committed codegen artifacts (i18n modules + API types + config/metrics references)
gen:
    cd web && bun run i18n:gen
    cd web && bun run gen:api
    cd server && UPDATE_CONFIG_REFERENCE=1 cargo test -p pub-config --test reference
    cd server && UPDATE_METRICS_REFERENCE=1 cargo test -p pub-telemetry --test catalogue

# --- infra -----------------------------------------------------------------

# Start optional dev containers; profiles: pg | s3 | redis | full
db-up profile='pg':
    docker compose -f docker/docker-compose.yml --profile {{profile}} up -d
    docker compose -f docker/docker-compose.yml ps

# Builds the image, waits for health, prints the addresses (decision 38).
# Start the two-replica acceptance stand: two app containers behind one nginx
cluster-up:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -f docker/.env ]; then
        echo "docker/.env is missing." >&2
        echo "The stand runs in production mode (S-25) and refuses to boot without real secret" >&2
        echo "material. Generate it once — the file is gitignored and never leaves this machine:" >&2
        echo >&2
        echo "  cargo run -p pubd -- generate-secrets --format env --out docker/.env" >&2
        echo >&2
        exit 1
    fi
    docker compose -f docker/docker-compose.yml --profile cluster up -d --build --wait
    echo
    echo "  proxy     http://localhost:${PUB_CLUSTER_PROXY_PORT:-18080}   <- clients use this"
    echo "  replica A http://localhost:${PUB_CLUSTER_A_PORT:-18081}"
    echo "  replica B http://localhost:${PUB_CLUSTER_B_PORT:-18082}"
    echo "  mail      http://localhost:${PUB_MAIL_UI_PORT:-8025}"
    echo
    echo "  run the acceptance claims:  just cluster-check"

# Needs `just cluster-up` first: without the gate variables the suite panics naming both.
# Run the four acceptance claims against the stand (roadmap Phase 3 item 3)
cluster-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cd server
    export PUB_TEST_CLUSTER_URL="${PUB_TEST_CLUSTER_URL:-http://localhost:18080}"
    cargo test -p pub-acceptance -- --test-threads=4 --nocapture

# Stop the two-replica stand (volumes preserved; add `-v` by hand to drop the registry)
cluster-down:
    docker compose -f docker/docker-compose.yml --profile cluster down

# Publishes through the proxy, then prints the ready-to-paste `oha` read profile.
# Measure the stand (Phase 2's owed load test) — numbers go to docs/ops/capacity.md
cluster-load total='24' concurrency='4' target='proxy':
    #!/usr/bin/env bash
    set -euo pipefail
    cd server
    export PUB_TEST_CLUSTER_URL="${PUB_TEST_CLUSTER_URL:-http://localhost:18080}"
    # Release, because a debug build measures the debug build. The read half is printed rather
    # than run: it needs a token the driver mints, and `oha` is the better tool for one URL.
    cargo run --release -p pub-acceptance --bin publish-load -- {{total}} {{concurrency}} {{target}}

# Stop dev containers (volumes preserved)
db-down:
    docker compose -f docker/docker-compose.yml --profile full down

# Build the production image
docker-build:
    docker build -f docker/Dockerfile -t pub:dev .

# Install git hooks (pre-commit: gitleaks, typos, rustfmt, taplo, biome, actionlint)
hooks:
    lefthook install

# The real measurement is `just cluster-load` (docs/ops/capacity.md); this is a smoke.
# One-URL HTTP smoke against a running instance
bench url='http://localhost:8080/healthz':
    oha -z 10s --no-tui {{url}}

# Inspect production image layers for size regressions (interactive)
image-dive: docker-build
    dive pub:dev

# --- hygiene ---------------------------------------------------------------

# Dependency and supply-chain checks: cargo audit/deny/machete for the server,
# bun audit for the web lockfile (mirrors security-ci.yml)
audit:
    cd server && cargo audit
    cd server && cargo deny --locked check
    cd server && cargo machete
    cd web && bun audit

# Secret scan: the working tree (catches staged/untracked files) AND the full
# commit history — mirrors security-ci.yml's history leg
secrets-scan:
    gitleaks dir . --no-banner --redact
    gitleaks git --no-banner --redact

# Lint GitHub workflow files
lint-ci:
    actionlint

# Spell-check docs and sources
spell:
    typos
