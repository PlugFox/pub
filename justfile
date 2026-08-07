# Canonical task runner for pub. `just` lists recipes; recipes mirror the
# validation pipelines documented in CLAUDE.md — keep the two in sync.

set working-directory := '.'

default:
    @just --list

# --- validation ------------------------------------------------------------

# Full server validation pipeline (fmt, clippy, tests)
server-check:
    cd server && cargo fmt --check
    cd server && cargo clippy --all-targets -- -D warnings
    cd server && cargo test --workspace

# Full web validation pipeline (typecheck+lint+contrast, build, tests)
web-check:
    cd web && bun run check
    cd web && bun run build
    cd web && bun test

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

# Regenerate committed codegen artifacts (i18n modules + API types)
gen:
    cd web && bun run i18n:gen
    cd web && bun run gen:api

# --- infra -----------------------------------------------------------------

# Start optional dev containers; profiles: pg | s3 | redis | full
db-up profile='pg':
    docker compose -f docker/docker-compose.yml --profile {{profile}} up -d
    docker compose -f docker/docker-compose.yml ps

# Stop dev containers (volumes preserved)
db-down:
    docker compose -f docker/docker-compose.yml --profile full down

# Build the production image
docker-build:
    docker build -f docker/Dockerfile -t pub:dev .

# Install git hooks (pre-commit: gitleaks, typos, rustfmt, taplo, biome, actionlint)
hooks:
    lefthook install

# HTTP load smoke against a running instance (Phase 2 exit criteria live here)
bench url='http://localhost:8080/healthz':
    oha -z 10s --no-tui {{url}}

# Inspect production image layers for size regressions (interactive)
image-dive: docker-build
    dive pub:dev

# --- hygiene ---------------------------------------------------------------

# Dependency and supply-chain checks
audit:
    cd server && cargo audit
    cd server && cargo deny check
    cd server && cargo machete

# Secret scan over the working tree
secrets-scan:
    gitleaks detect --source . --no-banner

# Lint GitHub workflow files
lint-ci:
    actionlint

# Spell-check docs and sources
spell:
    typos
