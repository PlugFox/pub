# Install

The supported production minimum is one container, one volume: SQLite + filesystem blobs + in-process KV ([decision 04](../decisions.md#04--single-binary-now-optional-split-later)). Postgres, S3, and Redis are configuration changes, not different builds ([decision 09](../decisions.md#09--always-compiled-backends-runtime-config-selection)).

## Docker quickstart

The image (`ghcr.io/plugfox/pub`, [decision 18](../decisions.md#18--ops-release-model-image-registry-reference-orchestrator)) runs in **production mode** by default: it refuses to boot until real secret material is configured, and the startup error names every missing key at once ([S-25](../security.md#6-secrets--configuration)).

```sh
# 1. Generate the three required secrets (Ed25519 JWT signing key + kid, OTP pepper, KEK):
docker run --rm ghcr.io/plugfox/pub generate-secrets --format env > pub-secrets.env

# 2. Run with the env file and a named volume (the registry survives container replacement):
docker run -d --name pub -p 8080:8080 \
  --env-file pub-secrets.env \
  -e PUB_SERVER__PUBLIC_URL=https://pub.example.com \
  -v pub-data:/data \
  ghcr.io/plugfox/pub

# 3. Verify:
curl -s http://localhost:8080/healthz
```

`pubd generate-secrets` draws from the OS CSPRNG and emits the material as an `.env` fragment (`--format env`), a TOML fragment (`--format toml`), or both (the default, stdout only). `--out PATH` writes the file `0600` and refuses to overwrite without `--force` — the file being clobbered may hold the keys a live instance still verifies tokens with. The generated `kid` is date-prefixed (`YYYYMMDD-xxxxxxxx`) so rotated keys sort chronologically ([S-27](../security.md#6-secrets--configuration), [security-runbook.md](security-runbook.md#rotating-the-jwt-signing-key)).

Two more things a real deployment needs on day one:

- **`server.public_url`** (`PUB_SERVER__PUBLIC_URL`) — the exact URL clients reach you on. It is load-bearing far beyond cosmetics; set it before anything else and read [reverse-proxy.md](reverse-proxy.md#public_url-is-load-bearing).
- **SMTP** (`PUB_SMTP__*`) — email OTP is the always-available sign-in factor ([decision 12](../decisions.md#12--auth-factors)), so an instance whose mail goes nowhere is an instance nobody can sign in to. Configure it in **boot config**: the admin-UI SMTP settings are accepted and stored but do not yet rebuild the mailer (roadmap D10).

### Production vs dev mode

`server.mode` gates the secret policy ([S-25](../security.md#6-secrets--configuration)). `production` (the image default): missing pepper/signing key/KEK is a startup error. `dev` (the bare-binary default): missing secrets fall back to loud ephemeral values — every restart invalidates all sessions, and anything sealed under the ephemeral KEK dies with the process. Dev mode in the container is an explicit opt-in: `-e PUB_SERVER__MODE=dev`.

## Configuration: where values come from

Layered, lowest to highest precedence ([decision 09](../decisions.md#09--always-compiled-backends-runtime-config-selection)):

1. built-in defaults;
2. an optional TOML file — `--config PATH` or `PUB_CONFIG=PATH`;
3. environment: prefix `PUB_`, nesting separator `__` — `server.public_url` → `PUB_SERVER__PUBLIC_URL`, `database.kind` → `PUB_DATABASE__KIND`;
4. CLI flags: `--listen`, `--public-url`, `--replicas`.

Any `PUB_*` variable also accepts a `_FILE` suffix (`PUB_AUTH__OTP_PEPPER_FILE=/run/secrets/pepper`): the value is read from the file with trailing newlines trimmed — the Docker/Kubernetes secret-mount convention, and preferable for secrets because a plain env var is readable via `docker inspect` and `/proc/<pid>/environ`. Setting both `X` and `X_FILE` is a hard startup error, never a silent precedence rule.

Two sections cannot be expressed through the env layer because they are **arrays of tables**: OIDC providers (`[[auth.oidc]]`) and JWT rotation overlap keys (`[[auth.jwt.verify_keys]]`). If you need either, use the TOML file. Every key is documented in [configuration.md](configuration.md); the server also prints an effective-config summary at startup with secrets masked, which is the fastest way to see what a layered setup actually resolved to.

Validation is fail-fast and semantic: `postgres` without a URL, `s3` without a bucket, `redis` without a URL, a malformed KEK, a heartbeat that would break the SSE revocation bound — each is a named startup error, not a runtime surprise.

## Data layout (image)

The container runs as non-root **uid 1000** with `WORKDIR /data`, declared as a `VOLUME`. The config defaults are relative paths, so everything durable lands under the volume:

| Path | What |
|------|------|
| `/data/data/pub.sqlite3` (+ `-wal`, `-shm`) | SQLite database (WAL mode) |
| `/data/data/blobs/` | Content-addressed archive store (`fs` backend) |

Bind mounts instead of a named volume work, but the host directory must be writable by uid 1000. What must survive a disaster is the database, the blob store, **and the secrets file** — the KEK in particular seals data that is unrecoverable without it ([backup-restore.md](backup-restore.md#back-up-the-secrets-too)).

## Compose

`docker/docker-compose.yml` provides optional infrastructure behind profiles — `pg` (PostgreSQL 17), `s3` (MinIO + bucket init), `redis` (Valkey 8), `mail` (Mailpit sink), and `full` (the app image wired to all of them):

```sh
docker compose -f docker/docker-compose.yml --profile full up -d --build
```

One thing `docker/.env.example` is explicit about and worth repeating: the variables in that file (`PUB_PG_*`, `PUB_S3_*`, `PUB_MAIL_*`, `PUB_APP_PORT`, …) are **compose interpolation variables, not server configuration keys**. They parameterize the container definitions; the server itself is configured by the `PUB_SERVER__*`/`PUB_DATABASE__*`-style variables the compose file sets on the `app` service. The `full` profile's app runs in production mode and needs generated secrets appended to `docker/.env` first — the flow is documented at the bottom of `.env.example`. Sign-in mail lands in Mailpit at `http://localhost:8025`. Details: [docker/README.md](../../docker/README.md).

## From source

Toolchain: Rust stable via rustup (deliberately not pinned in `.mise.toml`), Bun pinned there for the frontend (`mise install`).

```sh
# Frontend first, so the binary embeds the real UI instead of the committed placeholder:
cd web && bun install && bun run build && cd ..
rm -rf server/crates/api/embedded && mkdir -p server/crates/api/embedded
cp -R web/apps/site/dist/. server/crates/api/embedded/

# Then the server:
cd server && cargo build --release -p pubd
# → server/target/release/pubd
```

Skipping the frontend step still builds and serves the full API — `server/crates/api/embedded/` holds a placeholder page in git — but the web UI will be that placeholder. Run with a TOML config (`pubd --config pub.toml`) or env vars; without configured secrets the binary starts in dev mode with ephemeral material and loud warnings. A source build reports its version as the crate version marked `+dev` — visibly not a release ([decision 18](../decisions.md#18--ops-release-model-image-registry-reference-orchestrator)).

## First administrator

Bootstrap needs no console access ([decision 09 addendum](../decisions.md#09--always-compiled-backends-runtime-config-selection)):

- **Default**: with `auth.instance_admins` empty, the **first account registered on an admin-less instance** becomes instance administrator. The grant is a single race-safe statement, so two concurrent first registrations cannot both win it.
- **Explicit**: `auth.instance_admins` is a boot-config list of email addresses, applied idempotently at startup to existing accounts and at registration to new ones. It only ever promotes — removing an address does **not** demote; revoking administration is an audited action on the admin surface, not a side effect of a config edit. A malformed entry is a startup error, because a typo here is a silent lockout.

Instance administration is a plane orthogonal to org roles ([decision 19](../decisions.md#19--rbac-cumulative-role-levels-with-a-single-authorize-chokepoint)): an instance admin holds no org role they were not granted.

## Verifying an instance

`GET /healthz` is unauthenticated and always on ([decision 23](../decisions.md#23--monitoring-is-optional)):

```json
{
  "status": "ok",
  "version": "1.2.3",
  "backends": { "database": "sqlite", "blob": "fs", "kv": "memory" },
  "checks": { "database": true, "blob": true, "kv": true }
}
```

`status` is `ok` when every configured backend answers a **live ping** (these are real probes, not config echoes), `degraded` otherwise. Honest limits: `/healthz` does **not** report migration status, and there is no separate `/readyz` (roadmap D25) — a booted process has already applied its migrations, but a health probe cannot distinguish "migrating" from "down". `pubd --version` prints the same version plus git hash and build date.

## One replica, for now

The config validator accepts `cluster.replicas > 1` whenever the Redis KV backend is configured ([decision 03](../decisions.md#03--sessions-jwt-access--refresh-sessions-kv-backed-revocation)) — but the background-job leader lock is still per-process, so at two replicas the blob GC (a job that deletes bytes) can run twice concurrently and mirror sweeps race one durable cursor (roadmap D1, scheduled for Phase 3). **Run exactly one replica** until the distributed job lock lands; the validator's acceptance is currently a promise ahead of the code.

## Connecting `dart pub`

Each organization gets a virtual registry URL; the org base resolves the org's own packages, instance-public packages, and pub.dev via the proxy, in that fixed order — local always wins ([decision 01](../decisions.md#01--per-org-virtual-registry-urls)):

```sh
# Resolve through the org registry:
export PUB_HOSTED_URL=https://pub.example.com/o/acme/pub
dart pub token add "$PUB_HOSTED_URL"    # prompts for a token minted in the web UI
dart pub get
```

For publishing, put the same URL in the package's `pubspec.yaml`:

```yaml
publish_to: https://pub.example.com/o/acme/pub
```

The public root `https://pub.example.com/pub` serves only public and proxied packages and refuses publishes (a publish needs an owning org). Tokens are org-bound, scoped (`read`/`publish`/`retract`/`admin`), shown exactly once at mint time, and sent only as `Authorization: Bearer` ([decision 13](../decisions.md#13--cliapi-token-format)); the token panel in the org UI shows the exact `dart pub token add` command. One known defect: that copy snippet is built from the browser origin, so it is wrong behind a subpath reverse proxy (roadmap D32) — behind a subpath, hand your users the URL shape above.
