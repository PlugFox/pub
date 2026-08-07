# Docker

The **default dev loop needs no containers**: the server runs on SQLite + filesystem
blobs + in-memory KV out of the box. Everything here is optional infrastructure for
the backend matrix, plus a production-shaped single image.

## Quickstart — a deployable instance

The image runs in **production mode** by default: it refuses to boot until real secret
material is configured (S-25) and tells you exactly which `PUB_AUTH__*` keys are missing.
`/data` is a declared volume, so the registry survives container replacement.

```sh
# 1. Generate secret material (Ed25519 JWT keyring, OTP pepper, KEK):
docker run --rm ghcr.io/plugfox/pub generate-secrets --format env > pub-secrets.env

# 2. Run with the env file and a named data volume:
docker run -d --name pub -p 8080:8080 --env-file pub-secrets.env -v pub-data:/data ghcr.io/plugfox/pub
curl http://localhost:8080/healthz

# 3. Sign in — email OTP is the always-available factor, so mail must go somewhere:
#    production: point PUB_SMTP__* at your relay (add to the env file);
#    dev tour:   use the compose mail sink below and read the code at http://localhost:8025.
```

`pubd generate-secrets` also emits a TOML fragment (`--format toml`) for config-file
deployments, and `--out PATH` writes it `0600` (refusing to overwrite without `--force`).
Dev-mode ephemeral fallbacks are an explicit opt-in: `-e PUB_SERVER__MODE=dev`. Bind
mounts instead of a named volume: the directory must be writable by uid 1000. Full
operator docs (reverse proxy, backup, key rotation) are a separate roadmap item.

## Profiles

| Profile | Services | Use case |
|---------|----------|----------|
| `pg`    | PostgreSQL 17 | test the `db-postgres` backend |
| `s3`    | MinIO (S3 API :9000, console :9001) + bucket init | test the S3 blob backend |
| `redis` | Valkey 8 | test the Redis KV backend / multi-instance gate |
| `mail`  | Mailpit (SMTP :1025, UI/API :8025) | catch OTP + notification mail in dev |
| `full`  | app (built from `docker/Dockerfile`) + pg + s3 + redis + mail | run the whole stack in containers |

## One-liners

```sh
# from the repo root
docker compose -f docker/docker-compose.yml --profile pg up -d      # just Postgres
docker compose -f docker/docker-compose.yml --profile pg --profile redis up -d
docker compose -f docker/docker-compose.yml --profile full up -d --build
docker compose -f docker/docker-compose.yml --profile full down     # add -v to drop data

# production-shaped image alone (build from the repo root)
docker build -f docker/Dockerfile -t pub .
docker run --rm pub generate-secrets --format env > pub-secrets.env
docker run -d -p 8080:8080 --env-file pub-secrets.env -v pub-data:/data pub
```

Configuration: infra defaults work with zero setup; to override, `cp docker/.env.example
docker/.env` and edit. The `full` profile's app runs in production mode and needs the
generated secrets appended to `docker/.env` first (the flow is at the bottom of
`.env.example`); the MinIO bucket is created automatically by the `s3-init` one-shot.
Sign-in mail lands in Mailpit at <http://localhost:8025>.

## Releases

Published images live on **`ghcr.io/plugfox/pub`** (decision 18): multi-arch
`linux/amd64` + `linux/arm64`, tagged `vX.Y.Z` per release plus `latest` for the newest
stable. The version derives from the git tag and reaches the binary through the
`PUB_VERSION` build arg — `/healthz` and `pubd --version` report it:

```sh
docker build -f docker/Dockerfile --build-arg PUB_VERSION=1.2.3 -t pub .
```

Without the build arg (local builds, PR CI) the binary reports the crate version marked
`+dev` — visibly not a release. Releases are cut by tagging `vX.Y.Z`; the workflow in
[.github/workflows/release.yml](../.github/workflows/release.yml) builds both
architectures natively, smoke-tests `/healthz` against the tag's version, attaches
SBOM + provenance attestations, and publishes a GitHub release with the newest
changelog section. CI never commits version bumps.
