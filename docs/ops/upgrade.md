# Upgrade

Releases are cut by tagging `vX.Y.Z` ([decision 18](../decisions.md#18--ops-release-model-image-registry-reference-orchestrator)): the workflow builds multi-arch images to `ghcr.io/plugfox/pub`, smoke-tests `/healthz` against the tag's version, attaches an SBOM, and publishes a GitHub release carrying the matching [CHANGELOG](../../CHANGELOG.md) section. Read that section before upgrading — user-visible changes are always recorded there, tagged per component.

## Procedure

1. **Back up first** — database, then blobs ([backup-restore.md](backup-restore.md)). This is not ceremony: it is the rollback mechanism (below).
2. Pull the new tag and replace the container:

   ```sh
   docker pull ghcr.io/plugfox/pub:vX.Y.Z
   docker stop pub && docker rm pub
   docker run -d --name pub -p 8080:8080 --env-file pub-secrets.env \
     -e PUB_SERVER__PUBLIC_URL=https://pub.example.com \
     -v pub-data:/data ghcr.io/plugfox/pub:vX.Y.Z
   ```

   Durable state lives on the volume and the secrets in the env file, so replacing the container loses nothing. Compose deployments: bump the image tag and `docker compose up -d`. Source builds: build the new tag ([install.md](install.md#from-source)) and restart the process.
3. Watch the startup log. Migrations are applied **automatically at boot, before serving** — pin the release notes for anything schema-heavy; on a large Postgres instance a migration can hold boot for a moment, and the log line `database ready, migrations applied` marks the end of it. A failed migration is a fail-fast startup error, never a half-migrated serving instance.
4. Verify the version took:

   ```sh
   curl -s https://pub.example.com/healthz | grep '"version"'
   docker exec pub pubd --version   # version (git hash, build date)
   ```

Expect a brief downtime window: this is a single-replica deployment shape (roadmap D1 — see [install.md](install.md#one-replica-for-now)), so there is no rolling upgrade today. The `dart pub` client retries transient failures, so a short restart is invisible to most CI.

## Migrations are forward-only

Migrations are paired per dialect (one SQLite set, one Postgres set, kept in lockstep — `docs/rules/migrations.md`) and **forward-only: there are no down-migrations, by design**. A schema that can be walked backwards is a schema whose invariants can be un-enforced; the registry's core promises (tombstones survive, claims are forever — [decision 06](../decisions.md#06--retract--admin-only-hard-delete-with-tombstone)) are exactly the kind of thing a down-migration would casually destroy.

Consequences:

- **Rollback = restore.** To return to version N−1 after upgrading to N, restore the pre-upgrade backup and start the N−1 image. Whatever happened on the instance between the upgrade and the rollback is lost — which is why step 1 is the procedure's load-bearing line, and why upgrading soon after a fresh backup beats upgrading long after one.
- **Do not start an older binary against a newer schema.** It may boot (older migrations are all present), but it will run against tables whose newer invariants it does not know. Nothing checks for this today ([/healthz does not report migration state](install.md#verifying-an-instance), roadmap D25).
- Skipping versions is fine as far as migrations are concerned — they are a linear sequence and boot applies every missing step. Read the skipped releases' changelog sections anyway; config keys and defaults move between minor versions while the project is pre-1.0.
