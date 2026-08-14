# Backup & restore

Three things constitute the registry; lose any one and no upgrade or reinstall brings it back:

1. **The database** — users, orgs, packages, versions, name claims, tokens (hashed), the audit log.
2. **The blob store** — package archives, content-addressed by sha256 ([decision 10](../decisions.md#10--blob-storage-via-object_store)). These bytes are promised to be stable forever ([S-18](../security.md#4-supply-chain--registry-integrity)); a lost archive breaks every `pubspec.lock` that pins its hash.
3. **The secret material** — see below.

The KV store (in-process or Redis) needs **no** backup: it carries caches, rate-limit counters, and fast-path session state whose durable truth lives in the database ([decision 03](../decisions.md#03--sessions-jwt-access--refresh-sessions-kv-backed-revocation)). Losing it costs at most one access-TTL of blocklist warm-up on a single-node instance — an accepted, documented risk.

## Back up the secrets, too

The generated env/TOML fragment (`pubd generate-secrets`) is part of the backup set, and its pieces fail very differently:

- **`auth.kek`** — irreplaceable. It seals every TOTP seed, the runtime-stored SMTP password, **and the body of every queued message** ([S-26](../security.md#6-secrets--configuration)). A restore with a *different* KEK silently bricks every enrolled second factor (roadmap D27; [security-runbook.md](security-runbook.md#the-kek-cannot-be-rotated-today)) — and queued mail is worse than bricked: a body the KEK cannot open **dead-letters on the first attempt, not after eight**, so every in-flight sign-in code and invitation in the restored queue is discarded with no retry. Those rows live for minutes, so restoring a backup taken minutes ago under a new KEK costs a handful of undelivered codes; it is silent, which is why it is written here.
- **`auth.jwt.kid` + `signing_key`** — losing them logs every browser session out (users sign in again). Annoying, recoverable.
- **`auth.otp_pepper`** — losing it invalidates outstanding OTP codes, which live 10 minutes anyway. Trivial.

Store the fragment with the same care as the database — it is `0600` for a reason.

## Order: database first, then blobs

Dump the database **before** snapshotting the blob store. Blobs are written before the version rows that reference them ([decision 06 addendum](../decisions.md#06--retract--admin-only-hard-delete-with-tombstone)), so a blob snapshot taken *after* the DB dump is a superset of what that dump references — the extras are harmless orphans that blob GC would eventually collect. The reverse order can capture a version row whose archive is missing from the snapshot, which is a broken registry.

If blob GC is enabled (it ships **disabled and dry-run**), prefer pausing it for the duration of a backup (`jobs.blob_gc.enabled = false`, restart — or simply schedule backups apart from `jobs.blob_gc.interval_secs`). The `min_age_secs` grace (default 24 h) already protects young objects, but a GC deleting a just-orphaned blob between your DB dump and your blob sync is a race no grace period fully closes.

The **staged-upload sweep** (`staging-sweep`) is a different matter and needs no pausing: it ships **on** and only ever removes objects under `uploads/`, which no version row references and no restore needs ([decision 31](../decisions.md#31--blob-lifecycle-staged-uploads-swept-by-default-and-an-archive-gc-that-streams-batches-and-resumes)). A blob snapshot that happens to contain some of them just restores garbage the next pass collects again. What it *does* mean for a restore: an upload that was in flight when the snapshot was taken does not survive it, which is correct — the KV session record does not survive either, so the client's finalize would have failed anyway.

## SQLite (the default deployment)

The database runs in WAL mode, so it is **three files**: `pub.sqlite3`, `pub.sqlite3-wal`, `pub.sqlite3-shm` (under `/data/data/` in the container). Two safe procedures; copying the main file alone while the server runs is **not** one of them — you get a torn snapshot missing everything still in the WAL.

**Online** — `sqlite3 .backup` handles WAL correctly against a live database. The runtime image does not ship the `sqlite3` CLI, so run it from a one-off container sharing the volume:

```sh
docker run --rm -v pub-data:/data -v "$PWD/backups:/backup" alpine sh -c \
  'apk add --no-cache sqlite >/dev/null \
   && sqlite3 /data/data/pub.sqlite3 ".backup /backup/pub-$(date +%F).sqlite3"'
# then snapshot the blobs (AFTER the DB dump):
docker run --rm -v pub-data:/data -v "$PWD/backups:/backup" alpine \
  tar czf "/backup/blobs-$(date +%F).tgz" -C /data/data blobs
```

**Offline** — stop the container and archive the whole volume; one consistent snapshot of DB + blobs, at the cost of downtime:

```sh
docker stop pub
docker run --rm -v pub-data:/data -v "$PWD/backups:/backup" alpine \
  tar czf "/backup/pub-data-$(date +%F).tgz" -C /data data
docker start pub
```

## PostgreSQL

`pg_dump` (or `pg_dumpall` for roles) on whatever schedule your data-loss tolerance dictates, then snapshot the blob store. With the compose `pg` profile:

```sh
docker compose -f docker/docker-compose.yml exec pg pg_dump -U pub -d pub -Fc \
  > "backups/pub-$(date +%F).dump"
```

Point-in-time recovery (WAL archiving) works as with any Postgres; nothing in the schema requires special handling.

## Blob store

- **`fs`**: `tar`/`rsync` of `blob.path` (default `data/blobs`), after the DB dump. The layout is content-addressed (`pub/<xx>/<sha256>.tar.gz`), so incremental sync tools work well — objects are only ever added or deleted, never modified.
- **`s3`**: enable **bucket versioning** and cross-region replication (or a scheduled `mc mirror` to a second bucket) as the equivalent. Versioning also protects against the one writer the design allows to delete bytes — hard delete and blob GC — turning a mistaken deletion into a recoverable one.
- **`memory`**: not a production backend; nothing to back up and nothing survives a restart.

## Restore

1. Stop the server (or start a fresh host).
2. Restore the database: copy the `.backup` file to `data/pub.sqlite3` (delete any stale `-wal`/`-shm` sidecars from the failed instance), or `pg_restore` the dump.
3. Restore the blob store to `blob.path` / the bucket.
4. Configure the server with the **original secret material** — the same KEK above all.
5. Start, and verify (below). Migrations are forward-only and applied automatically at boot ([upgrade.md](upgrade.md)), so restoring an older dump into a **newer** binary is supported; restoring a newer dump into an older binary is not.

## Post-restore verification

```sh
# 1. Every backend answers:
curl -s https://pub.example.com/healthz     # status: ok, checks all true

# 2. The registry serves metadata AND bytes — a listing proves the DB,
#    a download proves the blob store agrees with it:
curl -s https://pub.example.com/pub/api/packages/<some_public_package> | head -c 400
curl -sfo /dev/null "<an archive_url from that listing>" && echo "archive ok"

# 3. Auth round-trips: sign in through the web UI and `dart pub get` a real project
#    against the instance (proves tokens). The sign-in proves the OTP pepper; it proves
#    SMTP only once the code actually arrives, because delivery is asynchronous — if it
#    does not, read mail_transport_unusable and the audit log (ops/monitoring.md).
```

If TOTP-enrolled users cannot pass their second factor after a restore, the running KEK is not the one the backup was sealed under — stop and fix the secret material before anything else; the seeds are unrecoverable without it.
