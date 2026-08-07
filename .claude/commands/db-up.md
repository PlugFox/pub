---
description: Start optional dev infrastructure (Postgres/MinIO/Redis) via docker compose
allowed-tools: Bash
---

Bring up dev infrastructure containers and verify they're healthy.

Reminder: the default dev loop needs NO containers (SQLite + fs blob + in-memory KV). Containers are only for exercising the Postgres/S3/Redis backends.

1. Pick the profile from the argument (default `pg`; valid: `pg`, `s3`, `redis`, `full`):
   `docker compose -f docker/docker-compose.yml --profile <profile> up -d`
2. Wait up to 30s for the containers to report healthy via `docker compose -f docker/docker-compose.yml ps`.
3. Print the final status (container, state, ports) in a compact table.
4. If Postgres is up, mention that `PUB_TEST_POSTGRES_URL` enables the Postgres contract-test leg.

If any container fails to become healthy: show the last 30 lines of its logs and stop.
