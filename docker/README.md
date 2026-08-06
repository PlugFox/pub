# Docker

The **default dev loop needs no containers**: the server runs on SQLite + filesystem
blobs + in-memory KV out of the box. Everything here is optional infrastructure for
the backend matrix, plus a production-shaped single image.

## Profiles

| Profile | Services | Use case |
|---------|----------|----------|
| `pg`    | PostgreSQL 17 | test the `db-postgres` backend |
| `s3`    | MinIO (S3 API :9000, console :9001) | test the S3 blob backend |
| `redis` | Valkey 8 | test the Redis KV backend / multi-instance gate |
| `full`  | app (built from `docker/Dockerfile`) + pg + s3 + redis | run the whole stack in containers |

## One-liners

```sh
# from the repo root
docker compose -f docker/docker-compose.yml --profile pg up -d      # just Postgres
docker compose -f docker/docker-compose.yml --profile pg --profile redis up -d
docker compose -f docker/docker-compose.yml --profile full up -d --build
docker compose -f docker/docker-compose.yml --profile full down     # add -v to drop data

# production-shaped image alone (build from the repo root)
docker build -f docker/Dockerfile -t pub .
docker run -p 8080:8080 pub
```

Configuration: defaults work with zero setup; to override, `cp docker/.env.example docker/.env`
and edit. In the `s3`/`full` profiles create the bucket (default `pub`) once via the MinIO
console at <http://localhost:9001>.

No release/publish pipeline yet — decision 18 (registry, release model) is tbd.
