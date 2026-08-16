# Capacity

What one measurement on one machine actually said. This is the load test [Phase 2's exit](../roadmap.md) has owed since that phase closed, taken against the two-replica stand rather than against a router in a test process ([decision 38](../decisions.md#38--two-replicas-behind-one-proxy-an-acceptance-stand-that-fails-closed-four-claims-proven-at-the-wire-and-a-measurement-that-is-a-number)).

**These numbers are not a threshold and nothing in CI compares against them.** A latency gate measured on whatever host happened to run it is noise with a version number. What a recorded measurement is good for is the *next* measurement: same method, same shapes, a number to compare.

## What was measured, and on what

| | |
|---|---|
| Date | 2026-08-16 |
| Stand | `docker compose --profile cluster` — two app replicas behind nginx, one Postgres 17, one Valkey 8, one MinIO, one Mailpit |
| Host | Apple M3 Max, 14 cores, 36 GB, macOS 26.4.1 |
| Docker | 27.4.0, **4 CPUs and 5.8 GB allocated to the VM** — the ceiling here is the VM, not the host |
| Client | same machine as the stand; loopback, so network latency is absent from every number below |
| Build | release binary in the production image (`docker/Dockerfile`) |

The client sharing the host with the server is the largest caveat in this table: it flatters latency and it steals CPU from the thing being measured. Read these as *shapes* — where the time goes, what the caps are — rather than as a capacity plan.

## Read path — what `dart pub get` actually asks for

`oha`, 4 connections, held to 8 requests/second so the measurement is of the server rather than of the rate limiter.

| Request | Requests | Average | Slowest | Errors |
|---|---|---|---|---|
| Version listing (`GET /o/{org}/pub/api/packages/{name}`) | 120 | **8.5 ms** | 19.8 ms | 0 |
| Archive download (`GET …/api/archives/{name}-{version}.tar.gz`) | 80 | **11.8 ms** | 21.3 ms | 0 |

Both are authenticated with a `read`-scoped token, which matters twice: an org's packages are private, so an unauthenticated run measures the 404 path, and an *identified* caller is metered on a different budget than an anonymous one (below).

## Where the read budget bites

The same listing, unthrottled, 8 connections, 20 seconds:

```
[200]   3 019 responses
[429] 139 118 responses
```

That is the S-24.f budget working exactly as documented, and it is the most useful number on this page: **one identity gets `http.rate_limit.read_per_identity_minute` = 3000 reads a minute** (an unidentified caller gets `read_per_ip_minute` = 600). Above it the answer is a cheap `429` — the whole 20-second run averaged 1.1 ms per response, refusals included, so a client in a retry loop costs the instance almost nothing. A CI fleet resolving through **one** token will meet this wall long before it meets the server; give the fleet its own tokens, or raise the budget deliberately.

## Write path — a publish is three round trips

The `publish-load` driver in `crates/acceptance`: distinct package names (so the per-name publish lock is not what is being measured), one org and one token minted up front.

| Target | Concurrency | Publishes | p50 | p95 | p99 | Throughput |
|---|---|---|---|---|---|---|
| proxy (both replicas) | 4 | 24 | 17.2 ms | 24.0 ms | 25.4 ms | 212/s |
| replica A directly | 4 | 24 | 16.1 ms | 21.1 ms | 21.3 ms | 237/s |
| proxy (both replicas) | 12 | 24 | 32.0 ms | 39.9 ms | 40.1 ms | 332/s |
| replica A directly | 12 | 24 | 32.6 ms | 36.5 ms | 36.6 ms | 327/s |

Two things this says, and one it does not.

- **A publish is tens of milliseconds, not seconds** — three authenticated round trips including a real multipart upload and a blob write to MinIO.
- **The second replica does not add publish throughput here.** At concurrency 12 the proxy and a single replica are within 1.5 % of each other, because what saturates first is shared: one Postgres, one blob store. A second replica buys **availability and read capacity**, not write throughput. Anybody sizing for publish volume should size the database, not the app tier.
- What it does *not* say is where the knee is. The runs are bounded at 24 publishes by `registry.rate_limit.publish_per_hour_org` (**30 per org per hour**, S-24.g), so this measures a burst rather than a sustained rate. Sustained publish load needs either more orgs or a raised budget — and an operator who raises it should know it is also the bound on how many staged uploads an org can park (S-20.b).

Direct-dial rows also skip the proxy hop, so they are not a clean single-variable comparison; the ~1 ms and slightly longer tail on the proxy rows is roughly what that hop costs.

## Reproducing this

```sh
just cluster-up
cd server
PUB_TEST_CLUSTER_URL=http://localhost:18080 cargo run --release -p pub-acceptance --bin publish-load -- 24 4
#  … prints the ready-to-paste `oha` command for the read profile, with a token
```

`just cluster-load [total] [concurrency] [proxy|a|b]` is the same thing in one line — it builds the release driver, runs the write profile, and prints the read command with a freshly minted token.

## What has never been measured

Ordinary honesty about the gaps, so the next person picks the right one:

- **Sustained load of any kind.** Every run here is seconds long; nothing has run for an hour, and nothing has measured what the queue, the retention pass or the mirror sweep do to the numbers while they run.
- **Concurrency above 12**, and therefore the knee.
- **A remote client.** Everything is loopback.
- **Archives of a realistic size.** The fixture archive is a few hundred bytes; `registry.max_archive_bytes` is 100 MiB, and the upload path's behaviour at that size is untested here.
- **More than two replicas, a rolling restart, or a partition** — the acceptance run's own limits, listed in [install.md](install.md#the-two-replica-stand).
