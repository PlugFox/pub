# Pub Protocol Notes — Hosted Pub Repository Spec v2

Canonical spec: `dart-lang/pub` → `doc/repository-spec-v2.md`. Ground truth beyond the spec text is the client source (`lib/src/source/hosted.dart`, `lib/src/http.dart`, `lib/src/command/lish.dart`, `lib/src/authentication/*`). This file catalogs the behaviors we must honor exactly — several are sharp-edged and, if violated, break or actively damage the client's state.

## Endpoint surface (per virtual base `B = /o/{org}/pub`, public root `B = /pub`; see [architecture.md](architecture.md#pub-protocol--resolution))

| # | Route | Notes |
|---|-------|-------|
| 1 | `GET B/api/packages/{name}` | Version listing — the hot path; the client re-fetches it before every download (no caching of `archive_url` client-side) |
| 2 | `GET B/api/packages/versions/new` | Publish step 1: returns `{"url": <upload>, "fields": {…}}`; bearer required. Carries **no package name** — authorize only "has publish scope" here; org/pattern/claim checks happen at finalize |
| 3 | `POST <upload-url>` | Publish step 2: multipart; all `fields` first, then the archive as field `file` (`package.tar.gz`); respond `204` + `Location: <finalize-url>` (any 2xx/3xx with `Location` works) |
| 4 | `GET <finalize-url>` | Publish step 3: `200 {"success":{"message":…}}` or `400 {"error":{"code","message"}}` — do ALL validation here |
| 5 | `GET B/api/packages/{name}/advisories` | Optional (v1.1); advertised via `advisoriesUpdated` in listing |
| 6 | `GET B/api/packages/{name}/versions/{v}` | Legacy (pre-Dart-2.8), trivial — implement |
| 7 | `GET B/packages/{name}/versions/{v}.tar.gz` | Legacy archive download — implement |

Keep upload/finalize URLs under `B` so the client's prefix rule attaches `Authorization` automatically to all three publish steps.

## Sharp edges (violate ⇒ break clients)

1. **401 destroys user credentials.** On 401 the client **deletes the stored token** and shows the `message` from `WWW-Authenticate: Bearer realm="pub", message="…"` (challenge must literally have scheme `Bearer`, `realm="pub"`; message sanitized, ≤1024 chars). The **same header is required on 403 too** and the client surfaces its message — it is our only messaging channel into the CLI (how to get a token, how to request access). Use 401 only for missing/invalid tokens; valid-but-insufficient on a *visible* resource ⇒ **403** (token survives); any package the principal cannot read ⇒ **404** — a deliberate, documented deviation from the spec's 401-for-protected-resources MUST, adopted for anti-enumeration ([decision 05](decisions.md#05--anonymous-read-configurable-default-allowed), [S-04](security.md#1-authentication)). With `require_auth_for_read` enabled, anonymous requests get the spec-mandated 401 + onboarding message.
2. **Permanent failures must be 4xx.** The client retries 408, 429, and all ≥500 up to **7 total attempts** (1 initial + up to 6 retries; `PUB_MAX_HTTP_RETRIES` overrides) with backoff. A 500 on a doomed request means up to 7 hammering requests and a confusing UX. Emit spec-shaped `{"error":{"code","message"}}` — only `message` is shown to users.
3. **Archives are byte-stable forever.** `archive_sha256` (64 lowercase hex) goes into version listings and users' `pubspec.lock`; the client hard-fails on mismatch and re-downloads when hashes differ. Store the exact uploaded bytes, never re-gzip/re-tar, serve identical bytes for eternity. Proxied packages: preserve upstream bytes and hash verbatim — but **rewrite `archive_url` in re-emitted listings to our own virtual base** (see [architecture.md, proxy ingest](architecture.md#pub-protocol--resolution)); serving upstream CDN URLs silently bypasses the cache, per-org policy, and stale-serving.
4. **`archive_url` auth prefix rule.** The client attaches `Authorization` to an archive/finalize URL **only if the normalized hosted URL is a case-insensitive prefix** of it. Private downloads must either live under `B` or use presigned URLs (expiry ≥25 min — retries + clock drift) that need no auth.
5. **Validate at finalize, not upload.** Step 2 is often a dumb blob sink (S3 POST-policy compatible); name/version/claim/size/dedup checks belong in step 3 where `{"error":…}` + 400 renders cleanly in the CLI.
6. **Accept header may be absent** — default to v2 semantics. Reserve **406** exclusively for "client too old / API version unsupported" (client shows an upgrade message).
7. **Listing response size**: full pubspec JSON per version; the client won't disk-cache responses ≥ ~1 MB. Keep listings lean, support gzip; this endpoint must be fast — online resolution always re-fetches it.
8. **Hosted URL normalization**: no user-info/query/fragment; path prefixes are legal and must work behind reverse proxies (`https://host/o/acme/pub` resolves as `…/o/acme/pub/api/packages/…`) — subpath breakage was unpub's #1 bug class.
9. **Retraction semantics**: `retracted: true` versions are excluded from new resolution but stay downloadable (lockfile-pinned builds keep working). `isDiscontinued`/`replacedBy` are package-level listing fields; the flags are the contract — management APIs are ours to design.
10. **Version listing field types are enforced** client-side: `archive_url` string; `archive_sha256` exactly 64 hex; `retracted`/`isDiscontinued` bool; `advisoriesUpdated` RFC3339 string. Unknown fields ignored (safe to extend).
11. **Advisories** (when implemented): OSV objects; the client consumes **only `affected[].versions`** (ranges ignored) — enumerate exhaustively or don't ship the endpoint; failures degrade to warnings. The response's `advisoriesUpdated` is a **required RFC3339 string** (the client errors otherwise) and must equal the value advertised in the version listing, changing only when advisory content actually changes: the client refetches by comparing the listing value against its cache with a 24-hour clock-drift buffer, so per-request or divergent timestamps either break caching or serve stale advisories.
12. **`PUB_HOSTED_URL` replaces pub.dev entirely** (not a fallback) and the hosted URL is written into `pubspec.lock` — this is exactly why the per-org virtual URL must serve upstream packages too, and why changing a team's registry URL forces a one-time full re-download (different client cache key).

## Client-side facts that shape our design

- Tokens: `dart pub token add <url>` (secret via stdin) or `--env-var NAME` for CI; charset per RFC 6750 (`[a-zA-Z0-9._~+/=-]`); HTTPS required except localhost. The token is sent on **every** request whose URL matches the credential prefix — download endpoints are authenticated traffic for private orgs; rate-limit accordingly.
- `PUB_CACHE` keys by hosted URL: per-org URLs mean per-org local caches — accepted cost of decision 01.
- The client sends `Accept: application/vnd.pub.v2+json` on API requests (not archive/upload), `User-Agent: Dart pub <sdk>`.
- Optional freebies: `x-goog-hash: crc32c=…` on archive responses is verified when present; `/api/package-names` + `/api/package-name-completion-data` (pub.dev conventions) enable mirroring and autocomplete tooling — we implement both (also used by our own mirror worker against upstream).

## Conformance testing

The integration suite encodes this file: status-code ladder (401/403/404/406/400), WWW-Authenticate shape, listing field types, publish flow happy/sad paths, byte-stability (hash of served bytes = hash at publish, across restarts and backends), retraction visibility, subpath reverse-proxy simulation. A CI job runs the real `dart pub` client end-to-end; that job, not unit tests, is the final arbiter of conformance.
