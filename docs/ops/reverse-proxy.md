# Reverse proxy

`pubd` speaks plain HTTP on `server.listen` (default `0.0.0.0:8080`); TLS termination belongs to a reverse proxy. The supported shape is **exactly one trusted proxy** between the internet and the listener. Three things must be configured correctly or the instance misbehaves in ways that look like application bugs: `server.public_url`, `server.trust_proxy_headers`, and the per-route buffering/size/timeout rules below.

## `public_url` is load-bearing

`server.public_url` must be the **exact** URL clients reach the instance on — scheme, host, port, and any path prefix. It is not cosmetic; three subsystems read it:

- **Every absolute URL the pub protocol returns** — `archive_url`, upload and finalize URLs — is built from `public_url`, *including any path prefix it carries*, and never from the request's `Host`/`X-Forwarded-*` headers. Subpath mounting therefore works by construction, and a client cannot make the server emit URLs pointing at a host it chose ([protocol.md sharp edge 8](../protocol.md#sharp-edges-violate--break-clients)). The corollary: a wrong `public_url` hands every `dart pub` client download URLs that do not resolve.
- **The OIDC redirect base**: providers redirect back to `{public_url}/auth/callback/{provider}` ([S-01](../security.md#1-authentication)); register exactly that URI at the IdP.
- **The server-side `Origin` check on every `/api` mutation** ([S-12](../security.md#2-sessions--web-plane)): a browser request whose `Origin` does not match `public_url`'s origin triple is rejected with 403. A wrong `public_url` breaks the entire web UI — every write returns 403 — while `curl` keeps working, which makes it a confusing failure if you do not know to look here.

Subpath example — registry mounted under `https://corp.example/registry`:

```toml
[server]
public_url = "https://corp.example/registry"
```

The prefix lives **only in generated URLs**. The router mounts every route at its absolute path — `/pub/…`, `/o/{org}/pub/…`, `/api/…` — and knows nothing about `/registry`, so the proxy **must strip the prefix before forwarding**: `https://corp.example/registry/o/acme/pub/api/…` has to reach the listener as `/o/acme/pub/api/…`. Forward the prefix intact and every request 404s. Advertised URLs still come out right — the org base becomes `https://corp.example/registry/o/acme/pub` because `public_url` carries the prefix — so the round trip closes: the server hands out prefixed URLs, the proxy strips the prefix, the listener sees the routes it actually has. Per proxy: nginx — prefix `location`s plus a `rewrite` that drops the prefix ([below](#nginx)); Caddy — `handle_path /registry/*`; Traefik — a `StripPrefix` middleware. One known frontend defect behind subpaths: the token panel's copy-paste `dart pub token add` snippet uses the browser origin instead of the advertised URL (roadmap D32).

## `trust_proxy_headers` (S-24.a/b)

Per-IP rate limits and audit trails are only as strong as the client identity they key on, and `X-Forwarded-For` is attacker-controlled unless something trustworthy wrote it ([S-24.a](../security.md#5-audit--abuse)):

- **`server.trust_proxy_headers = false`** (default): forwarding headers are ignored entirely; the socket peer address is the client identity. Correct for a directly exposed listener — and behind a proxy it means every client shares the proxy's one address and its rate-limit buckets, so set it to `true` once a proxy is in front.
- **`server.trust_proxy_headers = true`**: the server reads the **rightmost** `X-Forwarded-For` entry — the address the trusted proxy itself observed. Everything to the left is client-supplied and ignored.

[S-24.b](../security.md#5-audit--abuse) is normative MUST language: *deployments that terminate TLS at a proxy MUST set `server.trust_proxy_headers = true` **and** ensure the proxy overwrites (or appends to) `X-Forwarded-For`; a proxy that passes the client's header through unchanged makes the trusted mode strictly worse than the untrusted one* — the rightmost entry would then be whatever the attacker sent. All three example configs below produce the required shape. Chains (CDN → proxy → pubd) are not the supported shape: the rightmost entry becomes the CDN edge address and every client behind that edge shares one bucket. Keep it to one hop.

## Sizes and timeouts

The application is growing its own HTTP hygiene layer — an `[http]` config section with a request timeout (default 30 s), a longer upload deadline (`http.upload_timeout_secs`, default 300 s), a concurrency limit (default 1024), and a global body cap (default 2 MiB) for the app API (see [configuration.md](configuration.md)). The proxy must not be the tighter bound on the paths that legitimately exceed those defaults:

- **Publish uploads** travel through the app tier — there is no presigned-upload redirect yet (roadmap, Phase 2) — and are accepted up to `registry.max_archive_bytes` (default 100 MiB) plus 64 KiB of multipart overhead, on `…/pub/api/packages/versions/newUpload` under each registry base. The proxy's body-size limit on those paths must be ≥ that sum, and its read/send timeouts must exceed `http.upload_timeout_secs` (300 s) or slow publishes die at the proxy with a confusing status the `dart pub` client may retry.
- **Archive downloads** stream up to the same size in the other direction; response buffering to disk is a proxy-side performance decision, not a correctness one.
- **The SSE stream** (`GET /api/v1/events`, [decision 20](../decisions.md#20--realtime-sse-event-stream--notification-center)) needs response buffering **off** and a read timeout above the keep-alive cadence. The server writes a comment line at least every `realtime.heartbeat_secs × 4` (default 20 s × 4 = 80 s). It does **not** send `X-Accel-Buffering: no`, so with nginx the `proxy_buffering off` is on you.
- **HSTS**: the app emits `Strict-Transport-Security` itself whenever `server.public_url` is `https`. Do not add a second copy at the proxy — duplicate HSTS headers are a spec violation some clients reject.

## nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name pub.example.com;

    ssl_certificate     /etc/ssl/pub.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/pub.example.com/privkey.pem;
    # No add_header Strict-Transport-Security here: pubd emits HSTS itself
    # when server.public_url is https.

    # App UI + app API. The app-side body cap is 2 MiB (http.max_body_bytes).
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # $proxy_add_x_forwarded_for APPENDS the peer address, so the rightmost
        # entry is what this proxy observed — the shape S-24.b requires.
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 2m;
    }

    # SSE: unbuffered, and a read timeout above the 80 s keep-alive cadence.
    location = /api/v1/events {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;          # pubd sends no X-Accel-Buffering header
        proxy_cache off;
        proxy_read_timeout 300s;
    }

    # pub protocol (org bases /o/{org}/pub and the public root /pub):
    # uploads up to registry.max_archive_bytes + multipart overhead traverse the
    # app tier; timeouts must exceed http.upload_timeout_secs (300 s).
    location ~ ^/(o/[^/]+/)?pub/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 101m;    # nginx sizes are binary: 101 MiB ≥ the
                                      # 100 MiB archive cap + 64 KiB envelope
        proxy_request_buffering off;  # stream uploads instead of spooling to disk
        proxy_read_timeout  310s;
        proxy_send_timeout  310s;
    }
}
```

For a subpath mount, prefix every `location` with the path from `public_url` **and strip it before forwarding** — the listener's routes are absolute, so a forwarded prefix 404s every request ([above](#public_url-is-load-bearing)). Regex locations forbid a URI in `proxy_pass`, so the stripping has to be a `rewrite`; the same line works in the plain locations too:

```nginx
location ~ ^/registry/(o/[^/]+/)?pub/ {
    rewrite ^/registry(/.*)$ $1 break;   # strip the prefix: the listener sees /o/acme/pub/…
    proxy_pass http://127.0.0.1:8080;    # no URI here — regex locations forbid it
    # …same headers, body size, and timeouts as the host-mount block above
}
```

## Caddy

```caddyfile
pub.example.com {
    # TLS is automatic. pubd emits HSTS itself when server.public_url is https —
    # do not add a header directive for it.

    # Backstop body cap for the pub upload endpoints; the app enforces its own
    # tighter per-route limits (2 MiB app API, 100 MiB + 64 KiB uploads).
    # Caddy sizes are SI unless the iB suffix is used: 101MB would be
    # 101,000,000 bytes — below the app's upload limit, making the proxy the
    # tighter bound, which is exactly what this page tells you not to do.
    request_body {
        max_size 101MiB
    }

    reverse_proxy 127.0.0.1:8080 {
        # Caddy only honours incoming X-Forwarded-For from proxies listed in
        # trusted_proxies; from ordinary clients it writes the real peer address —
        # the overwrite shape S-24.b requires. Leave trusted_proxies unset.
        flush_interval -1   # stream SSE and archive bytes immediately
    }
}
```

Caddy streams `text/event-stream` responses without buffering by default; `flush_interval -1` extends that to every response. Its default timeouts are lax enough for 300 s uploads; if you set `timeouts` on the server, keep the read timeout above `http.upload_timeout_secs`.

For a subpath mount, use `handle_path` — it strips the matched prefix before the proxy runs, which is what the listener's absolute routes require ([above](#public_url-is-load-bearing)):

```caddyfile
corp.example {
    request_body {
        max_size 101MiB
    }

    handle_path /registry/* {
        reverse_proxy 127.0.0.1:8080 {
            flush_interval -1
        }
    }
}
```

## Traefik

Static configuration (entry point + ACME):

```yaml
entryPoints:
  websecure:
    address: ":443"
    transport:
      respondingTimeouts:
        readTimeout: 320s   # Traefik v3 defaults this to 60 s — too short for a
                            # 100 MiB publish on a slow link (> http.upload_timeout_secs)
        idleTimeout: 180s   # comfortably above the 80 s SSE keep-alive cadence
certificatesResolvers:
  le:
    acme:
      email: ops@example.com
      storage: /letsencrypt/acme.json
      tlsChallenge: {}
```

Labels on the pub container:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.pub.rule=Host(`pub.example.com`)
  - traefik.http.routers.pub.entrypoints=websecure
  - traefik.http.routers.pub.tls.certresolver=le
  - traefik.http.services.pub.loadbalancer.server.port=8080
  # Flush responses immediately (SSE, archive streaming) instead of buffering:
  - traefik.http.services.pub.loadbalancer.responseforwarding.flushinterval=1ms
```

With `forwardedHeaders` left untrusted on the entry point (the default), Traefik discards client-supplied `X-Forwarded-For` and writes the real peer address — the required S-24.b shape; do not add `forwardedHeaders.insecure`. Traefik imposes no request-body size limit unless you add the buffering middleware, so uploads need no size configuration.

For a subpath mount, route on the prefix and strip it with the `StripPrefix` middleware — the listener's routes are absolute, so the prefix must not be forwarded ([above](#public_url-is-load-bearing)):

```yaml
labels:
  - traefik.http.routers.pub.rule=Host(`corp.example`) && PathPrefix(`/registry`)
  - traefik.http.middlewares.pub-strip.stripprefix.prefixes=/registry
  - traefik.http.routers.pub.middlewares=pub-strip
```

## After wiring it up

Set `server.public_url` to the proxied URL, set `server.trust_proxy_headers = true`, restart, and verify from outside: `curl -s https://pub.example.com/healthz` answers; the response carries `Strict-Transport-Security`; signing in and saving any setting in the web UI works (proves the Origin check agrees with `public_url`); `dart pub token add https://pub.example.com/o/<org>/pub` followed by `dart pub get` resolves and downloads (proves emitted URLs are reachable through the proxy).
