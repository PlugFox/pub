//! Fail-fast semantic validation of the merged configuration (decision 09).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::{BlobKind, ConfigError, DatabaseKind, KvKind, RunMode, Secret, Settings};

impl Settings {
    /// Validates cross-field invariants. Called by [`crate::load`] after merging all layers.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server.listen.parse::<std::net::SocketAddr>().map_err(|err| {
            invalid(format!("server.listen '{}' is not a valid socket address: {err}", self.server.listen))
        })?;
        self.validate_public_url()?;

        if self.database.kind == DatabaseKind::Postgres && self.database.url.is_none() {
            return Err(invalid("database.kind = postgres requires database.url"));
        }
        if self.database.kind == DatabaseKind::Sqlite && self.database.path.is_empty() {
            return Err(invalid("database.kind = sqlite requires a non-empty database.path"));
        }
        self.validate_database_pool()?;

        if self.blob.kind == BlobKind::S3 && self.blob.bucket.is_none() {
            return Err(invalid("blob.kind = s3 requires blob.bucket"));
        }
        if self.blob.kind == BlobKind::Fs && self.blob.path.is_empty() {
            return Err(invalid("blob.kind = fs requires a non-empty blob.path"));
        }

        if self.kv.kind == KvKind::Redis && self.kv.url.is_none() {
            return Err(invalid("kv.kind = redis requires kv.url"));
        }

        if self.cluster.replicas == 0 {
            return Err(invalid("cluster.replicas must be at least 1"));
        }
        // Decision 03: the in-memory KV cannot share revocations, locks, or invalidations
        // across instances — a Redis-compatible store + broker gates any scale-out.
        if self.cluster.replicas > 1 && self.kv.kind == KvKind::Memory {
            return Err(invalid(format!(
                "cluster.replicas = {} requires kv.kind = redis (decision 03): \
                 the in-memory KV backend is only correct for a single instance",
                self.cluster.replicas
            )));
        }

        self.validate_http()?;
        self.validate_auth()?;
        self.validate_smtp()?;
        self.validate_registry()?;
        self.validate_upstream()?;
        self.validate_jobs()?;
        self.validate_realtime()?;
        self.validate_telemetry()?;
        Ok(())
    }

    /// Observability invariants (decision 28).
    fn validate_telemetry(&self) -> Result<(), ConfigError> {
        if !self.telemetry.prometheus {
            return Ok(());
        }
        let listen = &self.telemetry.metrics_listen;
        let addr = listen.parse::<std::net::SocketAddr>().map_err(|err| {
            invalid(format!("telemetry.metrics_listen '{listen}' is not a valid socket address: {err}"))
        })?;
        // The exposition is unauthenticated by design (decision 28), so sharing the port with
        // the application would publish it on the instance's own origin — which is the exact
        // outcome the separate listener exists to prevent. Caught here rather than at bind
        // time, where the error would be a bare "address in use".
        if let Ok(app) = self.server.listen.parse::<std::net::SocketAddr>()
            && app.port() == addr.port()
        {
            return Err(invalid(format!(
                "telemetry.metrics_listen must not share a port with server.listen ({app}): \
                 the Prometheus exposition is unauthenticated and belongs on its own socket"
            )));
        }
        Ok(())
    }

    /// Connection-pool invariants: every knob is a positive quantity, and the knobs must
    /// compose into a pool that can actually serve requests.
    fn validate_database_pool(&self) -> Result<(), ConfigError> {
        let pool = &self.database.pool;
        if pool.max_connections == Some(0) {
            // A zero-connection pool would time out every single query while looking like a
            // configured limit; "use the dialect default" is expressed by leaving it unset.
            return Err(invalid(
                "database.pool.max_connections must be at least 1; leave it unset for the dialect default \
                 (5 for sqlite, 10 for postgres)",
            ));
        }
        if pool.acquire_timeout_secs == 0 {
            // Zero would fail every acquire the moment the pool is saturated instead of
            // queueing — an outage dressed as a timeout setting.
            return Err(invalid("database.pool.acquire_timeout_secs must be greater than 0"));
        }
        if pool.idle_timeout_secs == 0 || pool.max_lifetime_secs == 0 {
            // Zero would close a connection the instant it goes idle / is created, turning
            // every request into a fresh connect (and, for SQLite, a fresh page cache).
            return Err(invalid(
                "database.pool.idle_timeout_secs and database.pool.max_lifetime_secs must be greater than 0",
            ));
        }
        if pool.max_lifetime_secs < pool.idle_timeout_secs {
            return Err(invalid(format!(
                "database.pool.max_lifetime_secs ({}) must be at least database.pool.idle_timeout_secs ({}): \
                 connections are recycled at end-of-life, so a longer idle timeout could never fire",
                pool.max_lifetime_secs, pool.idle_timeout_secs
            )));
        }
        Ok(())
    }

    /// Public-URL invariants (S-12).
    ///
    /// The CORS allowlist and the S-12 mutation guard both compare against this URL's
    /// *origin*, and `url::Url::origin()` of a non-special scheme is **opaque** — it
    /// serializes to the literal `"null"`, which is exactly the `Origin` a browser sends from
    /// sandboxed iframes and `file:` pages. A mistyped scheme would therefore allow-list every
    /// sandboxed attacker page; refuse it at boot instead.
    fn validate_public_url(&self) -> Result<(), ConfigError> {
        let raw = &self.server.public_url;
        let url =
            url::Url::parse(raw).map_err(|err| invalid(format!("server.public_url is not a valid URL: {err}")))?;
        match url.scheme() {
            "http" | "https" => {}
            other => {
                return Err(invalid(format!(
                    "server.public_url scheme '{other}' must be http or https (S-12: any other scheme has an \
                     opaque origin, which serializes to the \"null\" origin sandboxed pages can claim)"
                )));
            }
        }
        if url.cannot_be_a_base() || url.host_str().is_none() {
            return Err(invalid("server.public_url must have a host"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            // A query or fragment cannot survive into the advertised bases (`PUB_HOSTED_URL`,
            // upload/finalize URLs) and would only ever be a typo.
            return Err(invalid("server.public_url must not carry a query or fragment"));
        }
        Ok(())
    }

    /// HTTP hygiene invariants (D8/D13).
    fn validate_http(&self) -> Result<(), ConfigError> {
        let http = &self.http;
        if http.request_timeout_secs == 0 || http.upload_timeout_secs == 0 {
            // Zero would cancel every request at its first await point — an outage dressed as
            // a timeout setting. "No deadline" is not something these knobs express.
            return Err(invalid("http.request_timeout_secs and http.upload_timeout_secs must be greater than 0"));
        }
        if http.upload_timeout_secs < http.request_timeout_secs {
            return Err(invalid(format!(
                "http.upload_timeout_secs ({}) must be at least http.request_timeout_secs ({}): \
                 the upload deadline is the ordinary deadline with room for a 100 MB multipart body",
                http.upload_timeout_secs, http.request_timeout_secs
            )));
        }
        if http.concurrency_limit < 16 {
            // A handful of slots turns the load shed into the outage it exists to prevent:
            // static assets, auth, and the pub protocol all ride the same semaphore.
            return Err(invalid(format!("http.concurrency_limit = {} must be at least 16", http.concurrency_limit)));
        }
        // tokio's `Semaphore::new` panics above `MAX_PERMITS` (`usize::MAX >> 3`), so a huge
        // value would pass validation and then abort the process at router construction. One
        // million in-flight response heads is already far past what a single instance can
        // serve, so the ceiling costs nobody a real configuration.
        const MAX_CONCURRENCY: usize = 1_000_000;
        if http.concurrency_limit > MAX_CONCURRENCY {
            return Err(invalid(format!(
                "http.concurrency_limit = {} must be at most {MAX_CONCURRENCY}",
                http.concurrency_limit
            )));
        }
        if http.max_body_bytes == 0 {
            // Zero would reject every request with a body while looking like a configured cap.
            return Err(invalid("http.max_body_bytes must be greater than 0"));
        }
        // Zero here would refuse every read on the instance — including the pub protocol's, so
        // `dart pub get` stops working — while reading like "no limit configured" (S-24.f).
        if http.rate_limit.read_per_ip_minute == 0 || http.rate_limit.read_per_identity_minute == 0 {
            return Err(invalid("http.rate_limit values must be at least 1 (S-24.f)"));
        }
        Ok(())
    }

    /// Realtime invariants (decision 20, S-32).
    fn validate_realtime(&self) -> Result<(), ConfigError> {
        let realtime = &self.realtime;
        if realtime.heartbeat_secs == 0 {
            return Err(invalid("realtime.heartbeat_secs must be greater than 0"));
        }
        // S-32: "streams … terminate within one access TTL of session revocation". The
        // heartbeat is where a stream re-checks revocation, so a heartbeat longer than the
        // access TTL would silently break that requirement — the config is refused rather than
        // left to be discovered by a security review.
        let access_ttl_secs = self.auth.access_ttl_minutes.saturating_mul(60);
        if realtime.heartbeat_secs >= access_ttl_secs {
            return Err(invalid(format!(
                "realtime.heartbeat_secs = {} must be below auth.access_ttl_minutes = {} ({access_ttl_secs}s): \
                 the heartbeat is where an SSE stream re-checks revocation (S-32)",
                realtime.heartbeat_secs, self.auth.access_ttl_minutes
            )));
        }
        if realtime.max_connections_per_user == 0 {
            // Zero would refuse every stream while looking like a configured limit; switching
            // the feature off is not something this knob expresses.
            return Err(invalid("realtime.max_connections_per_user must be greater than 0"));
        }
        if realtime.replay_buffer == 0 {
            return Err(invalid("realtime.replay_buffer must be greater than 0"));
        }
        // The fan-out asks the repositories for one batched preference lookup per event, and
        // those bound how many ids a single `IN (…)`/`ANY(…)` may carry. Refusing the config is
        // better than a fan-out that starts failing once an org crosses the bound.
        const MAX_RECIPIENTS: usize = 500;
        if realtime.max_notification_recipients == 0 || realtime.max_notification_recipients > MAX_RECIPIENTS {
            return Err(invalid(format!(
                "realtime.max_notification_recipients must be between 1 and {MAX_RECIPIENTS}"
            )));
        }
        Ok(())
    }

    /// Background-job invariants (decision 03 scheduler, decision 07 mirror).
    fn validate_jobs(&self) -> Result<(), ConfigError> {
        let mirror = &self.upstream.mirror;
        if mirror.mode.is_enabled() && !self.upstream.enabled {
            // A mirror worker with the proxy switched off would fetch and store packages that
            // resolution can never serve — an expensive way to do nothing, and one that looks
            // like a working mirror from the outside.
            return Err(invalid(format!(
                "upstream.mirror.mode = '{}' requires upstream.enabled = true",
                mirror.mode.as_str()
            )));
        }
        if mirror.interval_secs == 0 || mirror.refresh_after_secs == 0 || mirror.resweep_after_secs == 0 {
            return Err(invalid(
                "upstream.mirror interval_secs, refresh_after_secs, and resweep_after_secs must be greater than 0",
            ));
        }
        if mirror.chunk == 0 || mirror.concurrency == 0 {
            // Zero would be a scheduled job that can never do work: an outage that looks like
            // a configured mirror. Turning the worker off is `mode = "off"`.
            return Err(invalid("upstream.mirror.chunk and upstream.mirror.concurrency must be greater than 0"));
        }
        if mirror.archives && mirror.archive_versions == 0 {
            return Err(invalid("upstream.mirror.archive_versions must be greater than 0 when archives are mirrored"));
        }

        let gc = &self.jobs.blob_gc;
        if gc.interval_secs == 0 {
            return Err(invalid("jobs.blob_gc.interval_secs must be greater than 0"));
        }
        // A staged upload is finalizable — and therefore live — for an hour after its bytes are
        // written, with no database row referencing it. A shorter grace period would let the
        // collector delete a publish out from under the client that is retrying its finalize.
        if gc.min_age_secs < 3600 {
            return Err(invalid(format!(
                "jobs.blob_gc.min_age_secs = {} must be at least 3600: a staged upload stays finalizable \
                 for an hour with nothing referencing it",
                gc.min_age_secs
            )));
        }

        let reindex = &self.jobs.reindex;
        if reindex.interval_secs == 0 || reindex.resweep_after_secs == 0 {
            return Err(invalid("jobs.reindex.interval_secs and jobs.reindex.resweep_after_secs must be > 0"));
        }
        if reindex.chunk == 0 {
            // Zero would be a scheduled sweep that can never advance its cursor — a job that
            // looks configured and rebuilds nothing. Turning it off is `enabled = false`.
            return Err(invalid("jobs.reindex.chunk must be greater than 0"));
        }

        let downloads = &self.jobs.downloads;
        if downloads.interval_secs == 0 {
            return Err(invalid("jobs.downloads.interval_secs must be greater than 0"));
        }
        if downloads.recent_window_days <= 0 {
            return Err(invalid("jobs.downloads.recent_window_days must be greater than 0"));
        }
        if downloads.buffer_capacity == 0 {
            // The buffer is the whole write path: a zero-capacity one silently discards every
            // download instead of counting it.
            return Err(invalid("jobs.downloads.buffer_capacity must be greater than 0"));
        }

        self.validate_queue()?;
        Ok(())
    }

    /// Work-queue invariants (decision 26).
    ///
    /// There is no `enabled` to check, on purpose: sign-in mail rides this queue, so "off" is
    /// not a state this section can express. What is checked is the set of relationships that
    /// silently break delivery rather than failing loudly.
    fn validate_queue(&self) -> Result<(), ConfigError> {
        let queue = &self.jobs.queue;
        if queue.interval_secs == 0 {
            return Err(invalid("jobs.queue.interval_secs must be greater than 0"));
        }
        if queue.batch == 0 {
            // A zero batch is a drain that claims nothing: a queue that fills up while the job
            // ticks happily. Switching the drain off is not expressible here at all.
            return Err(invalid("jobs.queue.batch must be greater than 0"));
        }
        if queue.max_attempts < 1 {
            // Below one, an item is dead-lettered by the completion of its first and only
            // attempt — every transient SMTP hiccup becomes permanent.
            return Err(invalid("jobs.queue.max_attempts must be at least 1"));
        }
        if queue.backoff_base_secs == 0 || queue.backoff_max_secs < queue.backoff_base_secs {
            return Err(invalid(format!(
                "jobs.queue.backoff_max_secs = {} must be at least jobs.queue.backoff_base_secs = {} (and the base > 0)",
                queue.backoff_max_secs, queue.backoff_base_secs
            )));
        }
        if queue.concurrency == 0 {
            // Zero deliveries in flight is a drain that claims a batch and sends none of it.
            return Err(invalid("jobs.queue.concurrency must be greater than 0"));
        }
        if queue.retain_done_hours <= 0 {
            return Err(invalid("jobs.queue.retain_done_hours must be greater than 0"));
        }
        if queue.retain_suppressed_hours <= 0 {
            return Err(invalid("jobs.queue.retain_suppressed_hours must be greater than 0"));
        }
        if queue.retain_dead_days <= 0 {
            // Zero would delete a dead letter on the tick after it was written, which is the
            // one record an operator has that a message never arrived (decision 26).
            return Err(invalid("jobs.queue.retain_dead_days must be greater than 0"));
        }
        if queue.send_timeout_secs == 0 {
            // Zero would mean every delivery times out before it starts — mail would retry
            // until the attempt budget ran out and then dead-letter, with SMTP never contacted.
            return Err(invalid("jobs.queue.send_timeout_secs must be greater than 0"));
        }
        // The lease is what stops two workers from holding one item, and the drain bounds
        // itself at *half* a lease (decision 26's amendment) — so one delivery has to fit in
        // that half, not merely in the whole. Below it a pass can never lease anything it has
        // time to run, and the drain claims nothing at all: a queue that fills up while every
        // signal says the job is ticking. The interval bound is the older half of the same
        // rule: a lease that expires while the tick that took it is still running hands the
        // item to the next claim and duplicates the message already on the wire.
        if queue.lease_secs <= queue.interval_secs || queue.lease_secs < queue.send_timeout_secs.saturating_mul(2) {
            return Err(invalid(format!(
                "jobs.queue.lease_secs = {} must exceed jobs.queue.interval_secs = {} and be at least twice \
                 jobs.queue.send_timeout_secs = {}: the drain stops at half a lease, so a delivery that does not \
                 fit in that half is work the drain can never claim",
                queue.lease_secs, queue.interval_secs, queue.send_timeout_secs
            )));
        }
        Ok(())
    }

    /// Upstream proxy invariants (decision 07, S-19).
    fn validate_upstream(&self) -> Result<(), ConfigError> {
        let upstream = &self.upstream;
        // A disabled proxy still gets validated: a typo in a section nobody reads today is a
        // startup failure the day somebody flips `enabled`, which is the worst time for it.
        let base = url::Url::parse(&upstream.base_url)
            .map_err(|err| invalid(format!("upstream.base_url is not a valid URL: {err}")))?;
        match base.scheme() {
            "https" => {}
            // Plain http is a dev/test convenience (a mock upstream on localhost). In
            // production the listing carries the `archive_sha256` we verify bytes against, so
            // a plaintext listing would hand an on-path attacker the integrity check itself
            // (S-19) — the same reasoning as the OIDC issuer rule.
            "http" if self.server.mode == RunMode::Dev => {}
            other => {
                return Err(invalid(format!(
                    "upstream.base_url scheme '{other}' is not allowed (https required in production)"
                )));
            }
        }
        if base.cannot_be_a_base() || base.host_str().is_none() {
            return Err(invalid("upstream.base_url must have a host"));
        }
        if !base.username().is_empty() || base.password().is_some() {
            // Credentials belong in `upstream.auth_token`, where they are a `Secret` and stay
            // out of every log line that ever prints the base URL (S-25.a).
            return Err(invalid("upstream.base_url must not carry user-info; use upstream.auth_token"));
        }
        if base.query().is_some() || base.fragment().is_some() {
            return Err(invalid("upstream.base_url must not carry a query or fragment"));
        }
        if upstream.user_agent.trim().is_empty() {
            return Err(invalid("upstream.user_agent must not be empty"));
        }
        if upstream.connect_timeout_secs == 0
            || upstream.listing_timeout_secs == 0
            || upstream.archive_timeout_secs == 0
        {
            return Err(invalid("upstream timeouts must be greater than 0"));
        }
        if upstream.retry_backoff_ms == 0 || upstream.retry_max_backoff_ms < upstream.retry_backoff_ms {
            return Err(invalid(format!(
                "upstream.retry_max_backoff_ms ({}) must be at least upstream.retry_backoff_ms ({}), which must be > 0",
                upstream.retry_max_backoff_ms, upstream.retry_backoff_ms
            )));
        }
        if upstream.max_archive_bytes == 0 || upstream.max_listing_bytes == 0 {
            return Err(invalid("upstream.max_archive_bytes and upstream.max_listing_bytes must be greater than 0"));
        }
        if upstream.max_concurrent_fetches == 0 {
            // Zero would be "the proxy is on but may never fetch" — an outage that looks like
            // a missing package. Turning the proxy off is `enabled = false`.
            return Err(invalid("upstream.max_concurrent_fetches must be greater than 0"));
        }
        if upstream.circuit_failure_threshold == 0 || upstream.circuit_open_secs == 0 {
            return Err(invalid("upstream circuit-breaker thresholds must be greater than 0"));
        }
        Ok(())
    }

    /// Registry ingest limits (S-20) and lifecycle policy (decision 06).
    fn validate_registry(&self) -> Result<(), ConfigError> {
        let registry = &self.registry;
        if registry.max_archive_bytes == 0 {
            return Err(invalid("registry.max_archive_bytes must be greater than 0"));
        }
        if registry.max_uncompressed_bytes < registry.max_archive_bytes {
            // Anything else is unreachable-by-construction: an archive can never decompress
            // to less than its compressed size, so the publish path would reject everything.
            return Err(invalid(format!(
                "registry.max_uncompressed_bytes ({}) must not be below registry.max_archive_bytes ({})",
                registry.max_uncompressed_bytes, registry.max_archive_bytes
            )));
        }
        if registry.max_entries == 0 {
            return Err(invalid("registry.max_entries must be greater than 0"));
        }
        if registry.max_compression_ratio == 0 {
            return Err(invalid("registry.max_compression_ratio must be greater than 0"));
        }
        if registry.max_captured_file_bytes == 0 {
            return Err(invalid("registry.max_captured_file_bytes must be greater than 0"));
        }
        if registry.unretract_window_days < 0 {
            return Err(invalid("registry.unretract_window_days must not be negative"));
        }
        // Zero would be a registry nobody can publish to — a misconfiguration that looks
        // exactly like an outage from the CLI (S-24 limits throttle abuse, they never close a
        // plane); an operator who wants that revokes the tokens instead.
        if registry.rate_limit.publish_per_hour_org == 0 {
            return Err(invalid("registry.rate_limit.publish_per_hour_org must be greater than 0"));
        }
        Ok(())
    }

    /// Auth invariants (S-07/S-25 + decisions 13/17).
    fn validate_auth(&self) -> Result<(), ConfigError> {
        let auth = &self.auth;

        // S-07: the access TTL is normatively capped at 15 minutes.
        if auth.access_ttl_minutes == 0 || auth.access_ttl_minutes > 15 {
            return Err(invalid(format!(
                "auth.access_ttl_minutes = {} must be between 1 and 15 (S-07)",
                auth.access_ttl_minutes
            )));
        }
        if auth.refresh_idle_days == 0 || auth.refresh_absolute_days == 0 {
            return Err(invalid("auth.refresh_idle_days and auth.refresh_absolute_days must be at least 1"));
        }
        if auth.refresh_absolute_days < auth.refresh_idle_days {
            return Err(invalid(format!(
                "auth.refresh_absolute_days ({}) must not be below auth.refresh_idle_days ({})",
                auth.refresh_absolute_days, auth.refresh_idle_days
            )));
        }

        // Decision 13/17 format: `<prefix>_<base62×30><crc32×6>` — the prefix carries its
        // own trailing underscore and stays scanner-friendly.
        let prefix = &auth.token_prefix;
        let body_ok = prefix
            .strip_suffix('_')
            .is_some_and(|body| !body.is_empty() && body.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        if !body_ok {
            return Err(invalid(format!(
                "auth.token_prefix '{prefix}' must be lowercase alphanumerics ending in '_' (e.g. pub_)"
            )));
        }

        // S-06: the step-up window must be a sane, finite freshness horizon.
        if auth.step_up_minutes == 0 || auth.step_up_minutes > 24 * 60 {
            return Err(invalid(format!(
                "auth.step_up_minutes = {} must be between 1 and 1440 (S-06)",
                auth.step_up_minutes
            )));
        }

        // S-25: production boots refuse to run without real secrets; dev mode falls back to
        // loud ephemeral values at startup instead. Every missing key is reported in ONE
        // error, named in both spellings (config path + env var) and pointing at the fix —
        // an operator discovering them one failed boot at a time is the D5 experience this
        // message replaces.
        if self.server.mode == RunMode::Production {
            let mut missing: Vec<&str> = Vec::new();
            if auth.otp_pepper.as_ref().is_none_or(Secret::is_empty) {
                missing.push("auth.otp_pepper (PUB_AUTH__OTP_PEPPER)");
            }
            if auth.jwt.signing_key.as_ref().is_none_or(Secret::is_empty) {
                missing.push("auth.jwt.kid + auth.jwt.signing_key (PUB_AUTH__JWT__KID, PUB_AUTH__JWT__SIGNING_KEY)");
            }
            if auth.kek.as_ref().is_none_or(Secret::is_empty) {
                missing.push("auth.kek (PUB_AUTH__KEK)");
            }
            if !missing.is_empty() {
                return Err(invalid(format!(
                    "server.mode = production requires configured secret material (S-25); missing: {} — \
                     run `pubd generate-secrets` to create a ready-to-use .env/TOML fragment",
                    missing.join(", ")
                )));
            }
        }

        // Whenever a KEK is present it must be exactly 32 base64-encoded bytes (AES-256).
        if let Some(kek) = &auth.kek
            && !kek.is_empty()
        {
            match B64.decode(kek.expose()) {
                Ok(bytes) if bytes.len() == 32 => {}
                Ok(bytes) => {
                    return Err(invalid(format!("auth.kek must decode to 32 bytes, got {}", bytes.len())));
                }
                Err(_) => return Err(invalid("auth.kek is not valid base64")),
            }
        }

        self.validate_oidc()?;

        // Whenever keys are present they must be well-formed, regardless of mode.
        if auth.jwt.signing_key.is_some() && auth.jwt.kid.as_deref().is_none_or(str::is_empty) {
            return Err(invalid("auth.jwt.signing_key requires auth.jwt.kid"));
        }
        if let Some(key) = &auth.jwt.signing_key {
            validate_seed("auth.jwt.signing_key", key)?;
        }
        let mut kids: Vec<&str> = auth.jwt.kid.as_deref().into_iter().collect();
        for verify in &auth.jwt.verify_keys {
            if verify.kid.is_empty() {
                return Err(invalid("auth.jwt.verify_keys entries need a non-empty kid"));
            }
            validate_seed(&format!("auth.jwt.verify_keys[{}]", verify.kid), &verify.key)?;
            kids.push(&verify.kid);
        }
        kids.sort_unstable();
        if kids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("auth.jwt kids must be unique across signing and verify keys"));
        }

        if auth.rate_limit.otp_per_email_hour == 0
            || auth.rate_limit.otp_per_ip_hour == 0
            || auth.rate_limit.login_per_ip_minute == 0
            || auth.rate_limit.token_auth_fail_per_ip_minute == 0
        {
            return Err(invalid("auth.rate_limit values must be at least 1 (S-24)"));
        }

        // A typo in the admin bootstrap list is a silent lockout: the instance comes up with
        // nobody able to reach `/api/v1/admin/*`, and the "first account" fallback has already
        // been spent by whoever signed in first. Fail at startup instead.
        for admin in &auth.instance_admins {
            if !admin.contains('@') || admin.trim() != admin || admin.chars().any(char::is_whitespace) {
                return Err(invalid(format!("auth.instance_admins entry '{admin}' is not an email address")));
            }
        }
        Ok(())
    }

    /// OIDC provider invariants (S-01, decision 12).
    fn validate_oidc(&self) -> Result<(), ConfigError> {
        let mut ids: Vec<&str> = Vec::new();
        for provider in &self.auth.oidc {
            let id = provider.id.as_str();
            let id_ok = !id.is_empty()
                && id.len() <= 32
                && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !id_ok {
                return Err(invalid(format!(
                    "auth.oidc provider id '{id}' must be 1-32 lowercase alphanumerics or dashes"
                )));
            }
            if ids.contains(&id) {
                return Err(invalid(format!("auth.oidc provider id '{id}' is configured twice")));
            }
            ids.push(id);

            if provider.display_name.trim().is_empty() {
                return Err(invalid(format!("auth.oidc.{id}.display_name must not be empty")));
            }
            let issuer = url::Url::parse(&provider.issuer)
                .map_err(|err| invalid(format!("auth.oidc.{id}.issuer is not a valid URL: {err}")))?;
            match issuer.scheme() {
                "https" => {}
                // Plain http is a dev/test convenience (local mock issuers); production
                // token exchange carries the client secret and must ride TLS (S-01).
                "http" if self.server.mode == RunMode::Dev => {}
                other => {
                    return Err(invalid(format!(
                        "auth.oidc.{id}.issuer scheme '{other}' is not allowed (https required in production)"
                    )));
                }
            }
            if provider.issuer.contains('?') || provider.issuer.contains('#') {
                return Err(invalid(format!("auth.oidc.{id}.issuer must not carry a query or fragment")));
            }
            if provider.client_id.is_empty() {
                return Err(invalid(format!("auth.oidc.{id}.client_id must not be empty")));
            }
            if provider.client_secret.is_empty() {
                return Err(invalid(format!(
                    "auth.oidc.{id}.client_secret must not be empty (confidential client, S-01)"
                )));
            }
            for scope in &provider.scopes {
                if scope.is_empty() || scope.chars().any(char::is_whitespace) {
                    return Err(invalid(format!("auth.oidc.{id}.scopes entries must be non-empty and space-free")));
                }
            }
            if !provider.scopes.is_empty() && !provider.scopes.iter().any(|scope| scope == "openid") {
                return Err(invalid(format!("auth.oidc.{id}.scopes must include 'openid' when set explicitly")));
            }
        }
        Ok(())
    }

    /// SMTP invariants: a configured host needs a sane mailbox and port.
    fn validate_smtp(&self) -> Result<(), ConfigError> {
        if self.smtp.host.is_some() {
            if self.smtp.port == 0 {
                return Err(invalid("smtp.port must be non-zero when smtp.host is set"));
            }
            if self.smtp.from.is_empty() {
                return Err(invalid("smtp.from must be set when smtp.host is set"));
            }
            if self.smtp.username.is_some() != self.smtp.password.is_some() {
                return Err(invalid("smtp.username and smtp.password must be set together"));
            }
        }
        Ok(())
    }
}

/// Checks that a configured JWT key is base64 of exactly 32 bytes (an Ed25519 seed).
///
/// Failure messages name the *field*, never the value: a "not valid base64: <seed>" message
/// would print a signing key into the startup log (S-25).
fn validate_seed(field: &str, value: &Secret) -> Result<(), ConfigError> {
    match B64.decode(value.expose()) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        Ok(bytes) => Err(invalid(format!("{field} must decode to 32 bytes, got {}", bytes.len()))),
        Err(_) => Err(invalid(format!("{field} is not valid base64"))),
    }
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use crate::{QueueConfig, Settings};

    fn with_queue(queue: QueueConfig) -> Settings {
        let mut settings = Settings::default();
        settings.jobs.queue = queue;
        settings
    }

    #[test]
    fn the_default_queue_section_validates_and_has_no_off_switch() {
        // Decision 26: sign-in mail rides this queue, so "off" is not a state this section can
        // express. The assertion is on the *shape* — a future `enabled` field would have to
        // come with a decision, and this is where that conversation starts.
        assert!(with_queue(QueueConfig::default()).validate().is_ok());
        let rendered = format!("{:?}", QueueConfig::default());
        assert!(!rendered.contains("enabled"), "the drain must have no enabled key: {rendered}");
    }

    #[test]
    fn a_lease_that_expires_mid_delivery_is_refused() {
        // The lease is what stops two workers from holding one item; one that runs out while a
        // message is still on the wire hands that message to the next claim and sends it twice.
        let short = QueueConfig { lease_secs: 30, send_timeout_secs: 30, ..QueueConfig::default() };
        assert!(with_queue(short).validate().is_err(), "lease == send timeout must be refused");
        let ticking = QueueConfig { lease_secs: 5, interval_secs: 5, ..QueueConfig::default() };
        assert!(with_queue(ticking).validate().is_err(), "lease == interval must be refused");
    }

    #[test]
    fn a_delivery_that_does_not_fit_in_half_a_lease_is_refused() {
        // The drain stops when it has spent half its lease (decision 26's amendment), and it
        // stops by *not claiming* — so a send timeout longer than that half is a drain whose
        // every pass is allowed zero items. The queue would fill up silently while the job
        // ticked, which is precisely the class of failure this wave exists to remove.
        let starved = QueueConfig { lease_secs: 40, send_timeout_secs: 30, ..QueueConfig::default() };
        assert!(
            with_queue(starved).validate().is_err(),
            "a lease longer than one delivery but shorter than two is a drain that claims nothing"
        );
        let exact = QueueConfig { lease_secs: 60, send_timeout_secs: 30, ..QueueConfig::default() };
        assert!(with_queue(exact).validate().is_ok(), "exactly twice is exactly one delivery per pass");
    }

    #[test]
    fn nonsensical_queue_settings_are_startup_errors() {
        let cases: [(&str, QueueConfig); 9] = [
            // A drain that claims nothing is a queue that fills while the job ticks happily.
            ("batch", QueueConfig { batch: 0, ..QueueConfig::default() }),
            ("interval", QueueConfig { interval_secs: 0, ..QueueConfig::default() }),
            // Below one attempt every transient SMTP hiccup becomes a permanent dead letter.
            ("max_attempts", QueueConfig { max_attempts: 0, ..QueueConfig::default() }),
            ("backoff", QueueConfig { backoff_base_secs: 600, backoff_max_secs: 60, ..QueueConfig::default() }),
            // Zero in flight is a drain that claims a batch and sends none of it.
            ("concurrency", QueueConfig { concurrency: 0, ..QueueConfig::default() }),
            ("retention", QueueConfig { retain_done_hours: 0, ..QueueConfig::default() }),
            // Every terminal state's window is bounded and none of them is zero: a suppressed
            // row must not outlive its request forever, and a dead letter must not be deleted
            // on the tick after it was written (decision 26, the per-terminal-state retention bullet).
            ("suppressed retention", QueueConfig { retain_suppressed_hours: 0, ..QueueConfig::default() }),
            ("dead retention", QueueConfig { retain_dead_days: 0, ..QueueConfig::default() }),
            // Zero would time out every delivery before it started: SMTP never contacted, every
            // message dead-lettered after burning its whole budget.
            ("send timeout", QueueConfig { send_timeout_secs: 0, ..QueueConfig::default() }),
        ];
        for (what, queue) in cases {
            assert!(with_queue(queue).validate().is_err(), "accepted a nonsensical {what}");
        }
    }
}
