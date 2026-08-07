//! The real [`UpstreamClient`]: HTTP over `reqwest` + rustls.
//!
//! Everything policy-shaped (what to store, what to refuse, when to serve stale) lives in the
//! parent module; this file is only the transport. It nevertheless owns three security
//! properties, because they are properties of *making the request*:
//!
//! - **Fetching a URL upstream chose is a request an attacker influences.** `archive_url`
//!   comes out of upstream's own listing, and pub.dev legitimately points it at another host,
//!   so it cannot simply be pinned to the base URL. It is instead scheme-checked and refused
//!   when it names a loopback, private, link-local, or cloud-metadata address — the SSRF
//!   ruleset S-33 states for webhooks, applied to the one other place where a remote party
//!   picks our destination. Redirects are re-checked with the same rule and capped.
//! - **Bodies are bounded while they arrive.** A listing is read through a byte counter, not
//!   buffered and measured afterwards; an upstream that lies about `Content-Length` must not
//!   get to decide how much memory this process allocates.
//! - **The bearer token, if configured, is attached only to the upstream we configured.** A
//!   redirect to another host must not carry a private mirror's credential; the redirect
//!   policy refuses any cross-host hop while a token is set.

use std::net::IpAddr;
use std::time::Duration as StdDuration;

use futures::StreamExt as _;
use futures::TryStreamExt as _;

use super::{UpstreamArchive, UpstreamClient, UpstreamError, UpstreamListing, UpstreamNamePage};

/// Media type the pub protocol speaks (docs/protocol.md).
const PUB_V2_MEDIA_TYPE: &str = "application/vnd.pub.v2+json";

/// Maximum redirect hops followed on an archive download.
const MAX_REDIRECTS: usize = 5;

/// Transport settings for [`HttpUpstream`], projected from the `[upstream]` config section.
#[derive(Clone)]
pub struct HttpUpstreamConfig {
    /// Upstream base URL without a trailing slash.
    pub base_url: String,
    /// `User-Agent` header value.
    pub user_agent: String,
    /// Bearer token for authenticated upstreams (S-25 secret; never logged).
    pub auth_token: Option<String>,
    /// TCP+TLS connect timeout.
    pub connect_timeout: StdDuration,
    /// Whole-request timeout for a listing fetch.
    pub listing_timeout: StdDuration,
    /// Whole-request timeout for an archive download.
    pub archive_timeout: StdDuration,
    /// Retries after the first attempt, for transient failures only.
    pub max_retries: u32,
    /// First retry backoff; doubles up to `retry_max_backoff`.
    pub retry_backoff: StdDuration,
    /// Ceiling for the exponential retry backoff.
    pub retry_max_backoff: StdDuration,
    /// Largest listing document accepted, in bytes.
    pub max_listing_bytes: u64,
    /// Whether plain `http` upstreams are acceptable (dev mode only — the config validator
    /// refuses them in production, because the listing carries the hash we verify against).
    pub allow_plaintext: bool,
}

impl std::fmt::Debug for HttpUpstreamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUpstreamConfig")
            .field("base_url", &self.base_url)
            .field("user_agent", &self.user_agent)
            .field("auth_token", &self.auth_token.as_ref().map(|_| "<redacted>"))
            .field("connect_timeout", &self.connect_timeout)
            .field("listing_timeout", &self.listing_timeout)
            .field("archive_timeout", &self.archive_timeout)
            .field("max_retries", &self.max_retries)
            .field("max_listing_bytes", &self.max_listing_bytes)
            .field("allow_plaintext", &self.allow_plaintext)
            .finish()
    }
}

/// [`UpstreamClient`] over HTTPS.
pub struct HttpUpstream {
    client: reqwest::Client,
    config: HttpUpstreamConfig,
    base: url::Url,
}

impl std::fmt::Debug for HttpUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUpstream").field("config", &self.config).finish_non_exhaustive()
    }
}

impl HttpUpstream {
    /// Builds the client. Fails only on an unusable base URL or a broken TLS stack — both
    /// startup errors, never request-time ones.
    pub fn new(config: HttpUpstreamConfig) -> pub_core::Result<Self> {
        let base = url::Url::parse(config.base_url.trim_end_matches('/')).map_err(|err| pub_core::Error::Config {
            message: format!("upstream.base_url is not a valid URL: {err}"),
        })?;

        let allow_plaintext = config.allow_plaintext;
        let base_host = base.host_str().unwrap_or_default().to_owned();
        let pin_host = config.auth_token.as_ref().map(|_| base_host.clone());
        let redirect_host = base_host.clone();
        let redirect = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error("too many upstream redirects");
            }
            if let Err(reason) = guard_url(attempt.url(), allow_plaintext, Some(&redirect_host)) {
                return attempt.error(reason);
            }
            // With a credential configured, a cross-host hop would leak it (or, if the client
            // strips it, silently produce an unauthenticated request whose 403 looks like a
            // missing package). Refuse the hop instead of guessing.
            if let Some(host) = &pin_host
                && attempt.url().host_str() != Some(host.as_str())
            {
                return attempt.error("refusing to follow an authenticated upstream across hosts");
            }
            attempt.follow()
        });

        let client = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .connect_timeout(config.connect_timeout)
            .redirect(redirect)
            // Nothing here is a browser session; a cookie jar would only be state we do not
            // want an upstream to set on us.
            .build()
            .map_err(|err| pub_core::Error::Config {
                message: format!("failed to build the upstream http client: {err}"),
            })?;

        Ok(Self { client, config, base })
    }

    /// Applies the configured credential, when there is one.
    fn authorized(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.config.auth_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    /// Runs `attempt` with the configured retry budget and exponential backoff.
    ///
    /// Only [`UpstreamError::Unavailable`] is retried: a 404 is an answer, and a malformed or
    /// oversized document will be exactly as malformed the second time.
    async fn with_retries<T, F, Fut>(&self, what: &str, attempt: F) -> std::result::Result<T, UpstreamError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = std::result::Result<T, UpstreamError>>,
    {
        let mut backoff = self.config.retry_backoff;
        let mut last = None;
        for round in 0..=self.config.max_retries {
            match attempt().await {
                Ok(value) => return Ok(value),
                Err(UpstreamError::Unavailable { message }) => {
                    tracing::debug!(what, round, message, "upstream attempt failed; retrying");
                    last = Some(UpstreamError::Unavailable { message });
                    if round < self.config.max_retries {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(self.config.retry_max_backoff);
                    }
                }
                Err(other) => return Err(other),
            }
        }
        Err(last.unwrap_or_else(|| UpstreamError::Unavailable { message: "no attempt was made".to_owned() }))
    }
}

#[async_trait::async_trait]
impl UpstreamClient for HttpUpstream {
    fn base_url(&self) -> &str {
        self.base.as_str().trim_end_matches('/')
    }

    async fn fetch_listing(&self, name: &str) -> std::result::Result<UpstreamListing, UpstreamError> {
        // The caller has already established that this is a legal pub package name
        // (`[a-z0-9_]`), so it needs no escaping — but a name that could carry `/` or `..`
        // must never reach a URL, so the check is repeated here rather than assumed.
        crate::pubspec::validate_package_name(name)
            .map_err(|err| UpstreamError::RefusedUrl { reason: err.to_string() })?;
        let url = format!("{}/api/packages/{name}", self.base_url());

        let raw = self
            .with_retries("listing", || async {
                let response = self
                    .authorized(self.client.get(&url))
                    .header(reqwest::header::ACCEPT, PUB_V2_MEDIA_TYPE)
                    .header(reqwest::header::ACCEPT_ENCODING, "gzip")
                    .timeout(self.config.listing_timeout)
                    .send()
                    .await
                    .map_err(|err| UpstreamError::Unavailable { message: transport_reason(&err) })?;
                let response = check_status(response)?;
                read_json_body(response, self.config.max_listing_bytes).await
            })
            .await?;

        let document: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|err| UpstreamError::Malformed { message: format!("listing is not JSON: {err}") })?;
        UpstreamListing::parse(name, document)
    }

    /// `GET {base}/api/package-names` — pub.dev's enumeration convention, the mirror's
    /// full-sweep input (docs/protocol.md "Client-side facts").
    ///
    /// The `nextUrl` upstream hands back is followed only when it stays on the configured
    /// upstream host. It is a URL a remote party chose, and unlike `archive_url` — which
    /// legitimately points at a CDN and is redeemed by a hash we already hold — a name page is
    /// an *instruction about what to mirror*, verified by nothing. A cross-host hop there would
    /// let one upstream hand the sweep to another.
    ///
    /// **pub.dev answers 406 without `Accept-Encoding: gzip`** on this endpoint specifically
    /// ("Client must accept gzip content") — verified against the live service on 2026-08-07.
    /// The header is therefore mandatory here, not an optimization, which is also why gzip is
    /// decoded by hand rather than by the HTTP client: see [`read_json_body`].
    async fn fetch_package_names(&self, cursor: Option<&str>) -> std::result::Result<UpstreamNamePage, UpstreamError> {
        let url = match cursor {
            Some(next) => {
                let parsed = url::Url::parse(next)
                    .map_err(|err| UpstreamError::RefusedUrl { reason: format!("unparsable next url: {err}") })?;
                guard_url(&parsed, self.config.allow_plaintext, self.base.host_str())
                    .map_err(|reason| UpstreamError::RefusedUrl { reason: reason.to_owned() })?;
                if parsed.host_str() != self.base.host_str() {
                    return Err(UpstreamError::RefusedUrl {
                        reason: "the package-name index must not page onto another host".to_owned(),
                    });
                }
                parsed.to_string()
            }
            None => format!("{}/api/package-names", self.base_url()),
        };

        let raw = self
            .with_retries("package-names", || async {
                let response = self
                    .authorized(self.client.get(&url))
                    .header(reqwest::header::ACCEPT, PUB_V2_MEDIA_TYPE)
                    .header(reqwest::header::ACCEPT_ENCODING, "gzip")
                    .timeout(self.config.listing_timeout)
                    .send()
                    .await
                    .map_err(|err| UpstreamError::Unavailable { message: transport_reason(&err) })?;
                let response = check_status(response)?;
                // The name index is one large JSON array — pub.dev's is 86 000 names, 1.6 MB
                // decompressed — so it rides the listing cap rather than an unbounded read.
                read_json_body(response, self.config.max_listing_bytes).await
            })
            .await?;

        let document: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|err| UpstreamError::Malformed { message: format!("package-names is not JSON: {err}") })?;
        parse_name_page(&document)
    }

    async fn fetch_archive(&self, url: &str) -> std::result::Result<UpstreamArchive, UpstreamError> {
        let parsed = url::Url::parse(url)
            .map_err(|err| UpstreamError::RefusedUrl { reason: format!("unparsable url: {err}") })?;
        guard_url(&parsed, self.config.allow_plaintext, self.base.host_str())
            .map_err(|reason| UpstreamError::RefusedUrl { reason: reason.to_owned() })?;

        // Retries cover establishing the response only; once bytes are flowing a failure is
        // surfaced to the caller, which refuses the archive rather than splicing two partial
        // downloads into something whose hash nobody has ever seen.
        let response = self
            .with_retries("archive", || async {
                let request = if Some(parsed.host_str().unwrap_or_default()) == self.base.host_str() {
                    // Same host as the configured upstream: the credential belongs here.
                    self.authorized(self.client.get(parsed.clone()))
                } else {
                    self.client.get(parsed.clone())
                };
                let response = request
                    .timeout(self.config.archive_timeout)
                    .send()
                    .await
                    .map_err(|err| UpstreamError::Unavailable { message: transport_reason(&err) })?;
                check_status(response)
            })
            .await?;

        let content_length = response.content_length();
        let body = response
            .bytes_stream()
            .map_err(|err| UpstreamError::Unavailable { message: transport_reason(&err) })
            .boxed();
        Ok(UpstreamArchive { content_length, body })
    }
}

/// Parses `{"packages": [...], "nextUrl": "…"|null}`.
///
/// Names that are not legal pub package names are dropped rather than failing the page: the
/// index is upstream's, one unusable entry in 60 000 must not stop a mirror, and every name is
/// re-validated before it reaches a URL or a database key anyway.
fn parse_name_page(document: &serde_json::Value) -> std::result::Result<UpstreamNamePage, UpstreamError> {
    let packages = document
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| UpstreamError::Malformed { message: "package-names has no packages array".to_owned() })?;
    let mut names = Vec::with_capacity(packages.len());
    let mut dropped = 0usize;
    for entry in packages {
        match entry.as_str() {
            Some(name) if crate::pubspec::validate_package_name(name).is_ok() => names.push(name.to_owned()),
            _ => dropped += 1,
        }
    }
    if dropped > 0 {
        tracing::warn!(dropped, kept = names.len(), "upstream package-name index carried unusable names");
    }
    Ok(UpstreamNamePage { names, next: document.get("nextUrl").and_then(serde_json::Value::as_str).map(str::to_owned) })
}

/// Maps a response status onto the error taxonomy.
fn check_status(response: reqwest::Response) -> std::result::Result<reqwest::Response, UpstreamError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Err(UpstreamError::NotFound);
    }
    // 408/429 and every 5xx are the transient family — the same set the pub client itself
    // retries (docs/protocol.md sharp edge 2). Everything else is permanent for this request.
    if status.is_server_error()
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        return Err(UpstreamError::Unavailable { message: format!("upstream answered {status}") });
    }
    Err(UpstreamError::Malformed { message: format!("upstream answered {status}") })
}

/// Reads a JSON response body, decoding `Content-Encoding: gzip` **by hand**.
///
/// The HTTP client is deliberately built *without* transparent content decoding, and that is a
/// byte-stability decision rather than a dependency one: a client that silently decodes response
/// bodies would also decode an archive body, and the archive path's whole contract is that the
/// bytes we hash and store are the bytes that arrived (docs/protocol.md sharp edge 3, S-19). So
/// content coding is negotiated on the two JSON endpoints only — where it is *required* by
/// pub.dev on `/api/package-names` — and archives are transferred with no coding at all.
///
/// The cap applies to the **decoded** document as well as to the wire bytes: otherwise a few
/// compressed kilobytes would decide how much memory this process allocates, which is the same
/// amplification the archive limits close one layer down (S-20.a).
async fn read_json_body(response: reqwest::Response, limit: u64) -> std::result::Result<Vec<u8>, UpstreamError> {
    let gzipped = response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|coding| coding.trim().eq_ignore_ascii_case("gzip")));
    let raw = read_capped(response, limit).await?;
    if !gzipped {
        return Ok(raw);
    }
    decode_gzip(&raw, limit)
}

/// Inflates a gzip body with the decoded size capped (see [`read_json_body`]).
fn decode_gzip(raw: &[u8], limit: u64) -> std::result::Result<Vec<u8>, UpstreamError> {
    use std::io::Read as _;

    let mut out = Vec::new();
    // Multi-member, because a proxy or CDN may re-chunk a gzip stream; `+ 1` so an output that
    // exactly fills the limit is still distinguishable from one that overruns it.
    let mut reader = flate2::read::MultiGzDecoder::new(raw).take(limit.saturating_add(1));
    reader
        .read_to_end(&mut out)
        .map_err(|err| UpstreamError::Malformed { message: format!("gzip body could not be decoded: {err}") })?;
    if out.len() as u64 > limit {
        return Err(UpstreamError::TooLarge { limit });
    }
    Ok(out)
}

/// Reads a response body with the cap enforced while it arrives.
async fn read_capped(response: reqwest::Response, limit: u64) -> std::result::Result<Vec<u8>, UpstreamError> {
    if response.content_length().is_some_and(|len| len > limit) {
        return Err(UpstreamError::TooLarge { limit });
    }
    let mut stream = response.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| UpstreamError::Unavailable { message: transport_reason(&err) })?;
        if buf.len() as u64 + chunk.len() as u64 > limit {
            return Err(UpstreamError::TooLarge { limit });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// A transport failure description that carries no response body.
///
/// `reqwest`'s `Display` includes the URL and the source error but never the payload, which is
/// what matters here: an upstream body is attacker-influenced text and must not be pasted into
/// our logs (the same rule the OIDC token exchange follows — S-01.a).
fn transport_reason(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        return "request timed out".to_owned();
    }
    if err.is_connect() {
        return "connection failed".to_owned();
    }
    err.to_string()
}

/// The SSRF ruleset for a URL a remote party chose (S-33's rules, applied to proxy fetches).
///
/// Deliberately *not* a same-host pin: pub.dev serves archives from a storage CDN, so pinning
/// would break the default upstream. The rule is instead about **who chose the destination**:
///
/// - The host the operator configured as `upstream.base_url` is trusted as configured, private
///   address or not. A corporate mirror on `https://packages.corp.internal` is a legitimate
///   deployment, and so is a mock upstream on `http://127.0.0.1:PORT` in dev.
/// - Any *other* host — a host upstream picked for us, whether in `archive_url` or a redirect —
///   must be public: loopback, private, link-local (which covers `169.254.169.254`),
///   unique-local, and unspecified addresses are refused, as are non-HTTP schemes, embedded
///   credentials, and the special-use *names* that are reserved for exactly those destinations
///   ([`is_special_use_name`]).
///
/// Address literals are covered whatever notation they arrive in: the `url` crate applies
/// WHATWG host parsing, so `https://2130706433/`, `https://0x7f000001/`, and `https://127.1/`
/// all normalize to `127.0.0.1` before this function sees them (pinned by
/// [`tests::ssrf_guard_sees_through_numeric_host_notations`]).
///
/// Its remaining limit is honest and recorded (S-19.a in docs/security.md): an
/// *ordinary* hostname that resolves to a private address still passes, because the check
/// happens before DNS. Closing that needs resolve-then-connect control, which is a separate
/// piece of work; the layer that actually protects the registry is the sha256 verification,
/// which no redirect can forge.
fn guard_url(url: &url::Url, allow_plaintext: bool, base_host: Option<&str>) -> std::result::Result<(), &'static str> {
    match url.scheme() {
        "https" => {}
        "http" if allow_plaintext => {}
        _ => return Err("only https upstream urls are fetched"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("upstream urls must not carry user-info");
    }
    let Some(host) = url.host() else {
        return Err("upstream url has no host");
    };
    if base_host.is_some_and(|base| url.host_str() == Some(base)) {
        // The operator picked this host; the address-range rules exist to constrain hosts
        // *upstream* picks.
        return Ok(());
    }
    let ip = match host {
        url::Host::Ipv4(addr) => Some(IpAddr::V4(addr)),
        url::Host::Ipv6(addr) => Some(IpAddr::V6(addr)),
        // A DNS name is checked by name only; see the doc comment for what that does not cover.
        url::Host::Domain(name) => {
            if is_special_use_name(name) {
                return Err("upstream url points at a special-use hostname");
            }
            None
        }
    };
    if let Some(ip) = ip
        && !is_public_ip(ip)
    {
        return Err("upstream url points at a non-public address");
    }
    Ok(())
}

/// Whether a hostname is reserved, by standard or by cloud convention, for a destination the
/// address rules already refuse.
///
/// The IP-literal rules block `127.0.0.1` and `169.254.169.254`; without this, the *names* for
/// the same destinations — `localhost`, `metadata.google.internal` — walked straight past them,
/// because the guard runs before DNS. These names can never legitimately appear in an
/// `archive_url` or a redirect chosen by a **public** registry, and the host the operator
/// configured is exempt before this is reached, so a corporate mirror at
/// `https://packages.corp.internal` keeps working.
///
/// Sources: RFC 6761 (`localhost`), RFC 6762 (`.local`, mDNS), RFC 8375 (`home.arpa`), and
/// ICANN's 2024 delegation of `.internal` for private use — which is where GCP's metadata
/// server lives, alongside its `metadata.goog` alias.
fn is_special_use_name(name: &str) -> bool {
    // A fully-qualified name may carry a root dot; comparison is ASCII-case-insensitive
    // because DNS names are.
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    const RESERVED_SUFFIXES: [&str; 4] = [".localhost", ".local", ".internal", ".home.arpa"];
    const RESERVED_NAMES: [&str; 4] = ["localhost", "local", "internal", "home.arpa"];

    RESERVED_NAMES.contains(&name.as_str())
        || name == "metadata.goog"
        || name.ends_with(".metadata.goog")
        || RESERVED_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// Whether an IP literal is one we are willing to fetch from.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                // 100.64.0.0/10 carrier-grade NAT, where cloud metadata proxies also live.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 0.0.0.0/8 "this network".
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique-local and fe80::/10 link-local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped addresses inherit the IPv4 rules.
                || v6.to_ipv4_mapped().is_some_and(|v4| !is_public_ip(IpAddr::V4(v4))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(raw: &str) -> std::result::Result<(), &'static str> {
        guard_url(&url::Url::parse(raw).expect("test url"), false, Some("pub.dev"))
    }

    #[test]
    fn ssrf_guard_refuses_internal_destinations() {
        // The cloud-metadata endpoint is the reason this check exists at all.
        assert!(guard("https://169.254.169.254/latest/meta-data/").is_err());
        assert!(guard("https://127.0.0.1/x.tar.gz").is_err());
        assert!(guard("https://10.0.0.5/x.tar.gz").is_err());
        assert!(guard("https://192.168.1.1/x.tar.gz").is_err());
        assert!(guard("https://172.16.0.1/x.tar.gz").is_err());
        assert!(guard("https://100.100.0.1/x.tar.gz").is_err());
        assert!(guard("https://[::1]/x.tar.gz").is_err());
        assert!(guard("https://[fd00::1]/x.tar.gz").is_err());
        assert!(guard("https://[fe80::1]/x.tar.gz").is_err());
        assert!(guard("https://[::ffff:127.0.0.1]/x.tar.gz").is_err());
    }

    #[test]
    fn the_configured_upstream_host_is_trusted_as_configured() {
        // A corporate mirror on a private address is a legitimate deployment; the address
        // rules exist to constrain hosts *upstream* picks, not the one the operator did.
        guard_url(&url::Url::parse("https://10.1.2.3/api/packages/http").unwrap(), false, Some("10.1.2.3"))
            .expect("the configured host");
        // …but only that exact host.
        assert!(guard_url(&url::Url::parse("https://10.1.2.4/x.tar.gz").unwrap(), false, Some("10.1.2.3")).is_err());
    }

    #[test]
    fn ssrf_guard_refuses_special_use_hostnames() {
        // The IP rules block 127.0.0.1 and 169.254.169.254; these are the *names* for the same
        // destinations, and the guard runs before DNS, so blocking the addresses alone left the
        // names as a way through. A public registry can never legitimately point here.
        for raw in [
            "https://localhost/x.tar.gz",
            "https://LOCALHOST./x.tar.gz",
            "https://cache.localhost/x.tar.gz",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://metadata.goog/x",
            "https://packages.corp.internal/x.tar.gz",
            "https://printer.local/x.tar.gz",
            "https://router.home.arpa/x.tar.gz",
        ] {
            assert!(guard(raw).is_err(), "accepted a special-use hostname: {raw}");
        }
        // Ordinary names that merely *contain* a reserved label are not reserved.
        guard("https://localhost.example.com/x.tar.gz").expect("a public name with a scary label");
        guard("https://internal-cdn.example.com/x.tar.gz").expect("a public name with a scary prefix");
        // …and the host the operator configured is still exempt, private TLD and all: that is
        // what makes a corporate mirror a supported deployment.
        guard_url(
            &url::Url::parse("https://packages.corp.internal/api/packages/http").unwrap(),
            false,
            Some("packages.corp.internal"),
        )
        .expect("the configured mirror");
    }

    #[test]
    fn ssrf_guard_sees_through_numeric_host_notations() {
        // WHATWG host parsing (which the `url` crate implements) normalizes every integer form
        // of an IPv4 address, so the address rules cannot be dodged by writing 127.0.0.1
        // differently. Pinned because it is a property of a dependency, not of this file.
        for raw in [
            "https://2130706433/x.tar.gz",
            "https://0x7f000001/x.tar.gz",
            "https://017700000001/x.tar.gz",
            "https://127.1/x.tar.gz",
            "https://[::ffff:169.254.169.254]/x",
        ] {
            assert!(guard(raw).is_err(), "accepted an obfuscated loopback/metadata address: {raw}");
        }
    }

    #[test]
    fn ssrf_guard_allows_the_real_upstream() {
        guard("https://storage.googleapis.com/pub-packages/http-1.2.0.tar.gz").expect("public cdn host");
        guard("https://pub.dev/api/archives/http-1.2.0.tar.gz").expect("public upstream host");
        guard("https://8.8.8.8/x.tar.gz").expect("a public ip literal is fine");
    }

    #[test]
    fn ssrf_guard_refuses_other_schemes_and_credentials() {
        assert!(guard("file:///etc/passwd").is_err());
        assert!(guard("ftp://pub.dev/x.tar.gz").is_err());
        assert!(guard("http://pub.dev/x.tar.gz").is_err(), "plaintext is dev-only");
        assert!(guard("https://user:pass@pub.dev/x.tar.gz").is_err());
        // Dev mode does allow plaintext — that is how a mock upstream on localhost is reached,
        // and localhost is then the *configured* host, not one upstream picked for us.
        guard_url(&url::Url::parse("http://127.0.0.1:9999/x.tar.gz").unwrap(), true, Some("127.0.0.1"))
            .expect("dev plaintext against the configured host");
    }

    #[test]
    fn status_mapping_separates_transient_from_permanent() {
        // Only the transient family may be retried or count against the circuit breaker.
        for status in [500u16, 502, 503, 504, 408, 429] {
            let response = http_response(status);
            assert!(
                matches!(check_status(response).unwrap_err(), UpstreamError::Unavailable { .. }),
                "{status} must be transient"
            );
        }
        assert_eq!(check_status(http_response(404)).unwrap_err(), UpstreamError::NotFound);
        assert_eq!(check_status(http_response(410)).unwrap_err(), UpstreamError::NotFound);
        for status in [400u16, 401, 403, 451] {
            assert!(
                matches!(check_status(http_response(status)).unwrap_err(), UpstreamError::Malformed { .. }),
                "{status} must be permanent"
            );
        }
        assert!(check_status(http_response(200)).is_ok());
    }

    fn http_response(status: u16) -> reqwest::Response {
        reqwest::Response::from(
            http::Response::builder().status(status).body(Vec::<u8>::new()).expect("build response"),
        )
    }

    #[test]
    fn the_name_index_drops_unusable_names_but_keeps_the_page() {
        // One bad entry in 60 000 must not stop a mirror; every kept name is re-validated
        // before it reaches a URL or a database key anyway.
        let page = parse_name_page(&serde_json::json!({
            "packages": ["http", "Bad-Name", "../etc/passwd", 42, "path"],
            "nextUrl": "https://pub.dev/api/package-names?page=2",
        }))
        .expect("page");
        assert_eq!(page.names, ["http", "path"]);
        assert_eq!(page.next.as_deref(), Some("https://pub.dev/api/package-names?page=2"));

        let last = parse_name_page(&serde_json::json!({ "packages": [] })).expect("last page");
        assert!(last.names.is_empty());
        assert_eq!(last.next, None);
        assert!(parse_name_page(&serde_json::json!({ "oops": true })).is_err());
    }

    #[test]
    fn gzip_json_bodies_are_decoded_with_the_cap_applied_to_the_decoded_size() {
        use std::io::Write as _;

        fn gzip(bytes: &[u8]) -> Vec<u8> {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(bytes).expect("gzip");
            encoder.finish().expect("finish")
        }

        let document = br#"{"packages":["http","path"]}"#;
        assert_eq!(decode_gzip(&gzip(document), 1024).unwrap(), document);

        // A few compressed kilobytes must not decide how much memory this process allocates:
        // the limit is on the *decoded* size, not on the wire bytes.
        let bomb = gzip(&vec![b'a'; 1024 * 1024]);
        assert!(bomb.len() < 8192, "the fixture has to be small on the wire to be a bomb");
        assert!(matches!(decode_gzip(&bomb, 4096).unwrap_err(), UpstreamError::TooLarge { .. }));
        // Exactly at the limit is fine; one byte over is not.
        assert_eq!(decode_gzip(&gzip(&vec![b'a'; 4096]), 4096).unwrap().len(), 4096);
        assert!(decode_gzip(&gzip(&vec![b'a'; 4097]), 4096).is_err());

        // Garbage that claims to be gzip is a permanent rejection, not a panic.
        assert!(matches!(decode_gzip(b"not gzip at all", 1024).unwrap_err(), UpstreamError::Malformed { .. }));
    }

    #[test]
    fn the_client_builds_from_config() {
        let client = HttpUpstream::new(HttpUpstreamConfig {
            base_url: "https://pub.dev/".to_owned(),
            user_agent: "pub-tests/1.0".to_owned(),
            auth_token: None,
            connect_timeout: StdDuration::from_secs(5),
            listing_timeout: StdDuration::from_secs(10),
            archive_timeout: StdDuration::from_secs(60),
            max_retries: 1,
            retry_backoff: StdDuration::from_millis(10),
            retry_max_backoff: StdDuration::from_millis(100),
            max_listing_bytes: 1024,
            allow_plaintext: false,
        })
        .expect("build client");
        // The trailing slash is trimmed so cached rows carry one canonical upstream string.
        assert_eq!(client.base_url(), "https://pub.dev");
    }

    #[test]
    fn a_configured_token_never_reaches_a_debug_line() {
        let config = HttpUpstreamConfig {
            base_url: "https://mirror.corp.test".to_owned(),
            user_agent: "pub".to_owned(),
            auth_token: Some("s3cret-mirror-token".to_owned()),
            connect_timeout: StdDuration::from_secs(1),
            listing_timeout: StdDuration::from_secs(1),
            archive_timeout: StdDuration::from_secs(1),
            max_retries: 0,
            retry_backoff: StdDuration::from_millis(1),
            retry_max_backoff: StdDuration::from_millis(1),
            max_listing_bytes: 1,
            allow_plaintext: false,
        };
        assert!(!format!("{config:?}").contains("s3cret-mirror-token"));
        assert!(!format!("{:?}", HttpUpstream::new(config).unwrap()).contains("s3cret-mirror-token"));
    }
}
