//! The two-replica acceptance harness — a client for a deployment, not for a router
//! ([decision 38](../../../docs/decisions.md#38--two-replicas-behind-one-proxy-an-acceptance-stand-that-fails-closed-four-claims-proven-at-the-wire-and-a-measurement-that-is-a-number)).
//!
//! Everything else in this workspace tests the application by calling it. This crate tests a
//! *deployment* by dialling it: two containers on one set of backends, an nginx in front, and a
//! mail sink where "exactly once" is finally observable to a human rather than to a counter.
//!
//! Three things shape the whole file:
//!
//! - **Two addressing modes, deliberately.** [`Cluster::proxy`] is the front door and answers
//!   what only the front door can — that it is not sticky, that `public_url` survives the hop.
//!   [`Cluster::replicas`] are the instances themselves, and every claim that *names* one is
//!   written against them: "A revoked it, B refuses it" is not a sentence a balancer can be
//!   asked to confirm.
//! - **Nothing here reaches inside the application.** No repository handles, no in-process
//!   mailer, no clock to advance. The observables are HTTP status codes, response bodies, the
//!   SSE stream, and the mail sink's API — the same four an operator has.
//! - **Waiting is explicit and bounded.** A cluster is asynchronous in ways a single process is
//!   not: a job tick, a broker hop, a lease expiry. Every wait in this crate has a deadline and
//!   fails with what it was waiting for, because a test that hangs teaches nothing.

use std::time::{Duration, Instant};

use futures::StreamExt as _;
pub use pub_test_support::{CLUSTER, Gate, cluster_mail_url, cluster_replicas};
use serde_json::{Value, json};

/// The `Accept` header the real `dart pub` client sends.
pub const PUB_ACCEPT: &str = "application/vnd.pub.v2+json";

/// The header every state-changing app-API request must carry (S-12).
pub const CUSTOM_HEADER: &str = "x-pub-request";

/// One HTTP answer, flattened to the three things a claim is ever written against.
#[derive(Debug)]
pub struct Res {
    /// HTTP status.
    pub status: u16,
    /// Parsed body, or `Value::Null` when the body was empty or not JSON.
    pub json: Value,
    /// Response headers — the stand reads `X-Upstream` out of these.
    pub headers: reqwest::header::HeaderMap,
}

impl Res {
    /// The value of a header, if present and printable.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|value| value.to_str().ok()).map(ToOwned::to_owned)
    }

    /// `data` out of the success envelope.
    #[must_use]
    pub fn data(&self) -> &Value {
        &self.json["data"]
    }
}

/// One running stand: the proxy, the replicas behind it, and the mail sink beside it.
pub struct Cluster {
    /// The front door — what a client is configured with.
    pub proxy: String,
    /// The replicas' own addresses, in the order the stand publishes them.
    pub replicas: Vec<String>,
    /// Mailpit's API base.
    pub mail: String,
    /// The address this handle presents as. Both replicas run with
    /// `server.trust_proxy_headers = true` (S-24.b), so a direct-dialled request is taken at
    /// its word — which is what lets each test spend its own per-IP budget instead of sharing
    /// one with every other test in the run, and what makes a second run inside the hour safe.
    /// Through the proxy this is overwritten by nginx, as it must be.
    client_ip: String,
    client: reqwest::Client,
}

impl Cluster {
    /// Gates on `PUB_TEST_CLUSTER_URL`, per [decision 35](../../../docs/decisions.md#35--backend-legs-that-fail-when-the-backend-is-absent-and-a-harness-that-admits-a-race).
    ///
    /// # Panics
    ///
    /// When neither `PUB_TEST_CLUSTER_URL` nor `PUB_TEST_NO_CLUSTER` is set, and when fewer
    /// than two replica addresses are configured — a "two replicas" claim written against one
    /// address is not a weaker test, it is a different one.
    #[must_use]
    pub fn gate(test: &str) -> Option<Self> {
        let proxy = match CLUSTER.gate(test) {
            Gate::Run(url) => url.trim_end_matches('/').to_owned(),
            Gate::Skipped => return None,
        };
        let replicas = cluster_replicas();
        assert!(
            replicas.len() >= 2,
            "{test} needs at least two replica addresses; $PUB_TEST_CLUSTER_REPLICAS holds {replicas:?}"
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            // Redirects are answers here: the pub protocol's finalize hop and the archive
            // download both use them, and a claim about which URL was handed back must not be
            // resolved silently by the client under test.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build the acceptance client");
        Some(Self { proxy, replicas, mail: cluster_mail_url(), client_ip: "198.51.100.1".to_owned(), client })
    }

    /// The same stand, addressed as a different client.
    ///
    /// Tests take one each: the per-IP buckets are real (`otp_per_ip_hour` is 20), and a run
    /// that shared one address would start failing on its second pass within the hour for a
    /// reason that has nothing to do with what it asserts.
    #[must_use]
    pub fn as_client(&self, ip: &str) -> Self {
        Self {
            proxy: self.proxy.clone(),
            replicas: self.replicas.clone(),
            mail: self.mail.clone(),
            client_ip: ip.to_owned(),
            client: self.client.clone(),
        }
    }

    /// The first replica's own address.
    #[must_use]
    pub fn a(&self) -> &str {
        &self.replicas[0]
    }

    /// The second replica's own address.
    #[must_use]
    pub fn b(&self) -> &str {
        &self.replicas[1]
    }

    // --- app API ------------------------------------------------------------------------

    /// `GET` on the app API.
    pub async fn get(&self, base: &str, path: &str, token: Option<&str>) -> Res {
        self.send(self.client.get(format!("{base}{path}")), token, false).await
    }

    /// `POST` on the app API, with the S-12 header a mutation needs.
    pub async fn post(&self, base: &str, path: &str, token: Option<&str>, body: Value) -> Res {
        self.send(self.client.post(format!("{base}{path}")).json(&body), token, true).await
    }

    /// `DELETE` on the app API.
    pub async fn delete(&self, base: &str, path: &str, token: Option<&str>) -> Res {
        self.send(self.client.delete(format!("{base}{path}")), token, true).await
    }

    /// A request shaped like the pub client's: bearer, the protocol `Accept`, and none of the
    /// app-API headers — the CLI cannot send those.
    pub async fn pub_get(&self, url: &str, token: Option<&str>) -> Res {
        let mut request =
            self.client.get(url).header(reqwest::header::ACCEPT, PUB_ACCEPT).header("x-forwarded-for", &self.client_ip);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        Self::finish(request).await
    }

    async fn send(&self, mut request: reqwest::RequestBuilder, token: Option<&str>, mutating: bool) -> Res {
        request = request.header("x-forwarded-for", &self.client_ip);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if mutating {
            request = request.header(CUSTOM_HEADER, "1");
        }
        Self::finish(request).await
    }

    async fn finish(request: reqwest::RequestBuilder) -> Res {
        let response = request.send().await.expect("the stand must answer");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.bytes().await.expect("read the body");
        let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
        Res { status, json, headers }
    }

    // --- sign-in, orgs, tokens ----------------------------------------------------------

    /// Full OTP sign-in against one instance, reading the code out of the mail sink the way a
    /// user reads their inbox. Returns the login payload.
    pub async fn login(&self, base: &str, email: &str) -> Value {
        let requested = self.post(base, "/api/v1/auth/otp/request", None, json!({ "email": email })).await;
        assert_eq!(requested.status, 200, "otp request failed: {:?}", requested.json);
        let pending_id = requested.data()["pending_id"].as_str().expect("pending_id").to_owned();

        // The mail travels through the durable queue and is delivered by whichever instance's
        // drain claims it, so the code is not there the instant the request returns.
        let code = self.await_code(email, Duration::from_secs(30)).await;
        let verified = self
            .post(
                base,
                "/api/v1/auth/otp/verify",
                None,
                json!({ "pending_id": pending_id, "email": email, "code": code }),
            )
            .await;
        assert_eq!(verified.status, 200, "otp verify failed: {:?}", verified.json);
        verified.data().clone()
    }

    /// Rotates a refresh token into a fresh access token.
    ///
    /// Needed by anything that reads the **stream**: the SSE audience filter authorizes against
    /// `claims.orgs`, which is a snapshot taken when the access token was minted. An owner who
    /// creates an org and keeps using the token they signed in with therefore carries no
    /// membership for it until the pair rotates — the request routes read the same claims, so
    /// this is not specific to the stream, but the stream is where it is visible as silence
    /// rather than as a 403.
    pub async fn refresh(&self, base: &str, refresh_token: &str) -> Value {
        let rotated = self.post(base, "/api/v1/auth/refresh", None, json!({ "refresh_token": refresh_token })).await;
        assert_eq!(rotated.status, 200, "refresh failed: {:?}", rotated.json);
        rotated.data().clone()
    }

    /// Signs `email` in through `base`, creates org `slug`, and returns `(access_token, org_id)`.
    pub async fn org_owner(&self, base: &str, email: &str, slug: &str) -> (String, String) {
        let login = self.login(base, email).await;
        let access = login["access_token"].as_str().expect("access token").to_owned();
        let created = self.post(base, "/api/v1/orgs", Some(&access), json!({ "name": slug, "slug": slug })).await;
        assert_eq!(created.status, 200, "org creation failed: {:?}", created.json);
        let org = created.data()["id"].as_str().expect("org id").to_owned();

        // The access token above was minted before this org existed, so its `orgs` claim is
        // empty — and every authorization in the instance, the stream's audience filter
        // included, reads that claim rather than the database. Rotating here is what makes the
        // returned token mean "owner of this org" instead of "a signed-in user".
        let refresh_token = login["refresh_token"].as_str().expect("refresh token");
        let rotated = self.refresh(base, refresh_token).await;
        let access = rotated["access_token"].as_str().expect("rotated access token").to_owned();
        (access, org)
    }

    /// Mints an ordinary CLI token through the real app API.
    pub async fn mint_token(&self, base: &str, access: &str, org: &str, scopes: &[&str]) -> String {
        let body = json!({
            "org_id": org,
            "scopes": scopes,
            "label": "acceptance",
            "expires_days": 90,
        });
        let response = self.post(base, "/api/v1/tokens", Some(access), body).await;
        assert_eq!(response.status, 200, "token mint failed: {:?}", response.json);
        response.data()["secret"].as_str().expect("secret").to_owned()
    }

    // --- pub protocol -------------------------------------------------------------------

    /// The three-step publish, through whichever base is given. Returns the finalize answer.
    ///
    /// The upload and finalize URLs come from the server rather than being constructed here:
    /// they are built from `server.public_url`, and following them is how a `dart pub` client
    /// behaves — which is also what makes a wrong `public_url` visible instead of papered over.
    pub async fn publish(&self, base: &str, org: &str, token: &str, name: &str, version: &str) -> Res {
        let ticket = self.pub_get(&format!("{base}/o/{org}/pub/api/packages/versions/new"), Some(token)).await;
        assert_eq!(ticket.status, 200, "publish step 1 failed: {:?}", ticket.json);
        let upload_url = ticket.json["url"].as_str().expect("upload url").to_owned();
        let fields = ticket.json["fields"].clone();

        let mut form = reqwest::multipart::Form::new();
        if let Some(map) = fields.as_object() {
            for (key, value) in map {
                form = form.text(key.clone(), value.as_str().unwrap_or_default().to_owned());
            }
        }
        form = form.part(
            "file",
            reqwest::multipart::Part::bytes(package_archive(name, version))
                .file_name(format!("{name}-{version}.tar.gz"))
                .mime_str("application/octet-stream")
                .expect("mime"),
        );
        let uploaded = self
            .client
            .post(&upload_url)
            .bearer_auth(token)
            .header("x-forwarded-for", &self.client_ip)
            .header(reqwest::header::ACCEPT, PUB_ACCEPT)
            .multipart(form)
            .send()
            .await
            .expect("upload");
        let status = uploaded.status().as_u16();
        let location = uploaded
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        assert_eq!(status, 204, "publish step 2 must answer 204, got {status}");
        let finalize = location.expect("step 2 must hand back a finalize location");
        self.pub_get(&finalize, Some(token)).await
    }

    // --- the mail sink ------------------------------------------------------------------

    /// Every message currently addressed to `email`, newest first.
    pub async fn mail_for(&self, email: &str) -> Vec<Value> {
        let response = self
            .client
            .get(format!("{}/api/v1/messages?limit=500", self.mail))
            .send()
            .await
            .expect("mailpit must answer");
        let body: Value = response.json().await.expect("mailpit json");
        body["messages"]
            .as_array()
            .map(|messages| {
                messages
                    .iter()
                    .filter(|message| {
                        message["To"]
                            .as_array()
                            .is_some_and(|to| to.iter().any(|recipient| recipient["Address"].as_str() == Some(email)))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The plain-text body of one message.
    pub async fn mail_text(&self, id: &str) -> String {
        let response =
            self.client.get(format!("{}/api/v1/message/{id}", self.mail)).send().await.expect("mailpit message");
        let body: Value = response.json().await.expect("mailpit json");
        body["Text"].as_str().unwrap_or_default().to_owned()
    }

    /// Waits for a sign-in code addressed to `email` and returns it.
    ///
    /// # Panics
    ///
    /// On the deadline, naming the address — a missing code here is the queue not draining,
    /// which is a finding rather than a flake.
    pub async fn await_code(&self, email: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            for message in self.mail_for(email).await {
                let id = message["ID"].as_str().unwrap_or_default();
                if let Some(code) = extract_code(&self.mail_text(id).await) {
                    return code;
                }
            }
            assert!(Instant::now() < deadline, "no sign-in code reached {email} within {within:?}");
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }

    /// Waits until `email` has at least `count` messages, then returns how many it has.
    ///
    /// Returns as soon as the target is reached and **keeps watching for a further grace
    /// period** — the point of an exactly-once claim is the message that arrives late, so a
    /// check that stopped at the first sighting could never see a duplicate.
    pub async fn await_mail_count(&self, email: &str, count: usize, within: Duration, grace: Duration) -> usize {
        let deadline = Instant::now() + within;
        loop {
            let seen = self.mail_for(email).await.len();
            if seen >= count {
                tokio::time::sleep(grace).await;
                return self.mail_for(email).await.len();
            }
            assert!(Instant::now() < deadline, "only {seen} of {count} messages reached {email} within {within:?}");
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }

    // --- the event stream ---------------------------------------------------------------

    /// Opens the SSE stream on `base` and returns the first event whose `type` matches, or
    /// `None` on the deadline.
    ///
    /// The stream is opened *before* the caller causes the event, which is the only ordering
    /// that tests delivery rather than replay.
    pub async fn await_event(&self, base: &str, token: &str, kind: &str, within: Duration) -> Option<Value> {
        let response = self
            .client
            .get(format!("{base}/api/v1/events"))
            .bearer_auth(token)
            .header("x-forwarded-for", &self.client_ip)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .timeout(within + Duration::from_secs(5))
            .send()
            .await
            .expect("open the stream");
        assert_eq!(response.status().as_u16(), 200, "the stream must open");

        let deadline = Instant::now() + within;
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(Some(chunk)) = tokio::time::timeout(remaining, stream.next()).await else { break };
            let chunk = chunk.expect("stream chunk");
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            // SSE frames are separated by a blank line; a `data:` line carries our JSON.
            while let Some(split) = buffer.find("\n\n") {
                let frame = buffer[..split].to_owned();
                buffer.drain(..split + 2);
                for line in frame.lines() {
                    let Some(payload) = line.strip_prefix("data:") else { continue };
                    let Ok(event) = serde_json::from_str::<Value>(payload.trim()) else { continue };
                    if event["type"].as_str() == Some(kind) {
                        return Some(event);
                    }
                }
            }
        }
        None
    }

    /// Which upstream the proxy used, per the stand's own `X-Upstream` header.
    pub async fn upstream_of(&self, path: &str) -> Option<String> {
        self.get(&self.proxy, path, None).await.header("x-upstream")
    }
}

/// A name no earlier run of this stand has taken.
///
/// The stand's Postgres and its blob store survive `docker compose down` without `-v`, which is
/// deliberate — an acceptance run that needed a fresh database would be testing installation
/// rather than operation. So org slugs, package names and email addresses are minted per run.
///
/// # Panics
///
/// If the system clock is before the Unix epoch.
#[must_use]
pub fn unique(prefix: &str) -> String {
    // The clock alone is not enough, and this was found the hard way: four names minted in one
    // tight loop came back **identical**, because the system clock's granularity is coarser than
    // the loop. The load driver then published one package three times and read the per-name
    // publish lock's `busy` as a defect in the lock. The counter makes uniqueness a property of
    // the process rather than of the platform's clock resolution.
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock at or after the epoch")
        .as_nanos();
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{prefix}{nanos:x}{sequence:x}")
}

/// The 8-digit sign-in code in a mail body, if there is one.
#[must_use]
pub fn extract_code(text: &str) -> Option<String> {
    text.split(|c: char| !c.is_ascii_digit()).find(|run| run.len() == 8).map(ToOwned::to_owned)
}

/// A minimal but real `.tar.gz` package archive — the same shape the wire tests build.
#[must_use]
pub fn package_archive(name: &str, version: &str) -> Vec<u8> {
    use std::io::Write as _;

    let pubspec = format!("name: {name}\nversion: {version}\ndescription: Acceptance fixture.\n");
    let readme = format!("# {name}\n\nAcceptance fixture.\n");
    let mut builder = tar::Builder::new(Vec::new());
    let mut append = |path: &str, content: &str| {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content.as_bytes()).expect("tar entry");
    };
    append("pubspec.yaml", &pubspec);
    append("README.md", &readme);
    let tar = builder.into_inner().expect("tar");

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar).expect("gzip");
    encoder.finish().expect("gzip finish")
}
