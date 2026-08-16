//! Hosted Pub Repository Spec v2 — the wire surface (`docs/protocol.md`).
//!
//! Every response shape here is the spec's, verbatim: no envelope, no renames, no extra
//! required fields. The three behaviours that break clients if we get them wrong:
//!
//! 1. **`archive_url` always points at us, under this request's base.** Never at an upstream
//!    CDN (sharp edge 3) and never at a bare host: a URL outside the base would fall outside
//!    the client's credential prefix and private downloads would arrive unauthenticated
//!    (sharp edge 4).
//! 2. **The archive bytes are the uploaded bytes.** We store what was uploaded and stream it
//!    back; `archive_sha256` is computed once, at publish, and pinned in users' `pubspec.lock`
//!    forever (sharp edge 3).
//! 3. **All publish validation happens at finalize** (sharp edge 5). Step 1 has no package
//!    name to check, step 2 is a byte sink; step 3 answers `200 {"success":…}` or
//!    `400 {"error":…}` and nothing in between.
//!
//! Proxied packages (decision 07) go out through the *same* shapes: a listing fetched from
//! upstream is re-emitted with upstream's flags, hashes, and pubspecs verbatim and with
//! `archive_url` rewritten under this request's base, and its archive is served from our own
//! blob store. A client cannot tell a proxied package from a local one, which is the point —
//! `PUB_HOSTED_URL` replaces pub.dev rather than sitting beside it (sharp edge 12).

use std::collections::BTreeMap;
use std::time::Duration as StdDuration;

use axum::body::Body;
use axum::extract::multipart::{MultipartError, MultipartRejection};
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use pub_core::audit::{AuditActor, AuditResult, NewAuditEvent};
use pub_core::authorize::{Action, Resource, authorize};
use pub_core::package::{Package, Resolution, Version, Visibility};
use pub_core::token::TokenScope;
use pub_core::traits::{ByteStream, DownloadMethod, DownloadPlan};
use pub_core::{Format, OrgId, PackageId, SemVer, TokenId, UserId};
use pub_registry::{ActorMeta, PublishRequest, RegistryService, latest_index, validate_package_name};
use serde::{Deserialize, Serialize};
use tower_http::compression::CompressionLayer;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::RequestMeta;
use crate::protocol::ApiVersion;
use crate::protocol::base::{Base, PathParams};
use crate::protocol::error::{PUB_V2_MEDIA_TYPE, ProtocolError, SpecError};
use crate::protocol::tokens::{Principal, TokenContext};
use crate::state::AppState;

/// The format this module speaks.
const FORMAT: Format = Format::Pub;

/// Upload endpoint, relative to the base (returned by step 1, so it must stay under `B`).
const UPLOAD_PATH: &str = "/api/packages/versions/newUpload";

/// Finalize endpoint prefix, relative to the base.
const FINALIZE_PATH: &str = "/api/packages/versions/newUploadFinish";

/// How long a staged upload stays finalizable. Generous next to the client's retry budget
/// (7 attempts with backoff), short enough that abandoned uploads do not accumulate.
const UPLOAD_TTL: StdDuration = StdDuration::from_secs(60 * 60);

/// Slack over `registry.max_archive_bytes` for the multipart envelope (boundaries, headers,
/// the extra fields a POST-policy sink would carry).
const MULTIPART_OVERHEAD: usize = 64 * 1024;

/// Page size used to walk a package's versions.
const VERSION_PAGE: u32 = 200;

/// Ceiling on how many versions one listing **carries**. Real packages are far below this; the
/// cap exists so a pathological package cannot turn the hot path into an OOM.
///
/// Deliberately not the same number as, and not the same question as,
/// [`pub_registry::index::LATEST_WINDOW`]: this one bounds how much of a package's history goes
/// on the wire, that one bounds how many of the newest versions the `latest` rule is evaluated
/// over. Conflating the two is what let three surfaces disagree (decision 32, D50).
///
/// Public only so the conformance suite can build a package that actually *reaches* it — a test
/// asserting which end truncates on a package below the cap would assert nothing.
pub const MAX_LISTED_VERSIONS: usize = 10_000;

// ------------------------------------------------------------------------------- wire shapes

/// A package's version listing — the response of `GET B/api/packages/{name}`.
///
/// Field types are enforced client-side (docs/protocol.md sharp edge 10) and unknown fields
/// are ignored, so this struct may grow but may never change a type or drop a field.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageListing {
    /// Package name.
    pub name: String,
    /// The version a fresh `pub add` should pick.
    pub latest: VersionInfo,
    /// Every non-tombstoned version, ascending by semver precedence.
    pub versions: Vec<VersionInfo>,
    /// Package-level discontinued flag (sharp edge 9).
    #[serde(rename = "isDiscontinued")]
    pub is_discontinued: bool,
    /// Suggested replacement; only meaningful while discontinued, so it is omitted otherwise.
    #[serde(rename = "replacedBy", skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
}

/// One version inside a listing (and the whole body of the legacy per-version endpoint).
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VersionInfo {
    /// The version number.
    pub version: String,
    /// Retracted versions are excluded from new resolutions but stay downloadable
    /// (sharp edge 9). Always emitted: the client reads it as a bool.
    pub retracted: bool,
    /// Absolute URL of the archive **on this host, under this base** (sharp edges 3 and 4).
    pub archive_url: String,
    /// Lowercase hex SHA-256 of the archive, exactly 64 characters (sharp edge 10).
    pub archive_sha256: String,
    /// The version's full pubspec document (sharp edge 7).
    #[schema(value_type = Object)]
    pub pubspec: serde_json::Value,
}

/// Response of publish step 1.
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadTicket {
    /// Where to POST the multipart upload — under the base, so the client keeps sending auth.
    pub url: String,
    /// Extra multipart fields to send before the file. Empty for our own sink; an S3
    /// POST-policy sink would fill it.
    pub fields: BTreeMap<String, String>,
}

/// Response of publish step 3 on success — the spec's `{"success":{"message":…}}`.
#[derive(Debug, Serialize, ToSchema)]
pub struct PublishSuccess {
    /// The success detail object.
    pub success: SuccessMessage,
}

/// Contents of [`PublishSuccess::success`].
#[derive(Debug, Serialize, ToSchema)]
pub struct SuccessMessage {
    /// Text the CLI prints on a successful publish.
    pub message: String,
}

/// Server-side record of a staged upload, held in KV while the archive sits in blob storage.
///
/// It binds the upload to the credential that created it: finalize is a plain `GET` on a URL
/// the client got over the wire, so without this binding a leaked finalize URL would let a
/// different token publish someone else's bytes under its own provenance (S-21).
///
/// `user_id` and `size` are written but not read by finalize (the token binding is the
/// stricter check): they are forensic fields. In particular the S-20.b storage quota does
/// **not** read `size` — staged bytes are not counted against the quota at all (a quota that
/// flapped with in-flight publishes would refuse the retry of the upload that caused it), and
/// the bound on the staging area is the refusal in [`guard_staged_bytes`] plus the sweep. That
/// "not counted at all" is a contract rather than an observation, so it is asserted rather than
/// asserted-about: `api/tests/pub_attack.rs::s20_b_a_staged_upload_adds_nothing_to_the_org_byte_total`
/// stages an upload, reads `org_storage_bytes`, and only then finalizes — an implementation that
/// folded the staging area into the sum would refuse the retry of the very upload that filled
/// it. The abandoned-upload sweep does not read these fields either — it collects staged bytes
/// by age alone and never consults this record, deliberately
/// ([decision 31](../../../../../docs/decisions.md), `pub_jobs::staging`).
#[derive(Debug, Serialize, Deserialize)]
struct UploadSession {
    token_id: TokenId,
    user_id: UserId,
    org_id: OrgId,
    size: u64,
    created_at: DateTime<Utc>,
}

/// JSON response carrying the pub v2 media type.
pub struct PubJson<T>(pub T);

impl<T: Serialize> IntoResponse for PubJson<T> {
    fn into_response(self) -> Response {
        let mut response = axum::Json(self.0).into_response();
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(PUB_V2_MEDIA_TYPE));
        response
    }
}

// ------------------------------------------------------------------------------------ router

/// The pub v2 route set, relative to a virtual base.
///
/// Three groups, because they need different middleware:
///
/// - **JSON endpoints** get gzip. Sharp edge 7 puts the version listing on the hot path *and*
///   caps it: the client re-fetches it before every resolve and refuses to disk-cache it past
///   ~1 MB, and a listing carries a whole pubspec per version. Compression is the difference
///   between a cached listing and a re-download on every command for a package with history.
/// - **Archive downloads** get none: the payload is already gzip, so re-compressing would burn
///   CPU for nothing and drop the `Content-Length` a downloader wants.
/// - **The upload** gets its own body limit. Axum's global default is 2 MB, which would reject
///   every real package; the limit here is the configured archive cap plus the multipart
///   envelope — a memory bound, not the S-20 size check, which is re-applied at finalize where
///   a rejection can carry a spec-shaped explanation.
pub fn router(state: &AppState) -> OpenApiRouter<AppState> {
    let body_limit = state.settings.registry.max_archive_bytes as usize + MULTIPART_OVERHEAD;
    let json = OpenApiRouter::new()
        .routes(routes!(version_listing))
        .routes(routes!(publish_start))
        .routes(routes!(publish_finalize))
        .routes(routes!(legacy_version))
        .layer(CompressionLayer::new());
    let archives = OpenApiRouter::new().routes(routes!(archive)).routes(routes!(legacy_archive));
    let upload = OpenApiRouter::new().routes(routes!(publish_upload)).layer(DefaultBodyLimit::max(body_limit));
    json.merge(archives)
        .merge(upload)
        // Anything else under a registry base is a registry 404, not the SPA shell: a client
        // asking for an endpoint we do not implement — `…/advisories`, a future spec addition —
        // must get parseable JSON, not an HTML page it will choke on.
        .fallback(unimplemented_endpoint)
        .layer(axum::middleware::from_fn(spec_shape_bare_statuses))
}

/// Fallback for unrouted paths under a registry base.
async fn unimplemented_endpoint() -> ProtocolError {
    ProtocolError::not_found("this registry endpoint")
}

/// Gives the router's own bodyless rejections the spec error shape.
///
/// A known path with an unsupported method is answered by axum's method router *before* any
/// handler runs, as a bare 405 with no body and no content type. Under a registry base that is
/// the same defect the [`unimplemented_endpoint`] fallback exists to prevent: the pub client
/// parses the body of every failure, and unparseable bytes turn a clear "wrong method" into a
/// decoding error. The status stays 405 — permanent, so the client will not retry it.
async fn spec_shape_bare_statuses(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let method = request.method().clone();
    let response = next.run(request).await;
    if response.status() == StatusCode::METHOD_NOT_ALLOWED && !response.headers().contains_key(header::CONTENT_TYPE) {
        return ProtocolError::method_not_allowed(format!("{method} is not supported on this registry endpoint"))
            .into_response();
    }
    response
}

// ---------------------------------------------------------------------------------- handlers

/// Version listing — the endpoint the client re-fetches before every resolve and download.
#[utoipa::path(
    get,
    path = "/api/packages/{name}",
    tag = "pub",
    params(("name" = String, Path, description = "Package name")),
    responses(
        (status = OK, description = "Version listing", content_type = "application/vnd.pub.v2+json", body = PackageListing),
        (status = UNAUTHORIZED, description = "Credentials required or rejected; carries WWW-Authenticate", body = SpecError),
        (status = NOT_FOUND, description = "Unknown name, or one this principal may not read (S-04)", body = SpecError),
        (status = NOT_ACCEPTABLE, description = "Unsupported pub API version", body = SpecError),
    )
)]
pub async fn version_listing(
    State(state): State<AppState>,
    _version: ApiVersion,
    principal: Principal,
    base: Base,
    params: PathParams,
) -> Result<PubJson<PackageListing>, ProtocolError> {
    let name = params.require("name")?;
    match resolve_target(&state, &base, &principal, name).await? {
        Target::Local(package) => {
            let versions = load_versions(&state, package.id).await?;
            if versions.is_empty() {
                // A claim or package row with nothing published (or everything hard-deleted)
                // is not resolvable; a listing with an empty `versions` array would make the
                // client fail with a confusing "no versions available" instead of "no such
                // package".
                return Err(ProtocolError::not_found(format!("package {name}")));
            }
            Ok(PubJson(build_listing(&base, &package, &versions)))
        }
        Target::Upstream(upstream) => {
            let listing = upstream
                .listing(FORMAT, name, (state.clock)())
                .await?
                .ok_or_else(|| ProtocolError::not_found(format!("package {}", clip(name))))?;
            Ok(PubJson(build_proxied_listing(&base, &listing)))
        }
    }
}

/// Publish step 1 — authorize "may publish *something*", hand back the upload URL.
///
/// This request carries no package name (docs/protocol.md endpoint 2), so name claims,
/// package patterns, and duplicate checks are impossible here and belong to finalize. What
/// *is* checked is everything name-independent: a token, the `publish` scope, the org binding,
/// and the Write role.
#[utoipa::path(
    get,
    path = "/api/packages/versions/new",
    tag = "pub",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "Upload ticket", content_type = "application/vnd.pub.v2+json", body = UploadTicket),
        (status = UNAUTHORIZED, description = "No usable token; carries WWW-Authenticate", body = SpecError),
        (status = FORBIDDEN, description = "Token lacks publish scope, org binding, or Write role", body = SpecError),
    )
)]
pub async fn publish_start(
    State(_state): State<AppState>,
    _version: ApiVersion,
    principal: Principal,
    base: Base,
) -> Result<PubJson<UploadTicket>, ProtocolError> {
    publisher(&principal, &base)?;
    Ok(PubJson(UploadTicket { url: base.absolute(UPLOAD_PATH), fields: BTreeMap::new() }))
}

/// Publish step 2 — the byte sink: store the archive, answer `204` + `Location`.
///
/// Deliberately dumb (docs/protocol.md sharp edge 5). The only checks are the ones a dumb sink
/// still needs: a credential, so the endpoint is not an open blob writer, and the body limit.
/// The client sends no `Accept` here, so no version negotiation runs either.
#[utoipa::path(
    post,
    path = "/api/packages/versions/newUpload",
    tag = "pub",
    security(("bearer_auth" = [])),
    request_body(content = String, description = "multipart/form-data with the archive in field `file`", content_type = "multipart/form-data"),
    responses(
        (status = NO_CONTENT, description = "Stored; `Location` points at the finalize URL"),
        (status = BAD_REQUEST, description = "Not a readable multipart body, no `file` field, or no room under the org's storage quota (S-20.b)", body = SpecError),
        (status = UNAUTHORIZED, description = "No usable token; carries WWW-Authenticate", body = SpecError),
        (status = FORBIDDEN, description = "Token lacks publish scope, org binding, or Write role", body = SpecError),
        (status = TOO_MANY_REQUESTS, description = "The org's S-24 publish budget is spent; carries Retry-After", body = SpecError),
    )
)]
pub async fn publish_upload(
    State(state): State<AppState>,
    principal: Principal,
    base: Base,
    RequestMeta(meta): RequestMeta,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ProtocolError> {
    let ctx = publisher(&principal, &base)?;
    let org = base.org.as_ref().expect("publisher() rejects the public root");
    charge_publish_budget(&state, ctx, org, &meta).await?;
    let archive = read_archive(multipart).await?;
    guard_staged_bytes(&state, org, archive.len()).await?;

    let session = new_session_id();
    // Bytes first, record second: a record pointing at absent bytes would fail finalize with
    // a 500, while an orphan blob is only garbage.
    state.blob.put(&staging_key(&session), archive.clone()).await?;
    let record = UploadSession {
        token_id: ctx.token.id,
        user_id: ctx.token.user_id,
        org_id: org.id,
        size: archive.len() as u64,
        created_at: (state.clock)(),
    };
    let json = serde_json::to_string(&record)
        .map_err(|err| pub_core::Error::Internal { message: format!("upload session serialization failed: {err}") })?;
    state.kv.set_ttl(&session_key(&session), &json, UPLOAD_TTL).await?;

    let location = base.absolute(&format!("{FINALIZE_PATH}/{session}"));
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location)
            .map_err(|_| pub_core::Error::Config { message: "server.public_url is not header-safe".into() })?,
    );
    Ok(response)
}

/// Publish step 3 — run the whole pipeline and answer `200 {"success":…}` or `400 {"error":…}`.
#[utoipa::path(
    get,
    path = "/api/packages/versions/newUploadFinish/{session}",
    tag = "pub",
    security(("bearer_auth" = [])),
    params(("session" = String, Path, description = "Upload session id from the Location header")),
    responses(
        (status = OK, description = "Published", content_type = "application/vnd.pub.v2+json", body = PublishSuccess),
        (status = BAD_REQUEST, description = "Any permanent rejection: bad archive, bad pubspec, duplicate version, expired session, storage quota exceeded (S-20.b)", body = SpecError),
        (status = UNAUTHORIZED, description = "No usable token; carries WWW-Authenticate", body = SpecError),
        (status = FORBIDDEN, description = "Wrong credential for this upload, missing scope/role, or a name owned elsewhere", body = SpecError),
    )
)]
pub async fn publish_finalize(
    State(state): State<AppState>,
    _version: ApiVersion,
    principal: Principal,
    base: Base,
    params: PathParams,
    RequestMeta(meta): RequestMeta,
) -> Result<PubJson<PublishSuccess>, ProtocolError> {
    let ctx = publisher(&principal, &base)?;
    let org = base.org.as_ref().expect("publisher() rejects the public root");
    let session = params.require("session")?;

    let raw = state
        .kv
        .get(&session_key(session))
        .await?
        .ok_or_else(|| ProtocolError::invalid("this upload has expired or was already finalized; publish again"))?;
    let record: UploadSession =
        serde_json::from_str(&raw).map_err(|_| ProtocolError::invalid("this upload is unusable; publish again"))?;
    // The finalize URL travels over the wire; the credential that created the upload is what
    // makes it single-owner (S-21 provenance is only meaningful if it cannot be borrowed).
    if record.token_id != ctx.token.id || record.org_id != org.id {
        return Err(ProtocolError::forbidden("this upload was created with a different credential"));
    }

    // A record whose bytes are gone (a sweeper ran, storage was restored from a snapshot) is a
    // dead upload, not a server fault — and the message must not echo the internal blob key.
    let archive = state.blob.get(&staging_key(session)).await.map_err(|err| match err {
        pub_core::Error::NotFound { .. } => {
            ProtocolError::invalid("the uploaded archive is no longer available; publish again")
        }
        other => ProtocolError::from_domain(other),
    })?;
    let now = (state.clock)();
    let request = PublishRequest {
        format: FORMAT,
        org_id: org.id,
        // Least privilege: a package created by a publish starts private, and the org decides
        // to publish it to the instance later.
        visibility: Visibility::Private,
        actor: ActorMeta {
            user_id: ctx.token.user_id,
            token_id: Some(ctx.token.id),
            ip: meta.ip.clone(),
            user_agent: meta.user_agent.clone(),
        },
        archive,
        expected_name: None,
        package_patterns: ctx.token.package_patterns.clone(),
        // S-20.b. Resolved here, not inside the service: the rule's two inputs are the org row
        // this request already loaded to route itself and the *runtime* instance setting, and
        // `RegistryService` deliberately holds a policy frozen at boot (decision 09 puts runtime
        // settings behind a cache the API layer reads per request). An operator who raises the
        // instance quota therefore affects the very next publish, not the next restart.
        storage_quota_bytes: effective_quota(&state, org),
    };

    match state.registry.publish(request, now).await {
        Ok(outcome) => {
            discard_upload(&state, session).await;
            Ok(PubJson(PublishSuccess {
                success: SuccessMessage {
                    message: format!(
                        "Successfully uploaded {} {} to {}.",
                        outcome.package.name,
                        outcome.version.version,
                        base.url()
                    ),
                },
            }))
        }
        Err(err) => {
            // The held per-name publish lock is the one *client-error* a retry can heal: the
            // holder may be this very client's timed-out first attempt, and the client retries
            // this exact URL — burning the staged bytes here would turn every timeout-and-retry
            // into "publish again from scratch". Checked structurally, never on message text.
            let held_lock = matches!(err, pub_core::Error::Busy { .. });
            let err = ProtocolError::from_domain(err);
            // A permanent rejection burns the upload — retrying the same bytes cannot help,
            // and leaving them around is a free 100 MB per doomed publish. A transient one
            // (database down, blob store unreachable, the lock above) leaves the session
            // finalizable, because the client *will* retry this exact URL up to seven times.
            if err.status().is_client_error() && !held_lock {
                discard_upload(&state, session).await;
            }
            Err(err)
        }
    }
}

/// Archive download — a redirect to a presigned URL where the backend can sign, the bytes
/// themselves otherwise (decision 10).
///
/// Retracted versions are served: lockfile-pinned builds must keep working (sharp edge 9).
/// Tombstoned ones are not: their bytes are gone (decision 06).
#[utoipa::path(
    get,
    path = "/api/archives/{file}",
    tag = "pub",
    params(("file" = String, Path, description = "`{name}-{version}.tar.gz`")),
    responses(
        (status = OK, description = "The archive, byte-identical to the upload", content_type = "application/octet-stream"),
        (status = TEMPORARY_REDIRECT, description = "Presigned URL for backends that sign"),
        (status = UNAUTHORIZED, description = "Credentials required or rejected; carries WWW-Authenticate", body = SpecError),
        (status = NOT_FOUND, description = "Unknown, unreadable, or hard-deleted", body = SpecError),
    )
)]
pub async fn archive(
    State(state): State<AppState>,
    method: Method,
    principal: Principal,
    base: Base,
    params: PathParams,
) -> Result<Response, ProtocolError> {
    let file = params.require("file")?;
    let (name, version) = parse_archive_file(file)?;
    serve_archive(&state, &method, &base, &principal, &name, &version).await
}

/// Legacy per-version metadata (pre-Dart-2.8 clients) — docs/protocol.md endpoint 6.
#[utoipa::path(
    get,
    path = "/api/packages/{name}/versions/{version}",
    tag = "pub",
    params(
        ("name" = String, Path, description = "Package name"),
        ("version" = String, Path, description = "Exact version"),
    ),
    responses(
        (status = OK, description = "One version", content_type = "application/vnd.pub.v2+json", body = VersionInfo),
        (status = NOT_FOUND, description = "Unknown, unreadable, or hard-deleted", body = SpecError),
    )
)]
pub async fn legacy_version(
    State(state): State<AppState>,
    _version: ApiVersion,
    principal: Principal,
    base: Base,
    params: PathParams,
) -> Result<PubJson<VersionInfo>, ProtocolError> {
    let name = params.require("name")?.to_owned();
    let requested = SemVer::parse(params.require("version")?)
        .map_err(|_| ProtocolError::not_found(format!("version of package {}", clip(&name))))?;
    match resolve_target(&state, &base, &principal, &name).await? {
        Target::Local(package) => {
            let version = live_version(&state, package.id, &requested).await?;
            Ok(PubJson(build_version(&base, &package.name, &version)))
        }
        Target::Upstream(upstream) => {
            let listing = upstream
                .listing(FORMAT, &name, (state.clock)())
                .await?
                .ok_or_else(|| ProtocolError::not_found(format!("package {}", clip(&name))))?;
            let found = listing
                .versions
                .iter()
                .find(|candidate| candidate.version == requested)
                .ok_or_else(|| ProtocolError::not_found(format!("version {requested}")))?;
            Ok(PubJson(build_proxied_version(&base, &listing.name, found)))
        }
    }
}

/// Legacy archive download (docs/protocol.md endpoint 7). Same bytes as [`archive`].
#[utoipa::path(
    get,
    path = "/packages/{name}/versions/{file}",
    tag = "pub",
    params(
        ("name" = String, Path, description = "Package name"),
        ("file" = String, Path, description = "`{version}.tar.gz`"),
    ),
    responses(
        (status = OK, description = "The archive, byte-identical to the upload", content_type = "application/octet-stream"),
        (status = TEMPORARY_REDIRECT, description = "Presigned URL for backends that sign"),
        (status = NOT_FOUND, description = "Unknown, unreadable, or hard-deleted", body = SpecError),
    )
)]
pub async fn legacy_archive(
    State(state): State<AppState>,
    method: Method,
    principal: Principal,
    base: Base,
    params: PathParams,
) -> Result<Response, ProtocolError> {
    let name = params.require("name")?.to_owned();
    let file = params.require("file")?;
    let raw = file
        .strip_suffix(".tar.gz")
        .ok_or_else(|| ProtocolError::not_found(format!("archive {} of package {}", clip(file), clip(&name))))?;
    let version = SemVer::parse(raw)
        .map_err(|_| ProtocolError::not_found(format!("version {} of package {}", clip(raw), clip(&name))))?;
    serve_archive(&state, &method, &base, &principal, &name, &version).await
}

// ----------------------------------------------------------------------------------- helpers

/// What a package name resolves to inside this base.
enum Target<'a> {
    /// A locally claimed package this principal may read (decision 01 steps 1 and 2).
    Local(Package),
    /// The name is claimed nowhere on this instance and this base may consult the proxy
    /// (decision 01 step 3). Carries the service so the caller cannot reach it any other way.
    Upstream(&'a pub_registry::UpstreamService),
}

/// Resolves a package name **through the base's resolution order** and nothing else.
///
/// Handlers never touch `get_by_name` directly: decision 01's ordering (org-owned →
/// instance-public → upstream-iff-unclaimed) lives in
/// [`pub_core::traits::PackageRepo::resolve_in_base`], so "local always wins" cannot be
/// bypassed by a handler that forgets a step. Everything unreadable — restricted, unclaimed
/// with no usable proxy, or syntactically impossible — collapses into the same 404 (S-04).
///
/// This is also the **only** place the proxy can be entered (S-16). Two facts make that
/// structural rather than conventional:
///
/// - [`Resolution::Unclaimed`] is produced on exactly one path inside `resolve_in_base` —
///   after `lookup_claim` came back empty — so a locally claimed name can never reach here as
///   a proxy candidate, whatever a caller does with the result.
/// - The [`Target::Upstream`] arm *carries* the service. A handler that wanted to proxy a
///   local name would have to obtain an `UpstreamService` reference some other way, and there
///   is no other way inside this module.
async fn resolve_target<'a>(
    state: &'a AppState,
    base: &Base,
    principal: &Principal,
    name: &str,
) -> Result<Target<'a>, ProtocolError> {
    let unknown = || ProtocolError::not_found(format!("package {}", clip(name)));
    // A name that could never be claimed cannot exist. Answering 400 would also make the
    // endpoint a name-syntax oracle with a different status than a real miss.
    if validate_package_name(name).is_err() {
        return Err(unknown());
    }
    let resolution = state.repos.packages.resolve_in_base(FORMAT, name, base.scope(), principal.actor()).await?;
    match principal.narrow(resolution) {
        Resolution::Readable(package) => Ok(Target::Local(package)),
        // Claimed here but not readable from this base — never a proxy candidate (S-16).
        Resolution::Restricted { .. } => Err(unknown()),
        Resolution::Unclaimed => upstream_for(state, base).map(Target::Upstream).ok_or_else(unknown),
        _ => Err(unknown()),
    }
}

/// The proxy service, if this base may use it (decision 01 per-org policy, S-16).
///
/// Two gates, and they are different things: `[upstream].enabled` is the instance operator's
/// switch (absent service = no proxying anywhere), while `orgs.upstream_policy` is the org's
/// own. A blocked org's registry serves exactly its own and the instance's public packages,
/// and an unclaimed name there answers the same 404 an unknown one does — a distinguishable
/// "blocked" status would tell a caller that the name exists upstream (S-04).
///
/// The public root has no org and therefore no org policy; it follows the instance switch.
///
/// The instance switch has **two halves** since the admin surface landed: the boot config
/// decides whether a proxy service exists at all (`None` = no upstream branch in the process,
/// which is what an air-gapped deployment buys), and the runtime setting decides whether the
/// existing one may be used. An operator stopping egress during an incident should not need a
/// restart, and a restart should not be what re-enables it.
fn upstream_for<'a>(state: &'a AppState, base: &Base) -> Option<&'a pub_registry::UpstreamService> {
    if !state.runtime.current().upstream.enabled {
        return None;
    }
    let allowed = match &base.org {
        Some(org) => org.upstream_policy.allows_upstream(),
        None => true,
    };
    if allowed { state.upstream.as_deref() } else { None }
}

/// Reads a package's live versions and returns them **ascending** by semver precedence, which
/// is the order the spec's listing is emitted in.
///
/// The read itself is **descending**, and reversed at the end, so the
/// [`MAX_LISTED_VERSIONS`] cap drops the *oldest* versions rather than the newest ones. That
/// end is the one a resolver can afford to lose: a client resolves against recent releases, and
/// a listing missing its newest entries makes the package look frozen at whatever the cap
/// happened to reach — while `latest` gets derived from a release nobody is installing. An
/// ascending read is how it worked before decision 32, and the failure was silent above 10 000
/// live versions, which an internal registry publishing per CI merge reaches.
///
/// Below the cap the two reads are the same set, and `list_versions_desc` is contract-tested as
/// the exact reverse of `list_versions`, so nothing observable changes for a normal package.
async fn load_versions(state: &AppState, package: PackageId) -> Result<Vec<Version>, ProtocolError> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = state.repos.packages.list_versions_desc(package, cursor.as_deref(), VERSION_PAGE).await?;
        all.extend(page.items);
        match page.cursor {
            Some(next) if all.len() < MAX_LISTED_VERSIONS => cursor = Some(next),
            Some(_) => {
                tracing::warn!(
                    %package,
                    listed = all.len(),
                    "version listing truncated at the safety cap; the oldest versions were dropped"
                );
                break;
            }
            None => break,
        }
    }
    all.reverse();
    Ok(all)
}

/// One version by exact number, tombstones excluded.
async fn live_version(state: &AppState, package: PackageId, version: &SemVer) -> Result<Version, ProtocolError> {
    state
        .repos
        .packages
        .get_version(package, version)
        .await?
        .filter(|found| !found.tombstone)
        .ok_or_else(|| ProtocolError::not_found(format!("version {version}")))
}

/// Resolve → look up → plan the download. Shared by the current and legacy archive routes so
/// the two can never diverge on visibility or on which bytes they serve.
///
/// Proxied archives take the same last step as local ones: the blob key is derived from the
/// content hash, so "serve the bytes for this sha256" is the *only* thing this function can
/// express. That is what makes S-19's serve-time re-verification structural — a wrong archive
/// would have to be stored under a key that is not its own hash.
async fn serve_archive(
    state: &AppState,
    method: &Method,
    base: &Base,
    principal: &Principal,
    name: &str,
    version: &SemVer,
) -> Result<Response, ProtocolError> {
    let (sha256, size) = match resolve_target(state, base, principal, name).await? {
        Target::Local(package) => {
            let found = live_version(state, package.id, version).await?;
            count_download(state, method, package.id, found.id);
            (found.archive_sha256, Some(found.archive_size))
        }
        Target::Upstream(upstream) => {
            // Cache miss, integrity failure, oversized archive, upstream down: every one of
            // them is a 404 here, never a 5xx the client would hammer (sharp edge 2).
            let proxied = upstream
                .archive(FORMAT, name, version, (state.clock)())
                .await?
                .ok_or_else(|| ProtocolError::not_found(format!("archive of {} {version}", clip(name))))?;
            (proxied.archive_sha256, proxied.archive_size)
        }
    };

    let key = RegistryService::blob_key(FORMAT, &sha256);
    // The plan is method-specific because a presigned URL is (decision 34): the client's cache
    // probe is a HEAD, and a GET-signed URL refuses it. `get` is the right answer for every
    // other method because the archive routes accept no others.
    let plan = if method == Method::HEAD { DownloadMethod::Head } else { DownloadMethod::Get };
    match state.blob.download(&key, plan).await {
        Ok(DownloadPlan::Redirect(url)) => redirect_to(&url),
        Ok(DownloadPlan::Stream(stream)) => Ok(stream_archive(name, version, &sha256, size, stream)),
        // Metadata without bytes is a broken store, not a missing package — but answering
        // anything but 404 here would leak that the version exists while the bytes do not.
        Err(pub_core::Error::NotFound { .. }) => {
            tracing::error!(package = %name, version = %version, key, "archive bytes missing for a live version");
            Err(ProtocolError::not_found(format!("archive of {name} {version}")))
        }
        Err(other) => Err(ProtocolError::from_domain(other)),
    }
}

/// Counts one served archive download, unless this is the client's cache probe.
///
/// **`HEAD` must not count.** The pub client issues a `HEAD` before every archive `GET` to
/// decide whether its `PUB_CACHE` copy is current, and axum routes `HEAD` to the `GET` handler
/// with the body discarded — so without this check every download would be counted twice, and
/// a fully cached `pub get` (which only ever HEADs) would be counted as a download nobody made.
///
/// Fire-and-forget by construction: the recorder is an in-process buffer with no I/O
/// (`pub_registry::stats`), so a statistic can neither slow a download nor fail one.
///
/// Only **local** versions are counted. A proxied archive's version row lives in
/// `upstream_versions`, and `download_stats` is keyed on `versions` — mixing the two would
/// attribute somebody else's package to a row that does not exist here.
fn count_download(state: &AppState, method: &Method, package: PackageId, version: pub_core::VersionId) {
    if method != Method::GET {
        return;
    }
    state.downloads.record(package, version, (state.clock)());
}

/// 307 to a presigned URL (decisions 10 and 34). 307 rather than 302: the method must not
/// change, and the client follows it without dropping its `Accept`.
///
/// `no-store` is set **here** rather than left to the S-28 response pass, which only fills in a
/// tier the handler left empty: a presigned URL is a bearer capability for the length of its
/// TTL ([S-18.a](../../../../../docs/security.md#4-supply-chain--registry-integrity)), so a
/// shared cache holding this response would hand the archive to whoever asks next. Setting it
/// at the site means a future change to the no-store path families cannot silently drop it.
fn redirect_to(url: &url::Url) -> Result<Response, ProtocolError> {
    let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
    let value = HeaderValue::from_str(url.as_str())
        .map_err(|_| pub_core::Error::Blob { message: "presigned url is not header-safe".into() })?;
    let headers = response.headers_mut();
    headers.insert(header::LOCATION, value);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Streams the stored bytes verbatim.
///
/// `size` is optional because it is metadata, not the payload: a proxied row whose size we
/// never measured would otherwise advertise `Content-Length: 0` for a body that is not empty,
/// which is worse than advertising nothing at all.
///
/// The cache headers are what content addressing buys (S-18): the bytes behind a
/// name+version can never change — a republish is refused, a hard delete removes the version
/// — so the archive is `immutable` with its own sha256 as a strong `ETag`. `private`,
/// because a registry may be private and a shared cache must not serve one org's archive to
/// another's request.
fn stream_archive(name: &str, version: &SemVer, sha256: &str, size: Option<i64>, stream: ByteStream) -> Response {
    let mut response = Response::new(Body::from_stream(stream));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=31536000, immutable"));
    if let Ok(value) = HeaderValue::from_str(&format!("\"{sha256}\"")) {
        headers.insert(header::ETAG, value);
    }
    if let Some(value) = size.filter(|size| *size > 0).and_then(|size| HeaderValue::from_str(&size.to_string()).ok()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{name}-{version}.tar.gz\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

/// The publishing principal for this base (S-13 scopes × decision 19 roles).
///
/// Order of denials is the status ladder: no credential ⇒ 401 (the CLI prompts for a token),
/// everything else ⇒ 403 with a message that says what to do — the publish endpoints are
/// visible to anyone, so 404 would be a lie here.
fn publisher<'a>(principal: &'a Principal, base: &Base) -> Result<&'a TokenContext, ProtocolError> {
    let base_url = base.url();
    let Some(ctx) = principal.token() else {
        return Err(ProtocolError::unauthorized(format!(
            "publishing requires a token; run `dart pub token add {base_url}`"
        )));
    };
    let Some(org) = base.org.as_ref() else {
        return Err(ProtocolError::forbidden(
            "packages are published through an organization's registry, not the public root; \
             set PUB_HOSTED_URL to your organization's URL and publish again",
        ));
    };
    if ctx.token.org_id != org.id {
        return Err(ProtocolError::forbidden(format!(
            "this token belongs to a different organization; run `dart pub token add {base_url}` with a token issued for it"
        )));
    }
    ctx.require_scope(TokenScope::Publish, &base_url)?;
    authorize(&ctx.actor, Action::PublishPackages, &Resource::Org(org.id)).map_err(|_| {
        ProtocolError::forbidden(format!(
            "your account needs the Write role in organization {} to publish; ask an organization admin",
            org.slug
        ))
    })?;
    Ok(ctx)
}

/// Spends one unit of the org's S-24 publish budget, before a single byte is stored.
///
/// The upload step is the one that costs storage: it writes the archive into the staging area
/// and hands back a finalize URL the client may or may not ever call. Without a bound, any
/// member holding a `publish`-scoped token can park unbounded staged blobs — abandoned uploads
/// are swept on a TTL, but only by a job that does not exist yet, so today the bound *is* this
/// budget (see S-20.a / S-24).
///
/// A KV outage **fails open** with a loud log line: this bucket is abuse control on an
/// already-authenticated, already-authorized write, and refusing every publish while Redis
/// blinks would be the larger outage. Auth-abuse buckets, which fail closed, are the ones
/// where an outage would grant access rather than merely lift a quota.
async fn charge_publish_budget(
    state: &AppState,
    ctx: &TokenContext,
    org: &pub_core::org::Org,
    meta: &pub_auth::flows::ClientMeta,
) -> Result<(), ProtocolError> {
    use pub_auth::ratelimit::{self, Decision};

    let now = (state.clock)();
    // Runtime setting (decision 09): an operator can tighten or loosen the publish budget
    // without a restart.
    let limit = state.runtime.current().rate_limits.publish_per_hour_org;
    let key = format!("rl:publish:org:{}", org.id);
    match ratelimit::hit(state.kv.as_ref(), &key, limit, chrono::Duration::hours(1), now).await {
        Ok(Decision::Allowed) => Ok(()),
        Ok(decision @ Decision::Limited { retry_after_secs, .. }) => {
            metrics::counter!("rate_limit_trips_total", "limit" => "publish_per_hour_org").increment(1);
            // S-22: throttle trips are audit events, and this one names the org and the token
            // that spent the budget — the operator's only view of a publish flood. One row per
            // org per window, not one per refused upload: a client that keeps retrying past the
            // budget would otherwise choose how many rows land in a table with no retention.
            if decision.is_first_refusal() {
                let event = NewAuditEvent {
                    actor: AuditActor::Token(ctx.token.id),
                    ip: meta.ip.clone(),
                    user_agent: meta.user_agent.clone(),
                    org_id: Some(org.id),
                    action: "package.publish.throttled".to_owned(),
                    target: None,
                    result: AuditResult::Failure,
                    metadata: Some(serde_json::json!({ "limit": "publish_per_hour_org", "value": limit })),
                };
                if let Err(err) = state.repos.audit.append(event, now).await {
                    tracing::error!(error = %err, "audit append failed for a publish throttle trip");
                }
            }
            Err(ProtocolError::from_domain(pub_core::Error::RateLimited { retry_after_secs }))
        }
        Err(err) => {
            tracing::error!(error = %err, org = %org.id, "publish throttle accounting failed; allowing the upload");
            Ok(())
        }
    }
}

/// This org's effective storage quota right now; `None` = unlimited (S-20.b).
///
/// One call into [`pub_registry::publish::effective_storage_quota`] from both checkpoints, so
/// the three-state rule — `NULL` follows the instance default, `0` is unlimited on *either*
/// surface, a positive number is bytes — cannot be spelled two ways in one file.
fn effective_quota(state: &AppState, org: &pub_core::org::Org) -> Option<u64> {
    pub_registry::publish::effective_storage_quota(
        org.storage_quota_bytes,
        state.runtime.current().registry.storage_quota_bytes,
    )
}

/// Refuses a staged write that the org has no room for (S-20.b, the **second** checkpoint).
///
/// This is not the finalize check run twice, and the difference is the reason it exists.
/// Finalize bounds what is *published*; staged bytes are not published, are not counted by
/// `org_storage_bytes`, and outlive their KV record by the whole staging grace (default two
/// hours, decision 31). An org already over its quota could therefore park
/// `publish_per_hour_org x max_archive_bytes` per hour in the blob store — every one of those
/// uploads doomed at finalize, and every one of them occupying the storage the quota exists to
/// bound. Neither check covers the other's case.
///
/// It runs **after** the S-24.c publish budget deliberately: that budget is the abuse bound and
/// answers 429, this one is the capacity bound and answers a permanent 400, and a caller who has
/// spent both should hear about the retryable one first.
///
/// Refusing here is also the cheaper refusal for the publisher — the bytes have crossed the wire
/// either way, but nothing is written and nothing has to be collected afterwards.
async fn guard_staged_bytes(state: &AppState, org: &pub_core::org::Org, incoming: usize) -> Result<(), ProtocolError> {
    let Some(quota) = effective_quota(state, org) else { return Ok(()) };
    let used = state.repos.packages.org_storage_bytes(org.id).await?;
    if let Err(err) = pub_registry::publish::check_storage_quota(used, incoming as i64, Some(quota)) {
        metrics::counter!("storage_quota_refusals_total", "stage" => "upload").increment(1);
        tracing::warn!(org = %org.id, used, incoming, quota, "upload refused: storage quota exceeded");
        return Err(ProtocolError::from_domain(err));
    }
    Ok(())
}

/// Pulls the archive out of the `file` field of a multipart body.
async fn read_archive(multipart: Result<Multipart, MultipartRejection>) -> Result<Bytes, ProtocolError> {
    let mut multipart = multipart.map_err(|rejection| upload_error(rejection.status(), &rejection.body_text()))?;
    while let Some(field) = multipart.next_field().await.map_err(multipart_error)? {
        if field.name() != Some("file") {
            continue;
        }
        let bytes = field.bytes().await.map_err(multipart_error)?;
        if bytes.is_empty() {
            return Err(ProtocolError::invalid("the uploaded archive is empty"));
        }
        return Ok(bytes);
    }
    Err(ProtocolError::invalid("the upload is missing the `file` field holding package.tar.gz"))
}

fn multipart_error(err: MultipartError) -> ProtocolError {
    upload_error(err.status(), &err.body_text())
}

/// Turns a multipart failure into a permanent 4xx with a message a user can act on.
///
/// Size failures get their own sentence because "could not read the upload" is actively
/// misleading when the real problem is a 120 MB archive.
fn upload_error(status: StatusCode, detail: &str) -> ProtocolError {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        return ProtocolError::invalid(
            "the uploaded archive is larger than this registry accepts; ask an administrator about registry.max_archive_bytes",
        );
    }
    let detail: String = detail.chars().take(200).collect();
    ProtocolError::invalid(format!("the upload could not be read as multipart/form-data: {detail}"))
}

/// Builds the listing body for a local package.
///
/// `latest` comes from [`latest_index`] — the registry's one `latest` rule, evaluated over the
/// newest [`pub_registry::index::LATEST_WINDOW`] entries of this array, which is the same rule
/// over the same window the package page and the search index use (decision 32). The array
/// itself may be far longer: what a listing *carries* and what `latest` is *derived from* are
/// two different bounds.
fn build_listing(base: &Base, package: &Package, versions: &[Version]) -> PackageListing {
    let infos: Vec<VersionInfo> = versions.iter().map(|v| build_version(base, &package.name, v)).collect();
    let ladder: Vec<(bool, bool)> = versions.iter().map(|v| (v.is_retracted(), v.version.is_pre_release())).collect();
    let latest = infos[latest_index(&ladder)].clone();
    PackageListing {
        name: package.name.clone(),
        latest,
        versions: infos,
        is_discontinued: package.discontinued,
        // `replacedBy` without `isDiscontinued` is meaningless to the client, and emitting a
        // stale one would advertise a migration nobody asked for.
        replaced_by: package.replaced_by.clone().filter(|_| package.discontinued),
    }
}

/// Builds one version entry for a local package.
fn build_version(base: &Base, name: &str, version: &Version) -> VersionInfo {
    VersionInfo {
        version: version.version.to_string(),
        retracted: version.is_retracted(),
        archive_url: base.absolute(&format!("/api/archives/{name}-{}.tar.gz", version.version)),
        archive_sha256: version.archive_sha256.clone(),
        pubspec: version.pubspec.clone(),
    }
}

/// Builds the listing body for a proxied package (decision 07).
///
/// Everything except `archive_url` is upstream's, verbatim: flags, hashes, and the pubspec
/// documents. `archive_url` is rewritten under *this request's* base (sharp edge 3) — serving
/// upstream's CDN URL would send the client past the cache, past the per-org policy, and past
/// stale-serving, and would break the credential prefix rule for a private instance (sharp
/// edge 4).
///
/// `replacedBy` is **not** filtered by `isDiscontinued` here, unlike the local path: upstream's
/// listing is upstream's truth and re-deriving parts of it is how a proxy starts disagreeing
/// with the registry it proxies.
///
/// [`pub_registry::ProxiedListing::stale`] is deliberately *not* consulted: the staleness
/// marker is tracing and metrics only (decision 07), and the service emits it once where the
/// staleness is decided. Re-emitting it here would double every counter, and putting it on the
/// wire would be a protocol change no client asked for.
///
/// `latest` is re-derived rather than copied from upstream, and through the same
/// [`latest_index`] — same rule, same [`pub_registry::index::LATEST_WINDOW`] — as a local
/// package. A proxied package that is indistinguishable from a local one on the wire (sharp
/// edge 12) has to be indistinguishable here too.
fn build_proxied_listing(base: &Base, listing: &pub_registry::ProxiedListing) -> PackageListing {
    let infos: Vec<VersionInfo> =
        listing.versions.iter().map(|version| build_proxied_version(base, &listing.name, version)).collect();
    let ladder: Vec<(bool, bool)> =
        listing.versions.iter().map(|v| (v.retracted, v.version.is_pre_release())).collect();
    let latest = infos[latest_index(&ladder)].clone();
    PackageListing {
        name: listing.name.clone(),
        latest,
        versions: infos,
        is_discontinued: listing.discontinued,
        replaced_by: listing.replaced_by.clone(),
    }
}

/// Builds one version entry for a proxied package.
fn build_proxied_version(base: &Base, name: &str, version: &pub_registry::ProxiedVersion) -> VersionInfo {
    VersionInfo {
        version: version.version.to_string(),
        retracted: version.retracted,
        archive_url: base.absolute(&format!("/api/archives/{name}-{}.tar.gz", version.version)),
        archive_sha256: version.archive_sha256.clone(),
        pubspec: version.pubspec.clone(),
    }
}

/// Splits `{name}-{version}.tar.gz`.
///
/// Unambiguous because pub package names are `[a-z0-9_]` — no hyphens — so the first hyphen is
/// always the separator, even though the version half may contain more of them
/// (`1.0.0-beta.1`).
fn parse_archive_file(file: &str) -> Result<(String, SemVer), ProtocolError> {
    let unknown = || ProtocolError::not_found(format!("archive {}", clip(file)));
    let stem = file.strip_suffix(".tar.gz").ok_or_else(unknown)?;
    let (name, raw) = stem.split_once('-').ok_or_else(unknown)?;
    // Checked here as well as in `resolve_package`: a name that cannot exist must not reach
    // the repository as a lookup key, whichever of the two archive routes produced it.
    validate_package_name(name).map_err(|_| unknown())?;
    let version = SemVer::parse(raw).map_err(|_| unknown())?;
    Ok((name.to_owned(), version))
}

/// Bounds a caller-supplied path segment before it is quoted back in an error message.
///
/// Package names and version strings arrive from the URL and are echoed into `message`, which
/// the CLI prints and which lands in our own logs. A legal name is at most 64 characters, so a
/// longer one is either a typo or an attempt to reflect a kilobyte of attacker text — the same
/// rule the ingest path applies to tar entry paths (S-20.a).
fn clip(text: &str) -> String {
    const MAX: usize = 80;

    if text.len() <= MAX {
        return text.to_owned();
    }
    let mut end = MAX;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Blob key of a staged upload. A namespace of its own, distinct from the content-addressed
/// `<format>/<shard>/<sha>.tar.gz` keys, so a sweep of abandoned uploads can never touch a
/// published archive.
fn staging_key(session: &str) -> String {
    format!("uploads/{}/{session}.tar.gz", FORMAT.as_str())
}

/// KV key of a staged upload's record.
fn session_key(session: &str) -> String {
    format!("pub:upload:{session}")
}

/// Drops a staged upload's record and bytes. Best-effort: the record has a TTL and the bytes
/// are unreferenced, so a failure here is garbage, not corruption.
async fn discard_upload(state: &AppState, session: &str) {
    if let Err(err) = state.kv.del(&session_key(session)).await {
        tracing::warn!(error = %err, "failed to drop upload session record");
    }
    if let Err(err) = state.blob.delete(&staging_key(session)).await {
        tracing::warn!(error = %err, "failed to drop staged upload bytes");
    }
}

/// A fresh 128-bit upload session id, hex-encoded.
///
/// Unguessable on purpose: the id is what a finalize URL is, and the credential binding is the
/// second lock, not the first.
fn new_session_id() -> String {
    use pub_auth::random::{OsRandom, RandomSource as _};

    let mut buf = [0u8; 16];
    OsRandom.fill(&mut buf);
    buf.iter().fold(String::with_capacity(32), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use pub_core::package::Publisher;
    use pub_core::{PackageId, UserId, VersionId};

    use super::*;

    #[test]
    fn a_presigned_redirect_carries_no_store_without_help_from_the_middleware() {
        // The wire test in `tests/protocol.rs` cannot prove this: the S-28 response pass puts
        // `no-store` on the whole pub family anyway, so deleting the line below leaves that
        // test green. What it would break is the day archives leave that family — which the
        // hygiene module's own comment already contemplates, because a *streamed* archive is
        // `immutable` and belongs nowhere near `no-store`. A presigned URL is a bearer
        // capability (S-18.a) and must not be storable whichever tier the family carries, so
        // the guarantee lives at the site and is asserted at the site.
        let url: url::Url = "https://blobs.example.test/pub-blobs/a?X-Amz-Signature=abc".parse().unwrap();
        let response = redirect_to(&url).expect("header-safe url");
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.headers()[header::LOCATION], url.as_str());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    /// Projects versions onto the `(retracted, pre_release)` pairs `latest_index` reads.
    fn ladder(versions: &[Version]) -> Vec<(bool, bool)> {
        versions.iter().map(|v| (v.is_retracted(), v.version.is_pre_release())).collect()
    }

    fn version(raw: &str, retracted: bool) -> Version {
        Version {
            id: VersionId::new(),
            package_id: PackageId::new(),
            version: SemVer::parse(raw).unwrap(),
            pubspec: serde_json::json!({ "name": "acme_core", "version": raw }),
            archive_sha256: "a".repeat(64),
            archive_size: 1024,
            published_by: Publisher { user_id: UserId::new(), token_id: None },
            published_at: Utc::now(),
            retracted_at: retracted.then(Utc::now),
            tombstone: false,
            readme_html: None,
            changelog_html: None,
        }
    }

    #[test]
    fn latest_prefers_the_newest_live_stable() {
        let versions = ladder(&[version("1.0.0", false), version("1.1.0", false), version("2.0.0-beta.1", false)]);
        assert_eq!(latest_index(&versions), 1);
    }

    #[test]
    fn latest_skips_retracted_versions() {
        let versions = ladder(&[version("1.0.0", false), version("1.1.0", true)]);
        assert_eq!(latest_index(&versions), 0);
    }

    #[test]
    fn latest_falls_back_to_a_prerelease_then_to_anything() {
        let only_pre = ladder(&[version("1.0.0-alpha", false), version("1.0.0-beta", false)]);
        assert_eq!(latest_index(&only_pre), 1);
        // Every version retracted: still has to name one, and the newest is the least wrong.
        let all_retracted = ladder(&[version("1.0.0", true), version("1.1.0", true)]);
        assert_eq!(latest_index(&all_retracted), 1);
    }

    #[test]
    fn archive_file_names_split_at_the_first_hyphen() {
        let (name, version) = parse_archive_file("acme_core-1.2.3.tar.gz").unwrap();
        assert_eq!(name, "acme_core");
        assert_eq!(version.to_string(), "1.2.3");
        // The version half keeps its own hyphens.
        let (name, version) = parse_archive_file("acme_core-2.0.0-beta.1+build.5.tar.gz").unwrap();
        assert_eq!(name, "acme_core");
        assert_eq!(version.to_string(), "2.0.0-beta.1+build.5");
    }

    #[test]
    fn junk_archive_file_names_are_404_not_400() {
        for file in ["acme_core.tar.gz", "acme_core-1.2.3.zip", "acme_core-not-a-version.tar.gz", "", "-1.0.0.tar.gz"] {
            let err = parse_archive_file(file).unwrap_err();
            assert_eq!(err.status(), StatusCode::NOT_FOUND, "{file:?} must not be distinguishable from a miss");
        }
    }

    #[test]
    fn staged_uploads_live_outside_the_content_addressed_namespace() {
        let key = staging_key("deadbeef");
        assert!(key.starts_with("uploads/pub/"), "{key}");
        assert!(!key.starts_with(&format!("{}/", FORMAT.as_str())), "{key} collides with published archives");
    }

    /// The shape is a contract with a job in another crate: `pub_jobs::staging` only collects
    /// `uploads/<format>/<32 lowercase hex>.tar.gz` and leaves everything else alone, so an id
    /// that changed length or alphabet would stop abandoned uploads from ever being swept —
    /// silently, and on the side of keeping garbage rather than deleting bytes (decision 31).
    #[test]
    fn session_ids_are_128_bit_hex_and_unique() {
        let a = new_session_id();
        let b = new_session_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn caller_supplied_names_are_clipped_before_they_reach_a_message() {
        let long = "a".repeat(4000);
        let err = parse_archive_file(&format!("{long}.tar.gz")).unwrap_err();
        assert!(err.message().len() < 200, "unbounded reflection: {} chars", err.message().len());
        assert!(err.message().ends_with('…'), "{}", err.message());
        // Ordinary names are quoted verbatim — the message has to stay useful.
        assert!(parse_archive_file("acme_core.tar.gz").unwrap_err().message().contains("acme_core"));
    }

    #[test]
    fn oversized_uploads_explain_themselves() {
        let err = upload_error(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(err.message().contains("max_archive_bytes"), "{}", err.message());
    }
}
