//! Wire DTOs for the app API — separate from domain types by rule (docs/rules/api.md), with
//! `From` conversions. Ids travel as strings; role levels travel as names (decision 19).

use chrono::{DateTime, Utc};
use pub_auth::flows::{LoginOutcome, LoginSuccess};
use pub_auth::oidc::{ProviderConfig, StartedFlow};
use pub_core::audit::AuditEvent;
use pub_core::org::{Invitation, Org, OrgMembership};
use pub_core::search::SearchHit;
use pub_core::session::Session;
use pub_core::token::Token;
use pub_core::user::User;
use pub_core::{RoleLevel, SessionId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// --- request bodies ---

/// Body of `POST /api/v1/auth/otp/request`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OtpRequestBody {
    /// Email to send the sign-in code to.
    pub email: String,
}

/// Body of `POST /api/v1/auth/otp/verify`.
///
/// [`Debug`] is hand-written: the code is a live credential (S-25).
#[derive(Deserialize, ToSchema)]
pub struct OtpVerifyBody {
    /// Opaque pending-auth id from the request step (S-03 binding).
    pub pending_id: String,
    /// The email the code was requested for.
    pub email: String,
    /// The 8-digit code from the email.
    pub code: String,
}

impl std::fmt::Debug for OtpVerifyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpVerifyBody")
            .field("pending_id", &self.pending_id)
            .field("email", &self.email)
            .field("code", &"<redacted>")
            .finish()
    }
}

/// Body of `POST /api/v1/auth/refresh`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshBody {
    /// The refresh token issued by verify/refresh.
    pub refresh_token: String,
}

/// Body of `POST /api/v1/auth/oidc/{provider}/callback`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OidcCallbackBody {
    /// Flow handle from the start step (server-side state binding, S-01).
    pub flow_id: String,
    /// Authorization code from the IdP redirect.
    pub code: String,
    /// `state` from the IdP redirect — must match the server-side record exactly.
    pub state: String,
}

/// Body of `POST /api/v1/auth/totp/confirm`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpConfirmBody {
    /// A live 6-digit code from the just-enrolled authenticator.
    pub code: String,
}

/// Body of `POST /api/v1/auth/totp/verify` — exactly one of the two fields.
///
/// [`Debug`] is hand-written: codes are live credentials (S-25).
#[derive(Deserialize, ToSchema)]
pub struct MfaVerifyBody {
    /// The pending-MFA handle from the first-factor response.
    pub mfa_token: String,
    /// 6-digit TOTP code.
    pub code: Option<String>,
    /// Single-use recovery code.
    pub recovery_code: Option<String>,
}

impl std::fmt::Debug for MfaVerifyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaVerifyBody")
            .field("mfa_token", &self.mfa_token)
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("recovery_code", &self.recovery_code.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Body of `POST /api/v1/auth/step-up` — exactly one of the two fields.
///
/// [`Debug`] is hand-written: codes are live credentials (S-25).
#[derive(Deserialize, ToSchema)]
pub struct StepUpBody {
    /// 6-digit TOTP code.
    pub code: Option<String>,
    /// Single-use recovery code.
    pub recovery_code: Option<String>,
}

impl std::fmt::Debug for StepUpBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepUpBody")
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("recovery_code", &self.recovery_code.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Body of `POST /api/v1/tokens`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenCreateBody {
    /// Optional label shown in the token list.
    pub label: Option<String>,
    /// Org the token is bound to (S-13).
    pub org_id: String,
    /// Requested scopes: `read` | `publish` | `retract` | `admin`.
    pub scopes: Vec<String>,
    /// Lifetime in days (1…3650), or `null` for a token that **never expires**.
    ///
    /// Since [decision 33](../../../../docs/decisions.md#33) this field is explicit and `null`
    /// is not "use the default": a non-expiring token may carry only the `read` scope
    /// ([S-13.c](../../../../docs/security.md#3-cliapi-tokens)) and minting one demands a fresh
    /// second factor at every scope ([S-06.d](../../../../docs/security.md#1-authentication)).
    /// `0` is refused. The UI sends 90 explicitly, which is where the product's default now lives.
    pub expires_days: Option<i64>,
    /// Package-name patterns narrowing the token further; absent or empty means no narrowing.
    ///
    /// One trailing `*` is a prefix match (`acme_*`), anything else is an exact package name.
    /// Validated at the mint against the matcher that enforces it (S-13.c), so a pattern that
    /// could never match is a 400 rather than a token that authorizes nothing.
    pub package_patterns: Option<Vec<String>>,
}

/// Body of `POST /api/v1/orgs`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OrgCreateBody {
    /// Display name.
    pub name: String,
    /// URL slug, unique per instance.
    pub slug: String,
}

// --- responses ---

/// Cursor-paginated list envelope (docs/rules/api.md: cursor pagination only).
#[derive(Debug, Serialize, ToSchema)]
pub struct ListDto<T> {
    /// Items of this page.
    pub items: Vec<T>,
    /// Opaque continuation cursor; `null` on the last page.
    pub cursor: Option<String>,
    /// Whether more items exist.
    pub has_more: bool,
}

impl<T> ListDto<T> {
    /// A single-page listing (the identity/session/org lists are small by construction).
    pub fn single_page(items: Vec<T>) -> Self {
        Self { items, cursor: None, has_more: false }
    }
}

/// Response of `POST /api/v1/auth/otp/request` — deliberately shape-identical for every
/// outcome (S-04).
#[derive(Debug, Serialize, ToSchema)]
pub struct PendingDto {
    /// Opaque pending-auth id to present at the verify step.
    pub pending_id: String,
}

/// Public user profile.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserDto {
    /// User id.
    pub id: String,
    /// Email, when set and not anonymized.
    pub email: Option<String>,
    /// Whether the email is verified.
    pub email_verified: bool,
    /// Display name.
    pub display_name: String,
    /// Account creation time.
    pub created_at: DateTime<Utc>,
}

impl From<&User> for UserDto {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.to_string(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            display_name: user.display_name.clone(),
            created_at: user.created_at,
        }
    }
}

/// Response of a sign-in step or refresh.
///
/// Two shapes behind one schema: `mfa_required = false` carries the full pair;
/// `mfa_required = true` carries only `mfa_token` — the client must redeem it at
/// `POST /api/v1/auth/totp/verify` with a TOTP or recovery code (S-05).
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginDto {
    /// Whether a second factor is still outstanding.
    pub mfa_required: bool,
    /// Pending-MFA handle (present iff `mfa_required`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_token: Option<String>,
    /// Short-lived access JWT (S-07).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// Opaque refresh token — rotates on every refresh (S-08).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Session id backing the pair.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The authenticated user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserDto>,
}

impl From<LoginSuccess> for LoginDto {
    fn from(login: LoginSuccess) -> Self {
        Self {
            mfa_required: false,
            mfa_token: None,
            access_token: Some(login.access_token),
            refresh_token: Some(login.refresh_token),
            session_id: Some(login.session_id.to_string()),
            user: Some(UserDto::from(&login.user)),
        }
    }
}

impl From<LoginOutcome> for LoginDto {
    fn from(outcome: LoginOutcome) -> Self {
        match outcome {
            LoginOutcome::Complete(login) => Self::from(login),
            LoginOutcome::MfaRequired { mfa_token } => Self {
                mfa_required: true,
                mfa_token: Some(mfa_token),
                access_token: None,
                refresh_token: None,
                session_id: None,
                user: None,
            },
        }
    }
}

/// One configured OIDC provider for the login screen (public — no secrets).
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderDto {
    /// Slug used in the start/callback routes.
    pub id: String,
    /// Human label ("Sign in with …").
    pub display_name: String,
}

impl From<&ProviderConfig> for ProviderDto {
    fn from(provider: &ProviderConfig) -> Self {
        Self { id: provider.id.clone(), display_name: provider.display_name.clone() }
    }
}

/// Response of `GET /api/v1/auth/providers`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProvidersDto {
    /// Configured providers, in config order; empty = email OTP only.
    pub providers: Vec<ProviderDto>,
}

/// Response of `POST /api/v1/auth/oidc/{provider}/start`.
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcStartDto {
    /// Where to send the browser.
    pub authorize_url: String,
    /// Flow handle to hold (e.g. sessionStorage) and present at the callback.
    pub flow_id: String,
}

impl From<StartedFlow> for OidcStartDto {
    fn from(flow: StartedFlow) -> Self {
        Self { authorize_url: flow.authorize_url, flow_id: flow.flow_id }
    }
}

/// Response of `POST /api/v1/auth/totp/enroll` (S-05).
#[derive(Debug, Serialize, ToSchema)]
pub struct TotpEnrollDto {
    /// Base32 seed for manual entry.
    pub secret: String,
    /// `otpauth://` provisioning URL (QR encoding is the client's job).
    pub otpauth_url: String,
}

/// Response of `POST /api/v1/auth/totp/confirm`: the recovery codes, shown exactly once.
#[derive(Debug, Serialize, ToSchema)]
pub struct TotpConfirmedDto {
    /// Ten single-use recovery codes (S-05) — never retrievable again.
    pub recovery_codes: Vec<String>,
}

/// Response of `POST /api/v1/auth/step-up` (S-06).
#[derive(Debug, Serialize, ToSchema)]
pub struct StepUpDto {
    /// Until when the session counts as step-up-fresh.
    pub valid_until: DateTime<Utc>,
}

/// One row of the session list UI (S-10).
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionDto {
    /// Session id.
    pub id: String,
    /// Sign-in time.
    pub created_at: DateTime<Utc>,
    /// Last activity (write-throttled).
    pub last_seen_at: DateTime<Utc>,
    /// IP captured at sign-in.
    pub ip: Option<String>,
    /// Coarse user agent captured at sign-in.
    pub user_agent: Option<String>,
    /// Whether this row is the session making the request.
    pub current: bool,
}

impl SessionDto {
    /// Converts a domain session, marking it current when it matches `current_sid`.
    pub fn from_session(session: &Session, current_sid: SessionId) -> Self {
        Self {
            id: session.id.to_string(),
            created_at: session.created_at,
            last_seen_at: session.last_seen_at,
            ip: session.ip.clone(),
            user_agent: session.user_agent.clone(),
            current: session.id == current_sid,
        }
    }
}

/// Token metadata for the token list UI — the secret never appears here (S-13).
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenDto {
    /// Token id.
    pub id: String,
    /// Org the token is bound to.
    pub org_id: String,
    /// User-chosen label.
    pub name: String,
    /// First 8 characters of the secret (S-13 display hint).
    pub display_hint: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Package-name patterns narrowing the token; empty means no narrowing (S-13).
    ///
    /// Rendered by the token list because the mint validates the pattern's *grammar* and never
    /// its intent: `acme_x*` is a well-formed pattern for an org whose packages are `acme_y*`,
    /// and the only way its owner finds that out before CI does is by reading it back.
    pub package_patterns: Vec<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry; `null` means the token never expires (S-13.c — `read` scope only).
    pub expires_at: Option<DateTime<Utc>>,
    /// Last use (write-throttled), if any.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<&Token> for TokenDto {
    fn from(token: &Token) -> Self {
        Self {
            id: token.id.to_string(),
            org_id: token.org_id.to_string(),
            name: token.name.clone(),
            display_hint: token.display_hint.clone(),
            scopes: token.scopes.iter().map(|scope| scope.as_str().to_owned()).collect(),
            package_patterns: token.package_patterns.clone(),
            created_at: token.created_at,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
        }
    }
}

/// Response of `POST /api/v1/tokens`: metadata plus the show-once secret (S-13).
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenCreatedDto {
    /// The plaintext secret — shown exactly once, never retrievable again.
    pub secret: String,
    /// Stored metadata.
    pub token: TokenDto,
}

/// An organization.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgDto {
    /// Org id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// URL slug — also the virtual registry base (`/o/{slug}/pub`), and therefore immutable.
    pub slug: String,
    /// Free-text description; empty when unset.
    pub description: String,
    /// Upstream proxy policy: `allow` | `block` (decision 01).
    pub upstream_policy: String,
    /// Whether the org was archived by a forced deletion — it has no members and serves
    /// nothing, but its name claims stay burned (decision 06).
    pub archived: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

impl From<&Org> for OrgDto {
    fn from(org: &Org) -> Self {
        Self {
            id: org.id.to_string(),
            name: org.name.clone(),
            slug: org.slug.clone(),
            description: org.description.clone(),
            upstream_policy: org.upstream_policy.as_str().to_owned(),
            archived: org.is_archived(),
            created_at: org.created_at,
        }
    }
}

/// An org together with the caller's role in it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgMembershipDto {
    /// The org.
    pub org: OrgDto,
    /// The caller's role name (`read`/`write`/`admin`/`owner`; raw level for future roles).
    pub role: String,
}

impl From<&OrgMembership> for OrgMembershipDto {
    fn from(membership: &OrgMembership) -> Self {
        Self { org: OrgDto::from(&membership.org), role: role_name(membership.role) }
    }
}

/// Result of a revocation endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokedDto {
    /// How many credentials were revoked.
    pub revoked: u64,
}

// --- public read model (search, package pages, home, org profiles) ---

/// Download counters as of the last rollup (docs/architecture.md `download_stats`).
///
/// Deliberately "as of the last rollup", not live: counting a download writes to an in-process
/// buffer that a background job drains, so these numbers trail reality by up to one flush
/// interval and must never be used for anything but display.
#[derive(Debug, Serialize, ToSchema)]
pub struct DownloadsDto {
    /// All-time downloads.
    pub total: i64,
    /// Downloads in the instance's trailing statistics window (30 days by default).
    pub recent: i64,
}

/// One package as a search result or listing row — everything a result card renders.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageSummaryDto {
    /// Package name.
    pub name: String,
    /// Artifact format (decision 21; `pub` in v1).
    pub format: String,
    /// Owning org's slug.
    pub org: String,
    /// `public` or `private`.
    pub visibility: String,
    /// Description from the newest live version's pubspec.
    pub description: String,
    /// Topics from that pubspec.
    pub topics: Vec<String>,
    /// The version a fresh `pub add` would pick.
    pub latest_version: String,
    /// Whether the **newest** version is retracted (which may not be `latest_version`).
    pub latest_retracted: bool,
    /// How many live versions exist.
    pub versions_count: i64,
    /// Whether the package is discontinued.
    pub discontinued: bool,
    /// Suggested replacement; only meaningful while discontinued.
    pub replaced_by: Option<String>,
    /// Whether the package is hidden from discovery.
    pub unlisted: bool,
    /// When the newest version was published.
    pub published_at: DateTime<Utc>,
    /// Freshness used by `sort=updated`.
    pub updated_at: DateTime<Utc>,
    /// Download counters.
    pub downloads: DownloadsDto,
}

impl From<&SearchHit> for PackageSummaryDto {
    fn from(hit: &SearchHit) -> Self {
        Self {
            name: hit.name.clone(),
            format: hit.format.as_str().to_owned(),
            org: hit.org_slug.clone(),
            visibility: hit.visibility.as_str().to_owned(),
            description: hit.description.clone(),
            topics: hit.topics.clone(),
            latest_version: hit.latest_version.clone(),
            latest_retracted: hit.latest_retracted,
            versions_count: hit.versions_count,
            discontinued: hit.discontinued,
            replaced_by: hit.replaced_by.clone().filter(|_| hit.discontinued),
            unlisted: hit.unlisted,
            published_at: hit.published_at,
            updated_at: hit.updated_at,
            downloads: DownloadsDto { total: hit.downloads_total, recent: hit.downloads_recent },
        }
    }
}

/// One facet bucket.
#[derive(Debug, Serialize, ToSchema)]
pub struct FacetDto {
    /// Bucket key (an org slug).
    pub value: String,
    /// How many matches fall in it.
    pub count: i64,
}

/// Facet aggregates over the whole result set, not just this page.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct FacetsDto {
    /// Top owning orgs by match count.
    pub orgs: Vec<FacetDto>,
}

/// Response of `GET /api/v1/packages`.
///
/// A superset of the standard cursor envelope: `items`/`cursor`/`has_more` are the pagination
/// contract (docs/rules/api.md), and the rest is search-specific context the results page needs
/// — a total, facet counts, the ordering actually applied, and the filter tokens the parser did
/// not understand, so the UI can say what it ignored instead of quietly returning odd results.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResultsDto {
    /// Matches on this page.
    pub items: Vec<PackageSummaryDto>,
    /// Opaque continuation cursor; `null` on the last page. Bound to `sort` — reusing it under
    /// a different ordering is a 400.
    pub cursor: Option<String>,
    /// Whether more matches exist.
    pub has_more: bool,
    /// Total matches across all pages.
    pub total: i64,
    /// Facet counts over the same filtered set.
    pub facets: FacetsDto,
    /// The ordering actually applied (`relevance` degrades to `updated` without query text).
    pub sort: String,
    /// Query tokens the parser did not understand, verbatim.
    pub unknown_filters: Vec<String>,
}

/// Who published a version.
///
/// Present only when the caller may read the owning org: the publishing *organization* is
/// public information (orgs replace pub.dev's publishers), the individual account behind a
/// release is not, and a public registry has no reason to hand out staff names.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PublisherDto {
    /// User id.
    pub id: String,
    /// Display name.
    pub display_name: String,
}

/// One row of a package's version list.
#[derive(Debug, Serialize, ToSchema)]
pub struct VersionSummaryDto {
    /// The version number.
    pub version: String,
    /// Retracted versions stay downloadable and are excluded from new resolutions.
    pub retracted: bool,
    /// When the retraction happened, if it did.
    pub retracted_at: Option<DateTime<Utc>>,
    /// Publication time.
    pub published_at: DateTime<Utc>,
    /// Who published it, for callers who may see that.
    pub publisher: Option<PublisherDto>,
    /// Archive size in bytes.
    pub archive_size: i64,
    /// Lowercase hex SHA-256 of the archive.
    pub archive_sha256: String,
}

/// Links declared in a package's pubspec.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct PackageLinksDto {
    /// `homepage:`.
    pub homepage: Option<String>,
    /// `repository:`.
    pub repository: Option<String>,
    /// `issue_tracker:`.
    pub issue_tracker: Option<String>,
    /// `documentation:`.
    pub documentation: Option<String>,
}

/// Response of `GET /api/v1/packages/{name}`.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageDetailDto {
    /// The listing-level summary, so a detail page needs no second call to render its header.
    #[serde(flatten)]
    pub summary: PackageSummaryDto,
    /// Display name of the owning org.
    pub org_name: String,
    /// When the package was first created on this instance.
    pub created_at: DateTime<Utc>,
    /// Links from the newest live version's pubspec.
    pub links: PackageLinksDto,
    /// The newest live version, in full.
    pub latest: VersionSummaryDto,
    /// Sanitized README HTML of the newest live version (S-11: rendered at publish, never at
    /// read). `null` when that version shipped without one.
    pub readme_html: Option<String>,
}

/// Response of `GET /api/v1/packages/{name}/versions/{version}`.
#[derive(Debug, Serialize, ToSchema)]
pub struct VersionDetailDto {
    /// Package name.
    pub name: String,
    /// The version's list-level summary.
    #[serde(flatten)]
    pub summary: VersionSummaryDto,
    /// Absolute archive URL under the owning org's virtual registry base (decision 01) — the
    /// same URL `dart pub` downloads from.
    pub archive_url: String,
    /// The full pubspec document, verbatim.
    #[schema(value_type = Object)]
    pub pubspec: serde_json::Value,
    /// Sanitized README HTML (S-11).
    pub readme_html: Option<String>,
    /// Sanitized CHANGELOG HTML (S-11).
    pub changelog_html: Option<String>,
}

/// Instance identity for the landing page (decision 17 white-label).
#[derive(Debug, Serialize, ToSchema)]
pub struct InstanceDto {
    /// Instance name.
    pub name: String,
    /// One-line description; `null` when unset.
    pub tagline: Option<String>,
    /// Logo URL; `null` when unset.
    pub logo_url: Option<String>,
    /// Accent colour as a CSS colour string; `null` when unset.
    pub primary_color: Option<String>,
    /// Public base URL — what a user puts in `dart pub token add`.
    pub public_url: String,
}

/// Instance counters, **scoped to what the caller may see**.
///
/// Scoped rather than absolute on purpose: an absolute package count on a public page publishes
/// the size of every org's private inventory, and an absolute zero on a fully private instance
/// is a useless dashboard. The same predicate as search, so the numbers always agree with what
/// a listing returns.
#[derive(Debug, Serialize, ToSchema)]
pub struct CountersDto {
    /// Visible packages holding at least one live version.
    pub packages: i64,
    /// Live versions of those packages.
    pub versions: i64,
    /// Organizations on the instance.
    pub orgs: i64,
}

/// Response of `GET /api/v1/home`.
#[derive(Debug, Serialize, ToSchema)]
pub struct HomeDto {
    /// Branding and base URL.
    pub instance: InstanceDto,
    /// Counters.
    pub counters: CountersDto,
    /// Recently updated packages.
    pub recently_updated: Vec<PackageSummaryDto>,
    /// Most downloaded packages (by all-time count as of the last rollup).
    pub most_downloaded: Vec<PackageSummaryDto>,
}

/// Response of `GET /api/v1/orgs/{slug}` — the public org profile.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgProfileDto {
    /// The org.
    pub org: OrgDto,
    /// The caller's role in it, when they are a member.
    pub role: Option<String>,
    /// The org's packages this caller may see, newest first.
    pub packages: ListDto<PackageSummaryDto>,
}

// --- org management (decision 19 danger zone; S-06 step-up gates) ---

/// Body of `PATCH /api/v1/orgs/{slug}`. Every field is optional — an absent field keeps the
/// stored value. The **slug is not patchable**: it is the org's virtual registry base
/// (decision 01), so renaming it would break every `PUB_HOSTED_URL` pointing at it.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct OrgUpdateBody {
    /// New display name.
    pub name: Option<String>,
    /// New description; `""` clears it.
    pub description: Option<String>,
    /// New upstream policy: `allow` | `block`.
    pub upstream_policy: Option<String>,
}

/// One row of the org members table.
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberDto {
    /// The member's user id.
    pub user_id: String,
    /// Display name; `"deleted user"` for an anonymized account (S-29).
    pub display_name: String,
    /// Email, when the account still has one.
    pub email: Option<String>,
    /// Role name (`read`/`write`/`admin`/`owner`).
    pub role: String,
    /// When the membership was created.
    pub created_at: DateTime<Utc>,
    /// When the role last changed.
    pub updated_at: DateTime<Utc>,
}

/// Body of `POST /api/v1/orgs/{slug}/members`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MemberAddBody {
    /// Verified email of an existing account. Unknown addresses are 404 — invite them instead.
    pub email: String,
    /// Role to grant; defaults to `read` (S-06 least privilege).
    pub role: Option<String>,
}

/// Body of `PATCH /api/v1/orgs/{slug}/members/{user_id}`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MemberRoleBody {
    /// New role name.
    pub role: String,
}

/// Result of a membership mutation.
#[derive(Debug, Serialize, ToSchema)]
pub struct MembershipChangedDto {
    /// The role the user now holds; `null` when the membership was removed.
    pub role: Option<String>,
    /// How many of the affected user's sessions this change revoked (S-09). Always `0` for a
    /// pure grant, which cannot be spent by a token issued before it.
    pub sessions_revoked: u64,
    /// How many of the affected user's CLI tokens **in this org** the change revoked
    /// (decision 13 addendum, D37): those whose scopes exceed a lowered level, every one of
    /// them on a removal, none on a grant or a raise.
    pub tokens_revoked: u64,
}

/// One invitation row.
#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationDto {
    /// Invitation id.
    pub id: String,
    /// Invited email.
    pub email: String,
    /// Role granted on acceptance.
    pub role: String,
    /// `pending` | `accepted` | `revoked` | `expired`.
    pub status: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry time.
    pub expires_at: DateTime<Utc>,
}

impl InvitationDto {
    /// Projects an invitation, resolving its lifecycle status against `now`.
    pub fn from_invitation(invitation: &Invitation, now: DateTime<Utc>) -> Self {
        let status = if invitation.accepted_at.is_some() {
            "accepted"
        } else if invitation.revoked_at.is_some() {
            "revoked"
        } else if invitation.expires_at <= now {
            "expired"
        } else {
            "pending"
        };
        Self {
            id: invitation.id.to_string(),
            email: invitation.email.clone(),
            role: role_name(invitation.role),
            status: status.to_owned(),
            created_at: invitation.created_at,
            expires_at: invitation.expires_at,
        }
    }
}

/// Body of `POST /api/v1/orgs/{slug}/invitations`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct InvitationCreateBody {
    /// Email to invite.
    pub email: String,
    /// Role granted on acceptance; defaults to `read` (S-06 least privilege).
    pub role: Option<String>,
}

/// Response of creating an invitation: the row plus its show-once token.
#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationCreatedDto {
    /// The stored invitation.
    pub invitation: InvitationDto,
    /// The single-use token, shown exactly once. Also mailed to the invitee; it is returned
    /// here so an instance with no SMTP configured can still onboard people. Only the holder
    /// of the invited address — verified — can redeem it.
    pub token: String,
}

/// Body of `POST /api/v1/invitations/accept`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct InvitationAcceptBody {
    /// The token from the invitation email.
    pub token: String,
}

/// Body of `DELETE /api/v1/orgs/{slug}`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OrgDeleteBody {
    /// The org's slug, typed again — a deliberate speed bump on an irreversible action.
    pub confirm: String,
    /// Proceed even though the org owns packages, archiving it instead of erasing it.
    #[serde(default)]
    pub force: bool,
}

/// Result of deleting an org.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgDeletedDto {
    /// `true` when the org row survives as an archive (it still owned packages, whose name
    /// claims and versions are kept forever by decision 06).
    pub archived: bool,
    /// How many packages were made unreachable.
    pub packages: i64,
    /// How many members were removed.
    pub members: i64,
    /// How many sessions those removals revoked (S-09).
    pub sessions_revoked: u64,
}

// --- package management ---

/// Body of `PATCH /api/v1/packages/{name}/options`. Absent fields keep their stored value.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct PackageOptionsBody {
    /// `public` | `private`.
    pub visibility: Option<String>,
    /// Discontinued flag.
    pub discontinued: Option<bool>,
    /// Suggested replacement; `""` clears it.
    pub replaced_by: Option<String>,
    /// Hidden from search, facets, counters, and org listings — still resolvable by name.
    pub unlisted: Option<bool>,
}

/// A package's mutable options after a change.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageOptionsDto {
    /// Package name.
    pub name: String,
    /// `public` | `private`.
    pub visibility: String,
    /// Discontinued flag.
    pub discontinued: bool,
    /// Suggested replacement.
    pub replaced_by: Option<String>,
    /// Hidden from discovery.
    pub unlisted: bool,
}

impl From<&pub_core::package::Package> for PackageOptionsDto {
    fn from(package: &pub_core::package::Package) -> Self {
        Self {
            name: package.name.clone(),
            visibility: package.visibility.as_str().to_owned(),
            discontinued: package.discontinued,
            replaced_by: package.replaced_by.clone().filter(|_| package.discontinued),
            unlisted: package.unlisted,
        }
    }
}

/// Result of a retraction or restoration.
#[derive(Debug, Serialize, ToSchema)]
pub struct VersionRetractedDto {
    /// The affected version.
    pub version: String,
    /// Whether it is retracted now.
    pub retracted: bool,
    /// When the retraction happened, if it is retracted.
    pub retracted_at: Option<DateTime<Utc>>,
    /// Until when a restoration is still allowed (decision 06 window); `null` when live.
    pub restorable_until: Option<DateTime<Utc>>,
}

/// Body of `DELETE /api/v1/packages/{name}/versions/{version}` (decision 06 hard delete).
#[derive(Debug, Deserialize, ToSchema)]
pub struct HardDeleteBody {
    /// `"{name}@{version}"`, typed again. The bytes are unrecoverable and the number is burned
    /// forever, so the request has to name exactly what it destroys.
    pub confirm: String,
    /// Why — recorded in the audit event (S-22). Required.
    pub reason: String,
}

/// Result of a hard delete.
#[derive(Debug, Serialize, ToSchema)]
pub struct HardDeletedDto {
    /// The deleted version.
    pub version: String,
    /// Always `true`: the row survives so the number can never be reused (S-18).
    pub tombstone: bool,
    /// Whether the archive bytes were removed. `false` means another live version shares the
    /// content hash, so erasing them would break a `pubspec.lock` that pins it.
    pub blob_removed: bool,
}

/// Body of `POST /api/v1/packages/{name}/transfer`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PackageTransferBody {
    /// Slug of the receiving org. The caller must be Owner of both.
    pub target_org: String,
    /// The package name, typed again.
    pub confirm: String,
}

/// Result of a package transfer.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageTransferredDto {
    /// Package name.
    pub name: String,
    /// Slug of the org that now owns it.
    pub org: String,
}

// --- instance administration ---

/// Registration policy (decision 09, S-31).
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RegistrationSettingsDto {
    /// `open` | `invite` | `closed`.
    pub mode: String,
    /// Sign-in email-domain allowlist; empty = every domain.
    pub allowed_email_domains: Vec<String>,
}

/// Rate-limit numbers (S-24). Every value must be at least 1.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RateLimitSettingsDto {
    /// OTP requests per email per hour.
    pub otp_per_email_hour: u32,
    /// OTP requests per IP per hour.
    pub otp_per_ip_hour: u32,
    /// Credential redemptions per IP per minute.
    pub login_per_ip_minute: u32,
    /// Failed CLI-token authentications per IP per minute.
    pub token_auth_fail_per_ip_minute: u32,
    /// Publish uploads per org per hour.
    pub publish_per_hour_org: u32,
    /// Reads per minute per client IP, for requests with no identity (S-24.f).
    pub read_per_ip_minute: u32,
    /// Reads per minute per CLI token or signed-in account (S-24.f, S-13.b).
    pub read_per_identity_minute: u32,
    /// App-API mutations per minute per client IP, for requests with no identity (S-24.g).
    pub write_per_ip_minute: u32,
    /// App-API mutations per minute per CLI token or signed-in account (S-24.g).
    pub write_per_identity_minute: u32,
    /// Invitations one org may send per rolling 24 hours (S-24.h). An exact database count
    /// rather than a bucket, reported here because it is a limit an administrator changes.
    pub invitations_per_day_org: u32,
    /// Invitations one member may send per rolling 24 hours within one org (S-24.h).
    pub invitations_per_day_actor: u32,
}

/// SMTP settings as returned — the password is never among them (S-26).
#[derive(Debug, Serialize, ToSchema)]
pub struct SmtpSettingsDto {
    /// SMTP hostname; `null` = not configured at runtime.
    pub host: Option<String>,
    /// SMTP port.
    pub port: u16,
    /// Login user.
    pub username: Option<String>,
    /// `From:` mailbox.
    pub from: String,
    /// `tls` | `starttls` | `none`.
    pub security: String,
    /// Whether a password is stored. The value itself is write-only.
    pub password_set: bool,
}

/// SMTP settings on a write.
///
/// [`Debug`] is hand-written: `password` is a live credential (S-25).
#[derive(Deserialize, ToSchema)]
pub struct SmtpSettingsPatchDto {
    /// SMTP hostname; `null` disables runtime SMTP.
    pub host: Option<String>,
    /// SMTP port.
    pub port: u16,
    /// Login user.
    pub username: Option<String>,
    /// `From:` mailbox.
    pub from: String,
    /// `tls` | `starttls` | `none`.
    pub security: String,
    /// New password. Omit to keep the stored one; `""` clears it. Sealed under the env KEK
    /// before storage and never returned (S-26).
    pub password: Option<String>,
}

impl std::fmt::Debug for SmtpSettingsPatchDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpSettingsPatchDto")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("from", &self.from)
            .field("security", &self.security)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// White-label instance identity (decision 17).
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct BrandingSettingsDto {
    /// Instance name.
    pub name: String,
    /// One-line description; empty = none.
    pub tagline: String,
    /// Absolute logo URL; empty = the UI's own mark.
    pub logo_url: String,
    /// Accent colour; empty = the theme default.
    pub primary_color: String,
}

/// Upstream proxy defaults (decision 07).
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct UpstreamSettingsDto {
    /// Instance-wide proxy switch. `false` removes step 3 of the resolution order.
    pub enabled: bool,
    /// Upstream policy a newly created org starts with: `allow` | `block`.
    pub default_org_policy: String,
}

/// Registry-plane policy (decision 05).
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RegistrySettingsDto {
    /// Whether every pub-protocol read demands a CLI token. `true` also closes the S-04.c proxy
    /// timing oracle, since there is then no anonymous prober.
    pub require_auth_for_read: bool,
    /// Default per-org storage quota in bytes; **`0` = unlimited** (S-20.b). A per-org override
    /// set by an instance admin wins over this number for that org.
    pub storage_quota_bytes: u64,
}

/// Response of `GET`/`PATCH /api/v1/admin/settings`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminSettingsDto {
    /// Instance settings version — increases on every write, and is what the cross-instance
    /// reconciliation poll compares.
    pub version: i64,
    /// Registration policy.
    pub registration: RegistrationSettingsDto,
    /// Rate limits.
    pub rate_limits: RateLimitSettingsDto,
    /// SMTP, credential-free.
    pub smtp: SmtpSettingsDto,
    /// Instance identity.
    pub branding: BrandingSettingsDto,
    /// Upstream defaults.
    pub upstream: UpstreamSettingsDto,
    /// Registry-plane policy.
    pub registry: RegistrySettingsDto,
}

/// Body of `PATCH /api/v1/admin/settings`: any subset of sections, each replaced wholesale.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct AdminSettingsPatchBody {
    /// Registration policy.
    pub registration: Option<RegistrationSettingsDto>,
    /// Rate limits.
    pub rate_limits: Option<RateLimitSettingsDto>,
    /// SMTP.
    pub smtp: Option<SmtpSettingsPatchDto>,
    /// Instance identity.
    pub branding: Option<BrandingSettingsDto>,
    /// Upstream defaults.
    pub upstream: Option<UpstreamSettingsDto>,
    /// Registry-plane policy.
    pub registry: Option<RegistrySettingsDto>,
}

/// Response of `POST /api/v1/admin/settings/smtp/test`.
///
/// A refused delivery answers `200` with `delivered: false` and the reason: a wrong SMTP
/// configuration is the operator's problem to see, not a server fault to hide behind a 5xx.
#[derive(Debug, Serialize, ToSchema)]
pub struct SmtpTestResultDto {
    /// Whether the mailer accepted the message.
    pub delivered: bool,
    /// Effective SMTP host; `null` = none configured, so nothing was delivered anywhere.
    pub host: Option<String>,
    /// Effective transport security: `tls` | `starttls` | `none`.
    pub security: String,
    /// Whether the transport presented credentials.
    pub credentialed: bool,
    /// The SMTP failure text, or the notice that no host is configured; `null` on a clean send.
    pub detail: Option<String>,
}

/// One row of the admin user table.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminUserDto {
    /// User id.
    pub id: String,
    /// Email; `null` after anonymization (S-29).
    pub email: Option<String>,
    /// Whether the email is verified.
    pub email_verified: bool,
    /// Display name.
    pub display_name: String,
    /// `active` | `suspended` | `deleted`.
    pub status: String,
    /// Whether the account administers the instance.
    pub instance_admin: bool,
    /// Account creation time.
    pub created_at: DateTime<Utc>,
}

impl From<&User> for AdminUserDto {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.to_string(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            display_name: user.display_name.clone(),
            status: user.status.as_str().to_owned(),
            instance_admin: user.is_instance_admin,
            created_at: user.created_at,
        }
    }
}

/// One row of the admin org table.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminOrgDto {
    /// The org.
    pub org: OrgDto,
    /// How many members it has.
    pub members: i64,
    /// How many packages it owns.
    pub packages: i64,
    /// The org's storage-quota override in bytes: `null` = follow the instance default,
    /// `0` = unlimited for this org (S-20.b).
    ///
    /// Admin-only on purpose. It is deliberately **not** on [`OrgDto`], which
    /// `GET /api/v1/orgs/{slug}` serves to anonymous callers — one org's quota is nobody
    /// else's business, and the field's absence from that payload is also what keeps
    /// `PATCH /api/v1/orgs/{slug}` structurally unable to round-trip it.
    pub storage_quota_bytes: Option<u64>,
    /// What that override resolves to against the current instance default; `null` = unlimited.
    ///
    /// The same number the sibling `PATCH` answers with, and it is here for the same reason it
    /// is there: the stored override alone does not answer "what is this org measured against",
    /// and the operator's question is always the second one. Resolved **server-side** through
    /// [`pub_registry::publish::effective_storage_quota`], which is the one place the
    /// three-state rule is written — without this field a client has to re-derive that rule from
    /// this override plus `GET /api/v1/admin/settings`, and a rule written in two languages is a
    /// rule that will disagree with itself.
    pub effective_quota_bytes: Option<u64>,
}

/// Body of `PATCH /api/v1/admin/orgs/{id}` — the instance-admin write over one org (S-20.b).
///
/// The field is a **double option** because all three of its states are meaningful and an
/// absent field is a fourth thing: `{"storage_quota_bytes": 1073741824}` sets a wall,
/// `{"storage_quota_bytes": 0}` makes this org unlimited whatever the instance default is,
/// `{"storage_quota_bytes": null}` clears the override so the org follows the instance default
/// again, and `{}` supplies nothing and is refused rather than silently treated as one of the
/// three.
///
/// **The inner type is `i64` and the accepted range is `0..=i64::MAX`**: the *negative* half of
/// the parsed range exists only so that refusal stays inside the error envelope
/// ([rules/api.md](../../../../docs/rules/api.md)). A narrower Rust type moves the refusal into
/// serde, and a serde refusal is a **422 carrying a bare deserializer string** that no client
/// can parse as an error: with `u64` the operator's `-1` died there, which also made
/// `AdminService::set_org_storage_quota`'s carefully worded negative refusal unreachable from
/// HTTP while its doc comment claimed to be what the operator sees. Parsing as `i64` puts the
/// negative back within reach, so the *handler* refuses it with a 400 that says what to type
/// instead — which is the direction an operator actually reaches by hand.
///
/// The schema advertises `Option<u64>` — the **accepted** range, not the parsed one — because
/// the accepted range is the operator's contract, and the wider parse exists only so the refusal
/// can be spoken in the envelope. A generated client that sends a `u64` is right; one that sends
/// `-1` gets a sentence instead of a deserializer trace.
///
/// The *other* out-of-range direction stays outside the envelope: a value above `i64::MAX` dies
/// in serde as a 422, exactly as a non-numeric one does. That is an app-wide gap — every route
/// taking plain `Json` has it — and closing it needs an enveloping extractor, not a wider
/// integer here. `i128` was tried and does not work: `serde_json` refuses it at the number,
/// so the negative case never reached the handler either.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct AdminOrgPatchBody {
    /// New storage-quota override in bytes; `null` clears it, `0` means unlimited. A negative
    /// number is a `400` naming the range; one above `i64::MAX` is a 422 from the deserializer.
    #[serde(default, deserialize_with = "explicit_null")]
    #[schema(value_type = Option<u64>, nullable)]
    pub storage_quota_bytes: Option<Option<i64>>,
}

/// Distinguishes an explicit JSON `null` (`Some(None)`) from an absent field (`None`).
///
/// Serde collapses both into `None` for a plain `Option`, which is exactly the distinction the
/// quota patch is built on: "clear the override" and "do not touch the override" are different
/// requests, and a payload that meant the first would otherwise be a no-op that answered 200.
fn explicit_null<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer).map(Some)
}

/// Response of `PATCH /api/v1/admin/orgs/{id}`: the override that is now stored, and what it
/// resolves to.
///
/// Both numbers, because the stored one alone does not answer the operator's question. `null`
/// and `0` are different rows with different futures — one follows the instance default, one
/// has opted out of it — and the effective value is what the next publish will actually be
/// measured against.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminOrgQuotaDto {
    /// Org id.
    pub id: String,
    /// Org slug.
    pub slug: String,
    /// The stored override: `null` = follow the instance default, `0` = unlimited for this org.
    pub storage_quota_bytes: Option<u64>,
    /// What that resolves to against the current instance default: `null` = unlimited.
    pub effective_quota_bytes: Option<u64>,
}

/// One audit row (S-22).
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventDto {
    /// ULID id — also the pagination cursor.
    pub id: String,
    /// Event time.
    pub created_at: DateTime<Utc>,
    /// `user` | `token` | `system`.
    pub actor_kind: String,
    /// Actor id; `null` for the system actor.
    pub actor_id: Option<String>,
    /// Client IP, when the action came from a request.
    pub ip: Option<String>,
    /// Coarse user agent.
    pub user_agent: Option<String>,
    /// Org context, when the action is org-scoped.
    pub org_id: Option<String>,
    /// Dot-namespaced action, e.g. `org.member.role`.
    pub action: String,
    /// Target of the action.
    pub target: Option<String>,
    /// `success` | `failure`.
    pub result: String,
    /// Structured before/after context; never contains secrets (S-22).
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

impl From<&AuditEvent> for AuditEventDto {
    fn from(event: &AuditEvent) -> Self {
        Self {
            id: event.id.to_string(),
            created_at: event.created_at,
            actor_kind: event.actor.kind().to_owned(),
            actor_id: event.actor.id_string(),
            ip: event.ip.clone(),
            user_agent: event.user_agent.clone(),
            org_id: event.org_id.map(|org| org.to_string()),
            action: event.action.clone(),
            target: event.target.clone(),
            result: event.result.as_str().to_owned(),
            metadata: event.metadata.clone(),
        }
    }
}

/// Account counts.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserCountsDto {
    /// Every account row.
    pub total: i64,
    /// Accounts that can sign in.
    pub active: i64,
    /// Suspended accounts.
    pub suspended: i64,
    /// Anonymized deletion tombstones (S-29).
    pub deleted: i64,
    /// Instance administrators.
    pub admins: i64,
}

/// Registry totals.
#[derive(Debug, Serialize, ToSchema)]
pub struct RegistryStatsDto {
    /// Package rows.
    pub packages: i64,
    /// Of those, public ones.
    pub public_packages: i64,
    /// Live version rows.
    pub versions: i64,
    /// Of those, currently retracted.
    pub retracted_versions: i64,
    /// Hard-deleted versions kept as burned numbers (S-18).
    pub tombstoned_versions: i64,
    /// Summed archive size of the live versions.
    pub archive_bytes: i64,
}

/// Proxy-cache totals (decision 07).
#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamCacheStatsDto {
    /// Upstream packages we hold a snapshot for.
    pub packages: i64,
    /// Upstream versions those snapshots know about.
    pub versions: i64,
    /// Of those, versions whose bytes we hold.
    pub cached_versions: i64,
    /// Size of those bytes.
    pub cached_bytes: i64,
}

/// One quarantined upstream archive (S-19).
#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantineDto {
    /// Artifact format the name lives in — part of the register's key (decision 21).
    pub format: String,
    /// Package name upstream.
    pub name: String,
    /// The refused version.
    pub version: String,
    /// Upstream base URL.
    pub upstream: String,
    /// The sha256 upstream advertised.
    pub expected_sha256: String,
    /// The sha256 of the bytes it served.
    pub actual_sha256: String,
    /// How many times this has been observed.
    pub occurrences: i64,
    /// First observation — the incident's start.
    pub first_seen_at: DateTime<Utc>,
    /// Most recent observation.
    pub last_seen_at: DateTime<Utc>,
}

/// One shadowing alarm (S-17).
#[derive(Debug, Serialize, ToSchema)]
pub struct ShadowingDto {
    /// Artifact format the name lives in — with `name`, the key an acknowledgement addresses.
    pub format: String,
    /// The shadowed name.
    pub name: String,
    /// Org holding the local claim.
    pub org_id: String,
    /// Upstream base URL where it was observed.
    pub upstream: String,
    /// The highest version upstream advertises, when known.
    pub upstream_version: Option<String>,
    /// How many sightings.
    pub observations: i64,
    /// Whether it still wants attention.
    pub active: bool,
    /// First sighting of the **current** incident: an acknowledged alarm that is seen again
    /// starts a new one (S-17.a), so this moves rather than recording the original sighting.
    pub first_seen_at: DateTime<Utc>,
    /// Most recent sighting.
    pub last_seen_at: DateTime<Utc>,
    /// When an administrator acknowledged it; `null` while it is still active.
    pub acknowledged_at: Option<DateTime<Utc>>,
}

/// Response of `POST /api/v1/admin/shadowing/{format}/{name}/acknowledge`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ShadowingAckDto {
    /// Whether an **active** alarm was acknowledged by this call. `false` means there was
    /// nothing to acknowledge — an unknown name or one already cleared — and nothing was
    /// written: a button pressed twice is not an event.
    pub acknowledged: bool,
}

impl From<&pub_core::package::QuarantineEntry> for QuarantineDto {
    fn from(entry: &pub_core::package::QuarantineEntry) -> Self {
        Self {
            format: entry.format.as_str().to_owned(),
            name: entry.name.clone(),
            version: entry.version.clone(),
            upstream: entry.upstream.clone(),
            expected_sha256: entry.expected_sha256.clone(),
            actual_sha256: entry.actual_sha256.clone(),
            occurrences: entry.occurrences,
            first_seen_at: entry.first_seen_at,
            last_seen_at: entry.last_seen_at,
        }
    }
}

impl From<&pub_core::package::ShadowingAlarm> for ShadowingDto {
    fn from(alarm: &pub_core::package::ShadowingAlarm) -> Self {
        Self {
            format: alarm.format.as_str().to_owned(),
            name: alarm.name.clone(),
            org_id: alarm.org_id.to_string(),
            upstream: alarm.upstream.clone(),
            upstream_version: alarm.upstream_version.clone(),
            observations: alarm.observations,
            active: alarm.is_active(),
            first_seen_at: alarm.first_seen_at,
            last_seen_at: alarm.last_seen_at,
            acknowledged_at: alarm.acknowledged_at,
        }
    }
}

/// Durable state of one background job.
#[derive(Debug, Serialize, ToSchema)]
pub struct JobStateDto {
    /// Job name.
    pub name: String,
    /// The job-defined phase its cursor belongs to.
    pub phase: String,
    /// When a run last started.
    pub last_run_at: Option<DateTime<Utc>>,
    /// When a run last succeeded — the freshness an operator watches.
    pub last_success_at: Option<DateTime<Utc>>,
    /// Seconds since that success; `null` when it never succeeded (a different alarm).
    pub lag_seconds: Option<i64>,
    /// The last failure's message.
    pub last_error: Option<String>,
    /// How many runs have started.
    pub runs: i64,
    /// How many work items were processed in total.
    pub processed: i64,
    /// How many failed.
    pub failures: i64,
}

/// Response of `GET /api/v1/admin/stats`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminStatsDto {
    /// Account counts.
    pub users: UserCountsDto,
    /// How many orgs exist.
    pub orgs: i64,
    /// Registry totals and storage.
    pub registry: RegistryStatsDto,
    /// Proxy-cache size.
    pub upstream_cache: UpstreamCacheStatsDto,
    /// Recent quarantine records (S-19).
    pub quarantine: Vec<QuarantineDto>,
    /// Recent shadowing alarms (S-17).
    pub shadowing: Vec<ShadowingDto>,
    /// How many of those alarms are unacknowledged.
    pub shadowing_active: i64,
    /// Background-job state, mirror included.
    pub jobs: Vec<JobStateDto>,
    /// Jobs this instance can run on demand.
    pub runnable_jobs: Vec<String>,
    /// The settings version this instance is serving.
    pub settings_version: i64,
}

/// Result of a manual job run.
#[derive(Debug, Serialize, ToSchema)]
pub struct JobRunDto {
    /// Job name.
    pub job: String,
    /// The job's own summary document.
    #[schema(value_type = Object)]
    pub summary: serde_json::Value,
}

// --- realtime: the SSE stream and the notification center (decision 20) ---

/// One frame of `GET /api/v1/events`, as it appears in the SSE `data:` field.
///
/// A projection, not the domain enum: the stream is a public wire contract the frontend
/// generates types from, and serializing `DomainEvent` directly would make every future
/// variant field a silent API change. The common fields are lifted out so a client can route on
/// them without a per-type match, and `data` carries the whole event document for the cases
/// that need more.
#[derive(Debug, Serialize, ToSchema)]
pub struct StreamEventDto {
    /// Event id — the value to send back as `Last-Event-ID` after a reconnect. Also the SSE
    /// `id:` field, so a browser client that uses `EventSource` semantics gets it for free.
    pub id: String,
    /// Dot-namespaced event type, identical to the SSE `event:` field (`package.publish`,
    /// `org.member`, `notification.new`, …).
    #[serde(rename = "type")]
    pub event_type: String,
    /// When the event happened (not when it was delivered).
    pub at: DateTime<Utc>,
    /// Org the event belongs to; `null` for instance-scoped and personal events.
    pub org_id: Option<String>,
    /// Package name, for the package-lifecycle events.
    pub package: Option<String>,
    /// Version, for the events that name one.
    pub version: Option<String>,
    /// The full event document (`type`-tagged, snake_case), for clients that need more than
    /// the lifted fields.
    #[schema(value_type = Object)]
    pub data: serde_json::Value,
}

impl From<&pub_core::event::EventEnvelope> for StreamEventDto {
    fn from(envelope: &pub_core::event::EventEnvelope) -> Self {
        let data = serde_json::to_value(&envelope.event).unwrap_or(serde_json::Value::Null);
        let string_field = |key: &str| data.get(key).and_then(serde_json::Value::as_str).map(ToOwned::to_owned);
        Self {
            id: envelope.id.to_string(),
            event_type: envelope.event.name().to_owned(),
            at: data
                .get("at")
                .and_then(serde_json::Value::as_str)
                .and_then(|at| DateTime::parse_from_rfc3339(at).ok())
                .map_or_else(Utc::now, |at| at.with_timezone(&Utc)),
            org_id: envelope.event.org_id().map(|org| org.to_string()),
            package: string_field("name"),
            version: string_field("version"),
            data,
        }
    }
}

/// One row of the notification feed.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationDto {
    /// Notification id — also the pagination cursor and the value to mark read.
    pub id: String,
    /// Subscription axis: `package` | `org` | `security`.
    pub category: String,
    /// The originating event's dot-namespaced name.
    pub event: String,
    /// Rendered one-line summary.
    pub title: String,
    /// Org context, when the event had one.
    pub org_id: Option<String>,
    /// The event document, verbatim — the same shape the SSE stream carried.
    #[schema(value_type = Object)]
    pub payload: serde_json::Value,
    /// When it was filed.
    pub created_at: DateTime<Utc>,
    /// When the caller marked it read; `null` = unread.
    pub read_at: Option<DateTime<Utc>>,
}

impl From<&pub_core::notification::Notification> for NotificationDto {
    fn from(notification: &pub_core::notification::Notification) -> Self {
        Self {
            id: notification.id.to_string(),
            category: notification.category.as_str().to_owned(),
            event: notification.event.clone(),
            title: notification.title.clone(),
            org_id: notification.org_id.map(|org| org.to_string()),
            payload: notification.payload.clone(),
            created_at: notification.created_at,
            read_at: notification.read_at,
        }
    }
}

/// Response of `GET /api/v1/notifications`: the standard cursor envelope plus the badge count.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationFeedDto {
    /// Notifications on this page, newest first.
    pub items: Vec<NotificationDto>,
    /// Opaque continuation cursor; `null` on the last page.
    pub cursor: Option<String>,
    /// Whether more notifications exist.
    pub has_more: bool,
    /// Total unread notifications — the badge, independent of this page.
    pub unread: i64,
}

/// Body of `POST /api/v1/notifications/read`: either specific ids or everything.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct NotificationsReadBody {
    /// Notification ids to mark read. Ignored when `all` is set.
    #[serde(default)]
    pub ids: Vec<String>,
    /// Mark every unread notification read.
    #[serde(default)]
    pub all: bool,
}

/// Result of marking notifications read.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationsReadDto {
    /// How many rows this call changed (already-read and foreign ids count for nothing).
    pub marked: u64,
    /// The unread count afterwards — the new badge value.
    pub unread: i64,
}

/// One category's delivery preference.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct NotificationPreferenceDto {
    /// `package` | `org` | `security`.
    pub category: String,
    /// Whether matching events appear in the feed.
    pub in_app: bool,
    /// Whether matching events are also emailed.
    pub email: bool,
}

/// Response of the preferences routes: every category, defaults filled in.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationPreferencesDto {
    /// One entry per category.
    pub preferences: Vec<NotificationPreferenceDto>,
}

/// Body of `PATCH /api/v1/notifications/preferences`. Categories left out keep their value.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NotificationPreferencesBody {
    /// The categories to change.
    pub preferences: Vec<NotificationPreferenceDto>,
}

/// Wire name of a role level (decision 19: names on the wire, numbers in storage) — the
/// rendering lives on [`RoleLevel`]'s `Display` in core, shared with the service-layer
/// denials, so no layer grows its own name table.
pub fn role_name(role: RoleLevel) -> String {
    role.to_string()
}

/// Parses a role name from the wire, rejecting the two values that are not grantable roles.
///
/// `none` is the absence of a membership, not a role you can hold; a bare number is refused
/// because a caller must not be able to invent an intermediate level the ladder does not
/// define yet (decision 19 reserves the gaps for *us*).
pub fn parse_role(raw: &str) -> Result<RoleLevel, pub_core::Error> {
    match raw {
        "read" => Ok(RoleLevel::READ),
        "write" => Ok(RoleLevel::WRITE),
        "admin" => Ok(RoleLevel::ADMIN),
        "owner" => Ok(RoleLevel::OWNER),
        other => Err(pub_core::Error::Invalid {
            message: format!("unknown role {other:?}: use read, write, admin, or owner"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_follow_decision_19() {
        assert_eq!(role_name(RoleLevel::OWNER), "owner");
        assert_eq!(role_name(RoleLevel::READ), "read");
        // Unknown intermediate levels fall back to the raw number instead of lying.
        assert_eq!(role_name(RoleLevel::new(150)), "150");
    }
}
