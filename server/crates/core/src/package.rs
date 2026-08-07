//! Registry entities: packages, immutable versions, name claims, and the upstream proxy
//! cache (decisions 01, 06, 07, 21).
//!
//! Everything here is **format-agnostic** (decision 21): a package is identified by
//! `(format, name)` instance-wide, versions carry the shared columns (version + precedence
//! key, sha256, size, retraction, timestamps) plus the format's own metadata document as
//! JSON (`pubspec` for pub, `package.json` for npm later). Format-specific parsing and wire
//! shapes live in the protocol modules, never here.
//!
//! Two invariants shape the types:
//!
//! - **Versions are immutable and their numbers are never reusable** (decision 06, S-18).
//!   The only mutable bits are the retraction flag and the [`Version::tombstone`] a hard
//!   delete leaves behind; the row survives deletion precisely so the number stays burned.
//! - **A name belongs to exactly one org per format** ([`NameClaim`], decision 01). The claim
//!   is what makes "local always wins" enforceable against upstream shadowing (S-16/S-17).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::semver::SemVer;
use crate::{Error, Format, OrgId, PackageId, Result, TokenId, UserId, VersionId};

/// Who may resolve and download a package.
///
/// Visibility is a package-level property; the read ladder around it (404 for anything the
/// principal cannot read, for anonymous and authenticated principals alike) is decision 05 /
/// S-04 and is applied by [`crate::traits::PackageRepo::resolve`] and the API layer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Readable by anyone who can reach the instance (subject to `require_auth_for_read`).
    Public,
    /// Readable only by members of the owning org (Read level and above).
    #[default]
    Private,
}

impl Visibility {
    /// Canonical lowercase name as stored and used on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Visibility {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "public" => Ok(Self::Public),
            "private" => Ok(Self::Private),
            other => Err(Error::Invalid { message: format!("unknown visibility: {other}") }),
        }
    }
}

/// A package: one name in one format, owned by one org.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    /// Entity id (UUID v7).
    pub id: PackageId,
    /// Artifact format (decision 21).
    pub format: Format,
    /// Package name, unique per `(format, name)` instance-wide.
    pub name: String,
    /// Owning org.
    pub org_id: OrgId,
    /// Who may read it.
    pub visibility: Visibility,
    /// Discontinued flag — surfaced as `isDiscontinued` in pub version listings
    /// (docs/protocol.md sharp edge 9).
    pub discontinued: bool,
    /// Suggested replacement package name (`replacedBy` in listings); only meaningful while
    /// [`Package::discontinued`] is set.
    pub replaced_by: Option<String>,
    /// Hidden from search and public listings; still resolvable and downloadable by name.
    pub unlisted: bool,
    /// Creation time (UTC) — the first publish or an explicit name claim.
    pub created_at: DateTime<Utc>,
    /// Last metadata change (UTC).
    pub updated_at: DateTime<Utc>,
}

/// Payload for creating a package row (id and timestamps are assigned by the repo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewPackage {
    /// Artifact format.
    pub format: Format,
    /// Package name.
    pub name: String,
    /// Owning org.
    pub org_id: OrgId,
    /// Initial visibility.
    pub visibility: Visibility,
}

/// The full mutable option set of a package (decision 06 lifecycle flags).
///
/// Deliberately a *replace* payload rather than a patch: the four flags are a small,
/// interdependent set (`replaced_by` is meaningless without `discontinued`), and read-modify-
/// write of individual fields is how flags silently resurrect each other under concurrency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageOptions {
    /// Who may read the package.
    pub visibility: Visibility,
    /// Discontinued flag.
    pub discontinued: bool,
    /// Suggested replacement; ignored by clients unless `discontinued` is set.
    pub replaced_by: Option<String>,
    /// Hidden from search and public listings.
    pub unlisted: bool,
}

impl From<&Package> for PackageOptions {
    fn from(package: &Package) -> Self {
        Self {
            visibility: package.visibility,
            discontinued: package.discontinued,
            replaced_by: package.replaced_by.clone(),
            unlisted: package.unlisted,
        }
    }
}

/// Publisher provenance recorded on every version (S-21 provenance-lite).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Publisher {
    /// The user the publish acted as.
    pub user_id: UserId,
    /// The CLI token used, when the publish came from the token plane (S-13).
    pub token_id: Option<TokenId>,
}

/// An immutable published version.
///
/// The archive bytes themselves live in the blob store, content-addressed by
/// [`Version::archive_sha256`]; the hash is what clients pin in `pubspec.lock`, so it — and
/// the bytes behind it — are stable forever (docs/protocol.md sharp edge 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    /// Entity id (UUID v7).
    pub id: VersionId,
    /// Owning package.
    pub package_id: PackageId,
    /// The version itself; ordering is semver precedence ([`SemVer`]).
    pub version: SemVer,
    /// The format's metadata document (pubspec) as JSON — served verbatim in listings.
    /// Cleared to `{}` when the version is tombstoned.
    pub pubspec: serde_json::Value,
    /// Lowercase hex SHA-256 of the uploaded archive (exactly 64 chars).
    pub archive_sha256: String,
    /// Size of the uploaded archive in bytes.
    pub archive_size: i64,
    /// Publisher provenance (S-21).
    pub published_by: Publisher,
    /// Publication time (UTC).
    pub published_at: DateTime<Utc>,
    /// When the version was retracted; `None` = live. Retracted versions stay downloadable
    /// and are excluded from new resolutions (docs/protocol.md sharp edge 9).
    pub retracted_at: Option<DateTime<Utc>>,
    /// Whether an admin hard-deleted this version (decision 06): the bytes and metadata are
    /// gone, the row remains so the number can never be reused (S-18).
    pub tombstone: bool,
    /// Sanitized README HTML, rendered at publish time and immutable afterwards (S-11).
    pub readme_html: Option<String>,
    /// Sanitized CHANGELOG HTML, rendered at publish time and immutable afterwards (S-11).
    pub changelog_html: Option<String>,
}

impl Version {
    /// Whether the version is retracted (excluded from new resolutions, still downloadable).
    pub fn is_retracted(&self) -> bool {
        self.retracted_at.is_some()
    }
}

/// Payload for publishing a version.
///
/// It carries `format` + `package_name` + `org_id` rather than a [`PackageId`] because the
/// first publish of a name creates the claim and the package row in the same transaction —
/// see [`crate::traits::PackageRepo::create_version`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewVersion {
    /// Artifact format.
    pub format: Format,
    /// Package name from the uploaded metadata document.
    pub package_name: String,
    /// Org publishing the version; must own the name claim.
    pub org_id: OrgId,
    /// Visibility applied **only** when this publish creates the package row.
    pub visibility: Visibility,
    /// The version being published.
    pub version: SemVer,
    /// Metadata document as JSON.
    pub pubspec: serde_json::Value,
    /// Lowercase hex SHA-256 of the archive.
    pub archive_sha256: String,
    /// Archive size in bytes.
    pub archive_size: i64,
    /// Publisher provenance (S-21).
    pub published_by: Publisher,
    /// Sanitized README HTML.
    pub readme_html: Option<String>,
    /// Sanitized CHANGELOG HTML.
    pub changelog_html: Option<String>,
}

/// Result of a successful [`crate::traits::PackageRepo::create_version`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedVersion {
    /// The package the version belongs to (created by this call when `package_created`).
    pub package: Package,
    /// The stored version row.
    pub version: Version,
    /// Whether this publish created the package row and its name claim (first publish).
    pub package_created: bool,
}

/// A name reservation: `(format, name)` → org (decision 01).
///
/// Written at the first publish (or by an explicit reservation) and never silently
/// transferred: it is what makes local packages win over upstream ones deterministically and
/// what a shadowing alarm is measured against (S-16/S-17).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameClaim {
    /// Artifact format.
    pub format: Format,
    /// The claimed name.
    pub name: String,
    /// Org holding the claim.
    pub org_id: OrgId,
    /// When the name was claimed (UTC).
    pub claimed_at: DateTime<Utc>,
}

/// Which virtual registry base a request arrived on (decision 01).
///
/// The base is not cosmetic: it *is* the namespace a name is resolved in. `/o/{org}/pub`
/// resolves org-owned → instance-public → upstream; `/pub` resolves instance-public →
/// upstream and never exposes anything private. A principal's membership in some *other* org
/// does not import that org's private packages into this base — otherwise the same
/// `PUB_HOSTED_URL` would mean different package sets for different users, and a lockfile
/// written by one developer would stop resolving for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BaseScope {
    /// `/o/{org}/pub` — the org's virtual registry.
    Org(OrgId),
    /// `/pub` — the instance's public root (public + proxied packages only).
    PublicRoot,
}

/// What resolving a `(format, name)` against the instance yields (decision 01 order:
/// org-owned → instance-public → upstream).
///
/// Read paths must answer **404** for [`Resolution::Restricted`] *and* for an unresolvable
/// [`Resolution::Unclaimed`] name — the two must stay indistinguishable to the caller, or any
/// account holder could enumerate other orgs' private names (S-04, decision 05).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The name is claimed locally and the principal may read the package.
    Readable(Package),
    /// The name is claimed locally but this principal cannot read it — another org's private
    /// package, or a claim without a published package. Never proxied: local always wins
    /// (S-16).
    Restricted {
        /// The org holding the claim (for audit and shadowing alarms — never for responses).
        owner: OrgId,
    },
    /// The name is not claimed on this instance: a proxy candidate (decision 07).
    Unclaimed,
}

/// Cached upstream package metadata (decision 07; the proxy pipeline lands later).
///
/// Upstream flags are stored **verbatim** — retraction/discontinued/advisory state is
/// upstream's truth and is re-emitted unchanged, except for `archive_url`, which is always
/// rewritten to our own virtual base (docs/protocol.md sharp edge 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamPackage {
    /// Entity id (UUID v7).
    pub id: PackageId,
    /// Artifact format.
    pub format: Format,
    /// Package name upstream.
    pub name: String,
    /// Upstream base URL the snapshot came from (e.g. `https://pub.dev`).
    pub upstream: String,
    /// Upstream `isDiscontinued`.
    pub discontinued: bool,
    /// Upstream `replacedBy`.
    pub replaced_by: Option<String>,
    /// Upstream `advisoriesUpdated` (RFC3339 string, preserved verbatim — the client compares
    /// it against its cache, so it must not be regenerated per request).
    pub advisories_updated: Option<String>,
    /// The raw listing document as fetched, for verbatim re-emission.
    pub listing: Option<serde_json::Value>,
    /// When the snapshot was last refreshed (UTC).
    pub fetched_at: DateTime<Utc>,
}

/// A whole upstream listing as one write: the package row plus every version it advertised
/// (decision 07 ingest, shared by the read-through path and the mirror worker).
///
/// It is a *snapshot*, not a diff: the repository upserts the package row and each version
/// row, and **never deletes** versions that are missing from it. Upstream removing a version
/// from a listing must not remove ours — we may already hold the bytes, and a hash somebody
/// pinned in `pubspec.lock` has to keep resolving (docs/protocol.md sharp edge 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamSnapshot {
    /// Artifact format.
    pub format: Format,
    /// Package name upstream.
    pub name: String,
    /// Upstream base URL the snapshot came from.
    pub upstream: String,
    /// Upstream `isDiscontinued`, verbatim.
    pub discontinued: bool,
    /// Upstream `replacedBy`, verbatim.
    pub replaced_by: Option<String>,
    /// Upstream `advisoriesUpdated`, verbatim (never regenerated — the client compares it
    /// against its own cache, docs/protocol.md sharp edge 11).
    pub advisories_updated: Option<String>,
    /// The raw listing document as fetched, kept for re-emission and for the archive URLs.
    pub listing: Option<serde_json::Value>,
    /// Every version the listing advertised.
    pub versions: Vec<NewUpstreamVersion>,
}

/// One version inside an [`UpstreamSnapshot`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewUpstreamVersion {
    /// The upstream version.
    pub version: SemVer,
    /// Upstream metadata document as JSON, preserved verbatim.
    pub pubspec: serde_json::Value,
    /// Upstream-advertised `archive_sha256` (64 lowercase hex).
    pub archive_sha256: String,
    /// Archive size in bytes, when upstream reports it.
    pub archive_size: Option<i64>,
    /// Upstream `retracted` flag, verbatim.
    pub retracted: bool,
    /// Upstream publication time, when reported.
    pub published_at: Option<DateTime<Utc>>,
}

/// One row of the admin-facing cache inventory: what an upstream package costs us.
///
/// Deliberately an aggregate rather than the raw rows: the question the admin UI asks is "what
/// is in the mirror and how big is it", and answering it by listing every version of every
/// cached package would be tens of thousands of rows for one screen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamCacheEntry {
    /// Artifact format.
    pub format: Format,
    /// Package name upstream.
    pub name: String,
    /// Upstream base URL the snapshot came from.
    pub upstream: String,
    /// How many versions the snapshot knows about.
    pub versions: i64,
    /// How many of them we hold bytes for.
    pub cached_versions: i64,
    /// Total size of the bytes we hold, in bytes. Only cached versions have a measured size.
    pub cached_bytes: i64,
    /// Whether upstream marks the package discontinued.
    pub discontinued: bool,
    /// When the snapshot was last refreshed (UTC) — the per-package sync lag.
    pub fetched_at: DateTime<Utc>,
}

/// A refused upstream archive, kept so the admin UI can list what the proxy is rejecting
/// (S-19: hash mismatch ⇒ never stored, never served).
///
/// The record is *not* the enforcement — the bytes were already refused when it is written —
/// it is the evidence. Repeated occurrences of one `(name, version)` collapse onto one row
/// with a counter, because a package under active tampering is fetched by every developer on
/// the team and a row per attempt would bury the signal it is meant to raise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Artifact format.
    pub format: Format,
    /// Package name upstream.
    pub name: String,
    /// The refused version, canonical string form.
    pub version: String,
    /// Upstream base URL the bytes came from.
    pub upstream: String,
    /// The sha256 upstream advertised in its listing.
    pub expected_sha256: String,
    /// The sha256 of the bytes it actually served.
    pub actual_sha256: String,
    /// How many times this mismatch has been observed.
    pub occurrences: i64,
    /// First observation (UTC).
    pub first_seen_at: DateTime<Utc>,
    /// Most recent observation (UTC).
    pub last_seen_at: DateTime<Utc>,
}

/// Payload for recording a quarantine (see [`QuarantineEntry`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewQuarantineEntry {
    /// Artifact format.
    pub format: Format,
    /// Package name upstream.
    pub name: String,
    /// The refused version, canonical string form.
    pub version: String,
    /// Upstream base URL.
    pub upstream: String,
    /// Advertised sha256.
    pub expected_sha256: String,
    /// Actual sha256 of the served bytes.
    pub actual_sha256: String,
}

/// An active shadowing alarm: a name claimed **here** was observed upstream (S-17).
///
/// The registry keeps serving the local package — that is decision 01's "local always wins",
/// and it is not negotiable — so this row is a *notification*, not a policy switch. It exists
/// because the condition is the dependency-confusion precondition: from this moment on, a
/// developer whose `PUB_HOSTED_URL` points somewhere else resolves a different package under
/// the same name, and the org's admins are the only people who can decide whether that is a
/// squat, a coincidence, or their own open-source release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowingAlarm {
    /// Artifact format.
    pub format: Format,
    /// The shadowed name.
    pub name: String,
    /// Org holding the local claim — the audience for the alarm.
    pub org_id: OrgId,
    /// Upstream base URL where the name was observed.
    pub upstream: String,
    /// The highest version upstream advertises, when the observation carried one.
    pub upstream_version: Option<String>,
    /// How many times the name has been observed upstream.
    pub observations: i64,
    /// First observation (UTC).
    pub first_seen_at: DateTime<Utc>,
    /// Most recent observation (UTC).
    pub last_seen_at: DateTime<Utc>,
    /// When an admin acknowledged the alarm; `None` = active. Acknowledging never changes
    /// resolution — the local package won before the alarm and keeps winning after it.
    pub acknowledged_at: Option<DateTime<Utc>>,
}

impl ShadowingAlarm {
    /// Whether the alarm still wants an admin's attention.
    pub fn is_active(&self) -> bool {
        self.acknowledged_at.is_none()
    }
}

/// Payload for recording a shadowing observation (see [`ShadowingAlarm`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewShadowingAlarm {
    /// Artifact format.
    pub format: Format,
    /// The shadowed name.
    pub name: String,
    /// Org holding the local claim.
    pub org_id: OrgId,
    /// Upstream base URL where the name was observed.
    pub upstream: String,
    /// Highest upstream version observed, when known.
    pub upstream_version: Option<String>,
}

/// Cached upstream version metadata (decision 07).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamVersion {
    /// Entity id (UUID v7).
    pub id: VersionId,
    /// Owning [`UpstreamPackage`].
    pub upstream_package_id: PackageId,
    /// The upstream version.
    pub version: SemVer,
    /// Upstream metadata document as JSON, preserved verbatim.
    pub pubspec: serde_json::Value,
    /// Upstream `archive_sha256`, verified at ingest and re-verified on serve (S-19).
    pub archive_sha256: String,
    /// Archive size in bytes, when upstream reports it.
    pub archive_size: Option<i64>,
    /// Upstream `retracted` flag.
    pub retracted: bool,
    /// Whether the archive bytes are in our blob store already (read-through cache state).
    pub cached: bool,
    /// Upstream publication time, when reported.
    pub published_at: Option<DateTime<Utc>>,
    /// When this row was last refreshed (UTC).
    pub fetched_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    #[test]
    fn visibility_round_trips_and_defaults_to_private() {
        for visibility in [Visibility::Public, Visibility::Private] {
            assert_eq!(Visibility::from_str(visibility.as_str()).unwrap(), visibility);
        }
        // Least privilege: a package with no explicit visibility is private.
        assert_eq!(Visibility::default(), Visibility::Private);
        assert_eq!(Visibility::from_str("internal").unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn visibility_serde_is_lowercase() {
        assert_eq!(serde_json::to_string(&Visibility::Public).unwrap(), "\"public\"");
        assert_eq!(serde_json::from_str::<Visibility>("\"private\"").unwrap(), Visibility::Private);
    }

    #[test]
    fn package_options_project_from_a_package() {
        let package = Package {
            id: PackageId::new(),
            format: Format::Pub,
            name: "acme_core".to_owned(),
            org_id: OrgId::new(),
            visibility: Visibility::Public,
            discontinued: true,
            replaced_by: Some("acme_core2".to_owned()),
            unlisted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let options = PackageOptions::from(&package);
        assert_eq!(options.visibility, Visibility::Public);
        assert!(options.discontinued);
        assert_eq!(options.replaced_by.as_deref(), Some("acme_core2"));
        assert!(!options.unlisted);
    }

    #[test]
    fn retraction_flag_reads_off_the_timestamp() {
        let mut version = Version {
            id: VersionId::new(),
            package_id: PackageId::new(),
            version: SemVer::parse("1.0.0").unwrap(),
            pubspec: serde_json::json!({"name": "acme_core"}),
            archive_sha256: "a".repeat(64),
            archive_size: 1024,
            published_by: Publisher { user_id: UserId::new(), token_id: None },
            published_at: Utc::now(),
            retracted_at: None,
            tombstone: false,
            readme_html: None,
            changelog_html: None,
        };
        assert!(!version.is_retracted());
        version.retracted_at = Some(Utc::now());
        assert!(version.is_retracted());
    }
}
