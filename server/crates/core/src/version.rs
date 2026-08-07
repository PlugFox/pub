//! The version this build reports — surfaced by `/healthz` and `pubd --version`.
//!
//! Release engineering (decision 18): the version derives from the git tag `vX.Y.Z` and is
//! injected at build time through the `PUB_VERSION` environment variable (Docker build arg →
//! compile-time env → this constant). Releases never commit version bumps from CI, so
//! `CARGO_PKG_VERSION` is *not* the release version — it is the fallback for builds nobody
//! tagged: dev builds, CI check builds, `cargo install` from a checkout. Those report the
//! crate version with `+dev` build metadata, which compares equal in semver precedence but
//! is visibly not a tagged release.

/// The surfaced version string.
///
/// `PUB_VERSION` from the build environment when set and non-empty (release builds inject
/// the tag's version here), otherwise `CARGO_PKG_VERSION` + `+dev`.
///
/// Cargo tracks `option_env!` in the dep-info file, so a change to `PUB_VERSION` recompiles
/// this crate — no `build.rs` needed for correct rebuilds.
pub const VERSION: &str = {
    const FALLBACK: &str = concat!(env!("CARGO_PKG_VERSION"), "+dev");
    match option_env!("PUB_VERSION") {
        // An empty value (a Docker `ARG PUB_VERSION` left at its default) is treated as
        // absent, not as a release named "".
        Some(version) => {
            if version.is_empty() {
                FALLBACK
            } else {
                version
            }
        }
        None => FALLBACK,
    }
};

#[cfg(test)]
mod tests {
    use super::VERSION;
    use crate::SemVer;

    /// Whatever the build injected, the surfaced version must be a strict semver string —
    /// the release smoke test compares it byte-for-byte against the tag.
    #[test]
    fn version_parses_as_strict_semver() {
        SemVer::parse(VERSION).expect("VERSION must parse as strict semver");
    }

    /// A build without `PUB_VERSION` (every dev and CI check build) reports the crate
    /// version marked `+dev` — never the bare crate version, so a dev binary cannot be
    /// mistaken for the release of the same number.
    #[test]
    fn untagged_build_falls_back_to_crate_version_plus_dev() {
        if option_env!("PUB_VERSION").is_none() {
            assert_eq!(VERSION, concat!(env!("CARGO_PKG_VERSION"), "+dev"));
        }
    }
}
