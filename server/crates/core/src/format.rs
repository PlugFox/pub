//! Package format discriminator (decision 21).
//!
//! The registry is a multi-format artifact space: every shared entity carries a `format`
//! discriminator and packages are unique per `(format, name)`. V1 ships `pub` only; `npm`,
//! `cargo`, … mount later as siblings.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::Error;

/// Artifact format served by this registry.
///
/// Extensible by design: adding a variant must not break consumers, hence `#[non_exhaustive]`.
/// On the wire and in storage formats are lowercase strings (`"pub"`).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Dart/Flutter packages — Hosted Pub Repository Spec v2.
    Pub,
}

impl Format {
    /// Canonical lowercase name, as used in URLs (`/o/{org}/pub`) and storage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pub => "pub",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pub" => Ok(Self::Pub),
            other => Err(Error::Invalid { message: format!("unknown package format: {other}") }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_round_trips_through_from_str() {
        let format = Format::Pub;
        assert_eq!(format.as_str().parse::<Format>().unwrap(), format);
    }

    #[test]
    fn unknown_format_is_invalid() {
        let err = "npm".parse::<Format>().unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
    }

    #[test]
    fn serde_uses_lowercase() {
        assert_eq!(serde_json::to_string(&Format::Pub).unwrap(), "\"pub\"");
        assert_eq!(serde_json::from_str::<Format>("\"pub\"").unwrap(), Format::Pub);
    }
}
