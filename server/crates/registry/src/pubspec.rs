//! `pubspec.yaml` parsing and pub package-name validation (S-20).
//!
//! # Why the event stream, and why not serde_yaml
//!
//! The pubspec is **untrusted input from an anonymous-ish uploader**, so the parser is attack
//! surface. Two decisions follow from that:
//!
//! - The parser is `yaml-rust2`: pure safe Rust. The `serde_yaml` lineage (including its
//!   maintained forks) is built on `unsafe-libyaml`, a C-to-Rust transpilation full of
//!   raw-pointer code — a poor thing to point hostile bytes at (S-30).
//! - The document is built from the parser's **event stream**, not from its DOM loader, so an
//!   `Alias` event (`*anchor`) is rejected instead of expanded. Every DOM/serde YAML loader
//!   materializes aliases by copying, which turns the "billion laughs" bomb — a few KiB of
//!   nested anchors — into gigabytes of allocation. That is exactly the amplification class
//!   [`crate::archive`] spends so much effort preventing one layer down, and a pubspec has no
//!   legitimate use for anchors.
//!
//! The cost is doing the YAML → JSON conversion by hand ([`JsonBuilder`]), which is also where
//! the depth cap lives.

use pub_core::{Error, SemVer};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};
use yaml_rust2::yaml::Yaml;

/// Maximum nesting depth accepted in a pubspec. Real ones are 3–4 deep; the cap bounds the
/// recursive conversion regardless.
const MAX_DEPTH: usize = 32;

/// Maximum package-name length (pub.dev's limit).
const MAX_NAME_LEN: usize = 64;

/// Dart reserved words — a package name must be a usable library identifier, and `import
/// 'package:class/…'` is not.
const RESERVED_WORDS: &[&str] = &[
    "assert", "break", "case", "catch", "class", "const", "continue", "default", "do", "else", "enum", "extends",
    "false", "final", "finally", "for", "if", "in", "is", "new", "null", "rethrow", "return", "super", "switch",
    "this", "throw", "true", "try", "var", "void", "while", "with",
];

/// Why a pubspec was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PubspecError {
    /// The document is not valid YAML.
    #[error("pubspec.yaml is not valid YAML: {0}")]
    MalformedYaml(String),
    /// The document is not a mapping (or is empty).
    #[error("pubspec.yaml must be a YAML mapping")]
    NotAMapping,
    /// The document nests deeper than [`MAX_DEPTH`].
    #[error("pubspec.yaml nests deeper than {MAX_DEPTH} levels")]
    TooDeep,
    /// The document uses YAML features a pubspec must not (anchors/aliases).
    #[error("pubspec.yaml uses unsupported YAML features (anchors or aliases)")]
    UnsupportedYaml,
    /// `name:` is missing or not a string.
    #[error("pubspec.yaml has no `name` field")]
    MissingName,
    /// `version:` is missing or not a string.
    #[error("pubspec.yaml has no `version` field")]
    MissingVersion,
    /// `name:` is not a legal pub package name.
    #[error("{name:?} is not a valid package name: {reason}")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// Human-readable reason (shown in the CLI).
        reason: &'static str,
    },
    /// `version:` does not parse as a semantic version.
    #[error("{version:?} is not a valid semantic version")]
    InvalidVersion {
        /// The rejected version string.
        version: String,
    },
    /// The pubspec's name disagrees with the name the publish was authorized for.
    #[error("pubspec declares package {found:?} but {expected:?} was expected")]
    NameMismatch {
        /// Name the caller expected.
        expected: String,
        /// Name the pubspec declares.
        found: String,
    },
}

impl From<PubspecError> for Error {
    /// Pubspec rejections are permanent caller errors — 4xx, never a retryable 5xx
    /// (docs/protocol.md sharp edge 2).
    fn from(err: PubspecError) -> Self {
        Error::Invalid { message: err.to_string() }
    }
}

/// A validated pubspec: the two fields the registry itself depends on, plus the whole
/// document as JSON for verbatim re-emission in version listings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pubspec {
    /// Validated package name.
    pub name: String,
    /// Parsed version.
    pub version: SemVer,
    /// The full document as JSON — what the pub version listing serves per version
    /// (docs/protocol.md sharp edge 7).
    pub json: serde_json::Value,
}

impl Pubspec {
    /// Parses and validates `pubspec.yaml` text.
    pub fn parse(raw: &str) -> Result<Self, PubspecError> {
        let json = parse_yaml_document(raw)?;
        if !json.is_object() {
            return Err(PubspecError::NotAMapping);
        }

        let name = json.get("name").and_then(serde_json::Value::as_str).ok_or(PubspecError::MissingName)?.to_owned();
        validate_package_name(&name)?;

        let raw_version = match json.get("version") {
            // A bare `version: 1.0` in YAML is a float, not a string — reject with the same
            // "not a valid version" message rather than "missing".
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(serde_json::Value::Number(number)) => {
                return Err(PubspecError::InvalidVersion { version: number.to_string() });
            }
            _ => return Err(PubspecError::MissingVersion),
        };
        let version = SemVer::parse(&raw_version).map_err(|_| PubspecError::InvalidVersion { version: raw_version })?;

        Ok(Self { name, version, json })
    }

    /// Fails unless the pubspec declares `expected` as its package name.
    ///
    /// The publish pipeline uses this whenever the upload was authorized for a specific name
    /// (a token package pattern, a pinned upload session): the archive must not be able to
    /// swap in a different package after authorization (S-20 "pubspec must match name").
    pub fn require_name(&self, expected: &str) -> Result<(), PubspecError> {
        if self.name == expected {
            Ok(())
        } else {
            Err(PubspecError::NameMismatch { expected: expected.to_owned(), found: self.name.clone() })
        }
    }
}

/// Validates a pub package name: lowercase `[a-z0-9_]`, starting with a letter, at most
/// [`MAX_NAME_LEN`] characters, and not a Dart reserved word.
///
/// Stricter than "a valid Dart identifier" on purpose: uppercase and leading-underscore names
/// are legal Dart but are rejected by pub.dev, and allowing them here would let `Acme_Core`
/// and `acme_core` coexist as two claims of one conceptual name (S-16 depends on the claim key
/// being unambiguous).
pub fn validate_package_name(name: &str) -> Result<(), PubspecError> {
    let reject = |reason: &'static str| Err(PubspecError::InvalidName { name: clip(name), reason });

    if name.is_empty() {
        return reject("it is empty");
    }
    if name.len() > MAX_NAME_LEN {
        return reject("it is longer than 64 characters");
    }
    if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return reject("only lowercase letters, digits, and underscores are allowed");
    }
    if !name.starts_with(|c: char| c.is_ascii_lowercase()) {
        return reject("it must start with a lowercase letter");
    }
    if RESERVED_WORDS.contains(&name) {
        return reject("it is a Dart reserved word");
    }
    Ok(())
}

/// Builds a JSON value straight from the YAML parser's event stream.
///
/// The stack holds the containers currently open; scalars are attached to whatever is on top.
/// The first error is latched and returned after parsing — [`MarkedEventReceiver::on_event`]
/// cannot fail, and stopping the parser early is not worth a panic-based unwind.
#[derive(Default)]
struct JsonBuilder {
    stack: Vec<Container>,
    /// The finished top-level document.
    root: Option<serde_json::Value>,
    /// First error encountered, if any.
    error: Option<PubspecError>,
    /// Whether the first document has been closed (later documents are ignored).
    done: bool,
}

/// One open container plus, for mappings, the key awaiting its value.
enum Container {
    Sequence(Vec<serde_json::Value>),
    Mapping(serde_json::Map<String, serde_json::Value>, Option<String>),
}

impl JsonBuilder {
    fn fail(&mut self, err: PubspecError) {
        if self.error.is_none() {
            self.error = Some(err);
        }
    }

    /// Attaches a finished value to the enclosing container (or makes it the document root).
    fn push_value(&mut self, value: serde_json::Value) {
        match self.stack.last_mut() {
            None => {
                if self.root.is_none() {
                    self.root = Some(value);
                } else {
                    self.done = true;
                }
            }
            Some(Container::Sequence(items)) => items.push(value),
            Some(Container::Mapping(map, pending)) => match pending.take() {
                // Mapping events alternate key, value, key, value…
                None => match value {
                    serde_json::Value::String(key) => *pending = Some(key),
                    // YAML allows non-string keys; JSON does not, and a pubspec never has
                    // one. Stringify rather than reject: the document must round-trip.
                    other => *pending = Some(other.to_string()),
                },
                Some(key) => {
                    map.insert(key, value);
                }
            },
        }
    }

    fn open(&mut self, container: Container) {
        if self.stack.len() >= MAX_DEPTH {
            self.fail(PubspecError::TooDeep);
            return;
        }
        self.stack.push(container);
    }

    fn close(&mut self) {
        let value = match self.stack.pop() {
            Some(Container::Sequence(items)) => serde_json::Value::Array(items),
            Some(Container::Mapping(map, _)) => serde_json::Value::Object(map),
            None => return,
        };
        self.push_value(value);
    }
}

impl MarkedEventReceiver for JsonBuilder {
    fn on_event(&mut self, event: Event, _mark: Marker) {
        if self.error.is_some() || self.done {
            return;
        }
        match event {
            Event::Scalar(text, style, _anchor, _tag) => {
                // Quoted and block scalars are strings by construction; plain ones get YAML's
                // type resolution (`true`, `42`, `~`, …) so the re-emitted document carries
                // the same JSON types pub.dev serves.
                let value = if style == TScalarStyle::Plain { resolve_plain(&text) } else { json_string(text) };
                self.push_value(value);
            }
            Event::SequenceStart(..) => self.open(Container::Sequence(Vec::new())),
            Event::MappingStart(..) => self.open(Container::Mapping(serde_json::Map::new(), None)),
            Event::SequenceEnd | Event::MappingEnd => self.close(),
            // The whole point of the event-level parse: an alias is never expanded.
            Event::Alias(_) => self.fail(PubspecError::UnsupportedYaml),
            Event::DocumentEnd => {
                if self.root.is_some() {
                    self.done = true;
                }
            }
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentStart => {}
        }
    }
}

/// Parses one YAML document into JSON.
fn parse_yaml_document(raw: &str) -> Result<serde_json::Value, PubspecError> {
    let mut builder = JsonBuilder::default();
    let mut parser = Parser::new_from_str(raw);
    parser.load(&mut builder, false).map_err(|err| PubspecError::MalformedYaml(err.to_string()))?;
    if let Some(err) = builder.error {
        return Err(err);
    }
    builder.root.ok_or(PubspecError::NotAMapping)
}

/// YAML type resolution for plain (unquoted) scalars.
fn resolve_plain(text: &str) -> serde_json::Value {
    match Yaml::from_str(text) {
        Yaml::Null => serde_json::Value::Null,
        Yaml::Boolean(value) => serde_json::Value::Bool(value),
        Yaml::Integer(value) => serde_json::Value::Number(value.into()),
        Yaml::Real(raw) => match raw.parse::<f64>().ok().and_then(serde_json::Number::from_f64) {
            Some(number) => serde_json::Value::Number(number),
            // Infinities and NaN have no JSON representation — keep the source text.
            None => serde_json::Value::String(raw),
        },
        _ => json_string(text.to_owned()),
    }
}

/// Wraps text as a JSON string.
fn json_string(text: String) -> serde_json::Value {
    serde_json::Value::String(text)
}

/// Truncates attacker-controlled text before it reaches an error message.
fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_NAME_LEN {
        return text.to_owned();
    }
    format!("{}…", text.chars().take(MAX_NAME_LEN).collect::<String>())
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Fixtures shared with the archive and publish tests.

    /// The smallest pubspec that validates.
    pub const MINIMAL_PUBSPEC: &str = "name: acme_core\nversion: 1.0.0\n";

    /// A pubspec for an arbitrary name/version pair.
    pub fn pubspec(name: &str, version: &str) -> String {
        format!("name: {name}\nversion: {version}\ndescription: A test package.\n")
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{MINIMAL_PUBSPEC, pubspec};
    use super::*;

    #[test]
    fn parses_the_fields_the_registry_depends_on() {
        let spec = Pubspec::parse(MINIMAL_PUBSPEC).expect("valid pubspec");
        assert_eq!(spec.name, "acme_core");
        assert_eq!(spec.version.to_string(), "1.0.0");
        assert_eq!(spec.json["name"], "acme_core");
    }

    #[test]
    fn keeps_the_whole_document_for_verbatim_listing() {
        let raw = r#"
name: acme_core
version: 2.1.0-beta.3
description: Core utilities.
environment:
  sdk: '>=3.0.0 <4.0.0'
dependencies:
  http: ^1.2.0
  meta: any
topics:
  - utils
  - core
executables: {}
publish_to: none
"#;
        let spec = Pubspec::parse(raw).expect("valid pubspec");
        assert_eq!(spec.version.to_string(), "2.1.0-beta.3");
        assert_eq!(spec.json["environment"]["sdk"], ">=3.0.0 <4.0.0");
        assert_eq!(spec.json["dependencies"]["http"], "^1.2.0");
        assert_eq!(spec.json["topics"], serde_json::json!(["utils", "core"]));
        assert_eq!(spec.json["executables"], serde_json::json!({}));
    }

    #[test]
    fn rejects_malformed_yaml() {
        let err = Pubspec::parse("name: [unclosed\nversion: 1.0.0").unwrap_err();
        assert!(matches!(err, PubspecError::MalformedYaml(_)), "got {err:?}");
    }

    #[test]
    fn rejects_documents_that_are_not_mappings() {
        for raw in ["", "- a\n- b\n", "just a string\n", "42\n"] {
            assert_eq!(Pubspec::parse(raw).unwrap_err(), PubspecError::NotAMapping, "accepted {raw:?}");
        }
    }

    #[test]
    fn rejects_yaml_anchors_and_aliases() {
        // The billion-laughs shape. `yaml-rust2` does not expand aliases, so this is cheap to
        // reject rather than expensive to survive.
        let raw = "name: acme_core\nversion: 1.0.0\na: &anchor [x, x]\nb: *anchor\n";
        assert_eq!(Pubspec::parse(raw).unwrap_err(), PubspecError::UnsupportedYaml);
    }

    #[test]
    fn rejects_a_missing_or_non_string_name() {
        assert_eq!(Pubspec::parse("version: 1.0.0\n").unwrap_err(), PubspecError::MissingName);
        assert_eq!(Pubspec::parse("name:\nversion: 1.0.0\n").unwrap_err(), PubspecError::MissingName);
        assert_eq!(Pubspec::parse("name: {a: b}\nversion: 1.0.0\n").unwrap_err(), PubspecError::MissingName);
    }

    #[test]
    fn rejects_a_missing_or_unparsable_version() {
        assert_eq!(Pubspec::parse("name: acme_core\n").unwrap_err(), PubspecError::MissingVersion);
        assert!(matches!(
            Pubspec::parse("name: acme_core\nversion: not.a.version\n").unwrap_err(),
            PubspecError::InvalidVersion { .. }
        ));
        // Unquoted `1.0` is a YAML float, and a float is not a version.
        assert!(matches!(
            Pubspec::parse("name: acme_core\nversion: 1.0\n").unwrap_err(),
            PubspecError::InvalidVersion { .. }
        ));
        assert!(matches!(
            Pubspec::parse(&pubspec("acme_core", "1.0.0.0")).unwrap_err(),
            PubspecError::InvalidVersion { .. }
        ));
    }

    #[test]
    fn accepts_realistic_package_names() {
        for name in ["acme_core", "http", "flutter_bloc", "a", "a1", "json_serializable_2"] {
            validate_package_name(name).unwrap_or_else(|err| panic!("{name} must be valid: {err}"));
        }
    }

    #[test]
    fn s20_rejects_illegal_package_names() {
        let cases: &[(&str, &str)] = &[
            ("", "empty"),
            ("Acme_Core", "uppercase"),
            ("acme-core", "hyphen"),
            ("acme.core", "dot"),
            ("_private", "leading underscore"),
            ("1package", "leading digit"),
            ("acme core", "space"),
            ("acme/core", "slash"),
            ("acmé", "non-ascii"),
            ("class", "reserved word"),
            ("void", "reserved word"),
        ];
        for (name, why) in cases {
            assert!(
                matches!(validate_package_name(name), Err(PubspecError::InvalidName { .. })),
                "must reject {name:?} ({why})"
            );
        }
        let long = "a".repeat(65);
        assert!(matches!(validate_package_name(&long), Err(PubspecError::InvalidName { .. })));
        validate_package_name(&"a".repeat(64)).expect("64 characters is the boundary and must pass");
    }

    #[test]
    fn parse_applies_the_name_rules() {
        assert!(matches!(
            Pubspec::parse(&pubspec("Acme_Core", "1.0.0")).unwrap_err(),
            PubspecError::InvalidName { .. }
        ));
    }

    #[test]
    fn require_name_catches_a_swapped_package() {
        let spec = Pubspec::parse(MINIMAL_PUBSPEC).expect("valid");
        spec.require_name("acme_core").expect("matching name");
        assert_eq!(
            spec.require_name("other_pkg").unwrap_err(),
            PubspecError::NameMismatch { expected: "other_pkg".to_owned(), found: "acme_core".to_owned() }
        );
    }

    #[test]
    fn rejects_absurdly_deep_documents() {
        let mut raw = String::from("name: acme_core\nversion: 1.0.0\ndeep:");
        for depth in 0..MAX_DEPTH + 5 {
            raw.push_str(&format!("\n{}k{depth}:", "  ".repeat(depth + 1)));
        }
        raw.push_str(" leaf\n");
        assert_eq!(Pubspec::parse(&raw).unwrap_err(), PubspecError::TooDeep);
    }

    #[test]
    fn errors_map_to_permanent_4xx_domain_errors() {
        let err: Error = PubspecError::MissingName.into();
        assert_eq!(err.code(), "invalid_argument");
    }
}
