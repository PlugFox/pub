//! Streaming tar.gz inspection with hard limits (S-20 ingest hardening).
//!
//! The uploaded archive is **never extracted to disk** and never fully decompressed into
//! memory: it is streamed through the gzip decoder into the tar reader, with the byte counter
//! sitting between them so every limit is enforced *while* decompressing rather than after.
//! Only four small files are captured (`pubspec.yaml`, `README`, `CHANGELOG`, and the example
//! document); every other entry is walked past — its bytes are counted, its content dropped.
//!
//! What that buys, concretely:
//!
//! - **Gzip bombs** die at the uncompressed cap and at the expansion-ratio cap, before the
//!   allocation they were designed to cause ([`ArchiveLimits::max_uncompressed_bytes`],
//!   [`ArchiveLimits::max_compression_ratio`]).
//! - **Path traversal, absolute paths, and escaping symlinks/hardlinks** cannot do damage in
//!   the first place (nothing is written), but they are rejected anyway: an archive containing
//!   them is hostile, and later consumers (a UI file browser, an SDK that *does* extract) must
//!   never be handed one.
//! - **Duplicate entries** are rejected because "which of the two wins" is a decision that
//!   differs between tar implementations — the classic way to make a reviewed file and an
//!   extracted file disagree.
//! - **Nothing may hide behind the end of the tar stream.** A tar reader stops at the
//!   end-of-archive marker and a single-member gzip reader stops at the end of member one, so
//!   anything appended past either point would be stored and served without ever having been
//!   looked at — the validated archive would be a *prefix* of the published one. The stream is
//!   therefore decoded multi-member and drained to EOF, and every remaining byte must be NUL
//!   padding ([`ArchiveError::TrailingData`]).
//!
//! The validator is CPU-bound and synchronous by design; callers run it on a blocking worker
//! (docs/rules/rust.md).

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::{self, Read};
use std::rc::Rc;

use flate2::read::MultiGzDecoder;
use pub_core::Error;

/// Longest path echoed back in an error message (attacker-controlled text).
const MAX_PATH_IN_MESSAGE: usize = 120;

/// Below this many decompressed bytes the expansion ratio is not enforced: tiny archives have
/// wild ratios for entirely innocent reasons (a few KiB of highly compressible manifest).
const RATIO_FLOOR_BYTES: u64 = 1024 * 1024;

/// The archive-root file names captured for rendering, matched case-insensitively.
const README_NAMES: &[&str] = &["readme.md", "readme.markdown", "readme"];

/// See [`README_NAMES`].
const CHANGELOG_NAMES: &[&str] = &["changelog.md", "changelog.markdown", "changelog"];

/// Example documents, in preference order (pub.dev's convention).
const EXAMPLE_PATHS: &[&str] =
    &["example/example.md", "example/README.md", "example/readme.md", "example/lib/main.dart", "example/main.dart"];

/// The metadata document every pub archive must carry at its root.
const PUBSPEC_PATH: &str = "pubspec.yaml";

/// Why an archive was rejected (S-20).
///
/// A dedicated enum rather than stringly-typed errors: these are the cases the ingest tests
/// enumerate, and "never match on error message strings" (docs/rules/rust.md) applies to our
/// own tests too.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ArchiveError {
    /// The upload is empty.
    #[error("the archive is empty")]
    Empty,
    /// The compressed upload exceeds the configured size cap.
    #[error("archive is {size} bytes, larger than the {limit}-byte limit")]
    ArchiveTooLarge {
        /// Actual compressed size.
        size: u64,
        /// Configured cap.
        limit: u64,
    },
    /// The decompressed content exceeds the configured cap.
    #[error("archive expands beyond the {limit}-byte uncompressed limit")]
    UncompressedTooLarge {
        /// Configured cap.
        limit: u64,
    },
    /// The decompressed:compressed ratio exceeds the cap — a gzip bomb.
    #[error("archive expands more than {limit}x its compressed size")]
    CompressionRatio {
        /// Configured cap.
        limit: u64,
    },
    /// The archive contains more entries than allowed.
    #[error("archive contains more than {limit} entries")]
    TooManyEntries {
        /// Configured cap.
        limit: usize,
    },
    /// An entry path escapes the archive root (`../`).
    #[error("entry {path:?} escapes the archive root")]
    PathTraversal {
        /// The offending path.
        path: String,
    },
    /// An entry path is absolute.
    #[error("entry {path:?} is an absolute path")]
    AbsolutePath {
        /// The offending path.
        path: String,
    },
    /// An entry path is not valid UTF-8 or contains illegal characters.
    #[error("entry path is not a valid relative UTF-8 path")]
    InvalidPath,
    /// A symlink or hardlink points outside the archive.
    #[error("entry {path:?} links outside the archive (target {target:?})")]
    LinkEscape {
        /// The link entry.
        path: String,
        /// Its target.
        target: String,
    },
    /// Two entries share one path.
    #[error("entry {path:?} appears more than once")]
    DuplicateEntry {
        /// The duplicated path.
        path: String,
    },
    /// A captured file (pubspec/README/CHANGELOG/example) is larger than allowed.
    #[error("file {path:?} is larger than the {limit}-byte limit")]
    FileTooLarge {
        /// The offending path.
        path: String,
        /// Configured cap.
        limit: u64,
    },
    /// A captured file is not valid UTF-8.
    #[error("file {path:?} is not valid UTF-8")]
    NotUtf8 {
        /// The offending path.
        path: String,
    },
    /// The gzip layer is truncated or corrupt.
    #[error("the archive is not a valid gzip stream")]
    MalformedGzip,
    /// The tar layer is truncated or corrupt.
    #[error("the archive is not a valid tar stream")]
    MalformedTar,
    /// No `pubspec.yaml` at the archive root.
    #[error("the archive has no pubspec.yaml at its root")]
    MissingPubspec,
    /// Bytes follow the end of the tar stream (a second concatenated gzip member, a second
    /// tar, or an appended payload) — content that would be stored and served but never
    /// validated.
    #[error("the archive carries {bytes} bytes of data after the end of the tar stream")]
    TrailingData {
        /// How many non-padding bytes followed the end-of-archive marker.
        bytes: u64,
    },
}

impl From<ArchiveError> for Error {
    /// Every archive rejection is caller error: a permanent 4xx, never a retryable 5xx
    /// (docs/protocol.md sharp edge 2 — the pub client hammers 5xx up to 7 times).
    fn from(err: ArchiveError) -> Self {
        Error::Invalid { message: err.to_string() }
    }
}

/// Ingest limits (S-20). Instance-configurable; the defaults match `[registry]` config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Maximum compressed upload size (default 100 MB).
    pub max_archive_bytes: u64,
    /// Maximum decompressed size across all entries.
    pub max_uncompressed_bytes: u64,
    /// Maximum number of tar entries.
    pub max_entries: usize,
    /// Maximum decompressed:compressed expansion ratio.
    pub max_compression_ratio: u64,
    /// Maximum size of a single captured file (pubspec, README, CHANGELOG, example).
    pub max_captured_file_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 100 * 1024 * 1024,
            max_uncompressed_bytes: 256 * 1024 * 1024,
            max_entries: 10_000,
            max_compression_ratio: 100,
            max_captured_file_bytes: 4 * 1024 * 1024,
        }
    }
}

/// A file lifted out of the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFile {
    /// Normalized path inside the archive.
    pub path: String,
    /// UTF-8 content.
    pub content: String,
}

/// What a validated archive yielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveContents {
    /// Raw `pubspec.yaml` text (parsing is the next stage).
    pub pubspec: CapturedFile,
    /// Root README, when present.
    pub readme: Option<CapturedFile>,
    /// Root CHANGELOG, when present.
    pub changelog: Option<CapturedFile>,
    /// The example document, when present.
    pub example: Option<CapturedFile>,
    /// Number of tar entries walked.
    pub entries: u64,
    /// Total decompressed bytes.
    pub uncompressed_bytes: u64,
}

/// Reader that counts decompressed bytes and trips the size/ratio limits mid-stream.
///
/// It also records *why* the stream stopped: without this, a gzip bomb, a truncated stream,
/// and a corrupt tar header all surface as the same opaque `io::Error` out of the tar reader.
struct LimitedReader<R> {
    inner: R,
    read: u64,
    compressed: u64,
    limits: ArchiveLimits,
    tripped: Rc<RefCell<Option<ArchiveError>>>,
}

impl<R: Read> LimitedReader<R> {
    fn trip(&self, err: ArchiveError) -> io::Error {
        let mut slot = self.tripped.borrow_mut();
        if slot.is_none() {
            *slot = Some(err);
        }
        io::Error::other("archive limit tripped")
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = match self.inner.read(buf) {
            Ok(read) => read,
            // The only source of errors below us is the gzip decoder.
            Err(err) => {
                tracing::debug!(error = %err, "gzip stream error while validating an archive");
                return Err(self.trip(ArchiveError::MalformedGzip));
            }
        };
        self.read += read as u64;
        if self.read > self.limits.max_uncompressed_bytes {
            return Err(self.trip(ArchiveError::UncompressedTooLarge { limit: self.limits.max_uncompressed_bytes }));
        }
        if self.read > RATIO_FLOOR_BYTES && self.read / self.compressed.max(1) > self.limits.max_compression_ratio {
            return Err(self.trip(ArchiveError::CompressionRatio { limit: self.limits.max_compression_ratio }));
        }
        Ok(read)
    }
}

/// Validates a `.tar.gz` package archive and captures the files the pipeline needs.
///
/// Never writes to disk and never holds more than one captured file plus one read buffer in
/// memory. See the module docs for the threat model.
pub fn validate_archive(bytes: &[u8], limits: &ArchiveLimits) -> Result<ArchiveContents, ArchiveError> {
    if bytes.is_empty() {
        return Err(ArchiveError::Empty);
    }
    let compressed = bytes.len() as u64;
    if compressed > limits.max_archive_bytes {
        return Err(ArchiveError::ArchiveTooLarge { size: compressed, limit: limits.max_archive_bytes });
    }

    let tripped: Rc<RefCell<Option<ArchiveError>>> = Rc::new(RefCell::new(None));
    let reader = LimitedReader {
        // Multi-member on purpose: a plain `GzDecoder` stops at the end of member one, so a
        // second concatenated member would never be seen here while still being stored and
        // served. What we cannot decode we must not accept.
        inner: MultiGzDecoder::new(bytes),
        read: 0,
        compressed,
        limits: *limits,
        tripped: Rc::clone(&tripped),
    };
    let mut archive = tar::Archive::new(reader);
    // Nothing is ever unpacked, but say so explicitly: a future refactor that reaches for
    // `unpack()` should have to remove these lines first.
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(false);

    let fail = |tripped: &Rc<RefCell<Option<ArchiveError>>>, fallback: ArchiveError| -> ArchiveError {
        tripped.borrow_mut().take().unwrap_or(fallback)
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut pubspec: Option<CapturedFile> = None;
    let mut readme: Option<CapturedFile> = None;
    let mut changelog: Option<CapturedFile> = None;
    let mut example: Option<(usize, CapturedFile)> = None;
    let mut entries: u64 = 0;

    let iter = archive.entries().map_err(|_| fail(&tripped, ArchiveError::MalformedTar))?;
    for entry in iter {
        let mut entry = entry.map_err(|_| fail(&tripped, ArchiveError::MalformedTar))?;
        entries += 1;
        if entries as usize > limits.max_entries {
            return Err(ArchiveError::TooManyEntries { limit: limits.max_entries });
        }

        let path = normalize_path(&entry.path_bytes())?;
        let entry_type = entry.header().entry_type();

        // Links carry no data; they are rejected only when their target escapes, so an
        // archive with ordinary internal symlinks still publishes (S-20).
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            let target = entry
                .link_name_bytes()
                .map(|raw| String::from_utf8_lossy(&raw).into_owned())
                .ok_or(ArchiveError::InvalidPath)?;
            if link_escapes(&path, &target) {
                return Err(ArchiveError::LinkEscape { path, target: clip(&target) });
            }
            continue;
        }
        if entry_type.is_dir() || path.is_empty() {
            continue;
        }
        if !entry_type.is_file() {
            // Device nodes, fifos, pax remnants: no content we would ever serve. Counted
            // against the entry budget, otherwise ignored.
            continue;
        }
        if !seen.insert(path.clone()) {
            return Err(ArchiveError::DuplicateEntry { path });
        }

        let lower = path.to_ascii_lowercase();
        let is_root_file = !path.contains('/');
        let wanted_example = EXAMPLE_PATHS.iter().position(|candidate| candidate.eq_ignore_ascii_case(&path));

        if path == PUBSPEC_PATH {
            pubspec = Some(capture(&mut entry, &path, limits, &tripped)?);
        } else if is_root_file && readme.is_none() && README_NAMES.contains(&lower.as_str()) {
            readme = Some(capture(&mut entry, &path, limits, &tripped)?);
        } else if is_root_file && changelog.is_none() && CHANGELOG_NAMES.contains(&lower.as_str()) {
            changelog = Some(capture(&mut entry, &path, limits, &tripped)?);
        } else if let Some(rank) = wanted_example
            && example.as_ref().is_none_or(|(best, _)| rank < *best)
        {
            let file = capture(&mut entry, &path, limits, &tripped)?;
            example = Some((rank, file));
        }
        // Everything else is walked past: the iterator consumes the entry's bytes through
        // the limiting reader, so skipped content still counts against the caps.
    }

    if entries == 0 {
        return Err(ArchiveError::Empty);
    }
    // A limit can trip while the tar reader is skipping the *last* entry's padding, after the
    // loop has already ended without an error.
    if let Some(err) = tripped.borrow_mut().take() {
        return Err(err);
    }

    // The tar reader stopped at the end-of-archive marker; everything the stream still holds
    // has to be padding. See the module docs: what we do not read, we would still store.
    let mut reader = archive.into_inner();
    drain_padding(&mut reader, &tripped)?;
    let uncompressed_bytes = reader.read;
    Ok(ArchiveContents {
        pubspec: pubspec.ok_or(ArchiveError::MissingPubspec)?,
        readme,
        changelog,
        example: example.map(|(_, file)| file),
        entries,
        uncompressed_bytes,
    })
}

/// Reads what is left of the decompressed stream and rejects anything that is not NUL padding.
///
/// This is the check that keeps "the archive we validated" and "the archive we store" the same
/// object. Two ways to hide bytes from a tar reader, both closed here:
///
/// - **A second gzip member.** `tar -xzf` and any multi-member decoder see it; a single-member
///   one does not. (The decoder above is multi-member precisely so those bytes reach us.)
/// - **A second tar, or any payload, after the end-of-archive marker.** `tar --ignore-zeros`
///   walks straight into it.
///
/// Real archives end in zero blocks — 1 KiB from `package:tar` and the Rust `tar` crate, up to
/// a 10 KiB blocking factor from GNU/bsdtar — so honest padding passes unchanged. The bytes are
/// still read through [`LimitedReader`], so a bomb hidden in the tail trips the size and ratio
/// caps instead of being decompressed in full.
fn drain_padding<R: Read>(
    reader: &mut LimitedReader<R>,
    tripped: &Rc<RefCell<Option<ArchiveError>>>,
) -> Result<(), ArchiveError> {
    let mut buf = [0u8; 8192];
    let mut trailing: u64 = 0;
    loop {
        let read = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => read,
            // Junk that is not a gzip member at all surfaces as a malformed stream; a limit
            // tripped while draining keeps its own reason.
            Err(_) => return Err(tripped.borrow_mut().take().unwrap_or(ArchiveError::MalformedGzip)),
        };
        trailing += buf[..read].iter().filter(|byte| **byte != 0).count() as u64;
        if trailing > 0 {
            return Err(ArchiveError::TrailingData { bytes: trailing });
        }
    }
    Ok(())
}

/// Reads one entry into memory under [`ArchiveLimits::max_captured_file_bytes`].
fn capture<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    path: &str,
    limits: &ArchiveLimits,
    tripped: &Rc<RefCell<Option<ArchiveError>>>,
) -> Result<CapturedFile, ArchiveError> {
    let limit = limits.max_captured_file_bytes;
    let mut buf = Vec::new();
    // `limit + 1` so an exactly-at-limit file passes and a larger one is detectable without
    // reading it all.
    entry
        .take(limit + 1)
        .read_to_end(&mut buf)
        .map_err(|_| tripped.borrow_mut().take().unwrap_or(ArchiveError::MalformedTar))?;
    if buf.len() as u64 > limit {
        return Err(ArchiveError::FileTooLarge { path: clip(path), limit });
    }
    let content = String::from_utf8(buf).map_err(|_| ArchiveError::NotUtf8 { path: clip(path) })?;
    Ok(CapturedFile { path: path.to_owned(), content })
}

/// Normalizes a tar entry path and rejects everything hostile.
///
/// Accepted: relative UTF-8 paths with `/` separators, optional `./` prefixes, trailing
/// slashes on directories. Rejected: absolute paths, Windows drive prefixes, backslash
/// separators, NUL bytes, and any `..` component.
fn normalize_path(raw: &[u8]) -> Result<String, ArchiveError> {
    if raw.is_empty() || raw.contains(&0) {
        return Err(ArchiveError::InvalidPath);
    }
    let text = std::str::from_utf8(raw).map_err(|_| ArchiveError::InvalidPath)?;
    if text.contains('\\') {
        return Err(ArchiveError::InvalidPath);
    }
    if text.starts_with('/') {
        return Err(ArchiveError::AbsolutePath { path: clip(text) });
    }
    // `C:\…` is already rejected by the backslash rule; `C:/…` is not.
    if text.len() >= 2 && text.as_bytes()[1] == b':' {
        return Err(ArchiveError::AbsolutePath { path: clip(text) });
    }

    let mut parts = Vec::new();
    for component in text.split('/') {
        match component {
            "" | "." => continue,
            ".." => return Err(ArchiveError::PathTraversal { path: clip(text) }),
            other => parts.push(other),
        }
    }
    Ok(parts.join("/"))
}

/// Whether a link target leaves the archive: absolute targets always do, relative ones do
/// when their `..` components climb above the link's own directory.
fn link_escapes(link_path: &str, target: &str) -> bool {
    if target.starts_with('/') || target.contains('\\') || (target.len() >= 2 && target.as_bytes()[1] == b':') {
        return true;
    }
    // Depth of the directory holding the link.
    let mut depth = link_path.split('/').count().saturating_sub(1) as i64;
    for component in target.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// Truncates attacker-controlled text before it reaches an error message.
fn clip(text: &str) -> String {
    if text.len() <= MAX_PATH_IN_MESSAGE {
        return text.to_owned();
    }
    let mut end = MAX_PATH_IN_MESSAGE;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Archive builders shared by the archive and publish tests.

    use std::io::Write as _;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    /// A `(path, content)` pair to place in a test archive.
    pub type Entry<'a> = (&'a str, &'a str);

    /// Builds a gzipped tar from regular-file entries.
    pub fn targz(entries: &[Entry<'_>]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, content.as_bytes()).expect("append entry");
        }
        gzip(&builder.into_inner().expect("finish tar"))
    }

    /// Builds a gzipped tar containing one link entry plus a pubspec.
    pub fn targz_with_link(link_path: &str, target: &str, hard: bool) -> Vec<u8> {
        let mut tar = Vec::new();
        raw_entry(&mut tar, "pubspec.yaml", crate::pubspec::tests_support::MINIMAL_PUBSPEC.as_bytes(), b'0', "");
        raw_entry(&mut tar, link_path, b"", if hard { b'1' } else { b'2' }, target);
        finish(&mut tar);
        gzip(&tar)
    }

    /// Builds a gzipped tar whose entry paths bypass `tar::Builder`'s own safety checks.
    ///
    /// The high-level builder refuses to *write* absolute paths and `..` — which is precisely
    /// why the fixtures for those cases have to be assembled byte by byte: the attack we must
    /// survive is an archive some other tool produced.
    pub fn hostile_targz(entries: &[Entry<'_>]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (path, content) in entries {
            raw_entry(&mut tar, path, content.as_bytes(), b'0', "");
        }
        finish(&mut tar);
        gzip(&tar)
    }

    /// Appends a hand-built 512-byte ustar header plus padded content.
    fn raw_entry(out: &mut Vec<u8>, path: &str, content: &[u8], type_flag: u8, link_target: &str) {
        let mut header = [0u8; 512];
        let write = |header: &mut [u8; 512], at: usize, bytes: &[u8]| {
            header[at..at + bytes.len()].copy_from_slice(bytes);
        };
        write(&mut header, 0, path.as_bytes());
        write(&mut header, 100, b"0000644\0");
        write(&mut header, 108, b"0000000\0");
        write(&mut header, 116, b"0000000\0");
        write(&mut header, 124, format!("{:011o}\0", content.len()).as_bytes());
        write(&mut header, 136, b"00000000000\0");
        header[148..156].copy_from_slice(b"        "); // checksum placeholder: spaces
        header[156] = type_flag;
        write(&mut header, 157, link_target.as_bytes());
        write(&mut header, 257, b"ustar\0");
        write(&mut header, 263, b"00");

        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        write(&mut header, 148, format!("{checksum:06o}\0 ").as_bytes());

        out.extend_from_slice(&header);
        out.extend_from_slice(content);
        let padding = (512 - content.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, padding));
    }

    /// Writes the two zero blocks that end a tar stream.
    fn finish(out: &mut Vec<u8>) {
        out.extend(std::iter::repeat_n(0u8, 1024));
    }

    /// Builds a gzipped tar whose *uncompressed* stream carries `extra` after the
    /// end-of-archive marker — the "hidden behind the zero blocks" shape.
    pub fn targz_with_trailer(entries: &[Entry<'_>], extra: &[u8]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (path, content) in entries {
            raw_entry(&mut tar, path, content.as_bytes(), b'0', "");
        }
        finish(&mut tar);
        tar.extend_from_slice(extra);
        gzip(&tar)
    }

    /// Gzips raw bytes.
    pub fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{gzip, hostile_targz, targz, targz_with_link, targz_with_trailer};
    use super::*;
    use crate::pubspec::tests_support::MINIMAL_PUBSPEC;

    fn limits() -> ArchiveLimits {
        ArchiveLimits::default()
    }

    fn validate(bytes: &[u8]) -> Result<ArchiveContents, ArchiveError> {
        validate_archive(bytes, &limits())
    }

    #[test]
    fn happy_path_captures_the_documents_it_needs() {
        let archive = targz(&[
            ("pubspec.yaml", MINIMAL_PUBSPEC),
            ("README.md", "# acme_core"),
            ("CHANGELOG.md", "## 1.0.0"),
            ("example/example.md", "usage"),
            ("lib/acme_core.dart", "void main() {}"),
        ]);
        let contents = validate(&archive).expect("valid archive");
        assert_eq!(contents.pubspec.content, MINIMAL_PUBSPEC);
        assert_eq!(contents.readme.expect("readme").content, "# acme_core");
        assert_eq!(contents.changelog.expect("changelog").content, "## 1.0.0");
        assert_eq!(contents.example.expect("example").path, "example/example.md");
        assert_eq!(contents.entries, 5);
        assert!(contents.uncompressed_bytes > 0);
    }

    #[test]
    fn readme_and_changelog_are_optional_and_matched_case_insensitively() {
        let contents = validate(&targz(&[("pubspec.yaml", MINIMAL_PUBSPEC)])).expect("valid");
        assert!(contents.readme.is_none());
        assert!(contents.changelog.is_none());
        assert!(contents.example.is_none());

        let contents = validate(&targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("readme.MD", "hi")])).expect("valid");
        assert_eq!(contents.readme.expect("readme").content, "hi");
    }

    #[test]
    fn nested_readme_is_not_the_package_readme() {
        let contents =
            validate(&targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("doc/README.md", "nested")])).expect("valid");
        assert!(contents.readme.is_none(), "only the archive root's README counts");
    }

    #[test]
    fn leading_dot_slash_is_normalized_not_rejected() {
        // GNU tar writes `./pubspec.yaml` by default — a perfectly ordinary archive.
        let contents = validate(&targz(&[("./pubspec.yaml", MINIMAL_PUBSPEC), ("./README.md", "x")])).expect("valid");
        assert_eq!(contents.pubspec.path, "pubspec.yaml");
        assert_eq!(contents.readme.expect("readme").path, "README.md");
    }

    #[test]
    fn s20_rejects_path_traversal() {
        let archive = hostile_targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("../escape.txt", "pwned")]);
        assert!(matches!(validate(&archive), Err(ArchiveError::PathTraversal { .. })));
        // …including traversal buried mid-path.
        let archive = hostile_targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("lib/../../escape.txt", "pwned")]);
        assert!(matches!(validate(&archive), Err(ArchiveError::PathTraversal { .. })));
    }

    #[test]
    fn s20_rejects_absolute_paths() {
        let archive = hostile_targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("/etc/passwd", "pwned")]);
        assert!(matches!(validate(&archive), Err(ArchiveError::AbsolutePath { .. })));
        let archive = hostile_targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("C:/windows/system32", "pwned")]);
        assert!(matches!(validate(&archive), Err(ArchiveError::AbsolutePath { .. })));
        let archive = hostile_targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("lib\\win.dart", "pwned")]);
        assert!(matches!(validate(&archive), Err(ArchiveError::InvalidPath)));
    }

    #[test]
    fn s20_rejects_symlinks_escaping_the_archive() {
        assert!(matches!(
            validate_archive(&targz_with_link("evil", "../../etc/passwd", false), &limits()),
            Err(ArchiveError::LinkEscape { .. })
        ));
        assert!(matches!(
            validate_archive(&targz_with_link("evil", "/etc/passwd", false), &limits()),
            Err(ArchiveError::LinkEscape { .. })
        ));
        // Hardlinks are held to the same rule.
        assert!(matches!(
            validate_archive(&targz_with_link("evil", "../outside", true), &limits()),
            Err(ArchiveError::LinkEscape { .. })
        ));
    }

    #[test]
    fn internal_symlinks_are_allowed() {
        // `lib/alias.dart -> ../lib/real.dart` stays inside the archive.
        let archive = targz_with_link("lib/alias.dart", "../lib/real.dart", false);
        assert!(validate(&archive).is_ok(), "internal links must not fail a publish");
    }

    #[test]
    fn s20_rejects_duplicate_entries() {
        let archive = targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("lib/a.dart", "one"), ("lib/a.dart", "two")]);
        assert!(matches!(validate(&archive), Err(ArchiveError::DuplicateEntry { .. })));
        // The `./` spelling of the same path is still the same path.
        let archive = hostile_targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("./pubspec.yaml", MINIMAL_PUBSPEC)]);
        assert!(matches!(validate(&archive), Err(ArchiveError::DuplicateEntry { .. })));
    }

    #[test]
    fn s20_rejects_oversized_archives_before_decompressing() {
        let archive = targz(&[("pubspec.yaml", MINIMAL_PUBSPEC)]);
        let tight = ArchiveLimits { max_archive_bytes: 10, ..limits() };
        assert!(matches!(validate_archive(&archive, &tight), Err(ArchiveError::ArchiveTooLarge { limit: 10, .. })));
    }

    #[test]
    fn s20_rejects_gzip_bombs_by_ratio_and_by_absolute_size() {
        // 8 MiB of zeros compresses to a few KiB: ratio far above any sane cap.
        let bomb = targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("payload.bin", &"0".repeat(8 * 1024 * 1024))]);
        assert!(bomb.len() < 200 * 1024, "the bomb must actually be small: {} bytes", bomb.len());

        let ratio_capped = ArchiveLimits { max_compression_ratio: 5, ..limits() };
        assert!(matches!(validate_archive(&bomb, &ratio_capped), Err(ArchiveError::CompressionRatio { limit: 5 })));

        let size_capped = ArchiveLimits { max_uncompressed_bytes: 1024, ..limits() };
        assert!(matches!(
            validate_archive(&bomb, &size_capped),
            Err(ArchiveError::UncompressedTooLarge { limit: 1024 })
        ));
    }

    #[test]
    fn small_highly_compressible_archives_are_not_mistaken_for_bombs() {
        // Under the ratio floor the check must not fire, or ordinary packages break.
        let archive = targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("lib/pad.dart", &"a".repeat(64 * 1024))]);
        let strict = ArchiveLimits { max_compression_ratio: 5, ..limits() };
        assert!(validate_archive(&archive, &strict).is_ok());
    }

    #[test]
    fn s20_rejects_too_many_entries() {
        let bodies: Vec<(String, String)> = (0..20).map(|i| (format!("lib/f{i}.dart"), format!("// {i}"))).collect();
        let mut entries: Vec<(&str, &str)> = vec![("pubspec.yaml", MINIMAL_PUBSPEC)];
        entries.extend(bodies.iter().map(|(path, body)| (path.as_str(), body.as_str())));
        let archive = targz(&entries);
        let capped = ArchiveLimits { max_entries: 5, ..limits() };
        assert!(matches!(validate_archive(&archive, &capped), Err(ArchiveError::TooManyEntries { limit: 5 })));
    }

    #[test]
    fn rejects_captured_files_above_the_per_file_cap() {
        let archive = targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("README.md", &"x".repeat(4096))]);
        let capped = ArchiveLimits { max_captured_file_bytes: 512, ..limits() };
        assert!(matches!(validate_archive(&archive, &capped), Err(ArchiveError::FileTooLarge { .. })));
    }

    #[test]
    fn rejects_a_missing_pubspec() {
        let archive = targz(&[("README.md", "# no pubspec here"), ("lib/a.dart", "x")]);
        assert_eq!(validate(&archive), Err(ArchiveError::MissingPubspec));
        // A nested pubspec is not the package's pubspec.
        let archive = targz(&[("acme/pubspec.yaml", MINIMAL_PUBSPEC)]);
        assert_eq!(validate(&archive), Err(ArchiveError::MissingPubspec));
    }

    #[test]
    fn rejects_an_empty_upload_and_an_empty_tar() {
        assert_eq!(validate(&[]), Err(ArchiveError::Empty));
        let empty_tar = tar::Builder::new(Vec::new()).into_inner().expect("finish");
        assert_eq!(validate(&gzip(&empty_tar)), Err(ArchiveError::Empty));
    }

    #[test]
    fn rejects_truncated_and_non_gzip_input() {
        let archive = targz(&[("pubspec.yaml", MINIMAL_PUBSPEC), ("lib/pad.dart", &"a".repeat(50_000))]);
        let truncated = &archive[..archive.len() / 2];
        assert_eq!(validate(truncated), Err(ArchiveError::MalformedGzip));
        // Plain (ungzipped) tar bytes: not a gzip stream at all.
        assert_eq!(validate(b"not a gzip stream at all, just text"), Err(ArchiveError::MalformedGzip));
    }

    #[test]
    fn s20_rejects_a_second_gzip_member_smuggled_after_the_package() {
        // The bytes we validate must be the bytes we store: `tar -xzf` decodes concatenated
        // gzip members, so a payload hidden in member two would ship inside a "validated"
        // archive without ever having been looked at.
        let good = targz(&[("pubspec.yaml", MINIMAL_PUBSPEC)]);
        let hidden = hostile_targz(&[("../../evil.sh", "rm -rf /")]);
        let mut smuggled = good.clone();
        smuggled.extend_from_slice(&hidden);
        assert!(validate(&good).is_ok(), "the honest half must still publish");
        assert!(
            matches!(validate(&smuggled), Err(ArchiveError::TrailingData { .. })),
            "a smuggled second member must not publish"
        );
    }

    #[test]
    fn s20_rejects_a_payload_appended_after_the_end_of_archive_marker() {
        // Same trick one layer down: inside a single gzip member, past the zero blocks, where
        // `tar --ignore-zeros` finds it.
        let archive = targz_with_trailer(&[("pubspec.yaml", MINIMAL_PUBSPEC)], b"smuggled payload");
        assert!(matches!(validate(&archive), Err(ArchiveError::TrailingData { bytes: 16 })));
    }

    #[test]
    fn zero_padding_after_the_marker_is_ordinary_and_accepted() {
        // GNU/bsdtar pad the output to a 10 KiB blocking factor; that padding is not a payload.
        let archive = targz_with_trailer(&[("pubspec.yaml", MINIMAL_PUBSPEC)], &[0u8; 9216]);
        assert!(validate(&archive).is_ok(), "honest zero padding must publish");
    }

    #[test]
    fn a_bomb_hidden_in_the_trailer_still_trips_the_limits() {
        // The drain reads through the limiting reader, so the tail cannot be a free
        // decompression budget either.
        let archive = targz_with_trailer(&[("pubspec.yaml", MINIMAL_PUBSPEC)], &vec![0u8; 8 * 1024 * 1024]);
        let capped = ArchiveLimits { max_uncompressed_bytes: 4096, ..limits() };
        assert!(matches!(validate_archive(&archive, &capped), Err(ArchiveError::UncompressedTooLarge { .. })));
    }

    #[test]
    fn rejects_corrupt_tar_inside_valid_gzip() {
        assert_eq!(validate(&gzip(&[0x42u8; 2048])), Err(ArchiveError::MalformedTar));
    }

    #[test]
    fn rejects_non_utf8_captured_files() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "pubspec.yaml", &[0xff, 0xfe][..]).expect("append");
        let archive = gzip(&builder.into_inner().expect("finish"));
        assert!(matches!(validate(&archive), Err(ArchiveError::NotUtf8 { .. })));
    }

    #[test]
    fn every_rejection_maps_to_a_permanent_4xx_domain_error() {
        // docs/protocol.md sharp edge 2: a doomed publish must never look retryable.
        let err: Error = ArchiveError::MissingPubspec.into();
        assert_eq!(err.code(), "invalid_argument");
    }

    #[test]
    fn attacker_controlled_paths_are_clipped_in_messages() {
        let long = format!("{}/../x", "a".repeat(500));
        let err = normalize_path(long.as_bytes()).unwrap_err();
        assert!(err.to_string().len() < 200, "message must stay bounded: {err}");
    }

    #[test]
    fn link_escape_detection_counts_depth() {
        assert!(!link_escapes("lib/alias.dart", "real.dart"));
        assert!(!link_escapes("lib/alias.dart", "../lib/real.dart"));
        assert!(link_escapes("lib/alias.dart", "../../outside"));
        assert!(link_escapes("alias", "../outside"));
        assert!(link_escapes("alias", "/etc/passwd"));
    }
}
