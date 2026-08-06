//! Cursor pagination envelope (docs/rules/rust.md: cursor pagination only, never offsets)
//! and the shared keyset-cursor codec.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Byte joining the components of a composite keyset cursor. ASCII unit separator: it cannot
/// occur in any cursor component we build (ids, semver sort keys, package names).
const CURSOR_SEPARATOR: char = '\u{1f}';

/// One page of a cursor-paginated listing.
///
/// The cursor is an opaque string the caller feeds back verbatim to fetch the next page; it is
/// `Some` exactly when [`Page::has_more`] is true. Cursors are keyset-based, so pages stay
/// stable under concurrent inserts (no skipped or duplicated items for already-read ranges).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// Items of this page, in the listing's documented order.
    pub items: Vec<T>,
    /// Opaque continuation cursor; `None` on the last page.
    pub cursor: Option<String>,
    /// Whether more items exist past this page.
    pub has_more: bool,
}

impl<T> Page<T> {
    /// A page with nothing in it (empty listing).
    pub const fn empty() -> Self {
        Self { items: Vec::new(), cursor: None, has_more: false }
    }
}

/// Encodes the components of a keyset position into one opaque cursor token.
///
/// Multi-column keysets (`(sort_key, id)`, `(name, id)`) need every component to resume
/// exactly where the previous page stopped. Base64url keeps the token URL-safe and signals
/// "opaque, do not parse" to clients — the encoding is an implementation detail both database
/// backends share, so cursors are portable across them.
pub fn encode_cursor(parts: &[&str]) -> String {
    B64URL.encode(parts.join(&CURSOR_SEPARATOR.to_string()))
}

/// Decodes a cursor produced by [`encode_cursor`], requiring exactly `arity` components.
///
/// Every failure mode — bad base64, non-UTF-8 bytes, wrong component count — is
/// [`Error::Invalid`]: a cursor is caller-supplied input, and a malformed one must be a clean
/// 400, never a database error or a silently reset listing.
pub fn decode_cursor(cursor: &str, arity: usize) -> Result<Vec<String>> {
    let invalid = || Error::Invalid { message: format!("malformed cursor: {cursor}") };
    let raw = B64URL.decode(cursor).map_err(|_| invalid())?;
    let text = String::from_utf8(raw).map_err(|_| invalid())?;
    let parts: Vec<String> = text.split(CURSOR_SEPARATOR).map(ToOwned::to_owned).collect();
    if parts.len() != arity {
        return Err(invalid());
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips_every_component() {
        let cursor = encode_cursor(&["00000000000000000001.1", "0192f0a0-0000-7000-8000-000000000000"]);
        let parts = decode_cursor(&cursor, 2).unwrap();
        assert_eq!(parts[0], "00000000000000000001.1");
        assert_eq!(parts[1], "0192f0a0-0000-7000-8000-000000000000");
    }

    #[test]
    fn cursor_is_url_safe_and_opaque() {
        let cursor = encode_cursor(&["a/b+c", "d?e=f"]);
        assert!(cursor.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "not URL-safe: {cursor}");
        assert_eq!(decode_cursor(&cursor, 2).unwrap(), vec!["a/b+c".to_owned(), "d?e=f".to_owned()]);
    }

    #[test]
    fn malformed_cursors_are_invalid_argument() {
        for (raw, arity) in [("!!!not-base64!!!", 2), ("", 2), (encode_cursor(&["only-one"]).as_str(), 2)] {
            let err = decode_cursor(raw, arity).unwrap_err();
            assert_eq!(err.code(), "invalid_argument", "accepted {raw:?}");
        }
        // Valid base64 over non-UTF-8 bytes.
        let bad = B64URL.encode([0xff, 0xfe]);
        assert_eq!(decode_cursor(&bad, 1).unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn empty_page_has_no_cursor() {
        let page: Page<u8> = Page::empty();
        assert!(page.items.is_empty());
        assert_eq!(page.cursor, None);
        assert!(!page.has_more);
    }
}
