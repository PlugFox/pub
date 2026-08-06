//! Cursor pagination envelope (docs/rules/rust.md: cursor pagination only, never offsets).

use serde::{Deserialize, Serialize};

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
