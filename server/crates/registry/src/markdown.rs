//! README/CHANGELOG rendering: CommonMark → sanitized HTML (S-11).
//!
//! Rendering happens **once, at publish time**, and the result is stored on the immutable
//! version row. That is deliberate: the frontend injects this HTML into the page under a
//! strict CSP with tokens sitting in `localStorage` (decision 03 consequences), so a single
//! escape here is a session-theft primitive. Rendering at read time would additionally mean
//! re-running an attacker's markdown on every page view.
//!
//! Two independent layers, in this order:
//!
//! 1. **comrak with `unsafe_ = false`** — raw HTML in the source is escaped, not passed
//!    through, so `<script>` never becomes a tag in the first place.
//! 2. **ammonia** over comrak's output — an allowlist sanitizer. It exists because layer 1 is
//!    one library's opinion about its own escaping; layer 2 does not care how the HTML was
//!    produced. It also applies the policy bits comrak has no concept of: `rel="nofollow ugc
//!    noopener"` on every link (S-11), `http(s)`/`mailto` schemes only (no `javascript:`, no
//!    `data:`), and absolute image sources only, so a relative `src` cannot be resolved
//!    against our own origin.

use std::sync::LazyLock;

use ammonia::UrlRelative;
use comrak::{Options, markdown_to_html};

/// Longest markdown document rendered. Beyond this the source is truncated: a README is
/// documentation, and an unbounded one is a rendering-cost amplifier.
const MAX_SOURCE_BYTES: usize = 512 * 1024;

/// `rel` forced onto every link (S-11).
const LINK_REL: &str = "nofollow ugc noopener";

/// The sanitizer, built once: ammonia compiles its allowlists on construction.
static SANITIZER: LazyLock<ammonia::Builder<'static>> = LazyLock::new(|| {
    let mut builder = ammonia::Builder::default();
    builder
        .link_rel(Some(LINK_REL))
        // Absolute http(s) only. `Deny` on relative URLs is what stops `src="/api/v1/…"`
        // from being resolved against the instance origin (and `href="//evil.example"` from
        // inheriting our scheme).
        .url_relative(UrlRelative::Deny)
        .url_schemes(["http", "https", "mailto"].into_iter().collect())
        // No inline styles, no ids: both are CSS-injection and DOM-clobbering surface inside
        // a page that also renders our own UI.
        .generic_attributes(["align", "title"].into_iter().collect())
        .rm_tags(["style"]);
    builder
});

/// Renders markdown to sanitized HTML.
///
/// Returns `None` for input that is empty or renders to nothing, so a blank README is stored
/// as SQL `NULL` rather than an empty string.
pub fn render(source: &str) -> Option<String> {
    let source = truncate_on_char_boundary(source, MAX_SOURCE_BYTES);
    if source.trim().is_empty() {
        return None;
    }

    let mut options = Options::default();
    // Layer 1: raw HTML is escaped, never passed through.
    options.render.r#unsafe = false;
    options.render.escape = false;
    options.render.hardbreaks = false;
    // GitHub-flavored markdown as package authors write it.
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    options.extension.footnotes = true;
    // No `header_ids`/`front_matter`: ids would collide with our own DOM, and front matter is
    // not a thing in package READMEs.
    options.parse.smart = false;

    let html = markdown_to_html(source, &options);
    // Layer 2: allowlist sanitizing, independent of what comrak produced.
    let clean = SANITIZER.clean(&html).to_string();
    let trimmed = clean.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) }
}

/// Truncates to at most `max` bytes without splitting a character.
fn truncate_on_char_boundary(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html(source: &str) -> String {
        render(source).unwrap_or_default()
    }

    #[test]
    fn renders_ordinary_markdown() {
        let out = html("# Title\n\nSome *emphasis* and `code`.\n\n- a\n- b\n");
        assert!(out.contains("<h1>Title</h1>"));
        assert!(out.contains("<em>emphasis</em>"));
        assert!(out.contains("<code>code</code>"));
        assert!(out.contains("<li>a</li>"));
    }

    #[test]
    fn renders_gfm_tables_fenced_code_and_task_lists() {
        let out = html("| a | b |\n|---|---|\n| 1 | 2 |\n\n```dart\nvoid main() {}\n```\n\n- [x] done\n");
        assert!(out.contains("<table>"), "{out}");
        assert!(out.contains("void main()"), "{out}");
        // The task-list extension is on so `[x]` does not render as literal text, but the
        // sanitizer drops the `<input>` it emits: form controls have no place in package
        // documentation injected into our own page (S-11). The item text survives.
        assert!(out.contains("done"), "{out}");
        assert!(!out.contains("<input"), "form control survived sanitizing: {out}");
    }

    #[test]
    fn s11_raw_html_never_passes_through() {
        let out = html("<script>alert(document.cookie)</script>\n\nhello\n");
        assert!(!out.contains("<script"), "script tag survived: {out}");
        assert!(!out.contains("alert(document.cookie)") || !out.contains("<script"), "{out}");

        let out = html("<img src=x onerror=\"alert(1)\">\n");
        assert!(!out.contains("onerror"), "event handler survived: {out}");

        let out = html("<iframe src=\"https://evil.example\"></iframe>\n");
        assert!(!out.contains("<iframe"), "iframe survived: {out}");
    }

    #[test]
    fn s11_dangerous_url_schemes_are_dropped() {
        for source in [
            "[click](javascript:alert(1))",
            "[click](JaVaScRiPt:alert(1))",
            "[click](data:text/html;base64,PHNjcmlwdD4=)",
            "[click](vbscript:msgbox)",
        ] {
            let out = html(source);
            assert!(!out.to_lowercase().contains("javascript:"), "{source} → {out}");
            assert!(!out.to_lowercase().contains("data:text/html"), "{source} → {out}");
            assert!(!out.to_lowercase().contains("vbscript:"), "{source} → {out}");
        }
    }

    #[test]
    fn s11_links_carry_nofollow_ugc_noopener() {
        let out = html("[docs](https://example.com/docs)");
        assert!(out.contains("href=\"https://example.com/docs\""), "{out}");
        for token in ["nofollow", "ugc", "noopener"] {
            assert!(out.contains(token), "missing rel token {token}: {out}");
        }
    }

    #[test]
    fn s11_image_sources_are_restricted_to_absolute_http_urls() {
        let out = html("![logo](https://cdn.example.com/logo.png)");
        assert!(out.contains("src=\"https://cdn.example.com/logo.png\""), "{out}");

        // Relative sources would resolve against the instance origin once injected into our
        // page — they must not survive.
        let out = html("![logo](/api/v1/secret)");
        assert!(!out.contains("/api/v1/secret"), "relative src survived: {out}");
        let out = html("![logo](../../etc/passwd)");
        assert!(!out.contains("etc/passwd"), "relative src survived: {out}");
        // Protocol-relative URLs inherit our scheme; ammonia treats them as relative.
        let out = html("![logo](//evil.example/pixel.png)");
        assert!(!out.contains("evil.example"), "protocol-relative src survived: {out}");
    }

    #[test]
    fn s11_style_tags_and_inline_styles_are_removed() {
        let out = html("<style>body{display:none}</style>\n\ntext\n");
        assert!(!out.contains("<style"), "{out}");
        let out = html("<p style=\"position:fixed;top:0\">overlay</p>\n");
        assert!(!out.contains("style="), "{out}");
    }

    #[test]
    fn empty_and_blank_documents_render_to_nothing() {
        assert_eq!(render(""), None);
        assert_eq!(render("   \n\n\t"), None);
        // A document that is *only* stripped markup also collapses to nothing.
        assert_eq!(render("<style>x{}</style>"), None);
    }

    #[test]
    fn oversized_documents_are_truncated_not_rejected() {
        let source = format!("# Title\n\n{}", "word ".repeat(200_000));
        let out = render(&source).expect("renders");
        assert!(out.len() < 2 * MAX_SOURCE_BYTES, "output must stay bounded: {} bytes", out.len());
        assert!(out.contains("<h1>Title</h1>"));
    }

    #[test]
    fn multibyte_truncation_never_splits_a_character() {
        let source = "é".repeat(MAX_SOURCE_BYTES);
        assert!(render(&source).is_some(), "truncation must not panic on a char boundary");
    }
}
