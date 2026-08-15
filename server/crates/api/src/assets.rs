//! Embedded frontend serving (decision 04): the Astro build output is compiled into the
//! binary via `rust-embed`. Unknown API paths return the JSON error envelope; everything else
//! resolves against the build output the way a static host would.
//!
//! Astro emits **directory-style** routes (`/app/search` → `app/search/index.html`) plus one
//! prerendered shell for the client-routed island (`app/index.html`) and a `404.html`. A
//! resolver that only tries the literal path therefore answers the *landing page* for every
//! app deep link, which is a blank marketing page where the SPA should have mounted. The
//! ladder below is what makes a reload of `/app/orgs/acme` behave like the first load:
//!
//! 1. the exact file (`/_astro/App.hash.js`, `/sw.js`);
//! 2. its directory index (`/app/search` → `app/search/index.html`, `/` → `index.html`);
//! 3. its `.html` sibling, for a host that emitted flat files;
//! 4. the app shell for anything under `/app` — @solidjs/router owns those paths in the
//!    browser and renders the in-app 404 itself (`apps/site/src/pages/app/[...rest].astro`);
//! 5. `404.html` with a real **404** status for everything else. A typo outside the app is
//!    not the landing page, and answering 200 would tell crawlers and the service worker that
//!    it is.
//!
//! Every served file also carries its cache tier and a strong `ETag` (D8); HTML documents
//! carry the strict document CSP with startup-computed inline-source hashes, and the root
//! `sw.js` worker entry a policy of its own (S-11) — see [`file_response`],
//! [`content_security_policy`], and [`document_csp`].

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::OnceLock;

use axum::Json;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rust_embed::EmbeddedFile;
use sha2::{Digest as _, Sha256};

use crate::envelope::ErrorEnvelope;

/// Frontend build output. The committed placeholder mirrors the real tree's shape (root page,
/// app shell, 404, one hashed `_astro/` asset, inline script/style stubs, the `sw.js` worker
/// entry) and is overwritten with `web/apps/site/dist` by the Docker build.
#[derive(rust_embed::RustEmbed)]
#[folder = "embedded/"]
struct Assets;

/// Prerendered shell mounting the SolidJS island; the fallback for every client-routed path.
const APP_SHELL: &str = "app/index.html";
/// Static not-found page emitted by the Astro build.
const NOT_FOUND_PAGE: &str = "404.html";
/// Root document, and the last-resort fallback when the build has no dedicated 404 page.
const INDEX: &str = "index.html";

/// Router fallback: JSON 404 for unknown API routes, the embedded frontend for everything else.
///
/// "Unknown API route" is [`crate::hygiene::is_app_api`], the same predicate the S-12 guard and
/// the S-24.g write bucket scope themselves with. It used to be a third hand-written copy of
/// the prefix test, and a fallback that answers the app envelope for a path the guard considers
/// off-plane is precisely how the bare `/api` became reachable unguarded.
pub async fn spa_fallback(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path();
    if crate::hygiene::is_app_api(path) {
        let body = ErrorEnvelope::new("not_found", format!("no route for {path}"));
        return (StatusCode::NOT_FOUND, Json(body)).into_response();
    }
    serve_embedded(path, &method, &headers)
}

fn serve_embedded(path: &str, method: &Method, request_headers: &HeaderMap) -> Response {
    let trimmed = path.trim_matches('/');
    // Defence in depth: rust-embed refuses to escape its folder, but a request that even
    // *contains* a traversal segment is never a legitimate asset path.
    if trimmed.split('/').any(|segment| segment == ".." || segment == ".") {
        return not_found(method, request_headers);
    }

    if trimmed.is_empty() {
        return match Assets::get(INDEX) {
            Some(file) => file_response(INDEX, StatusCode::OK, file, method, request_headers),
            None => not_found(method, request_headers),
        };
    }

    for candidate in [trimmed.to_owned(), format!("{trimmed}/{INDEX}"), format!("{trimmed}.html")] {
        if let Some(file) = Assets::get(&candidate) {
            return file_response(&candidate, StatusCode::OK, file, method, request_headers);
        }
    }

    // Client-side routes under /app resolve to the prerendered shell, which mounts the island;
    // the router then decides whether the path is a screen or the in-app 404.
    if trimmed == "app" || trimmed.starts_with("app/") {
        if let Some(file) = Assets::get(APP_SHELL) {
            return file_response(APP_SHELL, StatusCode::OK, file, method, request_headers);
        }
        // A build without a dedicated app shell (the committed placeholder, a split deployment
        // serving one document) still has to hand the browser *something* that boots.
        if let Some(file) = Assets::get(INDEX) {
            return file_response(INDEX, StatusCode::OK, file, method, request_headers);
        }
    }

    not_found(method, request_headers)
}

/// The static 404 page with a 404 status, or the bare status when the build has none.
fn not_found(method: &Method, request_headers: &HeaderMap) -> Response {
    match Assets::get(NOT_FOUND_PAGE) {
        Some(file) => file_response(NOT_FOUND_PAGE, StatusCode::NOT_FOUND, file, method, request_headers),
        None => match Assets::get(INDEX) {
            Some(file) => file_response(INDEX, StatusCode::NOT_FOUND, file, method, request_headers),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

/// One embedded file as a response: content type, cache tier, strong `ETag` (with `304`
/// handling), and — on HTML documents — the hashed document CSP (S-11).
fn file_response(
    path: &str,
    status: StatusCode,
    file: EmbeddedFile,
    method: &Method,
    request_headers: &HeaderMap,
) -> Response {
    // Strong ETag straight from rust-embed's build-time sha256 — never re-hash file bodies,
    // and never use mtimes: the embedded tree has no reproducible timestamps.
    let etag = format!("\"{}\"", hex(&file.metadata.sha256_hash()));
    let cache = cache_control(path);
    // Computed before the 304 branch on purpose: RFC 9111 §4.3.4 makes the headers of a 304
    // *replace* the stored ones, so a 304 that omitted the CSP would let the outer
    // `if_not_present` API-family layer stamp `default-src 'none'` onto the revalidated
    // document — and every navigation after the first would render the cached page blank.
    let csp = content_security_policy(path);

    // A conditional GET/HEAD whose validator still matches is a 304 — which keeps `ETag`,
    // `Cache-Control`, and the CSP, because the client refreshes its cache entry's metadata
    // from them (S-11: the revalidated document must keep the document policy).
    // Only for 200s: a 404 page's bytes matching is not "your copy of this URL is current".
    if status == StatusCode::OK
        && matches!(*method, Method::GET | Method::HEAD)
        && if_none_match(request_headers).any(|candidate| candidate == etag || candidate == "*")
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        let headers = response.headers_mut();
        if let Ok(value) = HeaderValue::from_str(&etag) {
            headers.insert(header::ETAG, value);
        }
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        if let Some(value) = &csp {
            headers.insert(header::CONTENT_SECURITY_POLICY, value.clone());
        }
        return response;
    }

    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut response = (status, file.data.into_owned()).into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if let Some(value) = csp {
        // Handler-set header wins over the global `if_not_present` API policy: documents get
        // the strict self+hashes policy, the worker its own, instead of `default-src 'none'`.
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

/// The CSP an embedded path answers with, when the API-family default would break it.
///
/// - **HTML documents** get the startup-computed hashed document policy (S-11).
/// - **`sw.js` at the root** — exactly the worker entry the app registers (decision 14), a
///   nested `sw.js` is an ordinary asset — gets a policy of its own, because a service
///   worker's CSP comes from **its own response headers** (CSP3), not from the page that
///   registered it: under the API family's `default-src 'none'` the install-time
///   `cache.addAll(…)` and every runtime `fetch(request)` would be blocked and the worker
///   would never install, silently voiding the offline promise. `connect-src 'self'` is the
///   load-bearing directive (it governs `fetch`/Cache API population for a classic worker);
///   everything else stays at `'none'`.
fn content_security_policy(path: &str) -> Option<HeaderValue> {
    if path.ends_with(".html") {
        Some(document_csp().clone())
    } else if path == "sw.js" {
        Some(HeaderValue::from_static("default-src 'none'; connect-src 'self'"))
    } else {
        None
    }
}

/// The cache tier of an embedded path (D8).
///
/// - `_astro/` carries a content hash in every filename — cacheable forever, immutable.
/// - HTML documents and `sw.js` are the *entry points* that name those hashes; `no-cache`
///   forces revalidation (the ETag makes that a 304, not a re-download), so a deploy is
///   picked up on the next navigation instead of after a year.
/// - Everything else (locales, icons, manifest) changes rarely but is not content-addressed:
///   five minutes bounds the staleness window without hammering the server.
fn cache_control(path: &str) -> &'static str {
    if path.starts_with("_astro/") {
        "public, max-age=31536000, immutable"
    } else if path == "sw.js" || path.ends_with(".html") {
        "no-cache"
    } else {
        "public, max-age=300"
    }
}

/// The candidate validators of an `If-None-Match` header, comma-split, weak prefixes dropped
/// (RFC 9110: `If-None-Match` uses the *weak* comparison, so `W/"x"` matches our strong `"x"`).
fn if_none_match(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(header::IF_NONE_MATCH)
        .into_iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .map(|candidate| candidate.strip_prefix("W/").unwrap_or(candidate))
}

/// Lowercase hex of a digest.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

// ------------------------------------------------------------------------- document CSP (S-11)

static DOCUMENT_CSP: OnceLock<HeaderValue> = OnceLock::new();

/// Forces the document-CSP computation at router construction.
///
/// The scanner treats a malformed embedded document (an unclosed inline block) as a defect
/// worth panicking over; forcing the `OnceLock` here turns that into a **startup** panic
/// instead of a panic on the first HTML request of a running instance.
pub(crate) fn init_document_csp() {
    let _ = document_csp();
}

/// The strict document policy, computed once at startup from whatever build is embedded.
///
/// CSP is *the* compensating control for localStorage tokens (decision 03), so `script-src`
/// carries no `unsafe-inline` — but Astro emits deterministic framework inline bootstraps
/// beyond our one authored anti-FOUC script (decision 14, recorded 2026-08-06). Rather than
/// hardcoding today's hashes and breaking on the next Astro upgrade, every embedded HTML
/// document is scanned for inline `<script>`/`<style>` blocks and their sha256 hashes are
/// emitted into the policy. The placeholder build carries stub inline blocks so the
/// integration suite exercises the same path the real image takes.
fn document_csp() -> &'static HeaderValue {
    DOCUMENT_CSP.get_or_init(|| {
        let policy = document_policy();
        // The policy is assembled from base64 and fixed ASCII — always a valid header value;
        // the fallback only exists so a surprise cannot panic the asset path.
        HeaderValue::from_str(&policy)
            .unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"))
    })
}

/// Builds the full document policy by scanning every embedded HTML file.
///
/// `'self'` everywhere because the app is same-origin by design (decision 04: one binary
/// serves app and API); `img-src` adds `data:` for inlined icons; `object-src 'none'` and
/// `base-uri 'none'` close the classic injection amplifiers; `frame-ancestors 'none'`
/// mirrors `X-Frame-Options: DENY`.
fn document_policy() -> String {
    let mut scripts = BTreeSet::new();
    let mut styles = BTreeSet::new();
    for path in Assets::iter() {
        if !path.ends_with(".html") {
            continue;
        }
        if let Some(file) = Assets::get(&path) {
            let html = String::from_utf8_lossy(&file.data).into_owned();
            collect_inline(&html, "script", &mut scripts);
            collect_inline(&html, "style", &mut styles);
        }
    }
    render_policy(&scripts, &styles)
}

/// Renders the document policy for the given inline-source hashes. Split from
/// [`document_policy`] so the real-build-output test can render a policy over
/// `web/apps/site/dist` with the exact same formatting.
fn render_policy(scripts: &BTreeSet<String>, styles: &BTreeSet<String>) -> String {
    format!(
        "default-src 'self'; script-src 'self'{}; style-src 'self'{}; img-src 'self' data:; \
         font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; \
         object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        hash_sources(scripts),
        hash_sources(styles)
    )
}

/// Renders a hash set as CSP source expressions (` 'sha256-…' 'sha256-…'`).
fn hash_sources(hashes: &BTreeSet<String>) -> String {
    hashes.iter().fold(String::new(), |mut out, hash| {
        let _ = write!(out, " '{hash}'");
        out
    })
}

/// Collects `sha256-…` hashes of every inline `<tag>…</tag>` block in `html`.
///
/// Deliberately dumb: browsers hash the bytes between the tags **exactly as they appear**, so
/// the scanner must not trim, unescape, or normalize anything. `<script>` blocks with a real
/// `src` attribute are external and skipped; a false positive would only add a hash nothing
/// matches (harmless), while a missed block would break the page — so ambiguity resolves
/// toward hashing. It does follow the parser where the parser is the contract, though:
///
/// - tag names are ASCII case-insensitive (`<SCRIPT>` is a script element), so matching runs
///   over a lowercased shadow of the input whose byte offsets are identical (ASCII lowercasing
///   is 1:1 and leaves multi-byte characters untouched) while hashing slices the original;
/// - browsers end the tag name (and the script data) at `</script` followed by whitespace,
///   `/`, or `>` — see [`close_of`];
/// - a `<script`/`<style` block that never closes means the scan — and therefore the policy —
///   would be silently truncated and wrong, so it is a panic: [`init_document_csp`] runs this
///   at startup, where a defective embedded build should refuse to boot.
fn collect_inline(html: &str, tag: &str, out: &mut BTreeSet<String>) {
    let lowered = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let mut at = 0;
    while let Some(found) = lowered[at..].find(&open) {
        let name_end = at + found + open.len();
        let after_name = &lowered[name_end..];
        // `<scripted …>` is a different element; the tag name must end here. `/` is a
        // terminator too (`<script/x>` parses as a script tag), which resolves toward hashing.
        if !(after_name.starts_with(['>', '/']) || after_name.starts_with(char::is_whitespace)) {
            at = name_end;
            continue;
        }
        let Some(gt) = after_name.find('>') else {
            panic!("unterminated <{tag} tag in an embedded HTML document: refusing a truncated CSP scan (S-11)");
        };
        let attributes = &lowered[name_end..name_end + gt];
        let body_start = name_end + gt + 1;
        let Some((body_end, resume)) = close_of(&lowered, body_start, tag) else {
            panic!("unclosed inline <{tag}> block in an embedded HTML document: refusing a truncated CSP scan (S-11)");
        };
        if !(tag == "script" && has_src_attribute(attributes)) {
            let digest = Sha256::digest(&html.as_bytes()[body_start..body_end]);
            out.insert(format!("sha256-{}", B64.encode(digest)));
        }
        at = resume;
    }
}

/// Finds the close tag of `tag` in `lowered` starting at `from`, the way a browser does:
/// `</tag` followed by whitespace, `/`, or `>` ends the element (anything else — `</scriptx` —
/// is content). Returns `(body_end, resume)` — where the hashed bytes stop and where scanning
/// continues after the close tag's `>`.
fn close_of(lowered: &str, from: usize, tag: &str) -> Option<(usize, usize)> {
    let close = format!("</{tag}");
    let mut at = from;
    while let Some(found) = lowered[at..].find(&close) {
        let body_end = at + found;
        let after = &lowered[body_end + close.len()..];
        let terminated = match after.chars().next() {
            Some('>') => true,
            Some(c) => c.is_whitespace() || c == '/',
            // `</script` as the very last bytes: never terminated.
            None => return None,
        };
        if terminated {
            // The close tag may carry whitespace (or a stray slash) before its `>`; without
            // one it is as unclosed as a missing tag.
            let gt = after.find('>')?;
            return Some((body_end, body_end + close.len() + gt + 1));
        }
        at = body_end + close.len();
    }
    None
}

/// Whether the open tag's attribute text carries a real `src` attribute — `src`,
/// case-insensitive, as its own token with optional whitespace around the `=` — rather than a
/// substring of another name (`data-src="…"` must not make a block look external: skipping it
/// would leave an inline script unhashed, and the page would break under its own policy).
fn has_src_attribute(attributes: &str) -> bool {
    let bytes = attributes.as_bytes();
    let mut at = 0;
    while let Some(found) = attributes[at..].find("src") {
        let start = at + found;
        let boundary = start == 0 || bytes[start - 1].is_ascii_whitespace() || bytes[start - 1] == b'/';
        let after = attributes[start + 3..].trim_start();
        if boundary && after.starts_with('=') {
            return true;
        }
        at = start + 3;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_hash(source: &str) -> String {
        format!("sha256-{}", B64.encode(Sha256::digest(source.as_bytes())))
    }

    #[test]
    fn s11_scanner_hashes_inline_blocks_exactly_as_written() {
        let html = "<head><script>\n  boot();\n</script><style>body{color:red}</style></head>";
        let mut scripts = BTreeSet::new();
        let mut styles = BTreeSet::new();
        collect_inline(html, "script", &mut scripts);
        collect_inline(html, "style", &mut styles);
        // The newline and indentation are part of what the browser hashes — no trimming.
        assert_eq!(scripts.into_iter().collect::<Vec<_>>(), vec![expected_hash("\n  boot();\n")]);
        assert_eq!(styles.into_iter().collect::<Vec<_>>(), vec![expected_hash("body{color:red}")]);
    }

    #[test]
    fn s11_external_scripts_are_not_hashed() {
        let mut scripts = BTreeSet::new();
        collect_inline("<script src=\"/_astro/app.js\"></script>", "script", &mut scripts);
        assert!(scripts.is_empty(), "a src= script is external; hashing its empty body would be noise");
    }

    #[test]
    fn s11_scripts_with_attributes_and_multiple_blocks_are_all_hashed() {
        let html = "<script type=\"module\">a()</script><p>text</p><script>b()</script>";
        let mut scripts = BTreeSet::new();
        collect_inline(html, "script", &mut scripts);
        let hashes: Vec<_> = scripts.into_iter().collect();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&expected_hash("a()")));
        assert!(hashes.contains(&expected_hash("b()")));
    }

    #[test]
    fn s11_lookalike_tags_do_not_confuse_the_scanner() {
        let mut scripts = BTreeSet::new();
        collect_inline("<scripted>nope</scripted><script>yes()</script>", "script", &mut scripts);
        assert_eq!(scripts.into_iter().collect::<Vec<_>>(), vec![expected_hash("yes()")]);
    }

    #[test]
    fn s11_tag_matching_is_case_insensitive_and_hashes_the_original_bytes() {
        // HTML tag names are ASCII case-insensitive; a `<SCRIPT>` block executes exactly like
        // a lowercase one, so skipping it would serve an unhashed inline script.
        let mut scripts = BTreeSet::new();
        let mut styles = BTreeSet::new();
        collect_inline("<SCRIPT>Boot();</SCRIPT><Script Type=\"module\">b()</Script>", "script", &mut scripts);
        collect_inline("<STYLE>Body{color:Red}</STYLE>", "style", &mut styles);
        let hashes: Vec<_> = scripts.into_iter().collect();
        assert!(hashes.contains(&expected_hash("Boot();")), "the ORIGINAL bytes are what the browser hashes");
        assert!(hashes.contains(&expected_hash("b()")));
        assert_eq!(styles.into_iter().collect::<Vec<_>>(), vec![expected_hash("Body{color:Red}")]);
    }

    #[test]
    fn s11_close_tags_may_carry_whitespace_or_a_slash_before_the_angle() {
        // Browsers end script data at `</script` + whitespace/`/`/`>`; all three forms close.
        let mut scripts = BTreeSet::new();
        collect_inline("<script>a()</script ><script>b()</script\n><script>c()</script/>", "script", &mut scripts);
        let hashes: Vec<_> = scripts.into_iter().collect();
        for source in ["a()", "b()", "c()"] {
            assert!(hashes.contains(&expected_hash(source)), "block {source:?} was not closed by its end tag");
        }
        // `</scriptx>` is content, not a close tag — the block runs on to the real one.
        let mut run_on = BTreeSet::new();
        collect_inline("<script>a()</scriptx>b()</script>", "script", &mut run_on);
        assert_eq!(run_on.into_iter().collect::<Vec<_>>(), vec![expected_hash("a()</scriptx>b()")]);
    }

    #[test]
    fn s11_data_src_is_not_a_src_attribute() {
        // `contains("src=")` would call this block external and skip its hash — and the page
        // would then break under its own policy. Ambiguity resolves TOWARD hashing.
        let mut scripts = BTreeSet::new();
        collect_inline("<script data-src=\"lazy\">inline()</script>", "script", &mut scripts);
        assert_eq!(scripts.into_iter().collect::<Vec<_>>(), vec![expected_hash("inline()")]);
    }

    #[test]
    fn s11_src_detection_survives_case_and_whitespace() {
        // A real external script stays external however the attribute is spelled…
        for html in [
            "<script src=\"/x.js\"></script>",
            "<script SRC=\"/x.js\"></script>",
            "<script src = \"/x.js\"></script>",
            "<script type=\"module\" src=\"/x.js\"></script>",
        ] {
            let mut scripts = BTreeSet::new();
            collect_inline(html, "script", &mut scripts);
            assert!(scripts.is_empty(), "{html:?} is external and must not be hashed");
        }
        // …while a valueless `src` is ambiguous, and ambiguity resolves toward hashing.
        let mut scripts = BTreeSet::new();
        collect_inline("<script src>maybe()</script>", "script", &mut scripts);
        assert_eq!(scripts.into_iter().collect::<Vec<_>>(), vec![expected_hash("maybe()")]);
    }

    #[test]
    #[should_panic(expected = "unclosed inline <script> block")]
    fn s11_an_unclosed_block_is_a_panic_not_a_truncated_scan() {
        // A truncated scan is a wrong policy: everything after the unclosed block would be
        // silently unhashed. The scan runs at startup (init_document_csp), so this refuses to
        // boot on a defective embedded build instead of shipping a broken CSP.
        let mut scripts = BTreeSet::new();
        collect_inline("<script>first()</script><script>never ends…", "script", &mut scripts);
    }

    #[test]
    #[should_panic(expected = "unterminated <script tag")]
    fn s11_an_unterminated_open_tag_is_a_panic_too() {
        let mut scripts = BTreeSet::new();
        collect_inline("<script type=\"module\" ", "script", &mut scripts);
    }

    #[test]
    fn s11_document_policy_carries_the_placeholder_hashes_and_no_unsafe_inline() {
        let policy = document_policy();
        assert!(policy.starts_with("default-src 'self'; "), "wrong base: {policy}");
        assert!(policy.contains("script-src 'self' 'sha256-"), "no script hash: {policy}");
        assert!(policy.contains("style-src 'self' 'sha256-"), "no style hash: {policy}");
        assert!(!policy.contains("unsafe-inline"), "unsafe-inline defeats S-11: {policy}");
        assert!(policy.contains("frame-ancestors 'none'"));
        assert!(policy.contains("object-src 'none'"));
        assert!(policy.contains("base-uri 'none'"));
    }

    /// Recursively collects every `.html` file under `dir`.
    fn html_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read dist directory") {
            let path = entry.expect("dist entry").path();
            if path.is_dir() {
                html_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "html") {
                out.push(path);
            }
        }
    }

    /// A naive, deliberately independent re-scan: lowercased search, first `>` ends the open
    /// tag, first `</tag>` ends the block, whitespace-split token check for `src`. It shares
    /// no helper with [`collect_inline`], so a production-scanner bug cannot hide inside a
    /// shared assumption. Returns the hashes of the inline blocks it finds.
    fn naive_inline_hashes(html: &str, tag: &str) -> Vec<String> {
        let lowered = html.to_ascii_lowercase();
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        let mut hashes = Vec::new();
        let mut at = 0;
        while let Some(found) = lowered[at..].find(&open) {
            let name_end = at + found + open.len();
            let next = lowered.as_bytes().get(name_end).copied();
            if !matches!(next, Some(b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/')) {
                at = name_end;
                continue;
            }
            let Some(gt) = lowered[name_end..].find('>') else { break };
            let attributes = &lowered[name_end..name_end + gt];
            let body_start = name_end + gt + 1;
            let Some(end) = lowered[body_start..].find(&close) else { break };
            let external = tag == "script"
                && attributes.split_whitespace().any(|token| token == "src" || token.starts_with("src="));
            if !external {
                let digest = Sha256::digest(&html.as_bytes()[body_start..body_start + end]);
                hashes.push(format!("sha256-{}", B64.encode(digest)));
            }
            at = body_start + end + close.len();
        }
        hashes
    }

    #[test]
    fn s11_real_astro_build_output_is_fully_covered_by_the_scanner() {
        // The only automated bridge between the scanner and the real frontend build: run the
        // production scanner over `web/apps/site/dist/*.html` and assert that every inline
        // block a naive independent re-scan finds is covered by a hash in the rendered policy.
        // Skips cleanly when the build output is absent (run `bun run build` in web/apps/site
        // to produce it); CI builds the frontend, so the bridge holds there.
        let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../web/apps/site/dist");
        if !dist.is_dir() {
            eprintln!("skipping: {} is absent — build the frontend to exercise this test", dist.display());
            return;
        }
        let mut files = Vec::new();
        html_files(&dist, &mut files);
        assert!(!files.is_empty(), "a dist directory without documents is not a build");

        let mut scripts = BTreeSet::new();
        let mut styles = BTreeSet::new();
        for file in &files {
            let html = std::fs::read_to_string(file).expect("read dist document");
            collect_inline(&html, "script", &mut scripts);
            collect_inline(&html, "style", &mut styles);
        }
        let policy = render_policy(&scripts, &styles);

        for file in &files {
            let html = std::fs::read_to_string(file).expect("read dist document");
            for tag in ["script", "style"] {
                for hash in naive_inline_hashes(&html, tag) {
                    assert!(
                        policy.contains(&format!("'{hash}'")),
                        "inline <{tag}> block in {} is not hashed into the policy — the real build \
                         would break under its own CSP (S-11): {policy}",
                        file.display()
                    );
                }
            }
        }
    }

    #[test]
    fn cache_tiers_match_the_asset_classes() {
        assert_eq!(cache_control("_astro/App.3xk2.js"), "public, max-age=31536000, immutable");
        assert_eq!(cache_control("index.html"), "no-cache");
        assert_eq!(cache_control("app/index.html"), "no-cache");
        assert_eq!(cache_control("sw.js"), "no-cache");
        assert_eq!(cache_control("manifest.webmanifest"), "public, max-age=300");
        assert_eq!(cache_control("locales/en.json"), "public, max-age=300");
        // Only the top-level worker is an entry point; a nested sw.js is an ordinary asset.
        assert_eq!(cache_control("vendor/sw.js"), "public, max-age=300");
    }

    #[test]
    fn s11_the_worker_entry_gets_its_own_policy_and_ordinary_assets_none() {
        let worker = content_security_policy("sw.js").expect("the root worker needs a policy of its own");
        let worker = worker.to_str().unwrap().to_owned();
        // `connect-src 'self'` is the load-bearing directive: it is what lets install-time
        // `cache.addAll('/', '/app/')` and runtime `fetch(request)` reach this origin.
        assert!(worker.contains("connect-src 'self'"), "{worker}");
        assert_ne!(worker, "default-src 'none'; frame-ancestors 'none'", "the API policy blocks the worker");
        assert!(content_security_policy("index.html").is_some(), "documents carry the hashed policy");
        // Only the top-level worker is the registered entry; everything else keeps the API
        // family's `if_not_present` default.
        assert!(content_security_policy("vendor/sw.js").is_none());
        assert!(content_security_policy("_astro/App.3xk2.js").is_none());
        assert!(content_security_policy("manifest.webmanifest").is_none());
    }

    #[test]
    fn if_none_match_splits_lists_and_drops_weak_prefixes() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("W/\"abc\", \"def\""));
        let candidates: Vec<_> = if_none_match(&headers).collect();
        assert_eq!(candidates, vec!["\"abc\"", "\"def\""]);
    }
}
