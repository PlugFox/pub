//! Generates `docs/ops/configuration.md` from the config structs and pins it byte-for-byte
//! (roadmap D7: "derive it from the config structs so it cannot drift").
//!
//! The page is the machine-checked twin of the configuration surface, in the spirit of the api
//! crate's `surface.rs` route inventory: it is rendered from two sources that must agree — the
//! struct definitions in `src/lib.rs` (field names, types, serde attributes, and every doc
//! comment, extracted by the small hand parser below) and the serialized
//! [`Settings::default`] (the exact map the defaults layer of `load_from` seeds the config
//! builder with). A field the parser cannot classify, a key present in only one source, or a
//! committed page that differs by one byte each fail the test — which is the point.
//!
//! Regenerate: `UPDATE_CONFIG_REFERENCE=1 cargo test -p pub-config --test reference`
//! (or `just gen`).
//!
//! The parser deliberately understands only the uniform style of this crate's `src/lib.rs`
//! (`///` docs, single-line `pub name: Type,` fields, unit enum variants) and panics on
//! anything else instead of guessing — extending it is part of extending the config surface.
//! It exists so the reference needs no proc-macro machinery (syn/quote) in the tree.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use pub_config::Settings;

// ---------------------------------------------------------------------------
// hand parser over src/lib.rs
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FieldDef {
    docs: Vec<String>,
    name: String,
    ty: String,
    /// Field-level `#[serde(default)]` (today: only `OidcProviderConfig::scopes`).
    field_default: bool,
}

#[derive(Debug)]
struct StructDef {
    docs: Vec<String>,
    /// Container-level `#[serde(default)]` — absent exactly on the array-element structs,
    /// whose fields are therefore required per entry.
    serde_default: bool,
    fields: Vec<FieldDef>,
}

#[derive(Debug)]
struct VariantDef {
    docs: Vec<String>,
    name: String,
    /// `false` for payload-carrying variants (`ConfigError::Source(…)`); documenting a config
    /// field typed by such an enum is a generator error.
    unit: bool,
}

#[derive(Debug)]
struct EnumDef {
    rename_all: Option<String>,
    variants: Vec<VariantDef>,
}

struct Model {
    structs: BTreeMap<String, StructDef>,
    enums: BTreeMap<String, EnumDef>,
}

fn ident_prefix(rest: &str) -> String {
    rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect()
}

fn strip_doc(line: &str) -> Option<String> {
    line.strip_prefix("///").map(|doc| doc.strip_prefix(' ').unwrap_or(doc).to_owned())
}

/// Doc comment and attribute lines directly above a `pub struct`/`pub enum` declaration.
fn docs_and_attrs_above(lines: &[&str], decl: usize) -> (Vec<String>, Vec<String>) {
    let mut docs = Vec::new();
    let mut attrs = Vec::new();
    let mut i = decl;
    while i > 0 {
        let prev = lines[i - 1];
        if prev.starts_with("#[") {
            attrs.push(prev.to_owned());
        } else if let Some(doc) = strip_doc(prev) {
            docs.push(doc);
        } else {
            break;
        }
        i -= 1;
    }
    docs.reverse();
    (docs, attrs)
}

fn parse_struct_body(lines: &[&str], start: usize) -> (Vec<FieldDef>, usize) {
    let mut fields = Vec::new();
    let mut docs: Vec<String> = Vec::new();
    let mut attrs: Vec<String> = Vec::new();
    let mut i = start;
    while lines[i] != "}" {
        let trimmed = lines[i].trim_start();
        if let Some(doc) = strip_doc(trimmed) {
            docs.push(doc);
        } else if trimmed.starts_with("#[") {
            attrs.push(trimmed.to_owned());
        } else if let Some(field) = trimmed.strip_prefix("pub ") {
            let Some((name, ty)) = field.split_once(": ") else {
                panic!("unparseable field line — teach tests/reference.rs to parse it: {trimmed:?}");
            };
            let Some(ty) = ty.strip_suffix(',') else {
                panic!("field line must end with a comma — teach tests/reference.rs otherwise: {trimmed:?}");
            };
            fields.push(FieldDef {
                docs: std::mem::take(&mut docs),
                name: name.to_owned(),
                ty: ty.to_owned(),
                field_default: attrs.iter().any(|attr| attr == "#[serde(default)]"),
            });
            attrs.clear();
        } else if trimmed.is_empty() {
            docs.clear();
            attrs.clear();
        } else {
            panic!("unexpected line inside a struct body — teach tests/reference.rs to parse it: {trimmed:?}");
        }
        i += 1;
    }
    (fields, i + 1)
}

fn parse_enum_body(lines: &[&str], start: usize) -> (Vec<VariantDef>, usize) {
    let mut variants = Vec::new();
    let mut docs: Vec<String> = Vec::new();
    let mut i = start;
    while lines[i] != "}" {
        let trimmed = lines[i].trim_start();
        if let Some(doc) = strip_doc(trimmed) {
            docs.push(doc);
        } else if trimmed.starts_with("#[") {
            // `#[default]`, `#[error(…)]` — variant attributes carry nothing the page renders.
        } else if let Some(variant) = trimmed.strip_suffix(',') {
            let name = ident_prefix(variant);
            assert!(!name.is_empty(), "unparseable enum variant: {trimmed:?}");
            variants.push(VariantDef { docs: std::mem::take(&mut docs), unit: name == variant, name });
        } else if trimmed.is_empty() {
            docs.clear();
        } else {
            panic!("unexpected line inside an enum body — teach tests/reference.rs to parse it: {trimmed:?}");
        }
        i += 1;
    }
    (variants, i + 1)
}

fn parse_lib_rs() -> Model {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let source = std::fs::read_to_string(&path).expect("read src/lib.rs");
    let lines: Vec<&str> = source.lines().collect();
    let mut structs = BTreeMap::new();
    let mut enums = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some(rest) = lines[i].strip_prefix("pub struct ") {
            if rest.contains('(') {
                // Tuple newtype (`Secret`): opaque by design, no fields to document.
                i += 1;
                continue;
            }
            let name = ident_prefix(rest);
            let (docs, attrs) = docs_and_attrs_above(&lines, i);
            let (fields, next) = parse_struct_body(&lines, i + 1);
            let serde_default = attrs.iter().any(|attr| attr == "#[serde(default)]");
            structs.insert(name, StructDef { docs, serde_default, fields });
            i = next;
        } else if let Some(rest) = lines[i].strip_prefix("pub enum ") {
            let name = ident_prefix(rest);
            let (_docs, attrs) = docs_and_attrs_above(&lines, i);
            let rename_all = attrs
                .iter()
                .find_map(|attr| attr.strip_prefix("#[serde(rename_all = \"")?.strip_suffix("\")]").map(str::to_owned));
            let (variants, next) = parse_enum_body(&lines, i + 1);
            enums.insert(name, EnumDef { rename_all, variants });
            i = next;
        } else {
            i += 1;
        }
    }
    Model { structs, enums }
}

// ---------------------------------------------------------------------------
// classification and rendering
// ---------------------------------------------------------------------------

enum LeafKind<'a> {
    String,
    Integer,
    Boolean,
    StringArray,
    Secret,
    Enum(&'a EnumDef, &'a str),
}

enum FieldKind<'a> {
    Leaf { leaf: LeafKind<'a>, optional: bool },
    Table(&'a str),
    ArrayOfTables(&'a str),
}

fn classify<'a>(model: &'a Model, ty: &'a str) -> FieldKind<'a> {
    if let Some(inner) = ty.strip_prefix("Option<").and_then(|t| t.strip_suffix('>')) {
        match classify(model, inner) {
            FieldKind::Leaf { leaf, optional: false } => FieldKind::Leaf { leaf, optional: true },
            _ => panic!("type {ty:?} is not something tests/reference.rs knows how to document"),
        }
    } else if let Some(inner) = ty.strip_prefix("Vec<").and_then(|t| t.strip_suffix('>')) {
        if inner == "String" {
            FieldKind::Leaf { leaf: LeafKind::StringArray, optional: false }
        } else if model.structs.contains_key(inner) {
            FieldKind::ArrayOfTables(inner)
        } else {
            panic!("type {ty:?} is not something tests/reference.rs knows how to document")
        }
    } else {
        match ty {
            "String" => FieldKind::Leaf { leaf: LeafKind::String, optional: false },
            "bool" => FieldKind::Leaf { leaf: LeafKind::Boolean, optional: false },
            "u16" | "u32" | "u64" | "usize" | "i64" => FieldKind::Leaf { leaf: LeafKind::Integer, optional: false },
            "Secret" => FieldKind::Leaf { leaf: LeafKind::Secret, optional: false },
            other if model.enums.contains_key(other) => {
                FieldKind::Leaf { leaf: LeafKind::Enum(&model.enums[other], other), optional: false }
            }
            other if model.structs.contains_key(other) => FieldKind::Table(other),
            other => panic!("type {other:?} is not something tests/reference.rs knows how to document"),
        }
    }
}

/// Doc comments link to the normative docs relative to the crate root (`../../../docs/…`); the
/// generated page lives inside `docs/ops/`, one level below those targets, so the prefix is
/// mechanically rebased. The text is otherwise verbatim.
fn rewrite_links(line: &str) -> String {
    line.replace("](../../../docs/", "](../")
}

fn push_docs(out: &mut String, docs: &[String]) {
    if docs.is_empty() {
        return;
    }
    for line in docs {
        out.push_str(&rewrite_links(line));
        out.push('\n');
    }
    out.push('\n');
}

fn enum_values_label(def: &EnumDef, name: &str) -> String {
    assert_eq!(
        def.rename_all.as_deref(),
        Some("lowercase"),
        "enum {name}: tests/reference.rs only understands #[serde(rename_all = \"lowercase\")]"
    );
    let values: Vec<String> = def
        .variants
        .iter()
        .map(|variant| {
            assert!(variant.unit, "enum {name}: variant {} carries data — not a config enum", variant.name);
            format!("`{}`", variant.name.to_lowercase())
        })
        .collect();
    values.join(" | ")
}

fn push_variants(out: &mut String, def: &EnumDef) {
    out.push_str("Allowed values:\n\n");
    for variant in &def.variants {
        let doc = variant.docs.join(" ");
        if doc.is_empty() {
            let _ = writeln!(out, "- `{}`", variant.name.to_lowercase());
        } else {
            let _ = writeln!(out, "- `{}` — {}", variant.name.to_lowercase(), rewrite_links(&doc));
        }
    }
    out.push('\n');
}

fn render_toml_value(value: &toml::Value) -> String {
    match value {
        toml::Value::String(text) => {
            assert!(!text.contains(['"', '\\']), "default string needs escaping — teach tests/reference.rs: {text:?}");
            format!("\"{text}\"")
        }
        toml::Value::Integer(number) => number.to_string(),
        toml::Value::Boolean(flag) => flag.to_string(),
        toml::Value::Array(items) if items.is_empty() => "[]".to_owned(),
        other => panic!("default value shape tests/reference.rs cannot render: {other:?}"),
    }
}

/// Dotted-path → default value, flattened out of the serialized [`Settings::default`]. `None`
/// fields are absent (the TOML serializer omits them), which is exactly the "no default" the
/// page renders for optional keys.
fn flatten(prefix: &str, value: &toml::Value, out: &mut BTreeMap<String, toml::Value>) {
    if let toml::Value::Table(table) = value {
        for (key, item) in table {
            let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
            flatten(&path, item, out);
        }
    } else {
        out.insert(prefix.to_owned(), value.clone());
    }
}

struct SectionCtx<'a> {
    path: &'a str,
    /// Whether this section is an array-of-tables element (`[[auth.oidc]]`): keys have no env
    /// spelling and no serialized default — they are required (or defaulted) per entry.
    array: bool,
    container_default: bool,
}

fn render_key(
    out: &mut String,
    ctx: &SectionCtx<'_>,
    field: &FieldDef,
    leaf: &LeafKind<'_>,
    optional: bool,
    defaults: &mut BTreeMap<String, toml::Value>,
) {
    let dotted = format!("{}.{}", ctx.path, field.name);
    let key_path = if ctx.array { format!("{}[].{}", ctx.path, field.name) } else { dotted.clone() };

    let type_label = match leaf {
        LeafKind::String => "string".to_owned(),
        LeafKind::Integer => "integer".to_owned(),
        LeafKind::Boolean => "boolean".to_owned(),
        LeafKind::StringArray => "array of strings".to_owned(),
        LeafKind::Secret => "secret".to_owned(),
        LeafKind::Enum(def, name) => enum_values_label(def, name),
    };
    let type_label =
        if optional && !matches!(leaf, LeafKind::Secret) { format!("{type_label} (optional)") } else { type_label };

    // Arrays cannot come from the environment at all: the env layer hands the deserializer a
    // plain string where a sequence is expected (verified — "invalid type: string, expected a
    // sequence"), so such keys are TOML-file only just like array-of-table sections.
    let env_label = if ctx.array || matches!(leaf, LeafKind::StringArray) {
        "TOML file only".to_owned()
    } else {
        format!("`PUB_{}`", dotted.replace('.', "__").to_uppercase())
    };

    let default_label = if ctx.array {
        assert!(
            !ctx.container_default,
            "{key_path}: array-element struct with #[serde(default)] — teach tests/reference.rs its defaults"
        );
        if field.field_default {
            match leaf {
                LeafKind::StringArray => "default: `[]`".to_owned(),
                _ => panic!("{key_path}: field-level #[serde(default)] — only Vec<String> is understood"),
            }
        } else {
            match leaf {
                LeafKind::Secret => "(secret — required)".to_owned(),
                _ => "required".to_owned(),
            }
        }
    } else {
        match leaf {
            LeafKind::Secret => {
                assert!(optional, "{dotted}: a required secret outside an array element — unexpected shape");
                assert!(
                    defaults.remove(&dotted).is_none(),
                    "{dotted}: a secret carries a serialized default — refusing to render it (S-25)"
                );
                if field.docs.join(" ").contains("Required in production") {
                    "(secret — none by default; required in production)".to_owned()
                } else {
                    "(secret — none by default)".to_owned()
                }
            }
            LeafKind::Enum(def, name) => {
                let Some(value) = defaults.remove(&dotted) else {
                    panic!("{dotted}: missing from the serialized Settings::default() — the two sources disagree");
                };
                let toml::Value::String(text) = &value else {
                    panic!("{dotted}: enum default is not a string: {value:?}");
                };
                let known: Vec<String> = def.variants.iter().map(|v| v.name.to_lowercase()).collect();
                assert!(known.contains(text), "{dotted}: default {text:?} is not a variant of {name} — rename drift?");
                format!("default: `{}`", render_toml_value(&value))
            }
            _ => match defaults.remove(&dotted) {
                Some(value) => format!("default: `{}`", render_toml_value(&value)),
                None if optional => "default: none".to_owned(),
                None => {
                    panic!("{dotted}: missing from the serialized Settings::default() — the two sources disagree")
                }
            },
        }
    };

    let _ = writeln!(out, "### `{key_path}`\n");
    let _ = writeln!(out, "{type_label} · {env_label} · {default_label}\n");
    push_docs(out, &field.docs);
    if let LeafKind::Enum(def, _) = leaf {
        push_variants(out, def);
    }
}

fn render_section(
    out: &mut String,
    model: &Model,
    struct_name: &str,
    path: &str,
    field_docs: &[String],
    array: bool,
    defaults: &mut BTreeMap<String, toml::Value>,
) {
    let def = &model.structs[struct_name];
    let header = if array { format!("[[{path}]]") } else { format!("[{path}]") };
    let _ = writeln!(out, "## `{header}`\n");
    // The section intro is the referencing field's doc plus the struct's own doc. When the
    // struct doc opens with the exact field doc (several sections repeat the one-liner and
    // then elaborate), only the superset is rendered — no duplicated first paragraph.
    if def.docs.join("\n").starts_with(&field_docs.join("\n")) {
        push_docs(out, &def.docs);
    } else {
        push_docs(out, field_docs);
        push_docs(out, &def.docs);
    }
    if array {
        out.push_str("*TOML file only: the environment layer cannot express arrays of tables.*\n\n");
    }

    let ctx = SectionCtx { path, array, container_default: def.serde_default };
    let mut subsections: Vec<&FieldDef> = Vec::new();
    for field in &def.fields {
        match classify(model, &field.ty) {
            FieldKind::Table(_) | FieldKind::ArrayOfTables(_) => {
                assert!(!array, "nested table inside an array-of-tables section: {path}.{}", field.name);
                subsections.push(field);
            }
            FieldKind::Leaf { leaf, optional } => render_key(out, &ctx, field, &leaf, optional, defaults),
        }
    }
    // Subsections come after the section's own keys, in declaration order (depth-first).
    for field in subsections {
        let sub_path = format!("{path}.{}", field.name);
        match classify(model, &field.ty) {
            FieldKind::Table(inner) => render_section(out, model, inner, &sub_path, &field.docs, false, defaults),
            FieldKind::ArrayOfTables(inner) => {
                match defaults.remove(&sub_path) {
                    Some(toml::Value::Array(items)) if items.is_empty() => {}
                    other => panic!("{sub_path}: expected an empty array in the serialized defaults, got {other:?}"),
                }
                render_section(out, model, inner, &sub_path, &field.docs, true, defaults);
            }
            FieldKind::Leaf { .. } => unreachable!("subsections only hold table fields"),
        }
    }
}

// ---------------------------------------------------------------------------
// the document
// ---------------------------------------------------------------------------

const GENERATED_HEADER: &str = "<!-- GENERATED by server/crates/config/tests/reference.rs — do not edit. \
Regenerate: just gen (or UPDATE_CONFIG_REFERENCE=1 cargo test -p pub-config --test reference) -->";

const PREAMBLE: &str = "\
# Configuration reference

Every key `pubd` reads at boot, rendered from the config structs in `server/crates/config/src/lib.rs`
and cross-checked against the built-in defaults, so this page cannot drift from the code.
Configuration is layered, lowest to highest precedence: built-in defaults → optional TOML file →
environment → CLI flags ([decision 09](../decisions.md#09--always-compiled-backends-runtime-config-selection)).
The merged result is validated fail-fast at startup — a nonsensical value is a refusal to boot with
a message naming the key, never a silent fallback — and the startup log renders the effective
configuration with every secret masked.

## Conventions

- **Environment variables.** Prefix `PUB_`, `__` separates nesting: `database.pool.max_connections`
  is `PUB_DATABASE__POOL__MAX_CONNECTIONS`.
- **`_FILE` variants.** Any `PUB_*` variable may instead be set as `PUB_*_FILE`, naming a file whose
  contents become the value (trailing newline trimmed) — the Docker/Kubernetes secret-mount
  convention and the preferred way to deliver secrets, since a mounted file answers to filesystem
  permissions while an environment variable leaks through `docker inspect` and
  `/proc/<pid>/environ` ([S-25](../security.md#6-secrets--configuration)). Setting both spellings
  of one key is a startup error.
- **Arrays are TOML-file only.** The environment layer cannot express arrays — neither arrays of
  tables (`[[auth.oidc]]`, `[[auth.jwt.verify_keys]]`) nor plain lists such as
  `auth.allowed_email_domains`; such keys are marked below.
- **CLI flags** are the highest-precedence layer: `--config PATH` (or `PUB_CONFIG`) selects the
  TOML file, `--listen ADDR` overrides `server.listen`, `--public-url URL` overrides
  `server.public_url`, `--replicas N` overrides `cluster.replicas`.
- **Secrets** are marked `secret` and never printed — not on this page, not in the startup
  summary, not in `Debug` output ([S-25](../security.md#6-secrets--configuration)).
  `pubd generate-secrets` emits a ready-to-use production fragment.

";

fn render_reference() -> String {
    let model = parse_lib_rs();
    let document = toml::to_string(&Settings::default()).expect("Settings::default() serializes to TOML");
    let value: toml::Value = toml::from_str(&document).expect("round-trip the defaults document");
    let mut defaults = BTreeMap::new();
    flatten("", &value, &mut defaults);

    let mut out = String::new();
    out.push_str(GENERATED_HEADER);
    out.push_str("\n\n");
    out.push_str(PREAMBLE);

    let settings = &model.structs["Settings"];
    for field in &settings.fields {
        match classify(&model, &field.ty) {
            FieldKind::Table(inner) => {
                render_section(&mut out, &model, inner, &field.name, &field.docs, false, &mut defaults);
            }
            _ => panic!("Settings field {} is not a section struct — teach tests/reference.rs about it", field.name),
        }
    }

    // The anti-drift teeth in the other direction: a serialized default the walk never
    // consumed means the parser is blind to a field and the page would silently omit it.
    assert!(
        defaults.is_empty(),
        "Settings::default() serializes keys the source parser never discovered: {:?}",
        defaults.keys().collect::<Vec<_>>()
    );

    let trimmed = out.trim_end().len();
    out.truncate(trimmed);
    out.push('\n');
    out
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[test]
fn the_committed_reference_matches_the_config_structs_exactly() {
    let rendered = render_reference();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docs/ops/configuration.md");
    if std::env::var_os("UPDATE_CONFIG_REFERENCE").is_some() {
        std::fs::write(&path, rendered).expect("write docs/ops/configuration.md");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "docs/ops/configuration.md could not be read ({err}). Generate it: \
             UPDATE_CONFIG_REFERENCE=1 cargo test -p pub-config --test reference   (or: just gen)"
        )
    });
    // Normalize CRLF on both sides before comparing: the repo carries no .gitattributes, so a
    // `core.autocrlf` checkout rewrites the committed page to CRLF and a raw byte-compare
    // would fail on line 1 with two identical-looking lines. Line *content* is the contract;
    // the checkout's line-ending convention is not.
    let committed = committed.replace("\r\n", "\n");
    let rendered = rendered.replace("\r\n", "\n");
    if committed != rendered {
        let diff = committed
            .lines()
            .zip(rendered.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| format!("first difference at line {}:\n  committed: {a}\n  generated: {b}", i + 1))
            .unwrap_or_else(|| {
                format!(
                    "one file is a prefix of the other ({} vs {} lines)",
                    committed.lines().count(),
                    rendered.lines().count()
                )
            });
        panic!(
            "docs/ops/configuration.md does not match what the config structs generate — the page \
             is generated output, never hand-edited ({diff}).\n\
             Regenerate: UPDATE_CONFIG_REFERENCE=1 cargo test -p pub-config --test reference   (or: just gen)"
        );
    }
}

#[test]
fn the_rendered_reference_pins_layout_and_conventions() {
    // Spot checks in the spirit of pubd's `deterministic_layout_*` tests: if the rendering
    // contract shifts, these fail with a smaller haystack than the whole-page byte diff.
    let rendered = render_reference();
    assert!(rendered.starts_with("<!-- GENERATED by server/crates/config/tests/reference.rs"), "header comment");
    // The [http] section documents itself like any other — nothing is hand-listed.
    assert!(rendered.contains("## `[http]`"), "http section missing");
    assert!(rendered.contains("### `http.max_body_bytes`"), "http keys missing");
    // Env derivation: PUB_ prefix, `__` nesting, straight from the dotted path.
    assert!(rendered.contains("`PUB_DATABASE__POOL__MAX_CONNECTIONS`"), "env derivation");
    // Secrets carry the masked style, never a value; production-required ones say so (S-25).
    assert!(rendered.contains("(secret — none by default; required in production)"), "production secrets");
    assert!(rendered.contains("(secret — none by default)"), "plain secrets");
    // Arrays of tables exist, carry the TOML-only note, and their element keys are spelled out.
    assert!(rendered.contains("## `[[auth.oidc]]`"), "oidc array section");
    assert!(rendered.contains("*TOML file only: the environment layer cannot express arrays of tables.*"));
    assert!(rendered.contains("### `auth.jwt.verify_keys[].kid`"), "array element keys");
    // Enum-typed keys list their allowed values.
    assert!(rendered.contains("`sqlite` | `postgres`"), "enum values");
}
