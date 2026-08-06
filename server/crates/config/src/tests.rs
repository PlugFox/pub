//! Unit tests: layer precedence, defaults, validation corner cases, secret masking.
//!
//! All tests inject an explicit env map through [`load_from`] instead of mutating process
//! env vars, so they are parallel-safe and immune to ambient `PUB_*` variables.

use std::io::Write as _;

use super::*;

fn env(pairs: &[(&str, &str)]) -> Option<config::Map<String, String>> {
    Some(pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect())
}

fn no_env() -> Option<config::Map<String, String>> {
    Some(config::Map::new())
}

fn toml_file(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().suffix(".toml").tempfile().expect("create temp toml");
    file.write_all(contents.as_bytes()).expect("write temp toml");
    file
}

// --- defaults ---

#[test]
fn defaults_load_without_any_sources() {
    let settings = load_from(&CliArgs::default(), no_env()).unwrap();
    assert_eq!(settings.server.listen, "0.0.0.0:8080");
    assert_eq!(settings.server.public_url, "http://localhost:8080");
    assert_eq!(settings.database.kind, DatabaseKind::Sqlite);
    assert_eq!(settings.database.path, "data/pub.sqlite3");
    assert_eq!(settings.blob.kind, BlobKind::Fs);
    assert_eq!(settings.blob.path, "data/blobs");
    assert_eq!(settings.kv.kind, KvKind::Memory);
    assert!(!settings.telemetry.prometheus);
    assert!(!settings.telemetry.otlp);
    assert_eq!(settings.cluster.replicas, 1);
}

// --- precedence ---

#[test]
fn file_overrides_defaults() {
    let file = toml_file("[server]\nlisten = \"127.0.0.1:1111\"\n");
    let cli = CliArgs { config: Some(file.path().to_path_buf()), ..CliArgs::default() };
    let settings = load_from(&cli, no_env()).unwrap();
    assert_eq!(settings.server.listen, "127.0.0.1:1111");
    // Untouched values keep their defaults.
    assert_eq!(settings.database.kind, DatabaseKind::Sqlite);
}

#[test]
fn env_overrides_file() {
    let file = toml_file("[server]\nlisten = \"127.0.0.1:1111\"\npublic_url = \"https://from-file.example\"\n");
    let cli = CliArgs { config: Some(file.path().to_path_buf()), ..CliArgs::default() };
    let settings = load_from(&cli, env(&[("PUB_SERVER__LISTEN", "127.0.0.1:2222")])).unwrap();
    // Env wins over the file…
    assert_eq!(settings.server.listen, "127.0.0.1:2222");
    // …while file values without an env override survive.
    assert_eq!(settings.server.public_url, "https://from-file.example");
}

#[test]
fn cli_overrides_env() {
    let cli = CliArgs { listen: Some("127.0.0.1:3333".to_owned()), ..CliArgs::default() };
    let settings = load_from(&cli, env(&[("PUB_SERVER__LISTEN", "127.0.0.1:2222")])).unwrap();
    assert_eq!(settings.server.listen, "127.0.0.1:3333");
}

#[test]
fn nested_env_keys_use_double_underscore() {
    let settings = load_from(
        &CliArgs::default(),
        env(&[
            ("PUB_DATABASE__KIND", "postgres"),
            ("PUB_DATABASE__URL", "postgres://pub@localhost/pub"),
            ("PUB_CLUSTER__REPLICAS", "1"),
        ]),
    )
    .unwrap();
    assert_eq!(settings.database.kind, DatabaseKind::Postgres);
    assert_eq!(settings.database.url.as_deref(), Some("postgres://pub@localhost/pub"));
}

#[test]
fn missing_explicit_config_file_is_an_error() {
    let cli = CliArgs { config: Some("/nonexistent/pub-config.toml".into()), ..CliArgs::default() };
    assert!(matches!(load_from(&cli, no_env()), Err(ConfigError::Source(_))));
}

// --- unknown kinds ---

#[test]
fn unknown_database_kind_is_an_error() {
    let err = load_from(&CliArgs::default(), env(&[("PUB_DATABASE__KIND", "mysql")])).unwrap_err();
    assert!(matches!(err, ConfigError::Source(_)), "unexpected: {err}");
}

#[test]
fn unknown_blob_kind_is_an_error() {
    let err = load_from(&CliArgs::default(), env(&[("PUB_BLOB__KIND", "ftp")])).unwrap_err();
    assert!(matches!(err, ConfigError::Source(_)), "unexpected: {err}");
}

#[test]
fn unknown_kv_kind_is_an_error() {
    let err = load_from(&CliArgs::default(), env(&[("PUB_KV__KIND", "memcached")])).unwrap_err();
    assert!(matches!(err, ConfigError::Source(_)), "unexpected: {err}");
}

// --- validation corner cases ---

#[test]
fn replicas_above_one_with_memory_kv_is_rejected() {
    // Decision 03: scaling out is gated on the Redis KV backend.
    let cli = CliArgs { replicas: Some(2), ..CliArgs::default() };
    let err = load_from(&cli, no_env()).unwrap_err();
    match err {
        ConfigError::Invalid(message) => {
            assert!(message.contains("redis"), "message must point at the fix: {message}");
            assert!(message.contains("decision 03"), "message must cite the decision: {message}");
        }
        other => panic!("expected Invalid, got: {other}"),
    }
}

#[test]
fn replicas_above_one_with_redis_kv_is_accepted() {
    let cli = CliArgs { replicas: Some(3), ..CliArgs::default() };
    let settings =
        load_from(&cli, env(&[("PUB_KV__KIND", "redis"), ("PUB_KV__URL", "redis://localhost:6379")])).unwrap();
    assert_eq!(settings.cluster.replicas, 3);
    assert_eq!(settings.kv.kind, KvKind::Redis);
}

#[test]
fn zero_replicas_is_rejected() {
    let cli = CliArgs { replicas: Some(0), ..CliArgs::default() };
    assert!(matches!(load_from(&cli, no_env()), Err(ConfigError::Invalid(_))));
}

#[test]
fn postgres_without_url_is_rejected() {
    let err = load_from(&CliArgs::default(), env(&[("PUB_DATABASE__KIND", "postgres")])).unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)), "unexpected: {err}");
}

#[test]
fn s3_without_bucket_is_rejected() {
    let err = load_from(&CliArgs::default(), env(&[("PUB_BLOB__KIND", "s3")])).unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)), "unexpected: {err}");
}

#[test]
fn s3_with_bucket_is_accepted() {
    let settings =
        load_from(&CliArgs::default(), env(&[("PUB_BLOB__KIND", "s3"), ("PUB_BLOB__BUCKET", "pub-blobs")])).unwrap();
    assert_eq!(settings.blob.kind, BlobKind::S3);
    assert_eq!(settings.blob.bucket.as_deref(), Some("pub-blobs"));
}

#[test]
fn redis_without_url_is_rejected() {
    let err = load_from(&CliArgs::default(), env(&[("PUB_KV__KIND", "redis")])).unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)), "unexpected: {err}");
}

#[test]
fn invalid_listen_address_is_rejected() {
    let cli = CliArgs { listen: Some("not-an-address".to_owned()), ..CliArgs::default() };
    assert!(matches!(load_from(&cli, no_env()), Err(ConfigError::Invalid(_))));
}

// --- summary & masking ---

#[test]
fn summary_masks_database_password() {
    let settings = load_from(
        &CliArgs::default(),
        env(&[("PUB_DATABASE__KIND", "postgres"), ("PUB_DATABASE__URL", "postgres://pub:supersecret@localhost/pub")]),
    )
    .unwrap();
    let summary = settings.summary();
    assert!(!summary.contains("supersecret"), "password leaked:\n{summary}");
    assert!(summary.contains("***"), "mask missing:\n{summary}");
    assert!(summary.contains("database.kind        = postgres"));
}

#[test]
fn summary_masks_s3_secret_key() {
    let settings = load_from(
        &CliArgs::default(),
        env(&[
            ("PUB_BLOB__KIND", "s3"),
            ("PUB_BLOB__BUCKET", "pub-blobs"),
            ("PUB_BLOB__ACCESS_KEY", "AKIAEXAMPLE"),
            ("PUB_BLOB__SECRET_KEY", "verysecretvalue"),
        ]),
    )
    .unwrap();
    let summary = settings.summary();
    assert!(!summary.contains("verysecretvalue"), "secret leaked:\n{summary}");
    assert!(!summary.contains("AKIAEXAMPLE"), "access key leaked:\n{summary}");
}

#[test]
fn summary_masks_redis_password() {
    let settings = load_from(
        &CliArgs::default(),
        env(&[("PUB_KV__KIND", "redis"), ("PUB_KV__URL", "redis://:redispass@localhost:6379")]),
    )
    .unwrap();
    let summary = settings.summary();
    assert!(!summary.contains("redispass"), "password leaked:\n{summary}");
}

#[test]
fn summary_lists_defaults() {
    let summary = load_from(&CliArgs::default(), no_env()).unwrap().summary();
    assert!(summary.contains("server.listen        = 0.0.0.0:8080"));
    assert!(summary.contains("database.kind        = sqlite"));
    assert!(summary.contains("blob.kind            = fs"));
    assert!(summary.contains("kv.kind              = memory"));
    assert!(summary.contains("cluster.replicas     = 1"));
}
