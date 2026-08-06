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
    assert!(summary.contains("server.mode          = dev"));
    assert!(summary.contains("database.kind        = sqlite"));
    assert!(summary.contains("blob.kind            = fs"));
    assert!(summary.contains("kv.kind              = memory"));
    assert!(summary.contains("cluster.replicas     = 1"));
    assert!(summary.contains("smtp                 = <unset — in-memory mailer>"));
}

// --- auth section ---

/// A valid base64-encoded 32-byte Ed25519 seed.
fn seed_b64() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

#[test]
fn auth_defaults_match_security_doc() {
    let settings = load_from(&CliArgs::default(), no_env()).unwrap();
    assert_eq!(settings.server.mode, RunMode::Dev);
    assert_eq!(settings.auth.access_ttl_minutes, 15); // S-07
    assert_eq!(settings.auth.refresh_idle_days, 30); // decision 03
    assert_eq!(settings.auth.refresh_absolute_days, 90);
    assert_eq!(settings.auth.otp_pepper, None);
    assert_eq!(settings.auth.token_prefix, "pub_"); // decision 17
    assert!(settings.auth.allow_registration);
    assert!(settings.auth.allowed_email_domains.is_empty()); // S-31: empty = allow all
    assert_eq!(settings.auth.rate_limit.otp_per_email_hour, 5); // S-24
    assert_eq!(settings.auth.rate_limit.otp_per_ip_hour, 20); // S-24
    assert_eq!(settings.auth.rate_limit.login_per_ip_minute, 10); // S-24
    assert_eq!(settings.smtp.port, 587);
    assert_eq!(settings.smtp.security, SmtpSecurityMode::Starttls);
}

#[test]
fn production_mode_requires_pepper_and_signing_key() {
    // Missing both.
    let err = load_from(&CliArgs::default(), env(&[("PUB_SERVER__MODE", "production")])).unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("otp_pepper")), "unexpected: {err}");
    // Pepper present, key still missing.
    let err = load_from(
        &CliArgs::default(),
        env(&[("PUB_SERVER__MODE", "production"), ("PUB_AUTH__OTP_PEPPER", "long-random-pepper")]),
    )
    .unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("signing_key")), "unexpected: {err}");
    // Pepper + key present, KEK still missing (S-05/S-25).
    let err = load_from(
        &CliArgs::default(),
        env(&[
            ("PUB_SERVER__MODE", "production"),
            ("PUB_AUTH__OTP_PEPPER", "long-random-pepper"),
            ("PUB_AUTH__JWT__KID", "2026-08"),
            ("PUB_AUTH__JWT__SIGNING_KEY", &seed_b64()),
        ]),
    )
    .unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("kek")), "unexpected: {err}");
    // Everything present passes.
    let settings = load_from(
        &CliArgs::default(),
        env(&[
            ("PUB_SERVER__MODE", "production"),
            ("PUB_AUTH__OTP_PEPPER", "long-random-pepper"),
            ("PUB_AUTH__JWT__KID", "2026-08"),
            ("PUB_AUTH__JWT__SIGNING_KEY", &seed_b64()),
            ("PUB_AUTH__KEK", &seed_b64()),
        ]),
    )
    .unwrap();
    assert_eq!(settings.server.mode, RunMode::Production);
    assert_eq!(settings.auth.jwt.kid.as_deref(), Some("2026-08"));
}

#[test]
fn kek_must_be_32_base64_bytes() {
    // Not base64.
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__KEK", "!!not-base64!!")])).unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("base64")), "unexpected: {err}");
    // Wrong length.
    use base64::Engine as _;
    let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__KEK", &short)])).unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("32 bytes")), "unexpected: {err}");
    // Valid value passes and is masked in the summary (S-25).
    let good = seed_b64();
    let settings = load_from(&CliArgs::default(), env(&[("PUB_AUTH__KEK", &good)])).unwrap();
    let summary = settings.summary();
    assert!(!summary.contains(&good), "kek leaked:\n{summary}");
    assert!(summary.contains("auth.kek             = ***"), "kek mask missing:\n{summary}");
}

#[test]
fn s06_step_up_window_is_bounded() {
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__STEP_UP_MINUTES", "0")])).unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("S-06")), "unexpected: {err}");
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__STEP_UP_MINUTES", "999999")])).unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));
    let settings = load_from(&CliArgs::default(), no_env()).unwrap();
    assert_eq!(settings.auth.step_up_minutes, 15, "S-06 default window");
}

#[test]
fn oidc_providers_are_validated_and_secrets_masked() {
    use crate::OidcProviderConfig;

    let provider = |id: &str, issuer: &str| OidcProviderConfig {
        id: id.to_owned(),
        display_name: "Corp IdP".to_owned(),
        issuer: issuer.to_owned(),
        client_id: "client-1".to_owned(),
        client_secret: Secret::new("oidc-secret-value"),
        scopes: Vec::new(),
    };

    // A valid provider passes and its secret never reaches the summary (S-25).
    let mut settings = load_from(&CliArgs::default(), no_env()).unwrap();
    settings.auth.oidc = vec![provider("google", "https://accounts.google.com")];
    settings.validate().expect("valid provider");
    let summary = settings.summary();
    assert!(!summary.contains("oidc-secret-value"), "client secret leaked:\n{summary}");
    assert!(summary.contains("accounts.google.com"), "issuer should be listed:\n{summary}");

    // Bad slug.
    settings.auth.oidc = vec![provider("Bad Slug!", "https://idp.corp.example")];
    assert!(settings.validate().is_err());
    // Duplicate ids.
    settings.auth.oidc = vec![provider("corp", "https://idp.corp.example"), provider("corp", "https://other.example")];
    assert!(settings.validate().is_err());
    // Empty client secret (confidential client, S-01).
    let mut anonymous = provider("corp", "https://idp.corp.example");
    anonymous.client_secret = Secret::new("");
    settings.auth.oidc = vec![anonymous];
    assert!(settings.validate().is_err());
    // http issuer is a dev convenience; production demands https (S-01).
    settings.auth.oidc = vec![provider("corp", "http://idp.corp.example")];
    settings.validate().expect("http allowed in dev");
    settings.server.mode = RunMode::Production;
    settings.auth.otp_pepper = Some(Secret::new("pepper"));
    settings.auth.kek = Some(Secret::new(seed_b64()));
    settings.auth.jwt.kid = Some("k1".to_owned());
    settings.auth.jwt.signing_key = Some(Secret::new(seed_b64()));
    assert!(settings.validate().is_err(), "http issuer must fail in production");
    settings.auth.oidc = vec![provider("corp", "https://idp.corp.example")];
    settings.validate().expect("https issuer passes in production");
    // Explicit scopes must include openid.
    let mut scoped = provider("corp", "https://idp.corp.example");
    scoped.scopes = vec!["email".to_owned()];
    settings.auth.oidc = vec![scoped];
    assert!(settings.validate().is_err());
}

#[test]
fn dev_mode_allows_missing_auth_secrets() {
    let settings = load_from(&CliArgs::default(), no_env()).unwrap();
    assert_eq!(settings.auth.otp_pepper, None);
    assert_eq!(settings.auth.jwt.signing_key, None);
}

#[test]
fn access_ttl_above_15_minutes_is_rejected() {
    // S-07: access TTL ≤ 15 min is normative.
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__ACCESS_TTL_MINUTES", "16")])).unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("S-07")), "unexpected: {err}");
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__ACCESS_TTL_MINUTES", "0")])).unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));
}

#[test]
fn refresh_windows_must_be_ordered() {
    let err = load_from(
        &CliArgs::default(),
        env(&[("PUB_AUTH__REFRESH_IDLE_DAYS", "90"), ("PUB_AUTH__REFRESH_ABSOLUTE_DAYS", "30")]),
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));
}

#[test]
fn malformed_signing_key_is_rejected() {
    // Not base64.
    let err = load_from(
        &CliArgs::default(),
        env(&[("PUB_AUTH__JWT__KID", "k1"), ("PUB_AUTH__JWT__SIGNING_KEY", "!!not-base64!!")]),
    )
    .unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("base64")), "unexpected: {err}");
    // Wrong decoded length.
    use base64::Engine as _;
    let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
    let err =
        load_from(&CliArgs::default(), env(&[("PUB_AUTH__JWT__KID", "k1"), ("PUB_AUTH__JWT__SIGNING_KEY", &short)]))
            .unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("32 bytes")), "unexpected: {err}");
    // Key without a kid.
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__JWT__SIGNING_KEY", &seed_b64())])).unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("kid")), "unexpected: {err}");
}

#[test]
fn verify_keys_load_from_toml_and_reject_duplicates() {
    let seed = seed_b64();
    let file = toml_file(&format!(
        "[auth.jwt]\nkid = \"gen2\"\nsigning_key = \"{seed}\"\n\
         [[auth.jwt.verify_keys]]\nkid = \"gen1\"\nkey = \"{seed}\"\n"
    ));
    let cli = CliArgs { config: Some(file.path().to_path_buf()), ..CliArgs::default() };
    let settings = load_from(&cli, no_env()).unwrap();
    assert_eq!(settings.auth.jwt.verify_keys.len(), 1);
    assert_eq!(settings.auth.jwt.verify_keys[0].kid, "gen1");

    // Duplicate kid across signing and verify keys is rejected.
    let dup = toml_file(&format!(
        "[auth.jwt]\nkid = \"gen1\"\nsigning_key = \"{seed}\"\n\
         [[auth.jwt.verify_keys]]\nkid = \"gen1\"\nkey = \"{seed}\"\n"
    ));
    let cli = CliArgs { config: Some(dup.path().to_path_buf()), ..CliArgs::default() };
    let err = load_from(&cli, no_env()).unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("unique")), "unexpected: {err}");
}

#[test]
fn token_prefix_shape_is_enforced() {
    for bad in ["pub", "_", "PUB_", "pu b_", ""] {
        let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__TOKEN_PREFIX", bad)])).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "accepted token_prefix {bad:?}");
    }
    let settings = load_from(&CliArgs::default(), env(&[("PUB_AUTH__TOKEN_PREFIX", "acme_")])).unwrap();
    assert_eq!(settings.auth.token_prefix, "acme_");
}

#[test]
fn zero_rate_limits_are_rejected() {
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__RATE_LIMIT__OTP_PER_EMAIL_HOUR", "0")])).unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));
}

// --- smtp section ---

#[test]
fn smtp_username_without_password_is_rejected() {
    let err =
        load_from(&CliArgs::default(), env(&[("PUB_SMTP__HOST", "smtp.corp.com"), ("PUB_SMTP__USERNAME", "mailer")]))
            .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));
}

#[test]
fn smtp_full_config_is_accepted_and_summary_masks_password() {
    let settings = load_from(
        &CliArgs::default(),
        env(&[
            ("PUB_SMTP__HOST", "smtp.corp.com"),
            ("PUB_SMTP__PORT", "465"),
            ("PUB_SMTP__SECURITY", "tls"),
            ("PUB_SMTP__USERNAME", "mailer"),
            // May come via env only for now; becomes a KEK-encrypted runtime setting later (S-26).
            ("PUB_SMTP__PASSWORD", "smtp-secret-value"),
            ("PUB_SMTP__FROM", "Pub <noreply@corp.com>"),
        ]),
    )
    .unwrap();
    assert_eq!(settings.smtp.host.as_deref(), Some("smtp.corp.com"));
    assert_eq!(settings.smtp.port, 465);
    assert_eq!(settings.smtp.security, SmtpSecurityMode::Tls);
    let summary = settings.summary();
    assert!(!summary.contains("smtp-secret-value"), "smtp password leaked:\n{summary}");
    assert!(summary.contains("smtp.password        = ***"));
}

#[test]
fn s25_file_suffixed_env_reads_mounted_secrets() {
    let mut pepper = tempfile::NamedTempFile::new().unwrap();
    // Written the way `echo` would: the trailing newline must not become part of the pepper.
    pepper.write_all(b"pepper-from-a-mounted-file\n").unwrap();
    let settings =
        load_from(&CliArgs::default(), env(&[("PUB_AUTH__OTP_PEPPER_FILE", pepper.path().to_str().unwrap())])).unwrap();
    assert_eq!(settings.auth.otp_pepper.as_ref().map(Secret::expose), Some("pepper-from-a-mounted-file"));
    // …and the mounted value never reaches the summary.
    assert!(settings.summary().contains("auth.otp_pepper      = ***"));
}

#[test]
fn s25_file_suffixed_env_fails_loudly() {
    // Unreadable path: fail fast rather than boot with no pepper.
    let err = load_from(&CliArgs::default(), env(&[("PUB_AUTH__OTP_PEPPER_FILE", "/nonexistent/pepper")])).unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("could not be read")), "unexpected: {err}");

    // Both forms set: ambiguous, so refuse instead of guessing.
    let mut pepper = tempfile::NamedTempFile::new().unwrap();
    pepper.write_all(b"from-file").unwrap();
    let err = load_from(
        &CliArgs::default(),
        env(&[("PUB_AUTH__OTP_PEPPER", "from-env"), ("PUB_AUTH__OTP_PEPPER_FILE", pepper.path().to_str().unwrap())]),
    )
    .unwrap_err();
    assert!(matches!(&err, ConfigError::Invalid(m) if m.contains("pick one")), "unexpected: {err}");
}

#[test]
fn s25_no_secret_survives_a_debug_dump_of_the_settings() {
    // The summary is the *intended* human output and is already masked. This asserts the
    // other half of S-25: a stray `{:?}` — a config dump, a `#[instrument]` field, a panic
    // message — must not be able to print a pepper, a signing seed, or a password either.
    let settings = load_from(
        &CliArgs::default(),
        env(&[
            ("PUB_DATABASE__KIND", "postgres"),
            ("PUB_DATABASE__URL", "postgres://pub:db-secret-value@localhost/pub"),
            ("PUB_KV__KIND", "redis"),
            ("PUB_KV__URL", "redis://:kv-secret-value@localhost:6379"),
            ("PUB_BLOB__KIND", "s3"),
            ("PUB_BLOB__BUCKET", "pub-blobs"),
            ("PUB_BLOB__ACCESS_KEY", "access-secret-value"),
            ("PUB_BLOB__SECRET_KEY", "blob-secret-value"),
            ("PUB_AUTH__OTP_PEPPER", "pepper-secret-value"),
            ("PUB_AUTH__JWT__KID", "2026-08"),
            ("PUB_AUTH__JWT__SIGNING_KEY", &seed_b64()),
            ("PUB_SMTP__HOST", "smtp.corp.com"),
            ("PUB_SMTP__USERNAME", "mailer"),
            ("PUB_SMTP__PASSWORD", "smtp-secret-value"),
        ]),
    )
    .unwrap();

    let dumped = format!("{settings:?}");
    for secret in [
        "db-secret-value",
        "kv-secret-value",
        "access-secret-value",
        "blob-secret-value",
        "pepper-secret-value",
        "smtp-secret-value",
        &seed_b64(),
    ] {
        assert!(!dumped.contains(secret), "secret {secret:?} leaked into Debug output:\n{dumped}");
    }
    // Non-secret context stays debuggable, otherwise the redaction is useless in practice.
    assert!(dumped.contains("2026-08"), "kid is public metadata and must survive:\n{dumped}");
    assert!(dumped.contains("smtp.corp.com"), "hostnames must survive:\n{dumped}");
}

#[test]
fn s25_secret_newtype_has_no_display_and_a_redacting_debug() {
    let secret = Secret::new("pepper-secret-value");
    assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
    assert_eq!(format!("{:?}", Some(secret.clone())), "Some(Secret(<redacted>))");
    assert_eq!(secret.expose(), "pepper-secret-value");
    assert!(Secret::new("").is_empty());
}

#[test]
fn s24_trusted_proxy_is_off_by_default_and_configurable() {
    // Default-deny: an operator must opt in before X-Forwarded-For is believed.
    assert!(!load_from(&CliArgs::default(), no_env()).unwrap().server.trust_proxy_headers);
    let behind_proxy = load_from(&CliArgs::default(), env(&[("PUB_SERVER__TRUST_PROXY_HEADERS", "true")])).unwrap();
    assert!(behind_proxy.server.trust_proxy_headers);
    assert!(behind_proxy.summary().contains("server.trust_proxy   = true"));
}

#[test]
fn summary_masks_auth_secrets() {
    let settings = load_from(
        &CliArgs::default(),
        env(&[
            ("PUB_AUTH__OTP_PEPPER", "super-secret-pepper"),
            ("PUB_AUTH__JWT__KID", "2026-08"),
            ("PUB_AUTH__JWT__SIGNING_KEY", &seed_b64()),
        ]),
    )
    .unwrap();
    let summary = settings.summary();
    assert!(!summary.contains("super-secret-pepper"), "pepper leaked:\n{summary}");
    assert!(!summary.contains(&seed_b64()), "signing key leaked:\n{summary}");
    assert!(summary.contains("auth.otp_pepper      = ***"));
    assert!(summary.contains("auth.jwt.kid         = 2026-08"), "kid is not a secret:\n{summary}");
}
