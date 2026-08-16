//! The [`BlobStore`] contract, run against every backend an operator can configure
//! ([decision 35](../../../../docs/decisions.md#35--backend-legs-that-fail-when-the-backend-is-absent-and-a-harness-that-admits-a-race)).
//!
//! The memory and filesystem legs run on every `cargo test`. The S3 leg runs against a real
//! server (MinIO locally through the `s3` compose profile, a service container in CI) when
//! `PUB_TEST_S3_ENDPOINT` is exported, and **panics** when neither it nor `PUB_TEST_NO_S3`
//! is set.
//!
//! Two things this leg exists for, beyond running the same assertions one backend further:
//!
//! - **A missing bucket is not a missing backend.** They are different failures and must not
//!   present the same way, so the leg pings before it asserts and says which one happened.
//! - **The presigned URL is dialled, not merely constructed.** The unit tests beside the
//!   implementation prove a signature moves when the method does; only a server can prove
//!   that S3 *refuses* the mismatch. Wave 6 found that by hand against live MinIO — a
//!   `GET`-signed URL is answered `403 SignatureDoesNotMatch` to the `HEAD` the pub client
//!   sends before every archive fetch, which every test in this repository was blind to. This
//!   is that finding, made repeatable.

use bytes::Bytes;
use futures::TryStreamExt as _;
use pub_blob::ObjectStoreBlob;
use pub_config::{BlobConfig, BlobKind, Secret};
use pub_core::traits::{BlobStore, DownloadMethod, DownloadPlan};
use pub_test_support::{Gate, S3};

/// A key space nothing else is using: the S3 leg shares one bucket with every other test in
/// this binary and with every previous run against the same MinIO.
fn root() -> String {
    format!("contract/{}", pub_core::UserId::new())
}

async fn collect(plan: DownloadPlan) -> Vec<u8> {
    match plan {
        DownloadPlan::Stream(stream) => {
            let chunks: Vec<Bytes> = stream.try_collect().await.expect("stream the object");
            chunks.concat()
        }
        DownloadPlan::Redirect(url) => panic!("expected streamed bytes, got a redirect to {url}"),
    }
}

// -------------------------------------------------------------------------- the contract

/// Bytes come back exactly as they went in, through both read paths.
///
/// Byte-stability is the registry's central promise ([sharp edge 3](../../../../docs/protocol.md)):
/// the key *is* the content hash, so a backend that transforms bytes in transit breaks every
/// `pubspec.lock` in the ecosystem, not merely one download.
async fn round_trip(blob: &dyn BlobStore, root: &str) {
    let key = format!("{root}/ab/abcd.tar.gz");
    let bytes = Bytes::from_static(b"\x1f\x8b\x08\x00tarball bytes\x00\xff");

    blob.put(&key, bytes.clone()).await.expect("put");
    assert_eq!(collect(blob.download(&key, DownloadMethod::Get).await.expect("download")).await, bytes);
    assert_eq!(blob.get(&key).await.expect("in-process read"), bytes, "`get` is the finalizer's path and must agree");
}

/// A key that is not there is [`pub_core::Error::NotFound`] — never empty bytes, never a
/// generic backend error. The publish finalizer and the S-19 re-verification both branch on it.
async fn missing_key_is_not_found(blob: &dyn BlobStore, root: &str) {
    let err = blob.download(&format!("{root}/ab/absent.tar.gz"), DownloadMethod::Get).await.expect_err("absent");
    assert_eq!(err.code(), "not_found", "got {err}");
    let err = blob.get(&format!("{root}/ab/absent.tar.gz")).await.expect_err("absent");
    assert_eq!(err.code(), "not_found", "got {err}");
    assert!(blob.head(&format!("{root}/ab/absent.tar.gz")).await.expect("head answers").is_none());
}

/// Deletion is idempotent: a retried hard delete and a second GC sweep must both succeed.
async fn deletion_is_idempotent(blob: &dyn BlobStore, root: &str) {
    let key = format!("{root}/cd/cdef.tar.gz");
    blob.put(&key, Bytes::from_static(b"bytes")).await.expect("put");
    blob.delete(&key).await.expect("first delete");
    blob.delete(&key).await.expect("second delete must be a no-op, not an error");
    blob.delete(&format!("{root}/cd/never-existed.tar.gz")).await.expect("deleting an absent key is not an error");
}

/// Enumeration, both shapes the byte collectors need: the recursive walk, and the delimited
/// one-level listing that yields shard prefixes plus whatever sits outside them.
///
/// The age is part of the contract rather than a nicety — the publish pipeline writes bytes
/// before the version row, so a fresh blob is legitimately unreferenced and a collector that
/// cannot tell its age cannot be run at all ([decision 31](../../../../docs/decisions.md)).
async fn enumeration(blob: &dyn BlobStore, root: &str) {
    blob.put(&format!("{root}/ab/abcd.tar.gz"), Bytes::from_static(b"12345")).await.expect("put");
    blob.put(&format!("{root}/cd/cdef.tar.gz"), Bytes::from_static(b"123")).await.expect("put");
    blob.put(&format!("{root}/stray.txt"), Bytes::from_static(b"outside every shard")).await.expect("put");

    let mut listed = blob.list(&format!("{root}/")).await.expect("recursive list");
    listed.sort_by(|a, b| a.key.cmp(&b.key));
    assert_eq!(listed.len(), 3, "the recursive walk descends into shards: {listed:?}");
    assert_eq!(listed[0].key, format!("{root}/ab/abcd.tar.gz"));
    assert_eq!(listed[0].size, 5);
    assert!(listed[0].last_modified.is_some(), "a collector needs an age to respect its grace period");

    let mut listing = blob.list_prefixes(&format!("{root}/")).await.expect("delimited list");
    listing.prefixes.sort();
    assert_eq!(listing.prefixes, [format!("{root}/ab/"), format!("{root}/cd/")], "the delimiter is included, always");
    assert_eq!(listing.objects.len(), 1, "only the key inside no shard: {listing:?}");
    assert_eq!(listing.objects[0].key, format!("{root}/stray.txt"));

    let empty = blob.list_prefixes(&format!("{root}/nothing/")).await.expect("empty prefix");
    assert!(empty.prefixes.is_empty() && empty.objects.is_empty());
}

/// `head` reports size and age for what is there and `None` for what is not — the collectors'
/// re-read before a delete, where "somebody deleted it first" is an ordinary outcome.
async fn head_reports_metadata(blob: &dyn BlobStore, root: &str) {
    let key = format!("{root}/ef/efab.tar.gz");
    blob.put(&key, Bytes::from_static(b"12345")).await.expect("put");
    let found = blob.head(&key).await.expect("head").expect("present");
    assert_eq!(found.key, key);
    assert_eq!(found.size, 5);
    assert!(found.last_modified.is_some());
}

/// Every property above, over one backend.
async fn full_contract(blob: &dyn BlobStore) {
    blob.ping().await.expect("ping");
    let root = root();
    round_trip(blob, &root).await;
    missing_key_is_not_found(blob, &root).await;
    deletion_is_idempotent(blob, &root).await;
    enumeration(blob, &root).await;
    head_reports_metadata(blob, &root).await;
}

// -------------------------------------------------------------------------- local legs

#[tokio::test]
async fn memory_backend() {
    full_contract(&ObjectStoreBlob::memory()).await;
}

#[tokio::test]
async fn fs_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = BlobConfig { path: dir.path().join("blobs").to_string_lossy().into_owned(), ..BlobConfig::default() };
    full_contract(&ObjectStoreBlob::fs(&cfg).expect("open the fs store")).await;
}

// -------------------------------------------------------------------------- s3 leg

/// The gated S3 configuration; `None` when the operator opted out of this backend.
fn s3_config(test: &str, presign: bool) -> Option<BlobConfig> {
    let endpoint = match S3.gate(test) {
        Gate::Run(endpoint) => endpoint,
        Gate::Skipped => return None,
    };
    let (access_key, secret_key, bucket) = pub_test_support::s3_credentials();
    Some(BlobConfig {
        kind: BlobKind::S3,
        bucket: Some(bucket),
        endpoint: Some(endpoint),
        access_key: Some(Secret::new(access_key)),
        secret_key: Some(Secret::new(secret_key)),
        presign,
        ..BlobConfig::default()
    })
}

/// Builds the store and proves the bucket is usable **before** any contract assertion, so a
/// server that is not running, credentials that are wrong and a bucket that was never created
/// surface as one legible failure here instead of as a confusing one three properties deep.
///
/// The store's own error is quoted rather than classified: `object_store` reports the
/// unreachable case as a transport error after its retries and the missing-bucket case as a
/// `404 NoSuchBucket` in milliseconds, which tells the reader which of the two happened
/// without this function claiming to know.
async fn s3_store(test: &str, presign: bool) -> Option<ObjectStoreBlob> {
    let cfg = s3_config(test, presign)?;
    let endpoint = cfg.endpoint.clone().unwrap_or_default();
    let bucket = cfg.bucket.clone().unwrap_or_default();
    let blob = ObjectStoreBlob::s3(&cfg).expect("configure the s3 store");
    if let Err(err) = blob.ping().await {
        panic!(
            "{test}: bucket '{bucket}' at {endpoint} is not usable: {err}\n\
             \n\
             Start the server and create the bucket:\n\
             \x20 docker compose -f docker/docker-compose.yml --profile s3 up -d   (s3-init makes the bucket)\n\
             Or point PUB_TEST_S3_ENDPOINT / PUB_TEST_S3_BUCKET / PUB_TEST_S3_ACCESS_KEY /\n\
             PUB_TEST_S3_SECRET_KEY at a server and bucket that exist.\n\
             \n\
             This is not the same failure as `PUB_TEST_S3_ENDPOINT` being unset, and decision 35 says\n\
             the two must not present the same way: an absent backend is a leg nobody asked to run, a\n\
             broken one is a leg that ran and could not."
        );
    }
    Some(blob)
}

#[tokio::test]
async fn s3_backend() {
    let Some(blob) = s3_store("s3_backend", false).await else { return };
    full_contract(&blob).await;
}

/// **S-18.a / decision 34.** The presigned URL is fetched, and the method it was signed for is
/// the only method it answers.
///
/// This is the assertion nothing offline can make. `presigning_signs_the_method_the_caller_will_use`
/// (beside the implementation) proves the signature *changes* with the method; that a mismatch
/// is **refused** is S3's behaviour, not ours, and the pub client's pre-fetch `HEAD` is what
/// makes it matter: sign one method for both and every cache probe on the S3 backend fails
/// while every test in this repository stays green.
#[tokio::test]
async fn s3_presigned_urls_answer_only_the_method_they_were_signed_for() {
    let Some(blob) = s3_store("s3_presigned_urls_answer_only_the_method_they_were_signed_for", true).await else {
        return;
    };
    let key = format!("{}/ab/presigned.tar.gz", root());
    let bytes = Bytes::from_static(b"presigned tarball bytes");
    blob.put(&key, bytes.clone()).await.expect("put");

    let DownloadPlan::Redirect(get_url) = blob.download(&key, DownloadMethod::Get).await.expect("plan a GET") else {
        panic!("blob.presign is on: the plan must be a redirect");
    };
    let DownloadPlan::Redirect(head_url) = blob.download(&key, DownloadMethod::Head).await.expect("plan a HEAD") else {
        panic!("blob.presign is on: the plan must be a redirect");
    };

    let client = reqwest::Client::new();
    let fetched = client.get(get_url.clone()).send().await.expect("dial the signed GET url");
    assert_eq!(fetched.status(), reqwest::StatusCode::OK, "a GET-signed url must serve the bytes");
    assert_eq!(fetched.bytes().await.expect("body"), bytes, "the client fetches the archive, not a rewrite of it");

    let probed = client.head(head_url).send().await.expect("dial the signed HEAD url");
    assert_eq!(probed.status(), reqwest::StatusCode::OK, "a HEAD-signed url must answer the client's cache probe");

    let mismatched = client.head(get_url).send().await.expect("dial the GET url with HEAD");
    assert_eq!(
        mismatched.status(),
        reqwest::StatusCode::FORBIDDEN,
        "S3 refuses a method the signature does not cover — this is why `download` takes one"
    );
}
