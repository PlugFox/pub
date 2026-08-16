//! Blob storage backends over `object_store` (decision 10).
//!
//! One implementation struct wraps any [`object_store::ObjectStore`]; constructors select
//! LocalFileSystem, InMemory, or an S3-compatible store from configuration. Downloads return
//! [`DownloadPlan::Stream`] for fs/memory and, when `blob.presign` is on, a
//! [`DownloadPlan::Redirect`] to a presigned URL for S3
//! ([decision 34](../../../../docs/decisions.md)).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path as ObjectPath;
use object_store::signer::Signer;
use object_store::{ObjectStore, ObjectStoreExt as _};
use pub_config::{BlobConfig, BlobKind};
use pub_core::traits::{BlobObject, BlobStore, DownloadMethod, DownloadPlan, PrefixListing};
use pub_core::{Error, Result};

/// The signing half of an S3 backend that answers downloads with redirects.
///
/// The signer is kept separately from the data store because they may be *different stores*: a
/// deployment whose object store sits at a private address (`http://s3:9000` in this
/// repository's own compose file) signs with a second `AmazonS3` built for
/// `blob.public_endpoint`. SigV4 covers the `host` header, so an already-signed URL cannot have
/// its origin rewritten afterwards — the public address has to be known at signing time.
#[derive(Debug)]
struct Presign {
    signer: Arc<dyn Signer>,
    ttl: Duration,
}

/// [`BlobStore`] backed by any `object_store` implementation.
#[derive(Debug)]
pub struct ObjectStoreBlob {
    kind: BlobKind,
    store: Arc<dyn ObjectStore>,
    /// `Some` only for S3 with `blob.presign` on; every other backend always streams.
    presign: Option<Presign>,
}

impl ObjectStoreBlob {
    /// In-memory store — tests and throwaway instances only.
    pub fn memory() -> Self {
        Self { kind: BlobKind::Memory, store: Arc::new(InMemory::new()), presign: None }
    }

    /// Local filesystem store rooted at `blob.path` (created if missing).
    pub fn fs(cfg: &BlobConfig) -> Result<Self> {
        std::fs::create_dir_all(&cfg.path)
            .map_err(|err| Error::Blob { message: format!("failed to create blob directory {}: {err}", cfg.path) })?;
        let store = LocalFileSystem::new_with_prefix(&cfg.path)
            .map_err(|err| Error::Blob { message: format!("failed to open blob directory {}: {err}", cfg.path) })?;
        Ok(Self { kind: BlobKind::Fs, store: Arc::new(store), presign: None })
    }

    /// S3-compatible store (AWS S3, MinIO) from configuration.
    pub fn s3(cfg: &BlobConfig) -> Result<Self> {
        let bucket = cfg
            .bucket
            .as_deref()
            .ok_or_else(|| Error::Config { message: "blob.kind = s3 requires blob.bucket".to_owned() })?;

        let store = Arc::new(build_s3(cfg, bucket, cfg.endpoint.as_deref())?);
        let presign = cfg
            .presign
            .then(|| -> Result<Presign> {
                // A second store only when the public address differs; otherwise the data store
                // already signs for the host clients will dial.
                let signer: Arc<dyn Signer> = match cfg.public_endpoint.as_deref() {
                    Some(public) => Arc::new(build_s3(cfg, bucket, Some(public))?),
                    None => Arc::clone(&store) as Arc<dyn Signer>,
                };
                Ok(Presign { signer, ttl: Duration::from_secs(cfg.presign_ttl_secs) })
            })
            .transpose()?;

        Ok(Self { kind: BlobKind::S3, store: store as Arc<dyn ObjectStore>, presign })
    }

    /// The configured backend kind (reported by `/healthz`).
    pub fn kind(&self) -> BlobKind {
        self.kind
    }

    /// Whether this backend answers downloads with presigned redirects.
    pub fn presigns(&self) -> bool {
        self.presign.is_some()
    }
}

/// One `AmazonS3` from the config, against `endpoint`.
///
/// Called twice when `blob.public_endpoint` is set — same bucket, same region, same
/// credentials, different host — so it takes the endpoint rather than reading `cfg.endpoint`.
fn build_s3(cfg: &BlobConfig, bucket: &str, endpoint: Option<&str>) -> Result<AmazonS3> {
    let mut builder = AmazonS3Builder::from_env()
        .with_bucket_name(bucket)
        .with_region(cfg.region.clone().unwrap_or_else(|| "us-east-1".to_owned()));
    if let Some(endpoint) = endpoint {
        // Custom endpoints are typically MinIO on plain HTTP inside a private network.
        builder = builder.with_endpoint(endpoint).with_allow_http(true);
    }
    if let Some(access_key) = &cfg.access_key {
        builder = builder.with_access_key_id(access_key.expose());
    }
    if let Some(secret_key) = &cfg.secret_key {
        builder = builder.with_secret_access_key(secret_key.expose());
    }
    builder.build().map_err(|err| Error::Blob { message: format!("failed to configure s3 blob store: {err}") })
}

/// The method a presigned URL is signed for.
///
/// Load-bearing: SigV4 signs the method, so a `GET` URL answers `SignatureDoesNotMatch` to the
/// `HEAD` the pub client sends before every archive fetch.
fn http_method(method: DownloadMethod) -> http::Method {
    match method {
        DownloadMethod::Get => http::Method::GET,
        DownloadMethod::Head => http::Method::HEAD,
    }
}

#[async_trait]
impl BlobStore for ObjectStoreBlob {
    async fn ping(&self) -> Result<()> {
        // Listing the root with a delimiter is cheap on every backend and proves reachability.
        self.store.list_with_delimiter(None).await.map_err(blob_err)?;
        Ok(())
    }

    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        self.store.put(&ObjectPath::from(key), bytes.into()).await.map_err(blob_err)?;
        Ok(())
    }

    /// Presigned redirect when signing is configured and succeeds, streamed bytes otherwise.
    ///
    /// **Signing failure falls back to streaming rather than failing the download.** A
    /// credential provider that cannot answer is an outage of the signing path, not of the
    /// download path; the bytes still arrive, more slowly, and the fallback is counted and
    /// logged so it does not present as "S3 egress vanished and the app tier got busy".
    ///
    /// Nothing here checks that the object exists first: signing is offline, and a `head`
    /// before every archive `GET` *and* every client cache probe would be two round trips per
    /// download to improve the diagnosis of a store that has lost bytes a live version row
    /// still references ([decision 34](../../../../docs/decisions.md)).
    async fn download(&self, key: &str, method: DownloadMethod) -> Result<DownloadPlan> {
        let path = ObjectPath::from(key);
        if let Some(presign) = &self.presign {
            match presign.signer.signed_url(http_method(method), &path, presign.ttl).await {
                Ok(url) => {
                    metrics::counter!("archive_presign_total", "outcome" => "signed").increment(1);
                    return Ok(DownloadPlan::Redirect(url));
                }
                Err(err) => {
                    metrics::counter!("archive_presign_total", "outcome" => "failed").increment(1);
                    tracing::warn!(
                        key,
                        error = %err,
                        "presigning failed; streaming this archive through the app process instead"
                    );
                }
            }
        }
        let result = self.store.get(&path).await.map_err(blob_err)?;
        let stream = result.into_stream().map(|chunk| chunk.map_err(blob_err)).boxed();
        Ok(DownloadPlan::Stream(stream))
    }

    /// Direct read rather than the trait's stream-draining default: `object_store` hands back
    /// the whole object in one call, and this override is what keeps in-process reads working
    /// on a presigning S3 backend — the default drains a plan, and a plan here is a redirect.
    async fn get(&self, key: &str) -> Result<Bytes> {
        let result = self.store.get(&ObjectPath::from(key)).await.map_err(blob_err)?;
        result.bytes().await.map_err(blob_err)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        match self.store.delete(&ObjectPath::from(key)).await {
            // Idempotent by contract: a retried hard delete or a GC pass over an already
            // cleaned store must not fail.
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(err) => Err(blob_err(err)),
        }
    }

    /// Recursive listing under `prefix`, streamed (the byte collectors' enumeration path).
    ///
    /// `object_store`'s `list` already walks every level below the prefix and already hands
    /// back a stream, so this is a rename of the item type and nothing else: nothing here
    /// collects, because the caller's whole reason for streaming is that the key space may not
    /// fit in memory.
    fn list_stream<'a>(&'a self, prefix: &'a str) -> BoxStream<'a, Result<BlobObject>> {
        let path = ObjectPath::from(prefix);
        self.store
            .list(Some(&path))
            .map(|meta| {
                let meta = meta.map_err(blob_err)?;
                Ok(BlobObject {
                    key: meta.location.as_ref().to_owned(),
                    size: meta.size,
                    last_modified: Some(meta.last_modified),
                })
            })
            .boxed()
    }

    /// One level below `prefix`: the shard directories, and anything sitting outside them.
    ///
    /// This is the delimited listing — the one the recursive walk above deliberately is not.
    /// `object_store` spells a common prefix without its trailing delimiter, so it is added
    /// back here: the caller concatenates it with a key and must not have to know which
    /// backend's convention it is holding.
    async fn list_prefixes(&self, prefix: &str) -> Result<PrefixListing> {
        let path = ObjectPath::from(prefix);
        let listing = self.store.list_with_delimiter(Some(&path)).await.map_err(blob_err)?;
        Ok(PrefixListing {
            prefixes: listing.common_prefixes.iter().map(|child| format!("{}/", child.as_ref())).collect(),
            objects: listing
                .objects
                .into_iter()
                .map(|meta| BlobObject {
                    key: meta.location.as_ref().to_owned(),
                    size: meta.size,
                    last_modified: Some(meta.last_modified),
                })
                .collect(),
        })
    }

    /// Current metadata for one key; `None` when it is gone.
    ///
    /// A missing object is an answer, not a failure: the collectors call this on a key they
    /// are about to delete, and "somebody deleted it first" is the ordinary outcome of a
    /// retried hard delete or a second sweep.
    async fn head(&self, key: &str) -> Result<Option<BlobObject>> {
        match self.store.head(&ObjectPath::from(key)).await {
            Ok(meta) => Ok(Some(BlobObject {
                key: meta.location.as_ref().to_owned(),
                size: meta.size,
                last_modified: Some(meta.last_modified),
            })),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(err) => Err(blob_err(err)),
        }
    }
}

fn blob_err(err: object_store::Error) -> Error {
    match err {
        object_store::Error::NotFound { path, .. } => Error::NotFound { what: format!("blob {path}") },
        other => Error::Blob { message: other.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;

    use super::*;

    async fn collect(plan: DownloadPlan) -> Vec<u8> {
        match plan {
            DownloadPlan::Stream(stream) => {
                let chunks: Vec<Bytes> = stream.try_collect().await.unwrap();
                chunks.concat()
            }
            DownloadPlan::Redirect(url) => panic!("expected a stream, got redirect to {url}"),
        }
    }

    #[tokio::test]
    async fn memory_put_download_round_trip() {
        let blob = ObjectStoreBlob::memory();
        blob.put("sha256/abc", Bytes::from_static(b"tarball bytes")).await.unwrap();
        let plan = blob.download("sha256/abc", DownloadMethod::Get).await.unwrap();
        assert_eq!(collect(plan).await, b"tarball bytes");
    }

    #[tokio::test]
    async fn fs_put_download_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BlobConfig { path: dir.path().join("blobs").to_string_lossy().into_owned(), ..BlobConfig::default() };
        let blob = ObjectStoreBlob::fs(&cfg).unwrap();
        blob.put("sha256/def", Bytes::from_static(b"fs bytes")).await.unwrap();
        let plan = blob.download("sha256/def", DownloadMethod::Get).await.unwrap();
        assert_eq!(collect(plan).await, b"fs bytes");
    }

    #[tokio::test]
    async fn missing_key_maps_to_not_found() {
        let blob = ObjectStoreBlob::memory();
        let err = blob.download("sha256/missing", DownloadMethod::Get).await.unwrap_err();
        assert_eq!(err.code(), "not_found");
    }

    #[tokio::test]
    async fn delete_removes_the_object_and_is_idempotent() {
        let blob = ObjectStoreBlob::memory();
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"bytes")).await.unwrap();
        blob.delete("pub/ab/abcd.tar.gz").await.unwrap();
        assert_eq!(blob.download("pub/ab/abcd.tar.gz", DownloadMethod::Get).await.unwrap_err().code(), "not_found");
        // Deleting an absent key is not an error (hard-delete retries, GC sweeps).
        blob.delete("pub/ab/abcd.tar.gz").await.unwrap();
    }

    #[tokio::test]
    async fn fs_delete_removes_the_object_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BlobConfig { path: dir.path().join("blobs").to_string_lossy().into_owned(), ..BlobConfig::default() };
        let blob = ObjectStoreBlob::fs(&cfg).unwrap();
        blob.put("pub/cd/cdef.tar.gz", Bytes::from_static(b"bytes")).await.unwrap();
        blob.delete("pub/cd/cdef.tar.gz").await.unwrap();
        assert_eq!(blob.download("pub/cd/cdef.tar.gz", DownloadMethod::Get).await.unwrap_err().code(), "not_found");
        blob.delete("pub/cd/cdef.tar.gz").await.unwrap();
    }

    #[tokio::test]
    async fn list_walks_shards_and_reports_sizes() {
        // GC enumerates content-addressed keys, which are sharded two levels deep — a
        // delimiter-based listing would hand back directories and no objects.
        let blob = ObjectStoreBlob::memory();
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"12345")).await.unwrap();
        blob.put("pub/cd/cdef.tar.gz", Bytes::from_static(b"123")).await.unwrap();
        blob.put("uploads/pub/session.tar.gz", Bytes::from_static(b"staged")).await.unwrap();

        let mut listed = blob.list("pub/").await.unwrap();
        listed.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(listed.len(), 2, "the staging namespace is outside the prefix: {listed:?}");
        assert_eq!(listed[0].key, "pub/ab/abcd.tar.gz");
        assert_eq!(listed[0].size, 5);
        assert!(listed[0].last_modified.is_some(), "GC needs an age to respect its grace period");
        assert_eq!(listed[1].size, 3);
        assert!(blob.list("nothing/").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_prefixes_reports_shards_and_what_is_outside_them() {
        // The archive collector walks shards and *reports* everything else, so both halves of
        // this answer are load-bearing: a prefix it does not get back is a prefix it never
        // visits, and an object it does not get back is one nothing would ever mention.
        let blob = ObjectStoreBlob::memory();
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"12345")).await.unwrap();
        blob.put("pub/cd/cdef.tar.gz", Bytes::from_static(b"123")).await.unwrap();
        blob.put("pub/zz/foreign.txt", Bytes::from_static(b"mystery")).await.unwrap();
        blob.put("pub/stray.txt", Bytes::from_static(b"outside every shard")).await.unwrap();

        let mut listing = blob.list_prefixes("pub/").await.unwrap();
        listing.prefixes.sort();
        assert_eq!(listing.prefixes, ["pub/ab/", "pub/cd/", "pub/zz/"], "the delimiter is included, always");
        assert_eq!(listing.objects.len(), 1, "only the key that is inside no shard: {listing:?}");
        assert_eq!(listing.objects[0].key, "pub/stray.txt");
        assert!(listing.objects[0].last_modified.is_some());

        let empty = blob.list_prefixes("nothing/").await.unwrap();
        assert!(empty.prefixes.is_empty() && empty.objects.is_empty());
    }

    #[tokio::test]
    async fn head_reports_metadata_and_absence_without_an_error() {
        // The collectors call `head` on a key they are about to delete: "somebody deleted it
        // first" is an ordinary outcome, not a failed pass.
        let blob = ObjectStoreBlob::memory();
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"12345")).await.unwrap();

        let found = blob.head("pub/ab/abcd.tar.gz").await.unwrap().expect("present");
        assert_eq!(found.key, "pub/ab/abcd.tar.gz");
        assert_eq!(found.size, 5);
        assert!(found.last_modified.is_some(), "the re-read exists to compare an age");
        assert!(blob.head("pub/ab/gone.tar.gz").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fs_head_and_prefixes_match_the_memory_backend() {
        // Same contract on the backend a default install actually runs.
        let dir = tempfile::tempdir().unwrap();
        let cfg = BlobConfig { path: dir.path().join("blobs").to_string_lossy().into_owned(), ..BlobConfig::default() };
        let blob = ObjectStoreBlob::fs(&cfg).unwrap();
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"12345")).await.unwrap();

        let listing = blob.list_prefixes("pub/").await.unwrap();
        assert_eq!(listing.prefixes, ["pub/ab/"]);
        assert!(listing.objects.is_empty());
        assert_eq!(blob.head("pub/ab/abcd.tar.gz").await.unwrap().expect("present").size, 5);
        assert!(blob.head("pub/ab/gone.tar.gz").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fs_list_walks_shards() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BlobConfig { path: dir.path().join("blobs").to_string_lossy().into_owned(), ..BlobConfig::default() };
        let blob = ObjectStoreBlob::fs(&cfg).unwrap();
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"12345")).await.unwrap();
        let listed = blob.list("pub/").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "pub/ab/abcd.tar.gz");
        assert_eq!(listed[0].size, 5);
    }

    #[tokio::test]
    async fn ping_succeeds_on_empty_stores() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BlobConfig { path: dir.path().join("blobs").to_string_lossy().into_owned(), ..BlobConfig::default() };
        ObjectStoreBlob::memory().ping().await.unwrap();
        ObjectStoreBlob::fs(&cfg).unwrap().ping().await.unwrap();
    }

    // ------------------------------------------------ presigned downloads (decision 34, S-18.a)

    /// An S3 config with static credentials — enough to sign, and signing is offline, so every
    /// assertion below runs without a store to talk to.
    fn s3_cfg() -> BlobConfig {
        BlobConfig {
            kind: BlobKind::S3,
            bucket: Some("pub-blobs".to_owned()),
            endpoint: Some("http://s3:9000".to_owned()),
            access_key: Some(pub_config::Secret::new("minio")),
            secret_key: Some(pub_config::Secret::new("minio123")),
            presign: true,
            ..BlobConfig::default()
        }
    }

    fn redirect_url(plan: DownloadPlan) -> url::Url {
        match plan {
            DownloadPlan::Redirect(url) => url,
            DownloadPlan::Stream(_) => panic!("expected a presigned redirect, got a stream"),
        }
    }

    fn query_param(url: &url::Url, key: &str) -> String {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| panic!("{key} missing from {url}"))
    }

    #[tokio::test]
    async fn presigning_signs_the_method_the_caller_will_use() {
        // The load-bearing property of `DownloadMethod`: SigV4 covers the method, so a
        // GET-signed URL answers SignatureDoesNotMatch to the HEAD the pub client sends before
        // every archive fetch. Two URLs for the same key must therefore differ in more than
        // their timestamp — the signature itself has to move.
        let blob = ObjectStoreBlob::s3(&s3_cfg()).unwrap();
        let key = "pub/ab/abcd.tar.gz";

        let get = redirect_url(blob.download(key, DownloadMethod::Get).await.unwrap());
        let head = redirect_url(blob.download(key, DownloadMethod::Head).await.unwrap());

        assert_eq!(get.path(), "/pub-blobs/pub/ab/abcd.tar.gz", "path-style key under the bucket");
        assert_eq!(get.path(), head.path());
        assert_eq!(query_param(&get, "X-Amz-Algorithm"), "AWS4-HMAC-SHA256");
        assert_eq!(
            query_param(&get, "X-Amz-Date"),
            query_param(&head, "X-Amz-Date"),
            "same instant, so the signatures may only differ because the method does"
        );
        assert_ne!(
            query_param(&get, "X-Amz-Signature"),
            query_param(&head, "X-Amz-Signature"),
            "a GET-signed URL handed to a HEAD is refused by S3; the plan must sign per method"
        );
    }

    #[tokio::test]
    async fn the_configured_ttl_is_the_url_lifetime() {
        // Bounded by the validator to sharp edge 4's floor and SigV4's ceiling; what this
        // asserts is that the number reaches the URL rather than a library default.
        let blob = ObjectStoreBlob::s3(&BlobConfig { presign_ttl_secs: 2400, ..s3_cfg() }).unwrap();
        let url = redirect_url(blob.download("pub/ab/abcd.tar.gz", DownloadMethod::Get).await.unwrap());
        assert_eq!(query_param(&url, "X-Amz-Expires"), "2400");
    }

    #[tokio::test]
    async fn presigning_uses_the_public_endpoint_and_not_the_one_this_process_dials() {
        // The reason there are two stores at all: SigV4 signs the `host` header, so the public
        // address cannot be patched into an already-signed URL. `http://s3:9000` is this
        // repository's own compose address, which no client outside that network resolves.
        let cfg = BlobConfig { public_endpoint: Some("https://blobs.example.com".to_owned()), ..s3_cfg() };
        let blob = ObjectStoreBlob::s3(&cfg).unwrap();

        let url = redirect_url(blob.download("pub/ab/abcd.tar.gz", DownloadMethod::Get).await.unwrap());
        assert_eq!(url.origin().ascii_serialization(), "https://blobs.example.com");
        assert_eq!(url.path(), "/pub-blobs/pub/ab/abcd.tar.gz");
        assert!(!url.as_str().contains("s3:9000"), "the private address must not leak into a client URL: {url}");
    }

    #[tokio::test]
    async fn presign_off_plans_a_stream_on_the_s3_backend_too() {
        // The store is in-memory so the streaming branch can actually be taken; what is under
        // test is the *choice*, which is `presign` and nothing else.
        let blob = ObjectStoreBlob { kind: BlobKind::S3, store: Arc::new(InMemory::new()), presign: None };
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"archive bytes")).await.unwrap();

        let plan = blob.download("pub/ab/abcd.tar.gz", DownloadMethod::Get).await.unwrap();
        assert_eq!(collect(plan).await, b"archive bytes");
    }

    /// A signer that cannot sign — the shape of a credential provider that stops answering.
    #[derive(Debug)]
    struct BrokenSigner;

    #[async_trait]
    impl Signer for BrokenSigner {
        async fn signed_url(
            &self,
            _method: http::Method,
            _path: &ObjectPath,
            _expires_in: Duration,
        ) -> object_store::Result<url::Url> {
            Err(object_store::Error::Generic { store: "test", source: "no credential".into() })
        }
    }

    #[tokio::test]
    async fn a_signing_failure_streams_the_bytes_instead_of_failing_the_download() {
        // Signing is a fast path, not the download path: an outage of the credential provider
        // must cost latency, never the archive. Asserted by getting the bytes back, because a
        // fallback that returned an error would also "not redirect".
        let blob = ObjectStoreBlob {
            kind: BlobKind::S3,
            store: Arc::new(InMemory::new()),
            presign: Some(Presign { signer: Arc::new(BrokenSigner), ttl: Duration::from_secs(1800) }),
        };
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"archive bytes")).await.unwrap();

        let plan = blob.download("pub/ab/abcd.tar.gz", DownloadMethod::Get).await.unwrap();
        assert_eq!(collect(plan).await, b"archive bytes");
    }

    #[test]
    fn presign_is_wired_only_where_it_is_asked_for() {
        assert!(!ObjectStoreBlob::memory().presigns());
        assert!(!ObjectStoreBlob::s3(&BlobConfig { presign: false, ..s3_cfg() }).unwrap().presigns());
        assert!(ObjectStoreBlob::s3(&s3_cfg()).unwrap().presigns());
    }

    #[test]
    fn s3_constructor_builds_from_config() {
        let cfg = BlobConfig {
            kind: BlobKind::S3,
            bucket: Some("pub-blobs".to_owned()),
            endpoint: Some("http://127.0.0.1:9000".to_owned()),
            access_key: Some(pub_config::Secret::new("minio")),
            secret_key: Some(pub_config::Secret::new("minio123")),
            ..BlobConfig::default()
        };
        let blob = ObjectStoreBlob::s3(&cfg).unwrap();
        assert_eq!(blob.kind(), BlobKind::S3);
    }

    #[test]
    fn s3_constructor_requires_bucket() {
        let cfg = BlobConfig { kind: BlobKind::S3, ..BlobConfig::default() };
        let err = ObjectStoreBlob::s3(&cfg).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }
}
