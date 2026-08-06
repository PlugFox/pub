//! Blob storage backends over `object_store` (decision 10).
//!
//! One implementation struct wraps any [`object_store::ObjectStore`]; constructors select
//! LocalFileSystem, InMemory, or an S3-compatible store from configuration. Downloads return
//! [`DownloadPlan::Stream`] for fs/memory; the S3 backend will add
//! [`DownloadPlan::Redirect`] with presigned URLs in a later roadmap step.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt as _};
use pub_config::{BlobConfig, BlobKind};
use pub_core::traits::{BlobStore, DownloadPlan};
use pub_core::{Error, Result};

/// [`BlobStore`] backed by any `object_store` implementation.
#[derive(Debug)]
pub struct ObjectStoreBlob {
    kind: BlobKind,
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreBlob {
    /// In-memory store — tests and throwaway instances only.
    pub fn memory() -> Self {
        Self { kind: BlobKind::Memory, store: Arc::new(InMemory::new()) }
    }

    /// Local filesystem store rooted at `blob.path` (created if missing).
    pub fn fs(cfg: &BlobConfig) -> Result<Self> {
        std::fs::create_dir_all(&cfg.path)
            .map_err(|err| Error::Blob { message: format!("failed to create blob directory {}: {err}", cfg.path) })?;
        let store = LocalFileSystem::new_with_prefix(&cfg.path)
            .map_err(|err| Error::Blob { message: format!("failed to open blob directory {}: {err}", cfg.path) })?;
        Ok(Self { kind: BlobKind::Fs, store: Arc::new(store) })
    }

    /// S3-compatible store (AWS S3, MinIO) from configuration.
    ///
    /// Compile-and-construct only in the skeleton: exercised by the CI backend matrix, not
    /// by local tests. Presigned-URL downloads arrive with the real publish pipeline.
    pub fn s3(cfg: &BlobConfig) -> Result<Self> {
        let bucket = cfg
            .bucket
            .as_deref()
            .ok_or_else(|| Error::Config { message: "blob.kind = s3 requires blob.bucket".to_owned() })?;

        let mut builder = AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .with_region(cfg.region.clone().unwrap_or_else(|| "us-east-1".to_owned()));
        if let Some(endpoint) = &cfg.endpoint {
            // Custom endpoints are typically MinIO on plain HTTP inside a private network.
            builder = builder.with_endpoint(endpoint).with_allow_http(true);
        }
        if let Some(access_key) = &cfg.access_key {
            builder = builder.with_access_key_id(access_key.expose());
        }
        if let Some(secret_key) = &cfg.secret_key {
            builder = builder.with_secret_access_key(secret_key.expose());
        }

        let store = builder
            .build()
            .map_err(|err| Error::Blob { message: format!("failed to configure s3 blob store: {err}") })?;
        Ok(Self { kind: BlobKind::S3, store: Arc::new(store) })
    }

    /// The configured backend kind (reported by `/healthz`).
    pub fn kind(&self) -> BlobKind {
        self.kind
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

    async fn download(&self, key: &str) -> Result<DownloadPlan> {
        let result = self.store.get(&ObjectPath::from(key)).await.map_err(blob_err)?;
        let stream = result.into_stream().map(|chunk| chunk.map_err(blob_err)).boxed();
        Ok(DownloadPlan::Stream(stream))
    }

    /// Direct read rather than the trait's stream-draining default: `object_store` hands back
    /// the whole object in one call, and this path stays correct once the S3 backend starts
    /// answering [`DownloadPlan::Redirect`] for client downloads.
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
        let plan = blob.download("sha256/abc").await.unwrap();
        assert_eq!(collect(plan).await, b"tarball bytes");
    }

    #[tokio::test]
    async fn fs_put_download_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BlobConfig { path: dir.path().join("blobs").to_string_lossy().into_owned(), ..BlobConfig::default() };
        let blob = ObjectStoreBlob::fs(&cfg).unwrap();
        blob.put("sha256/def", Bytes::from_static(b"fs bytes")).await.unwrap();
        let plan = blob.download("sha256/def").await.unwrap();
        assert_eq!(collect(plan).await, b"fs bytes");
    }

    #[tokio::test]
    async fn missing_key_maps_to_not_found() {
        let blob = ObjectStoreBlob::memory();
        let err = blob.download("sha256/missing").await.unwrap_err();
        assert_eq!(err.code(), "not_found");
    }

    #[tokio::test]
    async fn delete_removes_the_object_and_is_idempotent() {
        let blob = ObjectStoreBlob::memory();
        blob.put("pub/ab/abcd.tar.gz", Bytes::from_static(b"bytes")).await.unwrap();
        blob.delete("pub/ab/abcd.tar.gz").await.unwrap();
        assert_eq!(blob.download("pub/ab/abcd.tar.gz").await.unwrap_err().code(), "not_found");
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
        assert_eq!(blob.download("pub/cd/cdef.tar.gz").await.unwrap_err().code(), "not_found");
        blob.delete("pub/cd/cdef.tar.gz").await.unwrap();
    }

    #[tokio::test]
    async fn ping_succeeds_on_empty_stores() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BlobConfig { path: dir.path().join("blobs").to_string_lossy().into_owned(), ..BlobConfig::default() };
        ObjectStoreBlob::memory().ping().await.unwrap();
        ObjectStoreBlob::fs(&cfg).unwrap().ping().await.unwrap();
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
