//! Shared repository contract suite (docs/architecture.md testing strategy).
//!
//! Every database backend must pass [`contract`] through the plain [`Repositories`] trait
//! bundle — the suite never sees sqlx or backend types. The sqlite `:memory:` run lives in
//! `tests/sqlite.rs` (every local `cargo test`); the Postgres run in `tests/postgres.rs` is
//! gated at runtime by the `PUB_TEST_POSTGRES_URL` environment variable — set by the CI
//! backend matrix, skipped (with a note on stderr) when absent.
//!
//! [`Repositories`]: pub_core::traits::Repositories

pub mod contract;
