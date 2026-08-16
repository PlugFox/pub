//! Shared repository contract suite (docs/architecture.md testing strategy).
//!
//! Every database backend must pass [`contract`] through the plain [`Repositories`] trait
//! bundle — the suite never sees sqlx or backend types. The sqlite `:memory:` run lives in
//! `tests/sqlite.rs` (every local `cargo test`); the Postgres run in `tests/postgres.rs` is
//! gated at runtime by `PUB_TEST_POSTGRES_URL` and **fails** when neither that variable nor
//! the explicit `PUB_TEST_NO_POSTGRES` opt-out is set
//! ([decision 35](../../../docs/decisions.md#35--backend-legs-that-fail-when-the-backend-is-absent-and-a-harness-that-admits-a-race)).
//! `server-ci.yml` exports the URL beside the service container that serves it and sets no
//! opt-out, so a Postgres that fails to start is a red build.
//!
//! [`Repositories`]: pub_core::traits::Repositories

pub mod contract;
