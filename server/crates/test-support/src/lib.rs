//! Test-only helpers shared by the crates whose suites reach a real backend.
//!
//! The one thing here is the **optional-backend gate**
//! ([decision 35](../../../docs/decisions.md#35--backend-legs-that-fail-when-the-backend-is-absent-and-a-harness-that-admits-a-race)):
//! the rule that decides whether a leg runs, skips, or takes the process down with it.
//!
//! The rule exists because "the leg did not run" and "the leg passed" used to be the same
//! output. Demonstrated rather than argued: with the Docker daemon down, `cargo test
//! --workspace` answered `test result: ok. 31 passed; 0 failed; finished in 0.00s` for the
//! Postgres contract suite with port 5432 closed. Every test took an early return, and the
//! skip note went to stderr — which cargo prints only for *failing* tests, so a passing run
//! printed nothing at all. The tell was the duration, and nothing reads durations.
//!
//! So a missing backend is now a **panic**, and skipping is something a human types.

use std::fmt;

/// One backend a test leg needs, and the three ways a caller can be talking about it: the
/// variable that addresses it, the variable that silences it, and the compose profile that
/// starts it.
#[derive(Clone, Copy, Debug)]
pub struct OptionalBackend {
    /// Name used in messages.
    pub name: &'static str,
    /// Environment variable carrying the backend's address.
    pub url_env: &'static str,
    /// Environment variable that turns this leg off, explicitly.
    pub skip_env: &'static str,
    /// The documented way to start it locally, as a command a reader can paste. Not a compose
    /// profile name: the two-replica stand needs a build and a secrets check, so its command is
    /// not `just db-up <profile>` and a message that said so would be wrong.
    pub start: &'static str,
    /// An address that works against that profile's defaults, quoted in the failure message
    /// so nobody has to open `docker-compose.yml` to find out what to export.
    pub example: &'static str,
}

/// The repository contract suite's Postgres leg, and the HTTP suite's `Postgres` harness.
pub const POSTGRES: OptionalBackend = OptionalBackend {
    name: "postgres",
    url_env: "PUB_TEST_POSTGRES_URL",
    skip_env: "PUB_TEST_NO_POSTGRES",
    start: "just db-up pg",
    example: "postgres://pub:pub@127.0.0.1:5432/pub",
};

/// The `Kv` contract suite's Redis leg — the first automated execution `RedisKv` has ever had.
pub const REDIS: OptionalBackend = OptionalBackend {
    name: "redis",
    url_env: "PUB_TEST_REDIS_URL",
    skip_env: "PUB_TEST_NO_REDIS",
    start: "just db-up redis",
    example: "redis://127.0.0.1:6379",
};

/// The `BlobStore` contract suite's S3 leg (MinIO locally, a service container in CI).
///
/// The endpoint is the address; the credentials and bucket travel beside it in
/// [`s3_credentials`], defaulted to the `s3` compose profile so a local run needs one export
/// rather than four.
pub const S3: OptionalBackend = OptionalBackend {
    name: "s3",
    url_env: "PUB_TEST_S3_ENDPOINT",
    skip_env: "PUB_TEST_NO_S3",
    start: "just db-up s3",
    example: "http://127.0.0.1:9000",
};

/// The two-replica acceptance stand: two app containers on one set of backends, behind one
/// nginx ([decision 38](../../../docs/decisions.md#38--two-replicas-behind-one-proxy-an-acceptance-stand-that-fails-closed-four-claims-proven-at-the-wire-and-a-measurement-that-is-a-number)).
///
/// The URL is the **proxy's**. The replicas' own addresses travel beside it in
/// [`cluster_replicas`], defaulted to what the `cluster` profile publishes — a claim that names
/// an instance cannot be written against a balancer.
pub const CLUSTER: OptionalBackend = OptionalBackend {
    name: "cluster",
    url_env: "PUB_TEST_CLUSTER_URL",
    skip_env: "PUB_TEST_NO_CLUSTER",
    start: "just cluster-up",
    example: "http://localhost:18080",
};

/// What a leg was told to do about its backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    /// The backend is addressable; here is its URL.
    Run(String),
    /// The operator explicitly opted out of this backend.
    Skipped,
}

impl OptionalBackend {
    /// Decides whether `test` may run, and panics when nobody has said anything.
    ///
    /// Three inputs, in one deliberate order:
    ///
    /// 1. **The URL is set** → [`Gate::Run`]. It wins even when the skip variable is *also*
    ///    set, and that direction is chosen on purpose: a skip flag is the kind of thing that
    ///    lives in a shell profile forever, while an exported URL is a decision somebody made
    ///    for this run. Running is also the fail-safe direction — a leg that runs can fail, a
    ///    leg that skips cannot.
    /// 2. **Only the skip variable is set** → [`Gate::Skipped`]. The caller returns early.
    ///    Nothing is printed here: a note on stderr is invisible for a passing test, which is
    ///    the defect this module exists to remove. The announcement belongs to whoever set the
    ///    variable, and `just server-check` prints one line per leg it silenced.
    /// 3. **Neither** → panic, naming both ways out.
    ///
    /// # Panics
    ///
    /// When neither variable is set — which is the point.
    #[must_use]
    pub fn gate(&self, test: &str) -> Gate {
        if let Ok(url) = std::env::var(self.url_env)
            && !url.trim().is_empty()
        {
            return Gate::Run(url);
        }
        if std::env::var(self.skip_env).is_ok_and(|value| !value.trim().is_empty()) {
            return Gate::Skipped;
        }
        panic!("{}", self.missing_message(test));
    }

    /// The panic text. Separate so a test can assert its shape without provoking the panic.
    #[must_use]
    pub fn missing_message(&self, test: &str) -> String {
        format!(
            "{test} needs the {name} backend and ${url_env} is not set.\n\
             \n\
             Start it:  {start}   then  export {url_env}={example}\n\
             Skip it:   export {skip_env}=1    (`just server-check` does this for you and says so)\n\
             \n\
             This is a panic rather than a skip on purpose (decision 35): `test result: ok` with the\n\
             backend down is indistinguishable from `test result: ok` with it up, and that is how a\n\
             dead Postgres passed 31 tests in 0.00s.",
            test = test,
            name = self.name,
            url_env = self.url_env,
            skip_env = self.skip_env,
            start = self.start,
            example = self.example,
        )
    }
}

impl fmt::Display for OptionalBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

/// The two replicas' own addresses, defaulted to the ports the `cluster` compose profile
/// publishes.
///
/// Going through the proxy answers what only the front door can answer; everything that names
/// an instance — "A revoked it, B refuses it" — needs to reach that instance directly, which is
/// why the stand publishes both and why this is a list rather than a URL.
#[must_use]
pub fn cluster_replicas() -> Vec<String> {
    env_or("PUB_TEST_CLUSTER_REPLICAS", "http://localhost:18081,http://localhost:18082")
        .split(',')
        .map(|url| url.trim().trim_end_matches('/').to_owned())
        .filter(|url| !url.is_empty())
        .collect()
}

/// The mail sink the stand runs, whose API is where "exactly once" is actually observable.
#[must_use]
pub fn cluster_mail_url() -> String {
    env_or("PUB_TEST_CLUSTER_MAIL_URL", "http://localhost:8025").trim_end_matches('/').to_owned()
}

/// Access key, secret key and bucket for the [`S3`] leg, defaulted to the `s3` compose
/// profile's own values so a local run needs only the endpoint exported.
#[must_use]
pub fn s3_credentials() -> (String, String, String) {
    (
        env_or("PUB_TEST_S3_ACCESS_KEY", "pub-minio"),
        env_or("PUB_TEST_S3_SECRET_KEY", "pub_dev_password"),
        env_or("PUB_TEST_S3_BUCKET", "pub"),
    )
}

fn env_or(key: &str, fallback: &str) -> String {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => fallback.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message has to carry both exits, or the panic is just an obstacle.
    #[test]
    fn the_failure_message_names_the_way_in_and_the_way_out() {
        let message = POSTGRES.missing_message("some_contract");
        assert!(message.contains("some_contract"), "{message}");
        assert!(message.contains("PUB_TEST_POSTGRES_URL"), "{message}");
        assert!(message.contains("PUB_TEST_NO_POSTGRES"), "{message}");
        assert!(message.contains("just db-up pg"), "{message}");
        assert!(message.contains("postgres://pub:pub@127.0.0.1:5432/pub"), "{message}");
    }

    /// Every backend must be addressable and silenceable by *different* variables — a copied
    /// constant that reused another backend's `skip_env` would silence two legs at once.
    #[test]
    fn every_backend_carries_distinct_variables() {
        let all = [POSTGRES, REDIS, S3, CLUSTER];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.url_env, b.url_env, "{a} and {b} share a url variable");
                assert_ne!(a.skip_env, b.skip_env, "{a} and {b} share a skip variable");
            }
        }
    }
}
