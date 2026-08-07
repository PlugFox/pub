//! Fixed-window rate counters over the [`Kv`] seam (S-24, S-24.d).
//!
//! One atomic [`Kv::incr`] per hit, and the increment happens **before** the decision, which is
//! read from the returned count and never from a re-read. A `get` → decide → `set` round trip
//! bounds nothing: N concurrent tasks read the same count, all decide *allowed*, and a burst of
//! size N spends one unit.
//!
//! The window lives in the **key** (`{prefix}:{floor(now / window)}`), not in the value and not
//! in the key TTL. Both KV backends re-arm a key's TTL on every increment, so a TTL-shaped
//! window under sustained traffic would never reset; and the KV expires on real time while every
//! decision here is made against the injected clock the rest of the auth stack is tested with.
//! The TTL is retained purely as garbage collection. Windows are therefore aligned and tumbling:
//! `Retry-After` is the time to the next boundary, and up to 2× the limit may pass across one.
//!
//! KV-outage semantics are the *caller's* policy: auth-abuse limiting fails closed, the publish
//! budget fails open (S-24.c) — this module just propagates the error.

use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use pub_core::traits::Kv;
use pub_core::{Error, Result};

/// Outcome of one [`hit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Under the limit; the hit was recorded.
    Allowed,
    /// Over the limit; retry after this many seconds (the `Retry-After` value, ≥ 1).
    Limited { retry_after_secs: u64 },
}

impl Decision {
    /// Convenience: converts a limited decision into [`Error::RateLimited`].
    pub fn into_result(self) -> Result<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::Limited { retry_after_secs } => Err(Error::RateLimited { retry_after_secs }),
        }
    }
}

/// Records a hit on the bucket `prefix` under the aligned window containing `now`.
///
/// `prefix` is the caller's stable bucket identity (`rl:otp:email:dev@corp.com`); the window
/// index is appended here, so no call site derives it. Counting continues past the limit — the
/// extra increments are free and make "how hard is this bucket being hammered" observable.
pub async fn hit(kv: &dyn Kv, prefix: &str, limit: u32, window: Duration, now: DateTime<Utc>) -> Result<Decision> {
    let secs = window.num_seconds().max(1);
    // `div_euclid`/`rem_euclid`, never `/` and `%`: a pre-epoch timestamp is negative, and
    // truncating division would fold the two windows either side of the epoch into one key and
    // report a negative remainder as a `Retry-After` larger than the window itself.
    let key = format!("{prefix}:{}", now.timestamp().div_euclid(secs));
    // Twice the window, and garbage collection only: the key is dead the moment `now` crosses
    // into the next index regardless, so re-arming the TTL on every increment is harmless.
    let ttl = StdDuration::from_secs((secs as u64).saturating_mul(2));

    let count = kv.incr(&key, ttl).await?;
    if count > u64::from(limit) {
        // Seconds to the next boundary. `timestamp()` floors, so a sub-second remainder still
        // costs a whole second and a client obeying the header is never early.
        let retry_after_secs = (secs - now.timestamp().rem_euclid(secs)) as u64;
        return Ok(Decision::Limited { retry_after_secs });
    }
    Ok(Decision::Allowed)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::TimeZone as _;
    use pub_kv::MemoryKv;

    use super::*;

    /// Exactly on an aligned hour boundary — offsets are added per test so a window edge is
    /// never accidentally where the test started counting.
    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 6, 12, 0, 0).unwrap()
    }

    #[tokio::test]
    async fn allows_up_to_limit_then_blocks_with_retry_after() {
        let kv = MemoryKv::new();
        // Ten minutes into the aligned hour: an anchored-at-first-hit window would report a
        // deadline ten minutes later than the real one, which is what this offset discriminates.
        let start = t0() + Duration::minutes(10);
        for i in 0..5 {
            let decision = hit(&kv, "rl:test", 5, Duration::hours(1), start + Duration::minutes(i)).await.unwrap();
            assert_eq!(decision, Decision::Allowed, "hit {i} must pass");
        }
        let over = hit(&kv, "rl:test", 5, Duration::hours(1), start + Duration::minutes(20)).await.unwrap();
        // 30 minutes into the hour, so 30 remain — not the 40 an anchored window would report.
        assert_eq!(over, Decision::Limited { retry_after_secs: 30 * 60 });
    }

    #[tokio::test]
    async fn an_over_limit_bucket_stays_limited_for_the_rest_of_the_window() {
        let kv = MemoryKv::new();
        let start = t0() + Duration::minutes(5);
        hit(&kv, "rl:sticky", 1, Duration::hours(1), start).await.unwrap();
        // Over-limit hits keep incrementing; the decision must not flip back to allowed.
        for minute in 1..=10 {
            let decision = hit(&kv, "rl:sticky", 1, Duration::hours(1), start + Duration::minutes(minute)).await;
            assert!(matches!(decision.unwrap(), Decision::Limited { .. }), "minute {minute} must stay limited");
        }
    }

    #[tokio::test]
    async fn window_boundary_resets_the_counter() {
        let kv = MemoryKv::new();
        let last_second = t0() + Duration::hours(1) - Duration::seconds(1);
        for _ in 0..3 {
            hit(&kv, "rl:reset", 3, Duration::hours(1), last_second).await.unwrap();
        }
        let over = hit(&kv, "rl:reset", 3, Duration::hours(1), last_second).await.unwrap();
        assert_eq!(over, Decision::Limited { retry_after_secs: 1 }, "one second of the window is left");
        // That second lands in the next window index — a different key, a fresh budget.
        let boundary = t0() + Duration::hours(1);
        assert_eq!(hit(&kv, "rl:reset", 3, Duration::hours(1), boundary).await.unwrap(), Decision::Allowed);
    }

    #[tokio::test]
    async fn keys_are_independent() {
        let kv = MemoryKv::new();
        hit(&kv, "rl:a", 1, Duration::hours(1), t0()).await.unwrap();
        assert!(matches!(hit(&kv, "rl:a", 1, Duration::hours(1), t0()).await.unwrap(), Decision::Limited { .. }));
        assert_eq!(hit(&kv, "rl:b", 1, Duration::hours(1), t0()).await.unwrap(), Decision::Allowed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hit_is_atomic_under_concurrency() {
        // The whole point of S-24.d: with a read-modify-write counter every task in the burst
        // reads the same count, decides *allowed*, and 32 requests cost one unit of budget.
        let kv = Arc::new(MemoryKv::new());
        let mut burst = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let kv = Arc::clone(&kv);
            burst.spawn(async move { hit(kv.as_ref(), "rl:burst", 5, Duration::hours(1), t0()).await.unwrap() });
        }
        let allowed = burst.join_all().await.into_iter().filter(|d| *d == Decision::Allowed).count();
        assert_eq!(allowed, 5, "exactly the budget may pass, however parallel the burst");
    }

    #[tokio::test]
    async fn pre_epoch_timestamps_do_not_panic() {
        let kv = MemoryKv::new();
        let before = Utc.with_ymd_and_hms(1969, 12, 31, 23, 30, 0).unwrap();
        assert_eq!(hit(&kv, "rl:old", 1, Duration::hours(1), before).await.unwrap(), Decision::Allowed);
        let over = hit(&kv, "rl:old", 1, Duration::hours(1), before).await.unwrap();
        assert_eq!(over, Decision::Limited { retry_after_secs: 30 * 60 }, "a negative remainder is not a window");
        // Truncating division would have folded 23:30 and 00:30 into the same index, so this
        // hit would inherit the spent budget of the window before the epoch.
        let after = Utc.with_ymd_and_hms(1970, 1, 1, 0, 30, 0).unwrap();
        assert_eq!(hit(&kv, "rl:old", 1, Duration::hours(1), after).await.unwrap(), Decision::Allowed);
    }

    #[tokio::test]
    async fn a_corrupt_counter_restarts_the_window() {
        let kv = MemoryKv::new();
        // The key layout is `{prefix}:{floor(now / window)}` — spelled out here so a change to
        // it is a deliberate edit rather than a silently reset budget in production.
        let key = format!("rl:junk:{}", t0().timestamp() / 3600);
        kv.set_ttl(&key, "not-a-counter", StdDuration::from_secs(60)).await.unwrap();
        assert_eq!(hit(&kv, "rl:junk", 1, Duration::hours(1), t0()).await.unwrap(), Decision::Allowed);
        assert!(matches!(hit(&kv, "rl:junk", 1, Duration::hours(1), t0()).await.unwrap(), Decision::Limited { .. }));
    }

    #[test]
    fn limited_decision_converts_to_rate_limited_error() {
        let err = Decision::Limited { retry_after_secs: 42 }.into_result().unwrap_err();
        assert_eq!(err.code(), "rate_limited");
        assert!(Decision::Allowed.into_result().is_ok());
    }
}
