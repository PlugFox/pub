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
//! KV-outage semantics are the *caller's* policy: auth-abuse limiting fails closed onto
//! [`InProcessLimiter`] (S-24.e), the publish budget and the read-path buckets fail open
//! (S-24.c, S-24.f) — [`hit`] itself just propagates the error and each call site decides.

use std::hash::{Hash as _, Hasher as _};
use std::sync::atomic::{AtomicU64, Ordering};
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
    Limited {
        /// Seconds to the next window boundary.
        retry_after_secs: u64,
        /// Whether this is the **first** refusal of this bucket in this window.
        ///
        /// The audit trail wants the trip, not the storm. Without this flag a caller can only
        /// write one row per refused request, which makes every throttled bucket an
        /// amplification vector into `audit_log` — the attacker sets the row count, and the
        /// table has no retention yet ([D12](../../../docs/roadmap.md)). One row per bucket per
        /// window carries the same information: the trip happened, and `Retry-After` says when
        /// it ends. Volume belongs in a counter, which is what `rate_limit_trips_total` is for.
        first_in_window: bool,
    },
}

impl Decision {
    /// Convenience: converts a limited decision into [`Error::RateLimited`].
    pub fn into_result(self) -> Result<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::Limited { retry_after_secs, .. } => Err(Error::RateLimited { retry_after_secs }),
        }
    }

    /// Whether this refusal is the one worth an audit row (see `first_in_window`).
    pub fn is_first_refusal(self) -> bool {
        matches!(self, Self::Limited { first_in_window: true, .. })
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
    Ok(decide(count, limit, secs, now))
}

/// Turns a post-increment count into the decision, for both the KV path and the fallback.
///
/// Kept in one place on purpose: `Retry-After` is a normative value (S-24.a), and two copies of
/// this arithmetic would eventually disagree about which window is refusing the request.
fn decide(count: u64, limit: u32, secs: i64, now: DateTime<Utc>) -> Decision {
    if count > u64::from(limit) {
        // Seconds to the next boundary. `timestamp()` floors, so a sub-second remainder still
        // costs a whole second and a client obeying the header is never early.
        let retry_after_secs = (secs - now.timestamp().rem_euclid(secs)) as u64;
        // The count is post-increment, so `limit + 1` is exactly the hit that crossed. Counting
        // continues past the limit, so every later refusal in the window reports `false`.
        return Decision::Limited { retry_after_secs, first_in_window: count == u64::from(limit) + 1 };
    }
    Decision::Allowed
}

/// Spends `prefix`'s budget in the KV, and in this process's own table when the KV is down
/// ([S-24.e](../../../docs/security.md#5-audit--abuse)).
///
/// This is the entry point for the **auth-abuse** buckets, the ones S-24 requires to fail
/// closed. `bucket` is the family name (`otp_email`, `login_ip`, …) and is the only part of the
/// identity that reaches a log line or a metric label: a prefix carries the submitted address or
/// the client IP, and an outage is not a reason to start writing those to stdout.
pub async fn hit_or_fallback(
    kv: &dyn Kv,
    fallback: &InProcessLimiter,
    bucket: &'static str,
    prefix: &str,
    limit: u32,
    window: Duration,
    now: DateTime<Utc>,
) -> Decision {
    match hit(kv, prefix, limit, window, now).await {
        Ok(decision) => decision,
        Err(error) => {
            tracing::error!(
                %error,
                bucket,
                "rate-limit store unavailable; spending this instance's own budget instead (S-24.e)"
            );
            metrics::counter!("rate_limit_fallback_total", "bucket" => bucket).increment(1);
            fallback.hit(prefix, limit, window, now)
        }
    }
}

// ------------------------------------------------------------- the per-instance fallback

/// Bits of each slot given to the count; the rest carry the window index.
const COUNT_BITS: u32 = 24;
/// Largest count a slot can hold. Saturating there is harmless — every value above the limit
/// means the same thing, and the limits are four orders of magnitude below it.
const COUNT_MAX: u64 = (1 << COUNT_BITS) - 1;
/// Slots in the table. 8192 × 8 B = 64 KiB per process, allocated once at startup.
const SLOTS: usize = 8192;

/// Per-instance fixed-window counters for the moments the KV cannot answer (S-24.e).
///
/// **Bounded by construction, not by an eviction policy.** Bucket keys carry attacker-supplied
/// data (`rl:otp:email:{address}`), so a map would turn a KV outage into a memory-exhaustion
/// primitive at the exact moment the instance is already degraded. Instead the key is hashed
/// into a fixed table of atomic slots, each holding `(window index, count)` in one `u64`.
///
/// **Collisions merge budgets, and that is the safe direction.** Two buckets sharing a slot in
/// the same window share its count, so the fallback can only ever refuse *more* than the true
/// count — never less. That is why no rebalancing, no eviction and no per-key allocation exist
/// here, and why the hash needs no random seed: an attacker who deliberately collides with a
/// victim's bucket makes their own requests fail sooner, alongside the victim's.
///
/// The accepted cost is the one S-24.e states: N replicas count separately, so an outage lifts
/// the aggregate budget to N × the limit. That is a smaller failure than sign-in being down.
#[derive(Debug)]
pub struct InProcessLimiter {
    slots: Box<[AtomicU64]>,
}

impl Default for InProcessLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl InProcessLimiter {
    /// A zeroed table. Slot 0 is a legitimate `(window 0, count 0)`, which is why a count of
    /// zero never decides anything — the first hit stores 1 before it is read.
    pub fn new() -> Self {
        Self { slots: (0..SLOTS).map(|_| AtomicU64::new(0)).collect() }
    }

    /// Records a hit and returns the decision, using the same aligned/tumbling window as [`hit`].
    pub fn hit(&self, prefix: &str, limit: u32, window: Duration, now: DateTime<Utc>) -> Decision {
        let secs = window.num_seconds().max(1);
        // Same `div_euclid` as the KV path: a pre-epoch timestamp is negative, and the two
        // windows either side of the epoch must not fold into one index.
        let index = now.timestamp().div_euclid(secs);
        // Masked into the field width. Two indices alias only if they are 2^40 windows apart —
        // 34 million years at a one-second window.
        let window_bits = (index as u64) << COUNT_BITS;

        let slot = &self.slots[Self::slot_of(prefix)];
        let mut current = slot.load(Ordering::Relaxed);
        let count = loop {
            let same_window = current & !COUNT_MAX == window_bits;
            let next_count = if same_window { ((current & COUNT_MAX) + 1).min(COUNT_MAX) } else { 1 };
            let next = window_bits | next_count;
            match slot.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => break next_count,
                Err(observed) => current = observed,
            }
        };
        decide(count, limit, secs, now)
    }

    /// The slot a bucket lives in. `DefaultHasher` is unseeded and therefore stable across
    /// restarts and replicas, which is fine precisely because collisions only tighten.
    fn slot_of(prefix: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        prefix.hash(&mut hasher);
        (hasher.finish() % SLOTS as u64) as usize
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::TimeZone as _;
    use pub_core::traits::MessageStream;
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
        assert_eq!(over, Decision::Limited { retry_after_secs: 30 * 60, first_in_window: true });
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
        assert_eq!(
            over,
            Decision::Limited { retry_after_secs: 1, first_in_window: true },
            "one second of the window is left"
        );
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
        assert_eq!(
            over,
            Decision::Limited { retry_after_secs: 30 * 60, first_in_window: true },
            "a negative remainder is not a window"
        );
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
        let err = Decision::Limited { retry_after_secs: 42, first_in_window: true }.into_result().unwrap_err();
        assert_eq!(err.code(), "rate_limited");
        assert!(Decision::Allowed.into_result().is_ok());
    }

    // --- S-24.e: the per-instance fallback ---

    /// A `Kv` whose every operation fails — the outage the fallback exists for.
    #[derive(Debug)]
    struct DeadKv;

    #[async_trait]
    impl Kv for DeadKv {
        async fn ping(&self) -> Result<()> {
            Err(down())
        }
        async fn get(&self, _key: &str) -> Result<Option<String>> {
            Err(down())
        }
        async fn set_ttl(&self, _key: &str, _value: &str, _ttl: StdDuration) -> Result<()> {
            Err(down())
        }
        async fn incr(&self, _key: &str, _ttl: StdDuration) -> Result<u64> {
            Err(down())
        }
        async fn del(&self, _key: &str) -> Result<()> {
            Err(down())
        }
        async fn publish(&self, _topic: &str, _payload: &str) -> Result<()> {
            Err(down())
        }
        async fn subscribe(&self, _topic: &str) -> Result<MessageStream> {
            Err(down())
        }
    }

    fn down() -> Error {
        Error::Internal { message: "kv is down".to_owned() }
    }

    /// One minute, as a value rather than a `const` — `Duration::minutes` is not const-callable
    /// on every chrono in the supported range.
    fn minute() -> Duration {
        Duration::minutes(1)
    }

    #[test]
    fn s24_e_the_fallback_enforces_the_same_budget_and_the_same_retry_after() {
        let limiter = InProcessLimiter::new();
        let start = t0() + Duration::minutes(10);
        for i in 0..5 {
            assert_eq!(limiter.hit("rl:fb", 5, Duration::hours(1), start), Decision::Allowed, "hit {i}");
        }
        // Same aligned-and-tumbling arithmetic as the KV path: 20 minutes in, 40 remain.
        let over = limiter.hit("rl:fb", 5, Duration::hours(1), start + Duration::minutes(10));
        assert_eq!(over, Decision::Limited { retry_after_secs: 40 * 60, first_in_window: true });
        // ...and the next window is a fresh budget, not a permanently spent slot.
        assert_eq!(limiter.hit("rl:fb", 5, Duration::hours(1), t0() + Duration::hours(1)), Decision::Allowed);
    }

    #[test]
    fn s24_e_a_slot_collision_refuses_more_never_less() {
        // Two prefixes that land in the same slot, found by search rather than asserted blind:
        // the property under test is that sharing a slot *tightens* both budgets.
        let (a, b) = (0..100_000).map(|i| format!("rl:otp:email:user{i}@corp.com")).fold(
            (None, None),
            |(first, second), key| match (first, second) {
                (None, _) => (Some(key), None),
                (Some(first), None) if InProcessLimiter::slot_of(&key) == InProcessLimiter::slot_of(&first) => {
                    (Some(first), Some(key))
                }
                found => found,
            },
        );
        let (a, b) = (a.expect("a first key"), b.expect("a colliding key within 100k candidates"));

        let limiter = InProcessLimiter::new();
        assert_eq!(limiter.hit(&a, 2, Duration::minutes(1), t0()), Decision::Allowed);
        assert_eq!(limiter.hit(&b, 2, Duration::minutes(1), t0()), Decision::Allowed);
        // The third hit is `a`'s second, and under a private counter it would pass. Merged with
        // `b`'s it is the third of two — refused. Refusing early is the safe direction for a
        // bucket S-24 requires to fail closed.
        assert!(matches!(limiter.hit(&a, 2, Duration::minutes(1), t0()), Decision::Limited { .. }));
    }

    #[test]
    fn s24_e_pre_epoch_windows_do_not_fold_in_the_fallback() {
        let limiter = InProcessLimiter::new();
        let before = Utc.with_ymd_and_hms(1969, 12, 31, 23, 30, 0).unwrap();
        assert_eq!(limiter.hit("rl:old", 1, Duration::hours(1), before), Decision::Allowed);
        assert_eq!(
            limiter.hit("rl:old", 1, Duration::hours(1), before),
            Decision::Limited { retry_after_secs: 30 * 60, first_in_window: true }
        );
        let after = Utc.with_ymd_and_hms(1970, 1, 1, 0, 30, 0).unwrap();
        assert_eq!(limiter.hit("rl:old", 1, Duration::hours(1), after), Decision::Allowed);
    }

    #[test]
    fn s24_e_a_saturated_slot_stays_limited_rather_than_wrapping_to_allowed() {
        let limiter = InProcessLimiter::new();
        let slot = &limiter.slots[InProcessLimiter::slot_of("rl:sat")];
        let window = t0().timestamp().div_euclid(60) as u64;
        // One hit below the field's ceiling: the next increment must clamp, not carry into the
        // window bits — a carry would silently move the bucket into a different window and hand
        // the attacker a fresh budget at exactly the moment they have spent 16 million requests.
        slot.store((window << COUNT_BITS) | (COUNT_MAX - 1), Ordering::Relaxed);
        assert!(matches!(limiter.hit("rl:sat", 5, Duration::minutes(1), t0()), Decision::Limited { .. }));
        assert!(matches!(limiter.hit("rl:sat", 5, Duration::minutes(1), t0()), Decision::Limited { .. }));
        assert_eq!(slot.load(Ordering::Relaxed) >> COUNT_BITS, window, "the window index must not have moved");
    }

    #[test]
    fn s24_e_the_fallback_is_atomic_under_concurrency() {
        let limiter = Arc::new(InProcessLimiter::new());
        let mut threads = Vec::new();
        for _ in 0..8 {
            let limiter = Arc::clone(&limiter);
            threads.push(std::thread::spawn(move || {
                (0..64).filter(|_| limiter.hit("rl:race", 100, Duration::hours(1), t0()) == Decision::Allowed).count()
            }));
        }
        let allowed: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        // 512 hits against a budget of 100. A read-modify-write slot would let far more through.
        assert_eq!(allowed, 100, "exactly the budget may pass, however parallel the burst");
    }

    #[tokio::test]
    async fn s24_e_a_kv_outage_degrades_to_the_fallback_instead_of_erroring() {
        let fallback = InProcessLimiter::new();
        for i in 0..3 {
            let decision =
                hit_or_fallback(&DeadKv, &fallback, "otp_email", "rl:otp:email:a@b.c", 3, minute(), t0()).await;
            assert_eq!(decision, Decision::Allowed, "hit {i} must pass on the local budget");
        }
        let over = hit_or_fallback(&DeadKv, &fallback, "otp_email", "rl:otp:email:a@b.c", 3, minute(), t0()).await;
        assert!(matches!(over, Decision::Limited { .. }), "the local budget still ends");
    }

    #[tokio::test]
    async fn s24_e_a_healthy_kv_never_touches_the_fallback() {
        let kv = MemoryKv::new();
        let fallback = InProcessLimiter::new();
        for _ in 0..3 {
            hit_or_fallback(&kv, &fallback, "otp_email", "rl:live", 3, minute(), t0()).await;
        }
        // The fallback table must be untouched: a KV that answers is the only counter that ran.
        assert_eq!(fallback.hit("rl:live", 1, minute(), t0()), Decision::Allowed, "the local slot was never spent");
    }
}
