//! Fixed-window rate counters over the [`Kv`] seam (S-24).
//!
//! The window state is embedded in the value (`"{count}:{window_end_unix}"`) rather than
//! derived from the key TTL, so decisions are deterministic under an injected clock and
//! survive KV backends with coarse TTLs. The key TTL only garbage-collects stale windows.
//!
//! KV-outage semantics are the *caller's* policy: auth-abuse limiting fails closed, read-path
//! limiting fails open (S-24) — this module just propagates the error.

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

/// Records a hit on `key` under a fixed window of `window` seconds with the given `limit`.
///
/// Note the read-modify-write is not atomic across replicas — with the in-memory KV there is
/// one process anyway, and on Redis the worst case under-counts a burst by a few requests,
/// which is acceptable for abuse limiting (the durable policies sit behind it).
pub async fn hit(kv: &dyn Kv, key: &str, limit: u32, window: Duration, now: DateTime<Utc>) -> Result<Decision> {
    let window_end_default = now + window;
    let (count, window_end) = match kv.get(key).await?.and_then(|raw| parse(&raw)) {
        Some((count, end)) if now < end => (count, end),
        // Absent, corrupt, or already past its window: a fresh window starts now.
        _ => (0, window_end_default),
    };

    if count >= limit {
        let retry_after_secs = (window_end - now).num_seconds().max(1) as u64;
        return Ok(Decision::Limited { retry_after_secs });
    }

    let remaining = (window_end - now).num_seconds().max(1) as u64;
    let value = format!("{}:{}", count + 1, window_end.timestamp());
    kv.set_ttl(key, &value, StdDuration::from_secs(remaining)).await?;
    Ok(Decision::Allowed)
}

/// Parses `"{count}:{window_end_unix}"`; `None` on any corruption (treated as a fresh window).
fn parse(raw: &str) -> Option<(u32, DateTime<Utc>)> {
    let (count, end) = raw.split_once(':')?;
    let count: u32 = count.parse().ok()?;
    let end = DateTime::from_timestamp(end.parse().ok()?, 0)?;
    Some((count, end))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use pub_kv::MemoryKv;

    use super::*;

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 6, 12, 0, 0).unwrap()
    }

    #[tokio::test]
    async fn allows_up_to_limit_then_blocks_with_retry_after() {
        let kv = MemoryKv::new();
        for i in 0..5 {
            let decision = hit(&kv, "rl:test", 5, Duration::hours(1), t0() + Duration::minutes(i)).await.unwrap();
            assert_eq!(decision, Decision::Allowed, "hit {i} must pass");
        }
        let decision = hit(&kv, "rl:test", 5, Duration::hours(1), t0() + Duration::minutes(10)).await.unwrap();
        match decision {
            Decision::Limited { retry_after_secs } => {
                // The window started at t0; 50 minutes remain.
                assert_eq!(retry_after_secs, 50 * 60);
            }
            Decision::Allowed => panic!("sixth hit must be limited"),
        }
    }

    #[tokio::test]
    async fn window_resets_after_expiry() {
        let kv = MemoryKv::new();
        for _ in 0..3 {
            hit(&kv, "rl:reset", 3, Duration::hours(1), t0()).await.unwrap();
        }
        assert!(matches!(hit(&kv, "rl:reset", 3, Duration::hours(1), t0()).await.unwrap(), Decision::Limited { .. }));
        // One second past the window end everything is allowed again.
        let later = t0() + Duration::hours(1) + Duration::seconds(1);
        assert_eq!(hit(&kv, "rl:reset", 3, Duration::hours(1), later).await.unwrap(), Decision::Allowed);
    }

    #[tokio::test]
    async fn keys_are_independent() {
        let kv = MemoryKv::new();
        hit(&kv, "rl:a", 1, Duration::hours(1), t0()).await.unwrap();
        assert!(matches!(hit(&kv, "rl:a", 1, Duration::hours(1), t0()).await.unwrap(), Decision::Limited { .. }));
        assert_eq!(hit(&kv, "rl:b", 1, Duration::hours(1), t0()).await.unwrap(), Decision::Allowed);
    }

    #[tokio::test]
    async fn corrupt_state_falls_back_to_a_fresh_window() {
        let kv = MemoryKv::new();
        kv.set_ttl("rl:junk", "not-a-counter", StdDuration::from_secs(60)).await.unwrap();
        assert_eq!(hit(&kv, "rl:junk", 1, Duration::hours(1), t0()).await.unwrap(), Decision::Allowed);
    }

    #[test]
    fn limited_decision_converts_to_rate_limited_error() {
        let err = Decision::Limited { retry_after_secs: 42 }.into_result().unwrap_err();
        assert_eq!(err.code(), "rate_limited");
        assert!(Decision::Allowed.into_result().is_ok());
    }
}
