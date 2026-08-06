//! Runtime-changeable instance settings (decision 09): key → JSON with per-key versions.
//!
//! Caching, `ArcSwap`, and cross-instance invalidation live above the repository; the repo
//! only persists values and version counters. The *instance* settings version returned by
//! `SettingsRepo::get_version` is the sum of all per-key versions — it increases on **every**
//! upsert (a new key starts at 1, an update adds 1), which makes it a monotonic change counter
//! suitable for the reconciliation version-poll (docs/architecture.md).

use serde::{Deserialize, Serialize};

/// One settings entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingEntry {
    /// Setting key, e.g. `smtp`, `rate_limits`.
    pub key: String,
    /// JSON value.
    pub value: serde_json::Value,
    /// Per-key version: 1 on first write, +1 per subsequent upsert.
    pub version: i64,
}
