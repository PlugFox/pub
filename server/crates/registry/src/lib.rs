//! Domain services for the Pub registry.
//!
//! Planned modules (docs/architecture.md):
//! - publish pipeline: per-name lock → tar.gz safety validation → pubspec parse →
//!   sha256 → content-addressed blob write → README/CHANGELOG render → DB row + audit event;
//! - resolution policy: org-owned → instance-public → upstream proxy iff name unclaimed
//!   (local always wins — decision 01);
//! - proxy ingest shared by read-through cache and mirror mode (decision 07);
//! - retraction / discontinued / unlisted lifecycle (decision 06);
//! - name claims and shadowing alarms.
//!
//! Skeleton crate — implementations land with roadmap step 4 (pub protocol) and later.
//! Everything here builds against `pub-core` traits only; no infrastructure types leak in.

// Intentionally empty: see the module docs above for the build-out plan.
