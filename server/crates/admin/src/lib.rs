//! Management services: the organization lifecycle and the instance-administration surface.
//!
//! Everything an org admin or an instance admin *changes* goes through here rather than
//! through a handler, for three reasons that are each a bug class:
//!
//! 1. **S-09 lives at this layer, not in a route.** Any change that redefines or withdraws a
//!    member's authority revokes that member's sessions, and the only way to change a
//!    membership is [`OrgService`], which does it. A route physically cannot forget, because a
//!    route has no other way in — [`OrgRepo`](pub_core::traits::OrgRepo)'s mutators are called
//!    from exactly one place each.
//! 2. **Every mutation is audited** (S-22) with a before/after payload, and every one emits its
//!    domain event (decision 22). Both are one line in a service method and three forgotten
//!    lines in a handler.
//! 3. **Invariants that need more than one repository** — an org that owns packages cannot be
//!    erased, a forced deletion has to make those packages unreachable through the *registry*
//!    service so the search index follows — have nowhere else to live.
//!
//! Authorization itself is **not** here: it is the [`authorize`](pub_core::authorize) chokepoint,
//! called by the API layer before it reaches a service method, because only the API layer knows
//! how a denial has to look on the wire (403 vs the S-04 404).

pub mod account;
pub mod instance;
pub mod orgs;

pub use account::{AccountDeletion, AccountProfile, AccountService, AccountSnapshot};
pub use instance::{AdminService, InstanceStats, SettingsPatch, SettingsView};
pub use orgs::{AuthorityChange, AuthorityRevocations, InvitationCreated, OrgDeletion, OrgPolicy, OrgService};

/// Who is acting, and from where — shared with the registry services so one action carried out
/// across both layers (a forced org archive flips package options) records one actor.
pub use pub_registry::ActorMeta;
