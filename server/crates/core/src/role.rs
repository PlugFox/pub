//! Cumulative org role levels (decision 19).
//!
//! An org membership carries an ordered role level stored as a small integer with gaps for
//! future insertions. Checks are always `level >= required` and flow through the single
//! `authorize()` chokepoint (implemented in a later roadmap step). Wire protocol and UI use
//! role *names*; numbers are a storage/comparison detail.

use serde::{Deserialize, Serialize};

/// Ordered org role level.
///
/// Known levels: `NONE(0) < READ(50) < WRITE(100) < ADMIN(200) < OWNER(250)`. The gaps are
/// deliberate — a future role (e.g. a `150` Maintainer) slots in without migration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleLevel(u8);

impl RoleLevel {
    /// Not a member.
    pub const NONE: Self = Self(0);
    /// Resolve and download packages.
    pub const READ: Self = Self(50);
    /// Publish and manage own packages.
    pub const WRITE: Self = Self(100);
    /// Manage members, tokens, and package settings.
    pub const ADMIN: Self = Self(200);
    /// Org lifecycle and danger zone; every org keeps at least one Owner.
    pub const OWNER: Self = Self(250);

    /// Wraps a raw stored level. Unknown values are allowed by design (future roles).
    pub const fn new(level: u8) -> Self {
        Self(level)
    }

    /// Raw numeric level as stored in the database and JWT claims.
    pub const fn level(self) -> u8 {
        self.0
    }

    /// Cumulative permission check: does this level grant what `required` demands?
    pub const fn satisfies(self, required: Self) -> bool {
        self.0 >= required.0
    }

    /// Wire/UI name for the known levels; `None` for intermediate future values.
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            0 => Some("none"),
            50 => Some("read"),
            100 => Some("write"),
            200 => Some("admin"),
            250 => Some("owner"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_strictly_cumulative() {
        assert!(RoleLevel::NONE < RoleLevel::READ);
        assert!(RoleLevel::READ < RoleLevel::WRITE);
        assert!(RoleLevel::WRITE < RoleLevel::ADMIN);
        assert!(RoleLevel::ADMIN < RoleLevel::OWNER);
    }

    #[test]
    fn levels_match_decision_19() {
        assert_eq!(RoleLevel::NONE.level(), 0);
        assert_eq!(RoleLevel::READ.level(), 50);
        assert_eq!(RoleLevel::WRITE.level(), 100);
        assert_eq!(RoleLevel::ADMIN.level(), 200);
        assert_eq!(RoleLevel::OWNER.level(), 250);
    }

    #[test]
    fn gaps_admit_future_roles_without_migration() {
        // A hypothetical Maintainer(150) must slot strictly between WRITE and ADMIN.
        let maintainer = RoleLevel::new(150);
        assert!(RoleLevel::WRITE < maintainer);
        assert!(maintainer < RoleLevel::ADMIN);
        assert!(maintainer.satisfies(RoleLevel::WRITE));
        assert!(!maintainer.satisfies(RoleLevel::ADMIN));
        assert_eq!(maintainer.name(), None);
    }

    #[test]
    fn satisfies_is_reflexive_and_cumulative() {
        assert!(RoleLevel::OWNER.satisfies(RoleLevel::READ));
        assert!(RoleLevel::READ.satisfies(RoleLevel::READ));
        assert!(!RoleLevel::READ.satisfies(RoleLevel::WRITE));
        assert!(!RoleLevel::NONE.satisfies(RoleLevel::READ));
    }

    #[test]
    fn known_names_round_trip() {
        for (level, name) in [
            (RoleLevel::NONE, "none"),
            (RoleLevel::READ, "read"),
            (RoleLevel::WRITE, "write"),
            (RoleLevel::ADMIN, "admin"),
            (RoleLevel::OWNER, "owner"),
        ] {
            assert_eq!(level.name(), Some(name));
        }
    }

    #[test]
    fn serde_is_transparent_over_u8() {
        assert_eq!(serde_json::to_string(&RoleLevel::ADMIN).unwrap(), "200");
        assert_eq!(serde_json::from_str::<RoleLevel>("50").unwrap(), RoleLevel::READ);
    }
}
