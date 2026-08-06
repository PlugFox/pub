//! Authentication and credential management.
//!
//! Planned modules (docs/security.md, decisions 03, 12, 13):
//! - email OTP baseline: 8-digit CSPRNG codes, hashed at rest, 10-minute expiry, single-use;
//! - OIDC (`openidconnect`): optional multi-provider, code + PKCE S256, identity `(iss, sub)`;
//! - TOTP second factor + hashed recovery codes; step-up ("sudo mode") for S-06 actions;
//! - JWT access tokens: Ed25519 keyring with `kid` rotation, role-level claims;
//! - CLI token plane: `pub_` prefix, SHA-256 at rest, scopes, revocation ≤ 60 s;
//! - the single `authorize(actor, action, resource)` chokepoint (decision 19).
//!
//! Skeleton crate — implementations land with the auth roadmap step. Two credential planes
//! (web sessions vs CLI tokens) are never mixed.

// Intentionally empty: see the module docs above for the build-out plan.
