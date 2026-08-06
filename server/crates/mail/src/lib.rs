//! Outbound email delivery.
//!
//! Planned modules (docs/architecture.md):
//! - `lettre` SMTP transport configured from runtime settings (password encrypted with KEK);
//! - `askama` templates rendered as text+HTML multipart (OTP codes, invitations,
//!   token-expiry warnings, security notifications);
//! - the `core::Mailer` implementation used by auth and the notification center.
//!
//! Skeleton crate — implementations land with the auth/notifications roadmap steps.

// Intentionally empty: see the module docs above for the build-out plan.
