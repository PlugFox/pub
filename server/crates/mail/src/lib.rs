//! Outbound email delivery: the mailer that resolves its transport from runtime settings, two
//! [`Mailer`] implementations under it, plus askama templates.
//!
//! - [`RuntimeMailer`] — what every sender actually holds. It reads the runtime `smtp` section
//!   at the top of each send and rebuilds the transport only when a fingerprint of that section
//!   changed (decision 09 amendment, closing D10). Every consumer keeps one `Arc<dyn Mailer>`,
//!   so an administrator's SMTP change takes effect on the next message with no restart and no
//!   call-site churn.
//! - [`SmtpMailer`] — lettre async SMTP transport (rustls), built from a resolved section.
//! - [`InMemoryMailer`] — records every message behind a mutex; the test double and the
//!   fallback when no SMTP host is configured anywhere.
//!
//! **The KEK stays out of this crate.** `pub-auth` already depends on `pub-mail`, so unsealing
//! the stored password here would close a dependency cycle; [`PasswordUnsealer`] is the seam,
//! constructed by the binary that loaded the key (S-26).
//!
//! Templates render text + minimal HTML pairs; senders pass both through
//! [`Mailer::send_multipart`].

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use askama::Template;
use async_trait::async_trait;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor};
use pub_core::settings::{SettingsCache, SmtpSettings as SmtpSection};
use pub_core::traits::Mailer;
use pub_core::{Error, Result};

/// How the SMTP connection is secured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Implicit TLS from the first byte (usually port 465).
    Tls,
    /// Plaintext upgraded via STARTTLS (usually port 587) — the default.
    Starttls,
    /// No transport security — local relays and tests only.
    None,
}

/// Connection settings for [`SmtpMailer`] (mirrors the config `smtp` section).
///
/// [`Debug`] is hand-written so the SMTP password can never reach a log line through a stray
/// `{:?}` (S-25/S-26).
#[derive(Clone)]
pub struct SmtpSettings {
    /// SMTP server hostname.
    pub host: String,
    /// SMTP server port.
    pub port: u16,
    /// Optional credentials.
    pub username: Option<String>,
    /// Password for `username`, in the clear.
    ///
    /// This is the *resolved* value: either the runtime setting [`RuntimeMailer`] just unsealed
    /// from the settings table, or the boot `[smtp]` password when the section still points at
    /// the boot endpoint (S-26). Its plaintext lifetime is one transport build.
    pub password: Option<String>,
    /// `From:` mailbox, e.g. `Pub <noreply@pub.example>`.
    pub from: String,
    /// Transport security mode.
    pub security: SmtpSecurity,
}

impl std::fmt::Debug for SmtpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("from", &self.from)
            .field("security", &self.security)
            .finish()
    }
}

/// Production mailer over lettre's async SMTP transport.
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpMailer {
    /// Builds the transport from settings. Fails fast on unparsable host/from.
    pub fn new(settings: &SmtpSettings) -> Result<Self> {
        let from: Mailbox = settings
            .from
            .parse()
            .map_err(|err| Error::Config { message: format!("smtp.from is not a valid mailbox: {err}") })?;
        let mut builder = match settings.security {
            SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host),
            SmtpSecurity::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host),
            SmtpSecurity::None => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)),
        }
        .map_err(|err| Error::Config { message: format!("smtp transport setup failed: {err}") })?
        .port(settings.port);
        if let (Some(user), Some(password)) = (&settings.username, &settings.password) {
            // Unconditional, including on an unencrypted transport (decision 09's correction to
            // its own amendment, S-26.a). The endpoint gate one layer up is the *entire*
            // mechanism protecting the operator's credential: a runtime section whose security
            // mode differs from boot no longer matches the boot endpoint, so it is handed no
            // boot password at all. A second guard here could therefore never fire on the
            // instance administrator it was written for — and it did fire on the operator's own
            // `security = "none"` relay, which is a legal, validated, documented configuration
            // (a local relay wanting SMTP AUTH without TLS). Refusing to build it turned that
            // deployment into a total mail outage: every message dead-lettered and nobody could
            // sign in. An operator who configures an unencrypted relay with credentials in their
            // own boot file has made a decision about their own network.
            builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
        }
        Ok(Self { transport: builder.build(), from })
    }

    fn build_message(&self, to: &str, subject: &str) -> Result<lettre::message::MessageBuilder> {
        let to: Mailbox =
            to.parse().map_err(|err| Error::Invalid { message: format!("invalid recipient address: {err}") })?;
        Ok(Message::builder().from(self.from.clone()).to(to).subject(subject))
    }

    async fn deliver(&self, message: Message) -> Result<()> {
        self.transport
            .send(message)
            .await
            .map(|_| ())
            // The SMTP response is safe to log (no message content in it); the message body
            // never appears in errors.
            .map_err(|err| Error::Internal { message: format!("smtp delivery failed: {err}") })
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn ping(&self) -> Result<()> {
        // Configuration check only: a live NOOP per health poll would hold SMTP connections
        // hostage to orchestrator probe frequency.
        Ok(())
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        let message = self
            .build_message(to, subject)?
            .body(body.to_owned())
            .map_err(|err| Error::Internal { message: format!("mail build failed: {err}") })?;
        self.deliver(message).await
    }

    async fn send_multipart(&self, to: &str, subject: &str, text: &str, html: &str) -> Result<()> {
        let message = self
            .build_message(to, subject)?
            .multipart(MultiPart::alternative_plain_html(text.to_owned(), html.to_owned()))
            .map_err(|err| Error::Internal { message: format!("mail build failed: {err}") })?;
        self.deliver(message).await
    }
}

// ------------------------------------------------------------------------- runtime resolution

/// Builds a transport from a resolved SMTP section.
///
/// A seam rather than a direct call to [`SmtpMailer::new`]: it is what lets the integration
/// harness install a recording double, so a test that patches `smtp.host` never opens a socket.
pub trait MailerBuilder: Send + Sync {
    /// Builds the transport, or fails the way `SmtpMailer::new` fails (bad `from`, bad host).
    fn build(&self, settings: &SmtpSettings) -> Result<Arc<dyn Mailer>>;
}

/// The production builder: one pooled [`SmtpMailer`] per resolved section.
#[derive(Debug, Default, Clone, Copy)]
pub struct SmtpMailerBuilder;

impl MailerBuilder for SmtpMailerBuilder {
    fn build(&self, settings: &SmtpSettings) -> Result<Arc<dyn Mailer>> {
        Ok(Arc::new(SmtpMailer::new(settings)?))
    }
}

/// Opens the KEK-sealed SMTP password of the runtime settings document (S-26).
///
/// A trait object because the KEK belongs to the process, not to this crate: `pub-auth` owns
/// the single `secretbox` implementation and already depends on `pub-mail`, so calling it from
/// here would be a dependency cycle.
pub trait PasswordUnsealer: Send + Sync {
    /// Opens a base64 `nonce ‖ ct‖tag` blob into the plaintext password.
    fn unseal(&self, sealed_b64: &str) -> Result<String>;
}

struct ClosureUnsealer<F>(F);

impl<F> PasswordUnsealer for ClosureUnsealer<F>
where
    F: Fn(&str) -> Result<String> + Send + Sync,
{
    fn unseal(&self, sealed_b64: &str) -> Result<String> {
        (self.0)(sealed_b64)
    }
}

/// Wraps a closure as a [`PasswordUnsealer`] — the shape both `pubd` and the test harness want.
pub fn unsealer<F>(open: F) -> Arc<dyn PasswordUnsealer>
where
    F: Fn(&str) -> Result<String> + Send + Sync + 'static,
{
    Arc::new(ClosureUnsealer(open))
}

/// The boot `[smtp]` credential and the one endpoint it may ever be presented to.
///
/// [`Debug`] is hand-written: this holds the operator's SMTP password for the process lifetime
/// (S-25.a).
#[derive(Clone, Default)]
pub struct BootSmtp {
    /// Boot `smtp.host`.
    pub host: Option<String>,
    /// Boot `smtp.port`.
    pub port: u16,
    /// Boot `smtp.username`.
    pub username: Option<String>,
    /// Boot `smtp.security`, as its lowercase config name — part of the endpoint, because a
    /// downgrade to `none` redirects the credential onto the wire as effectively as a new
    /// hostname redirects it to another server (decision 09 amendment).
    pub security: String,
    /// Boot `smtp.password`, used **only** when the effective section still names the endpoint
    /// above (decision 09 amendment).
    pub password: Option<String>,
}

impl std::fmt::Debug for BootSmtp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootSmtp")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("security", &self.security)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// What [`RuntimeMailer`] resolved, credential-free — the test-mail action's diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtpDescription {
    /// Effective host; `None` = no SMTP anywhere, mail goes to the in-memory outbox.
    pub host: Option<String>,
    /// Effective port.
    pub port: u16,
    /// Effective transport security.
    pub security: String,
    /// Whether the transport will present credentials. Never the credential itself.
    pub credentialed: bool,
}

/// The transport currently memoized, and the section fingerprint it was built from.
struct Resolved {
    fingerprint: u64,
    mailer: Arc<dyn Mailer>,
}

/// What [`RuntimeMailer`] would do with the stored section right now.
///
/// Named rather than inlined because the send path and the diagnostics path need *different*
/// answers to the same question. Decision 09 keeps the previous transport alive across a failed
/// rebuild, so a message still leaves — but it leaves for an endpoint the stored section no
/// longer names, and the test-mail action has to call that a failure or it reports success for a
/// host it never contacted.
enum Resolution {
    /// No SMTP host anywhere: the in-memory sink, which delivers nothing and says so.
    Sink,
    /// The stored section is in force.
    Applied(Arc<dyn Mailer>),
    /// The stored section could not be built; `previous` is what is still delivering.
    Stale {
        /// The memoized transport that keeps sign-in alive while the section is broken.
        previous: Arc<dyn Mailer>,
        /// Why the stored section could not be applied.
        error: Error,
    },
    /// The stored section could not be built and nothing is memoized to fall back to — which is
    /// every send after a restart. There is no transport, so the send has to fail.
    Unusable(Error),
}

/// The [`Mailer`] every sender holds: resolves the transport from the runtime settings cache.
///
/// Three properties are load-bearing and none of them is polish:
///
/// - **Memoized on a fingerprint of the *sealed* section.** The SMTP transport is a connection
///   pool; rebuilding it per message would throw pooling away. Fingerprinting the sealed blob
///   detects a password rotation without unsealing anything on the hot path.
/// - **A failed rebuild keeps the previous transport — when there *is* one.** One unparsable
///   `from` typed into the admin UI must not turn off sign-in instance-wide, the same stance the
///   settings cache itself takes for an unparseable section. With nothing memoized — which is
///   every send after a restart — there is no transport to keep, and the send fails instead of
///   going to the in-memory sink: a black hole that answers `Ok` marks every queued sign-in code
///   delivered, keeps `dead_pending` at 0 and leaves an instance nobody can sign in to where
///   every signal says mail works (decision 09 amendment). The sink covers the *no host
///   configured* case and nothing else.
/// - **Propagation is lazy.** A peer that sends no mail never rebuilds; "the settings version is
///   current" and "the mailer is current" are different statements.
pub struct RuntimeMailer {
    cache: Arc<SettingsCache>,
    builder: Arc<dyn MailerBuilder>,
    unsealer: Arc<dyn PasswordUnsealer>,
    boot: BootSmtp,
    fallback: Arc<dyn Mailer>,
    resolved: ArcSwapOption<Resolved>,
    /// Fingerprint of the last build failure that was logged — so a broken section is reported
    /// once, not once per outgoing message.
    reported_failure: Mutex<Option<u64>>,
}

impl std::fmt::Debug for RuntimeMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeMailer").field("boot", &self.boot).finish_non_exhaustive()
    }
}

impl RuntimeMailer {
    /// Builds the resolver. Nothing is constructed until the first send.
    pub fn new(
        cache: Arc<SettingsCache>,
        builder: Arc<dyn MailerBuilder>,
        unsealer: Arc<dyn PasswordUnsealer>,
        boot: BootSmtp,
        fallback: Arc<dyn Mailer>,
    ) -> Self {
        Self {
            cache,
            builder,
            unsealer,
            boot,
            fallback,
            resolved: ArcSwapOption::empty(),
            reported_failure: Mutex::new(None),
        }
    }

    /// The effective transport for right now, building it only when the section changed.
    ///
    /// `Err` means there is no transport at all: a host is configured, the section cannot be
    /// built from, and nothing is memoized. The caller — the queue handler, or a request-path
    /// sender — turns that into a retry and eventually a dead letter, which is visible on the
    /// admin job surface and in `queue_jobs_total{outcome="dead"}`.
    ///
    /// Two senders racing a change both build and both store; the loser's transport is dropped
    /// unused. That is deliberately not locked: a mutex here would put every outgoing message
    /// behind one, to save a construction that opens no socket.
    pub fn resolve(&self) -> Result<Arc<dyn Mailer>> {
        let current = self.cache.current();
        match self.resolve_current(&current.smtp) {
            Resolution::Sink => Ok(Arc::clone(&self.fallback)),
            Resolution::Applied(mailer) | Resolution::Stale { previous: mailer, .. } => Ok(mailer),
            Resolution::Unusable(error) => Err(error),
        }
    }

    /// The one place the section is turned into a transport; both callers project from it.
    fn resolve_current(&self, section: &SmtpSection) -> Resolution {
        let Some(host) = section.host.as_deref().map(str::trim).filter(|host| !host.is_empty()) else {
            return Resolution::Sink;
        };
        let fingerprint = fingerprint(section);
        if let Some(resolved) = self.resolved.load_full()
            && resolved.fingerprint == fingerprint
        {
            return Resolution::Applied(Arc::clone(&resolved.mailer));
        }
        match self.resolve_section(section, host).and_then(|settings| self.builder.build(&settings)) {
            Ok(mailer) => {
                self.resolved.store(Some(Arc::new(Resolved { fingerprint, mailer: Arc::clone(&mailer) })));
                *self.reported_failure.lock().expect("mailer failure mutex poisoned") = None;
                Resolution::Applied(mailer)
            }
            Err(error) => {
                let mut reported = self.reported_failure.lock().expect("mailer failure mutex poisoned");
                if *reported != Some(fingerprint) {
                    *reported = Some(fingerprint);
                    // The message names the failing field, never the credential (S-25.a).
                    tracing::error!(host, %error, "smtp settings could not be applied");
                }
                drop(reported);
                // Deliberately no `resolved.store`: the section stays unapplied, so a corrected
                // edit is picked up on the next send instead of needing another change.
                match self.resolved.load_full() {
                    Some(previous) => Resolution::Stale { previous: Arc::clone(&previous.mailer), error },
                    None => Resolution::Unusable(error),
                }
            }
        }
    }

    /// Host, port, security and credentials as they stand — never the password itself.
    pub fn describe(&self) -> SmtpDescription {
        let current = self.cache.current();
        let section = &current.smtp;
        let host = section.host.as_deref().map(str::trim).filter(|host| !host.is_empty()).map(str::to_owned);
        SmtpDescription {
            credentialed: host.is_some()
                && section.username.is_some()
                && (section.password_sealed.is_some() || self.boot_credential_applies(section)),
            host,
            port: section.port,
            security: section.security.clone(),
        }
    }

    /// Resolves the stored section into connection settings, unsealing the password.
    fn resolve_section(&self, section: &SmtpSection, host: &str) -> Result<SmtpSettings> {
        let password = match section.password_sealed.as_deref() {
            Some(sealed) => Some(self.unsealer.unseal(sealed)?),
            // Clearing the runtime password falls back to boot — subject to the endpoint match,
            // which is the whole of S-26.a's protection (decision 09's correction).
            None if self.boot_credential_applies(section) => self.boot.password.clone(),
            None => None,
        };
        Ok(SmtpSettings {
            host: host.to_owned(),
            port: section.port,
            username: section.username.clone().filter(|user| !user.is_empty()),
            password,
            from: section.from.clone(),
            security: parse_security(&section.security),
        })
    }

    /// Whether the operator's boot password applies to this section (S-26.a).
    ///
    /// The endpoint rule itself lives on [`SmtpSection::same_endpoint`], next to the document it
    /// judges; this composes it with the one thing the settings table never carries — whether a
    /// boot password exists at all.
    fn boot_credential_applies(&self, section: &SmtpSection) -> bool {
        self.boot.password.is_some()
            && section.same_endpoint(
                self.boot.host.as_deref(),
                self.boot.port,
                self.boot.username.as_deref(),
                &self.boot.security,
            )
    }
}

#[async_trait]
impl Mailer for RuntimeMailer {
    async fn ping(&self) -> Result<()> {
        self.resolve()?.ping().await
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        self.resolve()?.send(to, subject, body).await
    }

    async fn send_multipart(&self, to: &str, subject: &str, text: &str, html: &str) -> Result<()> {
        self.resolve()?.send_multipart(to, subject, text, html).await
    }

    /// A `Stale` resolution is a failure here and a success on the send path — see
    /// [`Resolution`]. The message goes out on the memoized transport, and the operator asking
    /// "is my SMTP configuration working?" is told that the section they are looking at is not
    /// the one that carried it.
    fn resolution(&self) -> Result<()> {
        let current = self.cache.current();
        match self.resolve_current(&current.smtp) {
            Resolution::Sink | Resolution::Applied(_) => Ok(()),
            Resolution::Stale { error, .. } | Resolution::Unusable(error) => Err(error),
        }
    }
}

/// Cheap identity of an SMTP section: the memo key.
///
/// The **sealed** blob is hashed, never the plaintext — a rotation therefore changes the
/// fingerprint without the hot path ever touching the KEK.
fn fingerprint(section: &SmtpSection) -> u64 {
    use std::hash::{Hash as _, Hasher as _};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    section.host.hash(&mut hasher);
    section.port.hash(&mut hasher);
    section.username.hash(&mut hasher);
    section.from.hash(&mut hasher);
    section.security.hash(&mut hasher);
    section.password_sealed.hash(&mut hasher);
    hasher.finish()
}

/// Validates a stored `smtp` section the way the transport will build from it.
///
/// The admin write path's mirror of [`SmtpMailer::new`] — and deliberately *is* that call rather
/// than a copy of its two fallible steps, so the validator and the build cannot drift into
/// disagreeing about which sections are usable. Decision 09's amendment states the rule this
/// serves: an unbuildable section is refused at the write, not discovered at the send, because
/// the send path has no user attached to answer.
///
/// Credentials are left out on purpose: the stored password is sealed and this is validating the
/// transport, not the login. A section with no host builds nothing, so there is nothing to
/// refuse — that is the in-memory sink's case.
pub fn validate_section(section: &SmtpSection) -> Result<()> {
    let Some(host) = section.host.as_deref().map(str::trim).filter(|host| !host.is_empty()) else {
        return Ok(());
    };
    SmtpMailer::new(&SmtpSettings {
        host: host.to_owned(),
        port: section.port,
        username: None,
        password: None,
        from: section.from.clone(),
        security: parse_security(&section.security),
    })
    .map(drop)
}

/// The admin surface validates this to `tls | starttls | none`; a stored value from anywhere
/// else falls back to the default rather than refusing to build a transport at all.
fn parse_security(raw: &str) -> SmtpSecurity {
    match raw {
        "tls" => SmtpSecurity::Tls,
        "none" => SmtpSecurity::None,
        _ => SmtpSecurity::Starttls,
    }
}

/// One recorded message inside [`InMemoryMailer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentEmail {
    /// Recipient address.
    pub to: String,
    /// Subject line.
    pub subject: String,
    /// Plain-text body.
    pub text: String,
    /// HTML alternative, when the sender provided one.
    pub html: Option<String>,
}

/// Test/dev mailer: keeps every message in memory instead of delivering it.
#[derive(Default)]
pub struct InMemoryMailer {
    sent: Mutex<Vec<SentEmail>>,
}

impl InMemoryMailer {
    /// An empty outbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of everything sent so far, oldest first.
    pub fn sent(&self) -> Vec<SentEmail> {
        self.sent.lock().expect("outbox mutex poisoned").clone()
    }

    fn record(&self, mail: SentEmail) {
        self.sent.lock().expect("outbox mutex poisoned").push(mail);
    }
}

#[async_trait]
impl Mailer for InMemoryMailer {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        self.record(SentEmail { to: to.to_owned(), subject: subject.to_owned(), text: body.to_owned(), html: None });
        Ok(())
    }

    async fn send_multipart(&self, to: &str, subject: &str, text: &str, html: &str) -> Result<()> {
        self.record(SentEmail {
            to: to.to_owned(),
            subject: subject.to_owned(),
            text: text.to_owned(),
            html: Some(html.to_owned()),
        });
        Ok(())
    }
}

#[derive(Template)]
#[template(path = "otp.txt")]
struct OtpText<'a> {
    code: &'a str,
    requester_ip: &'a str,
    expiry_minutes: i64,
}

#[derive(Template)]
#[template(path = "otp.html")]
struct OtpHtml<'a> {
    code: &'a str,
    requester_ip: &'a str,
    expiry_minutes: i64,
}

#[derive(Template)]
#[template(path = "email_change.txt")]
struct EmailChangeText<'a> {
    code: &'a str,
    instance: &'a str,
    requester_ip: &'a str,
    expiry_minutes: i64,
}

#[derive(Template)]
#[template(path = "email_change.html")]
struct EmailChangeHtml<'a> {
    code: &'a str,
    instance: &'a str,
    requester_ip: &'a str,
    expiry_minutes: i64,
}

/// A rendered OTP email, ready for [`Mailer::send_multipart`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedEmail {
    /// Subject line.
    pub subject: String,
    /// Plain-text body.
    pub text: String,
    /// HTML alternative.
    pub html: String,
}

/// Renders the OTP sign-in email (S-03): the code, the requester IP, and the expiry window.
///
/// **The code never enters the subject** ([S-26.b](../../../docs/security.md)). Outbound mail is
/// queued, and a queued subject is an unsealed column: sealing the body while the subject read
/// `"{code} is your sign-in code"` put the redeemable code in the clear in the table, in every
/// dump, replica and backup, and in the payload type's hand-written `Debug` — next to the address
/// it belongs to. The subject stays cleartext by design so a dead letter is identifiable without
/// a KEK, which is exactly why nothing secret may go in one.
pub fn render_otp_email(code: &str, requester_ip: Option<&str>, expiry_minutes: i64) -> Result<RenderedEmail> {
    let ip = requester_ip.unwrap_or("unknown");
    let text = OtpText { code, requester_ip: ip, expiry_minutes }
        .render()
        .map_err(|err| Error::Internal { message: format!("otp text template failed: {err}") })?;
    let html = OtpHtml { code, requester_ip: ip, expiry_minutes }
        .render()
        .map_err(|err| Error::Internal { message: format!("otp html template failed: {err}") })?;
    Ok(RenderedEmail { subject: "Your sign-in code".to_owned(), text, html })
}

/// Renders the address-confirmation email for an account email change
/// ([S-03.b](../../../docs/security.md#1-authentication)).
///
/// The same subject rule as the sign-in code and for the same reason: **the code never enters the
/// subject**, because a queued subject is an unsealed column. The body says the account keeps its
/// current address until the code is entered — the recipient of a mistyped change needs to know
/// that ignoring the message is a complete answer, not a hopeful one.
pub fn render_email_change_email(
    code: &str,
    instance: &str,
    requester_ip: Option<&str>,
    expiry_minutes: i64,
) -> Result<RenderedEmail> {
    let ip = requester_ip.unwrap_or("unknown");
    let text = EmailChangeText { code, instance, requester_ip: ip, expiry_minutes }
        .render()
        .map_err(|err| Error::Internal { message: format!("email-change text template failed: {err}") })?;
    let html = EmailChangeHtml { code, instance, requester_ip: ip, expiry_minutes }
        .render()
        .map_err(|err| Error::Internal { message: format!("email-change html template failed: {err}") })?;
    Ok(RenderedEmail { subject: "Confirm your new email address".to_owned(), text, html })
}

#[cfg(test)]
mod tests {
    use pub_core::settings::RuntimeSettings;

    use super::*;

    /// Records what it was asked to build and hands back one shared outbox.
    #[derive(Default)]
    struct RecordingBuilder {
        built: Mutex<Vec<SmtpSettings>>,
        outbox: Arc<InMemoryMailer>,
        fail: Mutex<bool>,
    }

    impl RecordingBuilder {
        fn built(&self) -> Vec<SmtpSettings> {
            self.built.lock().expect("builder mutex").clone()
        }
    }

    impl MailerBuilder for RecordingBuilder {
        fn build(&self, settings: &SmtpSettings) -> Result<Arc<dyn Mailer>> {
            if *self.fail.lock().expect("builder mutex") {
                return Err(Error::Config { message: "smtp.from is not a valid mailbox".to_owned() });
            }
            self.built.lock().expect("builder mutex").push(settings.clone());
            Ok(Arc::clone(&self.outbox) as Arc<dyn Mailer>)
        }
    }

    fn section(host: Option<&str>, username: Option<&str>, sealed: Option<&str>) -> SmtpSection {
        secured_section(host, username, sealed, "starttls")
    }

    fn secured_section(
        host: Option<&str>,
        username: Option<&str>,
        sealed: Option<&str>,
        security: &str,
    ) -> SmtpSection {
        SmtpSection {
            host: host.map(str::to_owned),
            port: 587,
            username: username.map(str::to_owned),
            from: "Pub <noreply@corp.com>".to_owned(),
            security: security.to_owned(),
            password_sealed: sealed.map(str::to_owned),
        }
    }

    /// Boot `[smtp]` naming the same endpoint [`section`] does, with the operator's password.
    fn boot_smtp() -> BootSmtp {
        BootSmtp {
            host: Some("smtp.corp.com".to_owned()),
            port: 587,
            username: Some("mailer".to_owned()),
            security: "starttls".to_owned(),
            password: Some("boot-secret-value".to_owned()),
        }
    }

    /// A cache whose *stored* snapshot is `smtp`, over empty boot defaults.
    fn cache_with(smtp: SmtpSection) -> Arc<SettingsCache> {
        let cache = Arc::new(SettingsCache::new(RuntimeSettings::default()));
        store(&cache, smtp, 1);
        cache
    }

    fn store(cache: &SettingsCache, smtp: SmtpSection, version: i64) {
        let entry = pub_core::settings::SettingEntry {
            key: pub_core::settings::keys::SMTP.to_owned(),
            value: serde_json::to_value(&smtp).expect("serialize section"),
            version,
        };
        cache.apply(&[entry], version);
    }

    fn runtime(cache: Arc<SettingsCache>, builder: Arc<RecordingBuilder>, boot: BootSmtp) -> RuntimeMailer {
        RuntimeMailer::new(
            cache,
            builder as Arc<dyn MailerBuilder>,
            unsealer(|sealed: &str| Ok(format!("opened:{sealed}"))),
            boot,
            Arc::new(InMemoryMailer::new()) as Arc<dyn Mailer>,
        )
    }

    #[tokio::test]
    async fn the_runtime_mailer_rebuilds_only_when_the_smtp_fingerprint_changes() {
        let cache = cache_with(section(Some("smtp.corp.com"), None, None));
        let builder = Arc::new(RecordingBuilder::default());
        let mailer = runtime(Arc::clone(&cache), Arc::clone(&builder), BootSmtp::default());

        mailer.send("dev@corp.com", "one", "body").await.unwrap();
        mailer.send("dev@corp.com", "two", "body").await.unwrap();
        assert_eq!(builder.built().len(), 1, "an unchanged section must reuse the pooled transport");

        // A settings write that does not touch SMTP must not cost a rebuild either.
        cache.apply(
            &[pub_core::settings::SettingEntry {
                key: pub_core::settings::keys::BRANDING.to_owned(),
                value: serde_json::json!({ "name": "Acme Registry" }),
                version: 2,
            }],
            2,
        );
        mailer.send("dev@corp.com", "three", "body").await.unwrap();
        assert_eq!(builder.built().len(), 1, "a branding write is not an smtp change");

        // Changing the host is.
        store(&cache, section(Some("smtp2.corp.com"), None, None), 3);
        mailer.send("dev@corp.com", "four", "body").await.unwrap();
        assert_eq!(builder.built().len(), 2);
        assert_eq!(builder.built()[1].host, "smtp2.corp.com");

        // …and so is a password rotation, which is visible in the *sealed* blob alone.
        store(&cache, section(Some("smtp2.corp.com"), Some("mailer"), Some("c2VhbGVk")), 4);
        mailer.send("dev@corp.com", "five", "body").await.unwrap();
        assert_eq!(builder.built().len(), 3);
        assert_eq!(builder.built()[2].password.as_deref(), Some("opened:c2VhbGVk"));
    }

    #[tokio::test]
    async fn a_failed_rebuild_keeps_the_previous_transport_and_is_reported_once() {
        let cache = cache_with(section(Some("smtp.corp.com"), None, None));
        let builder = Arc::new(RecordingBuilder::default());
        let mailer = runtime(Arc::clone(&cache), Arc::clone(&builder), BootSmtp::default());
        mailer.send("dev@corp.com", "before", "body").await.unwrap();

        // One typo in the admin UI must not turn off sign-in instance-wide.
        *builder.fail.lock().unwrap() = true;
        store(&cache, section(Some("broken.corp.com"), None, None), 2);
        mailer.send("dev@corp.com", "during", "body").await.expect("the previous transport still delivers");
        mailer.send("dev@corp.com", "during-again", "body").await.expect("still delivers");
        assert_eq!(builder.built().len(), 1, "the broken section was never applied");
        assert_eq!(builder.outbox.sent().len(), 3, "every message went out on the old transport");

        // Correcting the section recovers without needing another change to it.
        *builder.fail.lock().unwrap() = false;
        mailer.send("dev@corp.com", "after", "body").await.unwrap();
        assert_eq!(builder.built().len(), 2);
        assert_eq!(builder.built()[1].host, "broken.corp.com");
    }

    #[tokio::test]
    async fn a_section_that_cannot_be_built_fails_the_send_when_nothing_is_memoized() {
        // Decision 09 amendment: "keep the previous transport" needs there to *be* one. After a
        // restart nothing is memoized, and the sink that used to stand in here accepted every
        // message and returned `Ok`, so the queue marked each sign-in code delivered while the
        // bytes went into a `Vec` — an instance nobody can sign in to where every signal says
        // mail works. The send has to fail so the queue can retry it and then dead-letter it.
        let cache = cache_with(section(Some("smtp.corp.com"), None, None));
        let builder = Arc::new(RecordingBuilder::default());
        *builder.fail.lock().unwrap() = true;
        let outbox = Arc::new(InMemoryMailer::new());
        let mailer = RuntimeMailer::new(
            cache,
            Arc::clone(&builder) as Arc<dyn MailerBuilder>,
            unsealer(|_: &str| Ok(String::new())),
            BootSmtp::default(),
            Arc::clone(&outbox) as Arc<dyn Mailer>,
        );

        let err = mailer.send("dev@corp.com", "code", "body").await.expect_err("the sink must not swallow this");
        assert_eq!(err.code(), "config_invalid");
        assert!(outbox.sent().is_empty(), "nothing may reach the in-memory outbox: a host IS configured");
        assert_eq!(mailer.resolution().expect_err("the section is not in force").code(), "config_invalid");
        // The multipart path is the one queued sign-in mail actually takes.
        assert!(mailer.send_multipart("dev@corp.com", "code", "text", "<p>html</p>").await.is_err());
        assert!(mailer.ping().await.is_err());
    }

    #[tokio::test]
    async fn a_stale_transport_still_delivers_and_the_diagnostics_still_call_it_a_failure() {
        // The two halves of `Resolution::Stale`, which is the whole reason the diagnostics are a
        // separate question: the message leaves on the memoized transport (sign-in survives one
        // admin typo), and the test-mail action must not answer "delivered" for the endpoint the
        // stored section names, because that endpoint was never contacted.
        let cache = cache_with(section(Some("smtp.corp.com"), None, None));
        let builder = Arc::new(RecordingBuilder::default());
        let mailer = runtime(Arc::clone(&cache), Arc::clone(&builder), BootSmtp::default());
        mailer.send("dev@corp.com", "before", "body").await.unwrap();
        assert!(mailer.resolution().is_ok(), "the applied section is in force");

        *builder.fail.lock().unwrap() = true;
        store(&cache, section(Some("broken.corp.com"), None, None), 2);
        mailer.send("dev@corp.com", "during", "body").await.expect("the previous transport still delivers");
        let err = mailer.resolution().expect_err("the stored section is not the one that ran");
        assert_eq!(err.code(), "config_invalid");
    }

    #[tokio::test]
    async fn s26_a_the_boot_password_is_only_used_for_the_boot_endpoint() {
        // The escalation this rule exists to stop: an instance administrator repoints `host`,
        // leaves the password unset, and receives the operator's SMTP credential.
        let cache = cache_with(section(Some("smtp.corp.com"), Some("mailer"), None));
        let builder = Arc::new(RecordingBuilder::default());
        let mailer = runtime(Arc::clone(&cache), Arc::clone(&builder), boot_smtp());

        mailer.send("dev@corp.com", "boot host", "body").await.unwrap();
        assert_eq!(builder.built()[0].password.as_deref(), Some("boot-secret-value"));
        assert!(mailer.describe().credentialed);

        store(&cache, section(Some("smtp.attacker.example"), Some("mailer"), None), 2);
        mailer.send("dev@corp.com", "moved host", "body").await.unwrap();
        assert_eq!(builder.built()[1].password, None, "the boot credential must not follow the host");
        assert!(!mailer.describe().credentialed);

        // A different login user on the boot host is just as much a redirection.
        store(&cache, section(Some("smtp.corp.com"), Some("someone-else"), None), 3);
        mailer.send("dev@corp.com", "moved user", "body").await.unwrap();
        assert_eq!(builder.built()[2].password, None);

        // …and so is a downgrade of the transport: same host, same port, same login user, and
        // `AUTH PLAIN` with the operator's password would have gone out in the clear.
        store(&cache, secured_section(Some("smtp.corp.com"), Some("mailer"), None, "none"), 4);
        mailer.send("dev@corp.com", "downgraded", "body").await.unwrap();
        assert_eq!(builder.built()[3].password, None, "the boot credential must not survive a security downgrade");
        assert!(!mailer.describe().credentialed);

        // Back on the boot endpoint, the operator's credential applies again.
        store(&cache, section(Some("smtp.corp.com"), Some("mailer"), None), 5);
        mailer.send("dev@corp.com", "back", "body").await.unwrap();
        assert_eq!(builder.built()[4].password.as_deref(), Some("boot-secret-value"));
    }

    #[tokio::test]
    async fn no_host_anywhere_resolves_to_the_in_memory_fallback() {
        let cache = Arc::new(SettingsCache::new(RuntimeSettings::default()));
        let builder = Arc::new(RecordingBuilder::default());
        let outbox = Arc::new(InMemoryMailer::new());
        let mailer = RuntimeMailer::new(
            cache,
            Arc::clone(&builder) as Arc<dyn MailerBuilder>,
            unsealer(|_: &str| Ok(String::new())),
            BootSmtp::default(),
            Arc::clone(&outbox) as Arc<dyn Mailer>,
        );
        mailer.send("dev@corp.com", "hello", "body").await.unwrap();
        assert!(builder.built().is_empty(), "there is nothing to build a transport from");
        assert_eq!(outbox.sent().len(), 1);
        assert_eq!(
            mailer.describe(),
            SmtpDescription { host: None, port: 0, security: String::new(), credentialed: false }
        );
    }

    #[test]
    fn s25_the_resolver_never_renders_a_credential() {
        let boot = boot_smtp();
        let mailer = runtime(
            cache_with(section(Some("smtp.corp.com"), Some("mailer"), Some("c2VhbGVk"))),
            Arc::new(RecordingBuilder::default()),
            boot.clone(),
        );
        for rendered in [format!("{boot:?}"), format!("{mailer:?}"), format!("{:?}", mailer.describe())] {
            assert!(!rendered.contains("boot-secret-value"), "credential leaked into Debug: {rendered}");
            assert!(!rendered.contains("c2VhbGVk"), "sealed blob leaked into Debug: {rendered}");
        }
        assert!(format!("{boot:?}").contains("<redacted>"));
        // The diagnostics type has no field a password could hide in.
        assert!(mailer.describe().credentialed);
    }

    #[test]
    fn s26_b_the_otp_subject_carries_no_code() {
        // The subject is the one field of a queued message that is *not* sealed, because a dead
        // letter has to stay identifiable without a KEK. That is exactly why the code may not be
        // in it: the row, every dump taken of it and every `{:?}` of it would hold a redeemable
        // credential next to the address it belongs to. This assertion is the inverse of the one
        // that shipped with the leak.
        let mail = render_otp_email("31415926", Some("203.0.113.7"), 10).unwrap();
        assert!(!mail.subject.contains("31415926"), "the code reached the unsealed subject: {}", mail.subject);
        assert!(!mail.subject.is_empty(), "a queued message still needs an identifiable subject");
    }

    #[test]
    fn otp_template_renders_code_ip_and_expiry() {
        let mail = render_otp_email("31415926", Some("203.0.113.7"), 10).unwrap();
        for body in [&mail.text, &mail.html] {
            assert!(body.contains("31415926"), "code missing:\n{body}");
            assert!(body.contains("203.0.113.7"), "ip missing:\n{body}");
            assert!(body.contains("10 minutes"), "expiry missing:\n{body}");
        }
    }

    #[test]
    fn otp_template_handles_unknown_ip() {
        let mail = render_otp_email("00000000", None, 10).unwrap();
        assert!(mail.text.contains("Requested from IP: unknown"));
        assert!(mail.html.contains("unknown"));
    }

    #[tokio::test]
    async fn in_memory_mailer_records_plain_and_multipart() {
        let mailer = InMemoryMailer::new();
        mailer.ping().await.unwrap();
        mailer.send("dev@corp.com", "hello", "plain body").await.unwrap();
        mailer.send_multipart("dev@corp.com", "hi", "text body", "<p>html body</p>").await.unwrap();
        let sent = mailer.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].to, "dev@corp.com");
        assert_eq!(sent[0].subject, "hello");
        assert_eq!(sent[0].text, "plain body");
        assert_eq!(sent[0].html, None);
        assert_eq!(sent[1].html.as_deref(), Some("<p>html body</p>"));
    }

    /// Connection settings for the real [`SmtpMailer`] builder, with no credential.
    fn connection(host: &str, from: &str, security: SmtpSecurity) -> SmtpSettings {
        SmtpSettings {
            host: host.to_owned(),
            port: 2525,
            username: None,
            password: None,
            from: from.to_owned(),
            security,
        }
    }

    // Building the pooled async transport requires a tokio runtime, hence tokio::test.
    #[test]
    fn s25_smtp_settings_debug_redacts_the_password() {
        let settings = SmtpSettings {
            username: Some("mailer".to_owned()),
            password: Some("smtp-secret-value".to_owned()),
            ..connection("smtp.corp.com", "Pub <noreply@corp.com>", SmtpSecurity::Starttls)
        };
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("smtp-secret-value"), "password leaked into Debug: {rendered}");
        assert!(rendered.contains("<redacted>"), "redaction marker missing: {rendered}");
        assert!(rendered.contains("smtp.corp.com"), "non-secret fields must stay debuggable: {rendered}");
    }

    #[tokio::test]
    async fn smtp_mailer_rejects_bad_from_mailbox() {
        let settings = connection("smtp.example.com", "definitely not a mailbox", SmtpSecurity::Starttls);
        let err = SmtpMailer::new(&settings).map(|_| ()).expect_err("bad mailbox must fail");
        assert_eq!(err.code(), "config_invalid");
    }

    #[tokio::test]
    async fn s26_a_a_boot_relay_with_no_transport_security_still_builds_and_delivers() {
        // The regression the "belt and braces" guard shipped, from the boot configuration that
        // produces it rather than from a hand-built `SmtpSettings`. `security = "none"` with a
        // password is legal (`Settings::validate_smtp` accepts it), documented ("local relays
        // and tests only") and unremarkable: an internal relay that wants SMTP AUTH without
        // TLS. On such an instance `runtime_defaults()` makes the effective section equal the
        // boot endpoint on all four fields, so the boot credential applies to every send — and
        // a guard that refused *that* combination made every message fail to build a transport
        // at all, which since the MF2 fix is an error rather than a sink: every OTP burns its
        // eight attempts and dead-letters, and nobody can sign in. The endpoint gate above is
        // what keeps an instance admin away from the credential (see the test before this one);
        // this one is what keeps the operator's own relay working.
        let boot = BootSmtp {
            host: Some("relay.internal".to_owned()),
            port: 25,
            username: Some("pub".to_owned()),
            security: "none".to_owned(),
            password: Some("boot-secret-value".to_owned()),
        };
        // Byte-identical to what `runtime_defaults()` projects from that boot section, which is
        // what an instance whose `settings` table was never written serves.
        let section = SmtpSection {
            host: Some("relay.internal".to_owned()),
            port: 25,
            username: Some("pub".to_owned()),
            from: "Pub <noreply@corp.example>".to_owned(),
            security: "none".to_owned(),
            password_sealed: None,
        };

        // The real transport builder — the call the guard used to refuse. The recording double
        // the integration harness installs never runs `SmtpMailer::new`, so nothing else in the
        // suite can see this.
        let real = RuntimeMailer::new(
            cache_with(section.clone()),
            Arc::new(SmtpMailerBuilder) as Arc<dyn MailerBuilder>,
            unsealer(|_: &str| Ok(String::new())),
            boot.clone(),
            Arc::new(InMemoryMailer::new()) as Arc<dyn Mailer>,
        );
        real.resolve().expect("an unencrypted boot relay must still build a transport");
        real.resolution().expect("…and the operator's own section must count as in force");

        // …and the credential really is presented, so the relay's AUTH succeeds and the message
        // leaves. `send_multipart` is the path queued sign-in mail takes.
        let builder = Arc::new(RecordingBuilder::default());
        let mailer = runtime(cache_with(section), Arc::clone(&builder), boot);
        mailer.send_multipart("dev@corp.com", "Your sign-in code", "text", "<p>html</p>").await.expect("delivers");
        assert_eq!(builder.built()[0].password.as_deref(), Some("boot-secret-value"));
        assert_eq!(builder.built()[0].security, SmtpSecurity::None);
        assert_eq!(builder.outbox.sent().len(), 1, "the message has to actually leave");
        assert!(mailer.describe().credentialed);
    }

    #[tokio::test]
    async fn s26_a_an_unbuildable_section_is_refused_by_the_write_path_validator() {
        // `validate_section` is what the admin surface calls, and it must refuse exactly what
        // `SmtpMailer::new` refuses — the same call, not a copy of its checks.
        let section = |host: Option<&str>, from: &str| SmtpSection {
            host: host.map(str::to_owned),
            port: 587,
            username: None,
            from: from.to_owned(),
            security: "starttls".to_owned(),
            password_sealed: None,
        };
        assert!(validate_section(&section(Some("smtp.corp.com"), "Pub <noreply@corp.com>")).is_ok());
        // The case the wave shipped: accepted by the write path, unbuildable by the transport.
        let err = validate_section(&section(Some("smtp.corp.com"), "Acme Pub")).expect_err("bad from must fail");
        assert_eq!(err.code(), "config_invalid");
        assert!(err.to_string().contains("smtp.from"), "the operator needs the offending field: {err}");
        // No host is the in-memory sink's case: there is no transport to refuse.
        assert!(validate_section(&section(None, "  ")).is_ok());
    }

    #[tokio::test]
    async fn smtp_mailer_builds_for_every_security_mode() {
        for security in [SmtpSecurity::Tls, SmtpSecurity::Starttls, SmtpSecurity::None] {
            let settings = SmtpSettings {
                username: Some("mailer".to_owned()),
                password: Some("secret".to_owned()),
                ..connection("smtp.example.com", "Pub <noreply@pub.example>", security)
            };
            assert!(SmtpMailer::new(&settings).is_ok(), "{security:?} must build");
        }
    }
}
