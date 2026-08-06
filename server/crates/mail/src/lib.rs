//! Outbound email delivery: two [`Mailer`] implementations plus askama templates.
//!
//! - [`SmtpMailer`] — lettre async SMTP transport (rustls). Credentials come from boot
//!   config for now; the password moves into runtime settings envelope-encrypted with the
//!   env KEK later (S-26).
//! - [`InMemoryMailer`] — records every message behind a mutex; the test double and the dev
//!   fallback when no SMTP host is configured.
//!
//! Templates render text + minimal HTML pairs; senders pass both through
//! [`Mailer::send_multipart`].

use std::sync::Mutex;

use askama::Template;
use async_trait::async_trait;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor};
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
    /// Password for `username`.
    ///
    /// Boot-config/env only for now; later this becomes a runtime setting stored
    /// envelope-encrypted with the env KEK (S-26) so admins can rotate it without a restart.
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
pub fn render_otp_email(code: &str, requester_ip: Option<&str>, expiry_minutes: i64) -> Result<RenderedEmail> {
    let ip = requester_ip.unwrap_or("unknown");
    let text = OtpText { code, requester_ip: ip, expiry_minutes }
        .render()
        .map_err(|err| Error::Internal { message: format!("otp text template failed: {err}") })?;
    let html = OtpHtml { code, requester_ip: ip, expiry_minutes }
        .render()
        .map_err(|err| Error::Internal { message: format!("otp html template failed: {err}") })?;
    Ok(RenderedEmail { subject: format!("{code} is your sign-in code"), text, html })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otp_template_renders_code_ip_and_expiry() {
        let mail = render_otp_email("31415926", Some("203.0.113.7"), 10).unwrap();
        assert!(mail.subject.contains("31415926"));
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

    // Building the pooled async transport requires a tokio runtime, hence tokio::test.
    #[test]
    fn s25_smtp_settings_debug_redacts_the_password() {
        let settings = SmtpSettings {
            host: "smtp.corp.com".to_owned(),
            port: 587,
            username: Some("mailer".to_owned()),
            password: Some("smtp-secret-value".to_owned()),
            from: "Pub <noreply@corp.com>".to_owned(),
            security: SmtpSecurity::Starttls,
        };
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("smtp-secret-value"), "password leaked into Debug: {rendered}");
        assert!(rendered.contains("<redacted>"), "redaction marker missing: {rendered}");
        assert!(rendered.contains("smtp.corp.com"), "non-secret fields must stay debuggable: {rendered}");
    }

    #[tokio::test]
    async fn smtp_mailer_rejects_bad_from_mailbox() {
        let settings = SmtpSettings {
            host: "smtp.example.com".to_owned(),
            port: 587,
            username: None,
            password: None,
            from: "definitely not a mailbox".to_owned(),
            security: SmtpSecurity::Starttls,
        };
        let err = SmtpMailer::new(&settings).map(|_| ()).expect_err("bad mailbox must fail");
        assert_eq!(err.code(), "config_invalid");
    }

    #[tokio::test]
    async fn smtp_mailer_builds_for_every_security_mode() {
        for security in [SmtpSecurity::Tls, SmtpSecurity::Starttls, SmtpSecurity::None] {
            let settings = SmtpSettings {
                host: "smtp.example.com".to_owned(),
                port: 2525,
                username: Some("mailer".to_owned()),
                password: Some("secret".to_owned()),
                from: "Pub <noreply@pub.example>".to_owned(),
                security,
            };
            assert!(SmtpMailer::new(&settings).is_ok(), "{security:?} must build");
        }
    }
}
