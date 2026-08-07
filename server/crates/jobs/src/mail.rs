//! Outbound mail delivery off the request path ([decision 26](../../../docs/decisions.md#26)).
//!
//! One row per message, one recipient per row: per-recipient rows are what give a single bad
//! address its own retry and its own dead letter instead of poisoning the other 199, which one
//! `To:` list with two hundred entries cannot.
//!
//! Two rules the handler exists to enforce:
//!
//! - **The send is bounded.** `tokio::time::timeout` around the transport is the replacement for
//!   the `[http]` request deadline that used to truncate a hung SMTP conversation. Without it a
//!   relay that accepts a connection and then says nothing holds this item's lease and, once the
//!   lease is reaped, the next one too.
//! - **Sealed bodies are opened here and nowhere else** ([S-26.b](../../../docs/security.md)).
//!   A rendered sign-in body is a live credential sitting in a table; it is sealed under the
//!   boot KEK before the row is written and opened on claim. "Sealed, and the KEK cannot open
//!   it" is the ephemeral-development-KEK case (a restart mints a new key), and it is a **dead
//!   letter, not a retry**: the key that sealed those bytes left with the process that made it,
//!   so no number of attempts recovers them. The rows live for minutes, so the cost is at most
//!   an undelivered code.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use pub_core::queue::{JobKind, MailJob, QueuedJob};
use pub_core::traits::Mailer;
use pub_core::{Error, Result};

use crate::queue::{HandlerReport, JobHandler};

/// Delivers [`JobKind::MailSend`] items.
pub struct MailHandler {
    mailer: Arc<dyn Mailer>,
    kek: Vec<u8>,
    timeout: StdDuration,
}

impl std::fmt::Debug for MailHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The KEK is the key every queued sign-in body is sealed under (S-25).
        f.debug_struct("MailHandler").field("timeout", &self.timeout).finish_non_exhaustive()
    }
}

impl MailHandler {
    /// Builds the handler over the process's one mailer and its boot KEK.
    ///
    /// The `Arc<dyn Mailer>` is deliberately the *same* handle every request-path sender holds:
    /// it resolves its transport from runtime settings per send, so an administrator's SMTP
    /// change reaches queued mail with no second transport and no restart (decision 09).
    pub fn new(mailer: Arc<dyn Mailer>, kek: Vec<u8>, timeout: StdDuration) -> Self {
        Self { mailer, kek, timeout }
    }

    /// The message body as the transport needs it: plaintext, unsealed when the row says so.
    fn open(&self, mail: &MailJob) -> Result<(String, Option<String>)> {
        if !mail.sealed {
            return Ok((mail.text.clone(), mail.html.clone()));
        }
        let text = self.unseal(&mail.text)?;
        let html = mail.html.as_deref().map(|html| self.unseal(html)).transpose()?;
        Ok((text, html))
    }

    fn unseal(&self, sealed_b64: &str) -> Result<String> {
        let sealed = B64
            .decode(sealed_b64)
            .map_err(|_| Error::Internal { message: "sealed mail body is not base64".to_owned() })?;
        let plaintext = pub_auth::secretbox::open(&self.kek, &sealed)?;
        String::from_utf8(plaintext)
            .map_err(|_| Error::Internal { message: "sealed mail body is not utf-8".to_owned() })
    }
}

#[async_trait]
impl JobHandler for MailHandler {
    fn kind(&self) -> JobKind {
        JobKind::MailSend
    }

    async fn run(&self, job: &QueuedJob, _now: DateTime<Utc>) -> HandlerReport {
        let mail: MailJob = match serde_json::from_value(job.payload.clone()) {
            Ok(mail) => mail,
            // A payload this build cannot parse is not going to parse on the ninth attempt.
            Err(err) => return HandlerReport::dead(format!("undecodable mail payload: {err}")),
        };
        let (text, html) = match self.open(&mail) {
            Ok(body) => body,
            Err(err) => return HandlerReport::dead(format!("sealed body could not be opened: {err}")),
        };

        let delivery = async {
            match &html {
                Some(html) => self.mailer.send_multipart(&mail.to, &mail.subject, &text, html).await,
                None => self.mailer.send(&mail.to, &mail.subject, &text).await,
            }
        };
        match tokio::time::timeout(self.timeout, delivery).await {
            Err(_elapsed) => HandlerReport::retry(format!("smtp delivery exceeded {}s", self.timeout.as_secs())),
            Ok(Ok(())) => HandlerReport::done(),
            // A malformed recipient is the one transport failure that is permanent: an address
            // the message builder rejects will never become valid, so spending eight attempts
            // on it only delays the dead letter that says so.
            Ok(Err(Error::Invalid { message })) => HandlerReport::dead(format!("undeliverable recipient: {message}")),
            Ok(Err(err)) => HandlerReport::retry(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use pub_auth::random::OsRandom;
    use pub_core::queue::{QueueOutcome, QueueState, QueuedJobId};

    use super::*;

    const KEK: [u8; 32] = [5u8; 32];

    struct Outbox(Mutex<Vec<(String, String, String)>>);

    #[async_trait]
    impl Mailer for Outbox {
        async fn ping(&self) -> Result<()> {
            Ok(())
        }

        async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
            self.0.lock().unwrap().push((to.to_owned(), subject.to_owned(), body.to_owned()));
            Ok(())
        }
    }

    fn queued(mail: &MailJob) -> QueuedJob {
        QueuedJob {
            id: QueuedJobId::new(),
            kind: JobKind::MailSend,
            payload: serde_json::to_value(mail).unwrap(),
            state: QueueState::Running,
            attempts: 1,
            run_after: Utc::now(),
            locked_until: None,
            dedupe_key: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn sealed_body(plaintext: &str) -> String {
        B64.encode(pub_auth::secretbox::seal(&KEK, &OsRandom, plaintext.as_bytes()).unwrap())
    }

    #[tokio::test]
    async fn s26_b_a_sealed_body_is_opened_before_it_reaches_the_transport() {
        let outbox = Arc::new(Outbox(Mutex::new(Vec::new())));
        let handler = MailHandler::new(Arc::clone(&outbox) as Arc<dyn Mailer>, KEK.to_vec(), StdDuration::from_secs(5));
        let mail = MailJob {
            to: "alice@corp.com".to_owned(),
            subject: "Your sign-in code".to_owned(),
            text: sealed_body("Your code is 12345678"),
            html: None,
            sealed: true,
        };
        // The row that will sit in the table must not contain the code.
        assert!(!mail.text.contains("12345678"));

        let report = handler.run(&queued(&mail), Utc::now()).await;
        assert_eq!(report.outcome, QueueOutcome::Done);
        let sent = outbox.0.lock().unwrap().clone();
        assert_eq!(sent[0].2, "Your code is 12345678");
    }

    #[tokio::test]
    async fn s26_b_a_body_sealed_under_a_lost_kek_dead_letters_instead_of_retrying() {
        // The ephemeral development KEK: a restart mints a new key and yesterday's rows can
        // never be opened. Retrying that is eight attempts spent on arithmetic that cannot work.
        let outbox = Arc::new(Outbox(Mutex::new(Vec::new())));
        let handler =
            MailHandler::new(Arc::clone(&outbox) as Arc<dyn Mailer>, vec![9u8; 32], StdDuration::from_secs(5));
        let mail = MailJob {
            to: "alice@corp.com".to_owned(),
            subject: "Your sign-in code".to_owned(),
            text: sealed_body("Your code is 12345678"),
            html: None,
            sealed: true,
        };
        let report = handler.run(&queued(&mail), Utc::now()).await;
        assert!(matches!(report.outcome, QueueOutcome::Dead(_)), "{:?}", report.outcome);
        assert!(outbox.0.lock().unwrap().is_empty(), "nothing may be sent when the body could not be opened");
    }

    #[tokio::test]
    async fn an_undecodable_payload_dead_letters() {
        let outbox = Arc::new(Outbox(Mutex::new(Vec::new())));
        let handler = MailHandler::new(outbox as Arc<dyn Mailer>, KEK.to_vec(), StdDuration::from_secs(5));
        let mut job = queued(&MailJob {
            to: "a@b.c".to_owned(),
            subject: "s".to_owned(),
            text: "t".to_owned(),
            html: None,
            sealed: false,
        });
        job.payload = serde_json::json!({ "not": "a mail job" });
        assert!(matches!(handler.run(&job, Utc::now()).await.outcome, QueueOutcome::Dead(_)));
    }
}
