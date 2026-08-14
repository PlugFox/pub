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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use pub_core::audit::{AuditActor, AuditResult, NewAuditEvent};
use pub_core::queue::{JobKind, MailJob, QueuedJob};
use pub_core::traits::{AuditRepo, Mailer};
use pub_core::{Error, Result};

use crate::queue::{HandlerReport, JobHandler};

/// Delivers [`JobKind::MailSend`] items.
pub struct MailHandler {
    mailer: Arc<dyn Mailer>,
    kek: Vec<u8>,
    timeout: StdDuration,
    /// Whether the last delivery attempt succeeded — the edge detector behind the
    /// `mail_transport_unusable` gauge and its audit rows (decision 29, closes D43).
    ///
    /// Starts *healthy*: an instance that has never sent a message has no evidence of a broken
    /// transport, and a gauge that reads 1 from boot on every deployment is a gauge operators
    /// learn to ignore. The boot resolve check sets it to 1 when it has real evidence.
    healthy: AtomicBool,
    /// Audit sink for the transition rows. `None` in unit tests that only exercise delivery.
    audit: Option<Arc<dyn AuditRepo>>,
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
        Self { mailer, kek, timeout, healthy: AtomicBool::new(true), audit: None }
    }

    /// Attaches the audit sink that records the mail plane going down and coming back.
    ///
    /// Optional so the delivery unit tests need no repository, and separate from [`Self::new`]
    /// because the *signal* is a different concern from the send: a handler with no audit sink
    /// still moves mail, it just cannot tell an operator that it stopped.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn AuditRepo>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Records the outcome of one delivery attempt on the transport-health signal.
    ///
    /// **Edge-triggered, not level-triggered.** The gauge is set on every attempt (it is a
    /// state, and a gauge that is only written on change goes stale after a restart), but the
    /// audit row is written only when the state *changes*. A row per failed attempt would grow
    /// with the retry ladder — 8 attempts per message, every message, for as long as the relay
    /// is down — which is a log nobody reads at exactly the moment somebody has to.
    async fn record_health(&self, now: DateTime<Utc>, failure: Option<&str>) {
        metrics::gauge!("mail_transport_unusable").set(if failure.is_some() { 1.0 } else { 0.0 });
        let was_healthy = self.healthy.swap(failure.is_none(), Ordering::Relaxed);
        if was_healthy == failure.is_none() {
            return;
        }
        let (action, metadata) = match failure {
            // The error text names the transport failure, never the message or the recipient:
            // this row is readable by anyone who can read the audit log.
            Some(error) => ("mail.delivery_failed", serde_json::json!({ "error": error })),
            None => ("mail.delivery_recovered", serde_json::json!({})),
        };
        tracing::error!(action, "outbound mail transport state changed");
        let Some(audit) = &self.audit else { return };
        let event = NewAuditEvent {
            actor: AuditActor::System,
            ip: None,
            user_agent: None,
            org_id: None,
            action: action.to_owned(),
            target: None,
            result: if failure.is_some() { AuditResult::Failure } else { AuditResult::Success },
            metadata: Some(metadata),
        };
        if let Err(err) = audit.append(event, now).await {
            tracing::error!(error = %err, "audit append failed for a mail transport transition");
        }
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

    async fn run(&self, job: &QueuedJob, now: DateTime<Utc>) -> HandlerReport {
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
            Err(_elapsed) => {
                let reason = format!("smtp delivery exceeded {}s", self.timeout.as_secs());
                self.record_health(now, Some(&reason)).await;
                HandlerReport::retry(reason)
            }
            Ok(Ok(())) => {
                self.record_health(now, None).await;
                HandlerReport::done()
            }
            // A malformed recipient is the one transport failure that is permanent: an address
            // the message builder rejects will never become valid, so spending eight attempts
            // on it only delays the dead letter that says so. It is also the one failure that
            // says nothing about the transport — one bad address does not mean the relay is
            // down — so it deliberately does not touch the health signal.
            Ok(Err(Error::Invalid { message })) => HandlerReport::dead(format!("undeliverable recipient: {message}")),
            Ok(Err(err)) => {
                let reason = err.to_string();
                self.record_health(now, Some(&reason)).await;
                HandlerReport::retry(reason)
            }
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

    /// A transport that fails every send, and one that fails until it is told to stop.
    struct Relay {
        failing: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Mailer for Relay {
        async fn ping(&self) -> Result<()> {
            Ok(())
        }

        async fn send(&self, _to: &str, _subject: &str, _body: &str) -> Result<()> {
            if self.failing.load(Ordering::Relaxed) {
                Err(Error::Internal { message: "connection refused".to_owned() })
            } else {
                Ok(())
            }
        }
    }

    /// Records the audit rows a transition writes.
    #[derive(Default)]
    struct AuditLog(Mutex<Vec<String>>);

    #[async_trait]
    impl AuditRepo for AuditLog {
        async fn ping(&self) -> Result<()> {
            Ok(())
        }

        async fn append(&self, event: NewAuditEvent, now: DateTime<Utc>) -> Result<pub_core::audit::AuditEvent> {
            self.0.lock().unwrap().push(event.action.clone());
            Ok(pub_core::audit::AuditEvent {
                id: pub_core::audit::AuditId::generate(),
                created_at: now,
                actor: event.actor,
                ip: event.ip,
                user_agent: event.user_agent,
                org_id: event.org_id,
                action: event.action,
                target: event.target,
                result: event.result,
                metadata: event.metadata,
            })
        }

        async fn list(
            &self,
            _filter: &pub_core::audit::AuditFilter,
            _cursor: Option<&str>,
            _limit: u32,
        ) -> Result<pub_core::page::Page<pub_core::audit::AuditEvent>> {
            unimplemented!("the health signal never reads the audit log")
        }

        async fn prune_before(&self, _cutoff: DateTime<Utc>, _now: DateTime<Utc>, _batch: u32) -> Result<u64> {
            unimplemented!("the health signal never prunes the audit log")
        }
    }

    fn queued(mail: &MailJob) -> QueuedJob {
        QueuedJob {
            id: QueuedJobId::new(),
            kind: JobKind::MailSend,
            priority: 0,
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

    /// **D43 / decision 29.** The mail plane going down is audited **once**, on the edge —
    /// not once per failed attempt, which with the shipped ladder is eight rows per message for
    /// as long as the relay is down.
    #[tokio::test]
    async fn d43_a_dead_transport_is_audited_on_the_edge_and_again_when_it_recovers() {
        let relay = Arc::new(Relay { failing: std::sync::atomic::AtomicBool::new(true) });
        let audit = Arc::new(AuditLog::default());
        let handler = MailHandler::new(Arc::clone(&relay) as Arc<dyn Mailer>, KEK.to_vec(), StdDuration::from_secs(5))
            .with_audit(Arc::clone(&audit) as Arc<dyn AuditRepo>);
        let mail = MailJob {
            to: "alice@corp.com".to_owned(),
            subject: "hello".to_owned(),
            text: "body".to_owned(),
            html: None,
            sealed: false,
        };

        // Five failures in a row: the operator learns about the first one and is not buried by
        // the other four.
        for _ in 0..5 {
            let report = handler.run(&queued(&mail), Utc::now()).await;
            assert!(matches!(report.outcome, QueueOutcome::Retry(_)), "{:?}", report.outcome);
        }
        assert_eq!(audit.0.lock().unwrap().as_slice(), ["mail.delivery_failed"], "one row for one outage");

        // ...and coming back is its own edge, so "when did mail start working again?" has an
        // answer that does not depend on reading the absence of rows.
        relay.failing.store(false, Ordering::Relaxed);
        for _ in 0..3 {
            let report = handler.run(&queued(&mail), Utc::now()).await;
            assert_eq!(report.outcome, QueueOutcome::Done);
        }
        assert_eq!(
            audit.0.lock().unwrap().as_slice(),
            ["mail.delivery_failed", "mail.delivery_recovered"],
            "recovery is one row too, not one per delivered message"
        );
    }

    /// **D43.** One malformed recipient is not evidence about the transport. Letting it move
    /// the signal would make `mail_transport_unusable` fire on a typo in somebody's address.
    #[tokio::test]
    async fn d43_an_undeliverable_recipient_does_not_mark_the_transport_dead() {
        struct Picky;
        #[async_trait]
        impl Mailer for Picky {
            async fn ping(&self) -> Result<()> {
                Ok(())
            }
            async fn send(&self, _to: &str, _subject: &str, _body: &str) -> Result<()> {
                Err(Error::Invalid { message: "not an address".to_owned() })
            }
        }
        let audit = Arc::new(AuditLog::default());
        let handler = MailHandler::new(Arc::new(Picky), KEK.to_vec(), StdDuration::from_secs(5))
            .with_audit(Arc::clone(&audit) as Arc<dyn AuditRepo>);
        let mail = MailJob {
            to: "not-an-address".to_owned(),
            subject: "hello".to_owned(),
            text: "body".to_owned(),
            html: None,
            sealed: false,
        };
        let report = handler.run(&queued(&mail), Utc::now()).await;
        assert!(matches!(report.outcome, QueueOutcome::Dead(_)), "{:?}", report.outcome);
        assert!(audit.0.lock().unwrap().is_empty(), "a bad address says nothing about the relay");
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
