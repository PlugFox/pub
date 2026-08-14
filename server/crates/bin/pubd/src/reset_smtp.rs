//! `pubd reset-smtp` — the offline way back into an instance whose mail plane is dead
//! ([decision 29](../../../../docs/decisions.md#29), closes roadmap D43).
//!
//! The failure this exists for is circular, which is why it needs a subcommand rather than a
//! runbook paragraph. Outbound mail is asynchronous (decision 26), so a broken relay costs
//! nothing at request time and surfaces ~21 minutes later as dead letters — on the admin API,
//! which needs a session, which on an OTP-only instance arrives *by mail*. And correcting the
//! config file does not help: a stored `smtp` section **replaces** the boot one wholesale, so
//! the bad section outlives every restart.
//!
//! This deletes that stored section. The boot `[smtp]` becomes authoritative again, a running
//! instance picks the change up through the settings version poll without a restart, and the
//! operator can sign in and fix the rest through the UI.
//!
//! It runs after the configuration **loads** — which is also where it gets the database URL and
//! the boot `[smtp]` it is restoring — and before anything is served. Unlike `generate-secrets`
//! it therefore needs a config that passes validation; that is the right trade here, because the
//! instance this rescues is a *running* one whose config already validates and whose mail plane
//! is what broke. An instance that cannot pass validation has a different problem and a
//! different tool.
//!
//! Deliberately *not* here: minting a session. On the default deployment the KV is in-process,
//! so an offline `pubd` shares no pending-auth state with the running server and could not
//! inject an OTP at all; and a minted refresh token would be a second credential-issuing path
//! guarded only by filesystem access. Decision 29 records that trade.

use anyhow::Context as _;
use pub_config::Settings;
use pub_core::settings::keys;

/// CLI arguments for `pubd reset-smtp`.
#[derive(Debug, clap::Args)]
pub struct ResetSmtpArgs {
    /// Report what would be deleted and change nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// Deletes the stored `smtp` settings section, if there is one.
///
/// Prints what the instance will fall back to, because "mail is fixed" and "mail now uses the
/// boot section, which is *this*" are different statements and only the second is actionable.
pub async fn run(settings: &Settings, args: &ResetSmtpArgs) -> anyhow::Result<()> {
    let repos = crate::build_database(settings).await.context("failed to connect the database")?;

    let stored = repos.settings.get_all().await.context("failed to read the settings table")?;
    let present = stored.iter().any(|entry| entry.key == keys::SMTP);

    let boot = match settings.smtp.host.as_deref() {
        Some(host) => format!(
            "[smtp] host = {host}, port = {}, security = {}",
            settings.smtp.port,
            settings.smtp.security.as_str()
        ),
        None => "[smtp] is not configured in the boot config either — mail will go nowhere until it is".to_owned(),
    };

    if !present {
        println!("no stored smtp section: the boot configuration is already authoritative.");
        println!("  {boot}");
        return Ok(());
    }
    if args.dry_run {
        println!("would delete the stored smtp section; the instance would fall back to:");
        println!("  {boot}");
        return Ok(());
    }

    let deleted = repos.settings.delete(keys::SMTP).await.context("failed to delete the stored smtp section")?;
    if deleted {
        println!("deleted the stored smtp section. The instance now uses:");
        println!("  {boot}");
        println!(
            "A running instance picks this up within one settings-poll interval; no restart is \
             required. Queued mail retries on the next drain tick."
        );
    } else {
        // Raced with an admin edit between the read and the delete. Not an error: the section
        // is gone either way, which is what was asked for.
        println!("the stored smtp section was already gone.");
        println!("  {boot}");
    }
    Ok(())
}
