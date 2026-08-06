//! Embeds build metadata: git hash and build date, with fallbacks when git (or a repo)
//! is absent — e.g. release tarball builds.

use std::process::Command;

fn main() {
    let git_hash = command_output("git", &["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    let build_date = command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=PUBD_GIT_HASH={git_hash}");
    println!("cargo:rustc-env=PUBD_BUILD_DATE={build_date}");
    // Repo root is four levels up from crates/bin/pubd; harmless when absent.
    println!("cargo:rerun-if-changed=../../../../.git/HEAD");
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() { None } else { Some(text) }
}
