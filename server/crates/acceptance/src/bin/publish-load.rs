//! The write half of the load measurement Phase 2's exit owes
//! ([decision 38](../../../../docs/decisions.md#38--two-replicas-behind-one-proxy-an-acceptance-stand-that-fails-closed-four-claims-proven-at-the-wire-and-a-measurement-that-is-a-number)).
//!
//! `oha` measures the read path, which is where `dart pub get`'s volume is and which is one
//! request per sample. A **publish** is three authenticated steps against three different URLs,
//! two of which the server hands back — no single-URL tool can express it, so this exists.
//!
//! What it reports is a distribution, not a verdict. There is no threshold here and no exit
//! code that depends on the numbers: a latency gate measured on whatever host happened to run
//! it is noise with a version number. The numbers go into `docs/ops/capacity.md` beside the
//! machine that produced them, and the next measurement is compared against that.
//!
//! ```text
//! PUB_TEST_CLUSTER_URL=http://localhost:18080 cargo run -p pub-acceptance --bin publish-load -- 24 4
//! ```
//!
//! Two arguments, both optional: how many versions to publish, and how many at a time. Each
//! publish is a **distinct package name**, so the per-name publish lock is not the thing being
//! measured — with one name, this would be a measurement of serialization, which claim 3 already
//! covers and which is not what an operator sizing a registry wants to know.

use std::time::{Duration, Instant};

use pub_acceptance::{Cluster, unique};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let total: usize = args.next().and_then(|value| value.parse().ok()).unwrap_or(24);
    let concurrency: usize = args.next().and_then(|value| value.parse().ok()).unwrap_or(4);
    // Where the publishes go. `proxy` is what a client is configured with and the number that
    // matters; `a` and `b` dial one instance directly, which is how "did the second replica
    // change anything" gets a number instead of an opinion — with the caveat, stated here and
    // in capacity.md, that a direct dial also removes the proxy hop.
    let target = args.next().unwrap_or_else(|| "proxy".to_owned());
    assert!(total > 0 && concurrency > 0, "usage: publish-load [total] [concurrency] [proxy|a|b]");

    let Some(cluster) = Cluster::gate("publish-load") else {
        println!("cluster leg opted out ($PUB_TEST_NO_CLUSTER); nothing measured");
        return;
    };
    let cluster = cluster.as_client("198.51.100.200");

    // One org and one token for the whole run: minting per publish would measure the auth path
    // rather than the publish path, and a load driver that measures its own setup is a liar.
    let slug = unique("load-");
    let email = format!("{}@corp.test", unique("load-"));
    let (access, org) = cluster.org_owner(cluster.a(), &email, &slug).await;
    let token = cluster.mint_token(cluster.a(), &access, &org, &["read", "publish"]).await;
    let base = match target.as_str() {
        "a" => cluster.a().to_owned(),
        "b" => cluster.b().to_owned(),
        "proxy" => cluster.proxy.clone(),
        other => panic!("unknown target {other:?}: expected proxy, a or b"),
    };
    println!("stand: {base} ({target}), org {slug}, {total} publishes at concurrency {concurrency}");

    let started = Instant::now();
    let mut samples: Vec<Duration> = Vec::with_capacity(total);
    let mut failures = 0_usize;
    let mut last_name: Option<String> = None;
    let mut refusals: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut remaining = total;
    while remaining > 0 {
        let batch = concurrency.min(remaining);
        let names: Vec<String> = (0..batch).map(|_| unique("load_pkg_")).collect();
        last_name = names.last().cloned();
        let running = names.iter().map(|name| async {
            let at = Instant::now();
            // The default is the **proxy**: the number an operator cares about is what a client
            // sees, and a client is configured with the front door.
            let answer = cluster.publish(&base, &slug, &token, name, "1.0.0").await;
            let refusal = (answer.status != 200).then(|| answer.json["error"].to_string());
            (at.elapsed(), answer.status, refusal)
        });
        for (elapsed, status, refusal) in futures::future::join_all(running).await {
            if status == 200 {
                samples.push(elapsed);
            } else {
                failures += 1;
                // A refusal that is not reported is a measurement that quietly halves itself.
                if let Some(refusal) = refusal {
                    *refusals.entry(refusal).or_insert(0_usize) += 1;
                }
            }
        }
        remaining -= batch;
    }
    let wall = started.elapsed();

    samples.sort_unstable();
    let percentile = |fraction: f64| -> Duration {
        if samples.is_empty() {
            return Duration::ZERO;
        }
        // Nearest-rank, and the index is clamped rather than assumed in range: with a handful
        // of samples p99 and p100 are the same measurement, which is worth being honest about.
        let rank = (fraction * samples.len() as f64).ceil() as usize;
        samples[rank.clamp(1, samples.len()) - 1]
    };

    println!("publishes: {} ok, {failures} failed, in {:.1?}", samples.len(), wall);
    for (refusal, count) in &refusals {
        println!("  refused {count}x: {refusal}");
    }
    println!("throughput: {:.2}/s", samples.len() as f64 / wall.as_secs_f64().max(f64::EPSILON));
    for (label, fraction) in [("p50", 0.50), ("p95", 0.95), ("p99", 0.99)] {
        println!("{label}: {:.1?}", percentile(fraction));
    }
    if let (Some(min), Some(max)) = (samples.first(), samples.last()) {
        println!("min: {min:.1?}  max: {max:.1?}");
    }
    // The read profile needs a package that exists **and** a credential that can see it: an
    // org's packages are private, so an unauthenticated `oha` measures the 404 path at whatever
    // rate the box can produce 404s. The rate cap is the other half — S-24.f gives one identity
    // 600 reads a minute, so a measurement that ignores it measures the rate limiter.
    if let Some(name) = last_name {
        let reader = cluster.mint_token(cluster.a(), &access, &org, &["read"]).await;
        println!();
        println!("read profile — the listing `dart pub get` resolves against, inside the S-24.f budget:");
        println!("  oha -z 15s -q 8 -c 4 --no-tui \\");
        println!("      -H 'Accept: application/vnd.pub.v2+json' -H 'Authorization: Bearer {reader}' \\");
        println!("      {}/o/{slug}/pub/api/packages/{name}", cluster.proxy);
    }
    assert_eq!(failures, 0, "the measurement is only meaningful when every publish succeeded");
}
