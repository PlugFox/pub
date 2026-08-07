---
name: rust-async-tokio
description: Write correct async Rust on Tokio in the pub server — cancel-safety, select!, spawn vs spawn_blocking, timeouts at boundaries, JobLock-guarded background loops, graceful shutdown. Use when writing async fns, background jobs, SSE streams, or anything touching tokio::spawn / select! / timeout.
---

# Rust Async / Tokio (pub server)

**Source:** adapted from [wshobson/agents — rust-async-patterns](https://skills.sh/wshobson/agents/rust-async-patterns) and the [Tokio docs](https://tokio.rs/tokio/topics), ported from foxic and re-grounded in this repo. Normative baseline: [docs/rules/rust.md](../../../../docs/rules/rust.md) § "Async & blocking" — this skill elaborates, never overrides.

## Core rules

- **`tokio::spawn` for async work, `spawn_blocking` for CPU-heavy or blocking sync calls.** In this codebase that means tar extraction, markdown rendering, and hashing large buffers (docs/rules/rust.md). Real examples: archive unpack in `server/crates/registry/src/publish.rs`, sha256 of downloaded upstream archives in `server/crates/registry/src/upstream.rs`. If it blocks > ~100µs, hand it off.
- **Never hold a `std::sync::Mutex` guard across `.await`.** Drop the guard first, use `tokio::sync::Mutex`, or restructure. `std::sync::Mutex` is fine for sync-only access (the test harness clock does exactly this).
- **Prefer channels over shared mutable state.** The domain event bus (`server/crates/events/src/bus.rs`) is a `tokio::sync::broadcast`; SSE connections bridge it to clients via `mpsc` + `ReceiverStream`.
- **Every `.await` is a potential cancellation point.** Code between `.await`s runs to completion; code across them can be dropped mid-way.

## Background loops — the pub pattern

Normative: `tokio::time::interval` + `MissedTickBehavior::Skip`, guarded by `JobLock` when the job must be single-instance in a cluster. The reference implementation is `server/crates/jobs/src/scheduler.rs`:

- One tokio task per job; the first tick fires immediately.
- `MissedTickBehavior::Skip` — a slow run never causes a burst of catch-up runs.
- Per-tick `JobLock::try_acquire` with a TTL (bounds how long a crashed holder blocks the cluster); release after the run; a failed run logs a warning and retries next tick — it never wedges the loop.
- `SchedulerHandle` stores the `JoinHandle`s and aborts them on shutdown/drop.

New periodic work goes through `Scheduler::add`, not a hand-rolled loop.

## Cancel-safety

A future is *cancel-safe* if dropping it mid-`.await` leaves no broken invariants. This matters inside `tokio::select!`: the losing branch is dropped.

- Cancel-safe: `broadcast::Receiver::recv`, `mpsc::Receiver::recv`, `Interval::tick`, `tokio::time::sleep` — which is why the SSE loop below is sound.
- **Not** cancel-safe: anything consuming input incrementally (`AsyncReadExt::read_exact`, custom state machines, `read_line` re-polled). Don't put such a future raw into `select!` — spawn it and select on the `JoinHandle` or a channel instead.

## `select!`

The in-repo model is the SSE connection loop in `server/crates/api/src/routes/events.rs`: select over `broadcast` recv and a heartbeat `Interval`, handle `RecvError::Lagged` by telling the client (`stream.lagged`) instead of dropping the connection, send one final frame (`stream.closed`) before terminating so the client can stop retrying, and hold the connection-cap guard for the life of the spawned task.

```rust
tokio::select! {
    biased;                                  // when ordering matters (shutdown must win)
    _ = shutdown.recv() => break,
    msg = rx.recv() => handle(msg).await,
    _ = ticker.tick() => heartbeat().await,
}
```

## Timeouts

- Pub puts deadlines in client configuration at the boundary, not scattered `tokio::time::timeout` deep in call stacks: the upstream client (`server/crates/registry/src/upstream/http.rs`) carries `connect_timeout`, `listing_timeout`, and `archive_timeout` from `[upstream]` config; the OIDC client sets a 10s request timeout on its reqwest builder. New outbound HTTP follows the same shape.
- `tokio::time::timeout(dur, fut)` is for ad-hoc waits (used in KV pub/sub tests); map `Elapsed` to a `core::Error` variant at the boundary — never match on message strings.
- No naked `.await` on a network call without a deadline somewhere above it.

## Graceful shutdown

Pub's actual pattern (`server/crates/bin/pubd/src/main.rs`):

- `shutdown_signal()` selects over `ctrl_c()` and SIGTERM (`std::future::pending` on non-unix).
- `axum::serve(...).with_graceful_shutdown(shutdown_signal())` drains in-flight connections.
- Job loops are stopped by `SchedulerHandle::shutdown` (abort) — safe because every tick is idempotent and the lock TTL expires a crashed holder.

Current Tokio guidance recommends `CancellationToken` + `TaskTracker` (tokio-util) when a task needs cleanup that a plain abort would break; no pub task needs that today — reach for it only if you introduce one, and say so in the PR.

## Async tests & time

- `#[tokio::test]` default flavor; multi-thread only when the test genuinely needs parallelism.
- Timing-sensitive loops: `#[tokio::test(start_paused = true)]` with the `test-util` tokio feature in dev-deps — the scheduler tests in `server/crates/jobs/src/scheduler.rs` are the model.
- Domain time is an injected clock, never wall clock — see the [rust-testing](../rust-testing/SKILL.md) skill.

## Common mistakes

- `tokio::spawn(async move { blocking_call() })` — use `spawn_blocking`.
- `let _ = tokio::spawn(...)` — the dropped `JoinHandle` swallows errors. Store it (as `SchedulerHandle` does), `.await` it, or comment that fire-and-forget is intentional (the SSE route does this deliberately: the task ends when the client goes away).
- `Arc<std::sync::Mutex<T>>` around something awaited — switch to `tokio::sync::Mutex` or a channel-owning task.
- Busy-looping with `yield_now()` instead of waiting on a real event.

## Related

- Testing async code, paused time, injected clocks: [rust-testing](../rust-testing/SKILL.md)
- Normative async rules: [docs/rules/rust.md](../../../../docs/rules/rust.md)
- Background jobs & SSE architecture: [docs/architecture.md](../../../../docs/architecture.md)
