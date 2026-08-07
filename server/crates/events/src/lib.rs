//! The domain event bus ([decision 22](../../../docs/decisions.md#22)) and the consumers that
//! hang off it.
//!
//! One bus, and the fan-out order is deliberate:
//!
//! ```text
//!   domain service ──emit──► EventBus ──┬──► in-process broadcast ──► SSE stream (decision 20)
//!                                       ├──► KV broker topic ────────► peer instances' streams
//!                                       ├──► NotificationEnqueuer ───► one durable job row
//!                                       └──► (webhooks: the seam, v1.1)
//!
//!   queue worker ──► NotificationCenter::deliver ──► feed rows + mail items
//!                └──► publish_followup ──────────► the stream, never the consumers
//! ```
//!
//! Three properties are load-bearing:
//!
//! - **The enqueue runs on the emitting instance; the drain runs on the leader.** A peer that
//!   receives an event over the broker feeds it to its *stream* and to nothing else, so exactly
//!   one instance files the fan-out job — and the durable claim then hands that job to exactly
//!   one worker. Running the notification center on every instance would file one row per
//!   replica for the same event, which is the classic way a fan-out becomes a duplicate factory.
//! - **Emission cannot fail a caller.** [`pub_core::event::EventSink::emit`] returns nothing;
//!   every consumer error and every broker outage is logged and swallowed. The bus is a hint
//!   channel — durable truth is the database and the audit log — so a broken subscriber must
//!   never fail a publish. What changed with the queue is the *cost* of one swallowed call: it
//!   is now a whole event's fan-out plus every email it would have produced, which is why the
//!   enqueuer counts its failures (`notification_enqueue_failed_total`) as part of the contract.
//! - **Follow-ups re-enter the stream, never the consumers.** The fan-out returns one
//!   [`pub_core::DomainEvent::UserNotified`] per recipient and the worker hands them back
//!   through [`EventBus::publish_followup`], which broadcasts and republishes but does not run
//!   the consumer list. There is therefore no cycle to bound.

mod bus;
mod notify;

pub use bus::{ConnectionGuard, EVENTS_TOPIC, EventBus, EventBusPolicy, EventConsumer};
pub use notify::{Fanout, NotificationCenter, NotificationEnqueuer, NotificationPolicy};
