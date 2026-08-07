//! The domain event bus ([decision 22](../../../docs/decisions.md#22)) and the consumers that
//! hang off it.
//!
//! One bus, four consumers, and the fan-out order is deliberate:
//!
//! ```text
//!   domain service ──emit──► EventBus ──┬──► in-process broadcast ──► SSE stream (decision 20)
//!                                       ├──► KV broker topic ────────► peer instances' streams
//!                                       ├──► NotificationCenter ─────► feed rows + email
//!                                       └──► (webhooks: the seam, v1.1)
//! ```
//!
//! Three properties are load-bearing:
//!
//! - **Consumers run on the emitting instance only.** A peer that receives an event over the
//!   broker feeds it to its *stream* and to nothing else. Running the notification center on
//!   every instance would file one row per replica for the same event, which is the classic way
//!   a fan-out becomes a duplicate factory.
//! - **Emission cannot fail a caller.** [`pub_core::event::EventSink::emit`] returns nothing;
//!   every consumer error and every broker outage is logged and swallowed. The bus is a hint
//!   channel — durable truth is the database and the audit log — so a broken subscriber must
//!   never fail a publish.
//! - **Consumer output re-enters the stream, never the consumers.** A consumer returns follow-up
//!   events (the notification center returns one [`pub_core::DomainEvent::UserNotified`] per
//!   recipient); those are broadcast and republished, but not fed back through the consumer
//!   list. There is therefore no cycle to bound.

mod bus;
mod notify;

pub use bus::{ConnectionGuard, EVENTS_TOPIC, EventBus, EventBusPolicy, EventConsumer};
pub use notify::{NotificationCenter, NotificationPolicy};
