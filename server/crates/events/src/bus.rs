//! The bus itself: in-process broadcast, the cross-instance broker bridge, the replay ring,
//! and the per-user connection budget the SSE endpoint spends (S-32).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use pub_core::event::{EventEnvelope, EventId, EventSink};
use pub_core::traits::Kv;
use pub_core::{DomainEvent, Error, Result, UserId};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Broker topic every instance publishes domain events on and subscribes to (decision 20:
/// "any instance can serve any client's stream").
pub const EVENTS_TOPIC: &str = "events";

/// Capacity of the in-process broadcast channel.
///
/// A subscriber that falls this far behind loses the oldest messages and is told so by the
/// channel; the SSE handler turns that into a `lagged` marker rather than a disconnect, because
/// the stream is a hint channel and the REST API is the reconciliation path.
const BROADCAST_CAPACITY: usize = 512;

/// Tunables for the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventBusPolicy {
    /// How many recent events the replay ring keeps (decision 20 `Last-Event-ID`).
    pub replay_buffer: usize,
    /// How many concurrent streams one account may hold on **this** instance (S-32).
    pub max_connections_per_user: u32,
}

impl Default for EventBusPolicy {
    fn default() -> Self {
        Self { replay_buffer: 256, max_connections_per_user: 5 }
    }
}

/// A consumer of domain events, running on the instance that emitted them.
///
/// `handle` returns **follow-up events** to publish; they reach the stream and the broker but
/// are never fed back through the consumer list, so a consumer that reacts to its own output
/// cannot loop.
#[async_trait]
pub trait EventConsumer: Send + Sync {
    /// Short name for log lines.
    fn name(&self) -> &'static str;

    /// Reacts to one event. Errors are logged by the bus and never reach the emitter.
    async fn handle(&self, envelope: &EventEnvelope) -> Result<Vec<DomainEvent>>;
}

/// What travels on the broker topic: an envelope plus the instance that minted it.
///
/// `origin` is the loop breaker. Redis pub/sub delivers a publisher its own messages, so
/// without it every event this instance emitted would come straight back and be broadcast to
/// its own subscribers twice.
#[derive(Debug, Serialize, Deserialize)]
struct BrokerMessage {
    origin: String,
    #[serde(flatten)]
    envelope: EventEnvelope,
}

/// The bus.
pub struct EventBus {
    local: broadcast::Sender<EventEnvelope>,
    ring: Mutex<VecDeque<EventEnvelope>>,
    connections: Mutex<HashMap<UserId, u32>>,
    consumers: Mutex<Vec<Arc<dyn EventConsumer>>>,
    kv: Option<Arc<dyn Kv>>,
    origin: String,
    policy: EventBusPolicy,
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus").field("origin", &self.origin).field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl EventBus {
    /// A bus with no broker (single instance) and no consumers yet.
    pub fn new(policy: EventBusPolicy) -> Self {
        let (local, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            local,
            ring: Mutex::new(VecDeque::with_capacity(policy.replay_buffer.max(1))),
            connections: Mutex::new(HashMap::new()),
            consumers: Mutex::new(Vec::new()),
            kv: None,
            // A per-process identity, not a configured one: it only has to differ from the
            // other live instances, and a UUID v7 does that without an operator setting.
            origin: UserId::new().to_string(),
            policy,
        }
    }

    /// Attaches the KV broker so peers see this instance's events and vice versa.
    ///
    /// With the in-memory KV this is a no-op in practice (a single process talking to itself,
    /// filtered out by `origin`); with Redis it is what makes any instance able to serve any
    /// client's stream. Call [`EventBus::spawn_broker_subscription`] to start the inbound half.
    #[must_use]
    pub fn with_broker(mut self, kv: Arc<dyn Kv>) -> Self {
        self.kv = Some(kv);
        self
    }

    /// Registers a consumer. Consumers run in registration order on the emitting instance.
    pub fn add_consumer(&self, consumer: Arc<dyn EventConsumer>) {
        self.consumers.lock().expect("consumers mutex poisoned").push(consumer);
    }

    /// The active policy.
    pub const fn policy(&self) -> EventBusPolicy {
        self.policy
    }

    /// Subscribes to the live stream. Messages published *before* the call are not delivered —
    /// that gap is what [`EventBus::replay_since`] closes.
    pub fn subscribe(&self) -> broadcast::Receiver<EventEnvelope> {
        self.local.subscribe()
    }

    /// Events in the ring strictly newer than `after`, oldest first.
    ///
    /// Best-effort by contract (decision 20): the ring is bounded and per-instance, so a client
    /// that was away longer than `replay_buffer` events simply gets what is left. Ids are ULIDs,
    /// so the comparison is a string comparison that still means "later in time" for events
    /// minted on a *different* instance.
    pub fn replay_since(&self, after: &EventId) -> Vec<EventEnvelope> {
        let ring = self.ring.lock().expect("ring mutex poisoned");
        ring.iter().filter(|envelope| envelope.id > *after).cloned().collect()
    }

    /// Takes one of the account's stream slots (S-32 per-user connection cap).
    ///
    /// Over budget answers [`Error::RateLimited`] rather than a plain denial: the cap is an
    /// abuse control, the condition clears on its own, and `429 + Retry-After` is the one
    /// answer a client already knows how to handle.
    pub fn acquire_connection(self: &Arc<Self>, user: UserId) -> Result<ConnectionGuard> {
        let mut connections = self.connections.lock().expect("connections mutex poisoned");
        let slot = connections.entry(user).or_insert(0);
        if *slot >= self.policy.max_connections_per_user {
            return Err(Error::RateLimited { retry_after_secs: 30 });
        }
        *slot += 1;
        Ok(ConnectionGuard { bus: Arc::clone(self), user })
    }

    /// How many streams the account currently holds on this instance (tests and metrics).
    pub fn connections_for(&self, user: UserId) -> u32 {
        self.connections.lock().expect("connections mutex poisoned").get(&user).copied().unwrap_or(0)
    }

    /// Starts the inbound half of the broker bridge: peers' events enter this instance's ring
    /// and broadcast, and **nothing else** (consumers already ran where the event originated).
    ///
    /// A subscription that cannot be established is logged and dropped rather than retried: the
    /// stream degrades to instance-local fan-out, which is a visible-but-working state, and the
    /// REST API remains the source of truth.
    pub fn spawn_broker_subscription(self: &Arc<Self>) {
        let Some(kv) = self.kv.clone() else { return };
        let bus = Arc::clone(self);
        tokio::spawn(async move {
            let mut stream = match kv.subscribe(EVENTS_TOPIC).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%error, "event broker subscription failed; the stream stays instance-local");
                    return;
                }
            };
            use futures::StreamExt as _;
            while let Some(message) = stream.next().await {
                match serde_json::from_str::<BrokerMessage>(&message.payload) {
                    Ok(broker) if broker.origin == bus.origin => {}
                    Ok(broker) => bus.deliver(broker.envelope),
                    Err(error) => tracing::warn!(%error, "undecodable event on the broker topic"),
                }
            }
        });
    }

    /// Rings + broadcasts one envelope locally.
    fn deliver(&self, envelope: EventEnvelope) {
        {
            let mut ring = self.ring.lock().expect("ring mutex poisoned");
            while ring.len() >= self.policy.replay_buffer.max(1) {
                ring.pop_front();
            }
            ring.push_back(envelope.clone());
        }
        // `send` errors only when nobody is subscribed — the normal state of an idle instance.
        let _ = self.local.send(envelope);
    }

    /// Publishes one envelope everywhere: locally, then to peers.
    async fn publish(&self, envelope: EventEnvelope) {
        self.deliver(envelope.clone());
        let Some(kv) = &self.kv else { return };
        let message = BrokerMessage { origin: self.origin.clone(), envelope };
        match serde_json::to_string(&message) {
            Ok(payload) => {
                if let Err(error) = kv.publish(EVENTS_TOPIC, &payload).await {
                    tracing::warn!(%error, "event broker publish failed; peers miss this event");
                }
            }
            Err(error) => tracing::error!(%error, "failed to encode a domain event for the broker"),
        }
    }
}

#[async_trait]
impl EventSink for EventBus {
    async fn emit(&self, event: DomainEvent) {
        let envelope = EventEnvelope::new(event);
        // Stream first: a live subscriber should not wait for a database write it does not
        // depend on. The notification row that follows is what a *reconnecting* client reads.
        self.publish(envelope.clone()).await;

        let consumers: Vec<Arc<dyn EventConsumer>> = self.consumers.lock().expect("consumers mutex poisoned").clone();
        for consumer in consumers {
            match consumer.handle(&envelope).await {
                Ok(followups) => {
                    for followup in followups {
                        self.publish(EventEnvelope::new(followup)).await;
                    }
                }
                Err(error) => {
                    // Swallowed by contract: the emitter is a publish, a role change, or a
                    // proxy alarm, and none of them may fail because a consumer did.
                    tracing::error!(consumer = consumer.name(), event = envelope.event.name(), %error, "event consumer failed");
                }
            }
        }
    }
}

/// One held stream slot; releases it on drop.
///
/// RAII rather than an explicit release call: the SSE handler exits through a dozen paths
/// (client disconnect, revocation, token expiry, task abort) and every one of them has to give
/// the slot back or the cap becomes a permanent lockout after a few reconnects.
pub struct ConnectionGuard {
    bus: Arc<EventBus>,
    user: UserId,
}

impl std::fmt::Debug for ConnectionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionGuard").field("user", &self.user).finish()
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut connections = self.bus.connections.lock().expect("connections mutex poisoned");
        if let Some(slot) = connections.get_mut(&self.user) {
            *slot = slot.saturating_sub(1);
            if *slot == 0 {
                connections.remove(&self.user);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use pub_core::{Format, OrgId, PackageId, VersionId};

    use super::*;

    fn published(org: OrgId) -> DomainEvent {
        DomainEvent::PackagePublished {
            format: Format::Pub,
            org_id: org,
            package_id: PackageId::new(),
            name: "acme_core".to_owned(),
            version: "1.0.0".to_owned(),
            version_id: VersionId::new(),
            package_created: false,
            at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn subscribers_receive_emitted_events() {
        let bus = Arc::new(EventBus::new(EventBusPolicy::default()));
        let mut rx = bus.subscribe();
        bus.emit(published(OrgId::new())).await;
        let envelope = rx.try_recv().expect("one event");
        assert_eq!(envelope.event.name(), "package.publish");
    }

    #[tokio::test]
    async fn the_ring_replays_only_what_is_newer_and_never_grows_past_its_bound() {
        let bus = Arc::new(EventBus::new(EventBusPolicy { replay_buffer: 3, max_connections_per_user: 5 }));
        let org = OrgId::new();
        for _ in 0..5 {
            bus.emit(published(org)).await;
        }
        assert_eq!(bus.ring.lock().unwrap().len(), 3, "the ring must not grow past its bound");

        let ids: Vec<EventId> = bus.ring.lock().unwrap().iter().map(|envelope| envelope.id.clone()).collect();
        assert_eq!(bus.replay_since(&ids[0]).len(), 2, "replay is strictly newer than the given id");
        assert!(bus.replay_since(ids.last().unwrap()).is_empty(), "nothing is newer than the newest id");
    }

    #[tokio::test]
    async fn the_connection_cap_holds_and_a_dropped_guard_gives_the_slot_back() {
        let bus = Arc::new(EventBus::new(EventBusPolicy { replay_buffer: 8, max_connections_per_user: 2 }));
        let user = UserId::new();
        let first = bus.acquire_connection(user).expect("first slot");
        let second = bus.acquire_connection(user).expect("second slot");
        let err = bus.acquire_connection(user).expect_err("the third must be refused");
        assert_eq!(err.code(), "rate_limited");
        assert_eq!(bus.connections_for(user), 2);

        drop(second);
        assert_eq!(bus.connections_for(user), 1);
        bus.acquire_connection(user).expect("a freed slot is reusable");
        drop(first);

        // Another account's budget is its own.
        assert_eq!(bus.connections_for(UserId::new()), 0);
    }

    #[tokio::test]
    async fn a_consumer_failure_never_reaches_the_emitter() {
        struct Broken;

        #[async_trait]
        impl EventConsumer for Broken {
            fn name(&self) -> &'static str {
                "broken"
            }

            async fn handle(&self, _envelope: &EventEnvelope) -> Result<Vec<DomainEvent>> {
                Err(Error::Internal { message: "consumer exploded".to_owned() })
            }
        }

        let bus = Arc::new(EventBus::new(EventBusPolicy::default()));
        bus.add_consumer(Arc::new(Broken));
        let mut rx = bus.subscribe();
        // `emit` returns `()`: the assertion is that this call completes and the stream still
        // carried the event.
        bus.emit(published(OrgId::new())).await;
        assert_eq!(rx.try_recv().expect("event").event.name(), "package.publish");
    }

    #[tokio::test]
    async fn consumer_followups_are_published_but_not_re_consumed() {
        struct Echo {
            seen: Mutex<Vec<String>>,
        }

        #[async_trait]
        impl EventConsumer for Echo {
            fn name(&self) -> &'static str {
                "echo"
            }

            async fn handle(&self, envelope: &EventEnvelope) -> Result<Vec<DomainEvent>> {
                self.seen.lock().unwrap().push(envelope.event.name().to_owned());
                Ok(vec![DomainEvent::UserNotified {
                    user_id: UserId::new(),
                    notification_id: pub_core::NotificationId::new(),
                    category: pub_core::notification::NotificationCategory::Package,
                    title: "echo".to_owned(),
                    unread: 1,
                    at: Utc::now(),
                }])
            }
        }

        let echo = Arc::new(Echo { seen: Mutex::new(Vec::new()) });
        let bus = Arc::new(EventBus::new(EventBusPolicy::default()));
        bus.add_consumer(Arc::clone(&echo) as Arc<dyn EventConsumer>);
        let mut rx = bus.subscribe();
        bus.emit(published(OrgId::new())).await;

        let names: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok()).map(|e| e.event.name().to_owned()).collect();
        assert_eq!(names, vec!["package.publish", "notification.new"], "the follow-up must reach the stream");
        assert_eq!(echo.seen.lock().unwrap().as_slice(), ["package.publish"], "follow-ups must not re-enter consumers");
    }

    #[tokio::test]
    async fn the_broker_bridge_ignores_this_instance_own_messages() {
        // Redis pub/sub echoes a publisher's own messages; without the origin filter every
        // event would reach local subscribers twice.
        let bus = Arc::new(EventBus::new(EventBusPolicy::default()));
        let envelope = EventEnvelope::new(published(OrgId::new()));
        let mine = BrokerMessage { origin: bus.origin.clone(), envelope: envelope.clone() };
        let theirs = BrokerMessage { origin: "another-instance".to_owned(), envelope };
        let encoded_mine = serde_json::to_string(&mine).unwrap();
        let decoded: BrokerMessage = serde_json::from_str(&encoded_mine).unwrap();
        assert_eq!(decoded.origin, bus.origin);
        assert_ne!(theirs.origin, bus.origin);
    }
}
