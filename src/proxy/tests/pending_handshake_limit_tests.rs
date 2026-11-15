use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::{AesCtr, sha256};
use crate::protocol::constants::{
    DC_IDX_POS, HANDSHAKE_LEN, IV_LEN, PREKEY_LEN, PROTO_TAG_POS, ProtoTag, SKIP_LEN,
};
use crate::proxy::client::handle_client_stream_with_shared;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;
use crate::{
    config::ProxyConfig,
    crypto::SecureRandom,
    ip_tracker::UserIpTracker,
    stats::{ReplayChecker, Stats, beobachten::BeobachtenStore},
    stream::BufferPool,
    transport::UpstreamManager,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

struct Harness {
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    shared: Arc<ProxySharedState>,
}

fn harness(limit: u32, dry_run: bool) -> Harness {
    harness_with(limit, dry_run, |_| {})
}

fn harness_with_first_byte_idle(
    limit: u32,
    dry_run: bool,
    first_byte_idle: Option<u64>,
) -> Harness {
    harness_with(limit, dry_run, |cfg| {
        if let Some(secs) = first_byte_idle {
            cfg.timeouts.client_first_byte_idle_secs = secs;
        }
    })
}

fn harness_with(limit: u32, dry_run: bool, customize: impl FnOnce(&mut ProxyConfig)) -> Harness {
    let mut cfg = ProxyConfig::default();
    cfg.censorship.mask = false;
    cfg.general.modes.classic = true;
    cfg.general.modes.secure = true;
    cfg.timeouts.client_handshake = 30;
    cfg.server.max_pending_handshakes_per_ip = limit;
    cfg.server.pending_handshakes_per_ip_dry_run = dry_run;
    customize(&mut cfg);
    Harness {
        config: Arc::new(cfg),
        stats: Arc::new(Stats::new()),
        shared: ProxySharedState::new(),
    }
}

/// Opens a connection that sends one byte and then stalls inside the
/// handshake. Returns the client side (keep it alive to keep the handshake
/// pending) and the handler task.
async fn stalled_connection(
    h: &Harness,
    peer: &str,
) -> (DuplexStream, JoinHandle<crate::error::Result<()>>) {
    let (mut client_side, task) = silent_connection(h, peer);
    client_side.write_all(&[0xef]).await.unwrap();
    (client_side, task)
}

/// Opens a connection that never sends a byte.
fn silent_connection(
    h: &Harness,
    peer: &str,
) -> (DuplexStream, JoinHandle<crate::error::Result<()>>) {
    let (server_side, client_side) = duplex(4096);
    let peer: SocketAddr = peer.parse().unwrap();
    let stats = h.stats.clone();
    let task = tokio::spawn(handle_client_stream_with_shared(
        server_side,
        peer,
        h.config.clone(),
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![UpstreamConfig {
                upstream_type: UpstreamType::Direct {
                    interface: None,
                    bind_addresses: None,
                    bindtodevice: None,
                },
                weight: 1,
                enabled: true,
                scopes: String::new(),
                selected_scope: String::new(),
                ipv4: None,
                ipv6: None,
                prefer: None,
            }],
            1,
            1,
            // Connect budget in milliseconds: generous, so a loaded test
            // runner does not time out connecting to the local stand-in DC.
            5_000,
            10,
            1,
            false,
            stats,
        )),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        h.shared.clone(),
        false,
    ));
    (client_side, task)
}

async fn wait_pending(h: &Harness, ip: &str, expected: u32) {
    let ip = ip.parse().unwrap();
    for _ in 0..200 {
        if h.shared.pending_handshakes.pending_for(ip) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "pending handshakes for {ip}: got {}, want {expected}",
        h.shared.pending_handshakes.pending_for(ip)
    );
}

#[tokio::test]
async fn over_limit_handshake_is_closed_and_slot_is_released_after_handshake_ends() {
    let h = harness(2, false);

    let (first, _t1) = stalled_connection(&h, "198.51.100.20:40001").await;
    let (_second, _t2) = stalled_connection(&h, "198.51.100.20:40002").await;
    wait_pending(&h, "198.51.100.20", 2).await;

    // The third pending handshake from the same address is closed right away.
    let (_third, t3) = stalled_connection(&h, "198.51.100.20:40003").await;
    let result = tokio::time::timeout(Duration::from_secs(2), t3)
        .await
        .expect("rejected connection must be closed promptly")
        .unwrap();
    assert!(result.is_ok());
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 1);
    wait_pending(&h, "198.51.100.20", 2).await;

    // Other addresses are not affected.
    let (_other, _t4) = stalled_connection(&h, "203.0.113.7:40004").await;
    wait_pending(&h, "203.0.113.7", 1).await;

    // When a pending handshake ends (here: the client goes away), its slot is
    // released and a new connection from the same address is admitted.
    drop(first);
    wait_pending(&h, "198.51.100.20", 1).await;
    let (_fourth, _t5) = stalled_connection(&h, "198.51.100.20:40005").await;
    wait_pending(&h, "198.51.100.20", 2).await;
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 1);
}

#[tokio::test]
async fn dry_run_admits_over_limit_and_counts_it() {
    let h = harness(1, true);

    let (_first, _t1) = stalled_connection(&h, "198.51.100.30:40001").await;
    wait_pending(&h, "198.51.100.30", 1).await;
    let (_second, _t2) = stalled_connection(&h, "198.51.100.30:40002").await;
    wait_pending(&h, "198.51.100.30", 2).await;

    assert_eq!(h.stats.get_pending_handshake_per_ip_observed_total(), 1);
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 0);
}

#[tokio::test]
async fn disabled_by_default_tracks_nothing() {
    let h = harness(0, false);

    let mut clients = Vec::new();
    for port in 0..20 {
        clients.push(stalled_connection(&h, &format!("198.51.100.40:{}", 41000 + port)).await);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.shared.pending_handshakes.tracked_ips(), 0);
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 0);
}

// Review: with client_first_byte_idle_secs = 0 the idle wait is skipped, and
// the slot used to be taken before any byte arrived, so two silent connections
// from one IP with limit 1 got the second one closed. Silent connections must
// not hold a slot; the slot is taken once the first byte is actually received.
#[tokio::test]
async fn silent_connections_do_not_hold_slots_when_first_byte_idle_is_zero() {
    let h = harness_with_first_byte_idle(1, false, Some(0));

    let (_a, ta) = silent_connection(&h, "198.51.100.50:40001");
    let (_b, tb) = silent_connection(&h, "198.51.100.50:40002");
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        h.shared
            .pending_handshakes
            .pending_for("198.51.100.50".parse().unwrap()),
        0
    );
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 0);
    assert!(!ta.is_finished(), "a silent connection must stay open");
    assert!(!tb.is_finished(), "a silent connection must stay open");

    // Once a byte arrives, the connection is in the handshake and counted.
    let (_c, _tc) = stalled_connection(&h, "198.51.100.50:40003").await;
    wait_pending(&h, "198.51.100.50", 1).await;
}

// Review: a drain-reload created a new limiter for the new runtime generation,
// so with limit N one IP could hold up to 2N slots while the old generation was
// still finishing handshakes. The limiter is process-owned and shared.
#[test]
fn runtime_generations_share_the_pending_handshake_limiter() {
    use crate::proxy::direct_buffer_budget::{
        DirectBufferBudget, fallback_direct_buffer_hard_limit,
    };
    use crate::proxy::pending_handshake::{PendingHandshakeAdmission, PendingHandshakeLimiter};
    use crate::proxy::traffic_limiter::TrafficLimiter;
    use crate::proxy::user_admission::UserAdmissionAuthority;

    let limiter = Arc::new(PendingHandshakeLimiter::default());
    let generation = || {
        ProxySharedState::new_with_process_authorities(
            DirectBufferBudget::new(fallback_direct_buffer_hard_limit()),
            TrafficLimiter::new(),
            UserAdmissionAuthority::new(),
            limiter.clone(),
        )
    };
    let old_generation = generation();
    let new_generation = generation();
    let ip = "198.51.100.60".parse().unwrap();

    let _held = match old_generation.pending_handshakes.try_acquire(ip, 1, false) {
        PendingHandshakeAdmission::Admitted(guard) => guard,
        other => panic!("expected admission, got {other:?}"),
    };
    assert!(matches!(
        new_generation.pending_handshakes.try_acquire(ip, 1, false),
        PendingHandshakeAdmission::Rejected
    ));
}

const SECRET_HEX: &str = "77777777777777777777777777777777";

/// Builds a valid obfuscated MTProto handshake for `SECRET_HEX` and `dc_idx`.
fn valid_mtproto_handshake(proto_tag: ProtoTag, dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    let secret = hex::decode(SECRET_HEX).unwrap();

    let mut handshake = [0x5Au8; HANDSHAKE_LEN];
    for (idx, b) in handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
        .iter_mut()
        .enumerate()
    {
        *b = (idx as u8).wrapping_add(1);
    }

    let mut dec_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
    dec_key_input.extend_from_slice(&handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN]);
    dec_key_input.extend_from_slice(&secret);
    let dec_key = sha256(&dec_key_input);

    let mut dec_iv = [0u8; IV_LEN];
    dec_iv.copy_from_slice(&handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    let keystream =
        AesCtr::new(&dec_key, u128::from_be_bytes(dec_iv)).encrypt(&[0u8; HANDSHAKE_LEN]);

    let mut plain = [0u8; HANDSHAKE_LEN];
    plain[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag.to_bytes());
    plain[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_idx.to_le_bytes());
    for idx in PROTO_TAG_POS..HANDSHAKE_LEN {
        handshake[idx] = plain[idx] ^ keystream[idx];
    }
    handshake
}

/// Accepts connections on a local listener and keeps them open, standing in
/// for a Telegram DC or a mask backend. Returns the address and the number of
/// connections accepted so far.
async fn holding_backend() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_in_task = accepted.clone();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            accepted_in_task.fetch_add(1, Ordering::SeqCst);
            held.push(tokio::spawn(async move {
                let mut sink = [0u8; 1024];
                while let Ok(n) = stream.read(&mut sink).await {
                    if n == 0 {
                        break;
                    }
                }
            }));
        }
    });
    (addr, accepted, task)
}

async fn wait_accepted(accepted: &AtomicUsize, expected: usize) {
    for _ in 0..300 {
        if accepted.load(Ordering::SeqCst) >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "backend accepted {}, want {expected}",
        accepted.load(Ordering::SeqCst)
    );
}

// An authenticated session is past the handshake and must not hold a
// pending-handshake slot while it relays, otherwise with limit = 1 every
// client could keep only one connection per IP.
#[tokio::test]
async fn authenticated_session_does_not_hold_a_pending_slot() {
    let (dc_addr, dc_accepted, dc_task) = holding_backend().await;
    let h = harness_with(1, false, |cfg| {
        cfg.access
            .users
            .insert("user".to_string(), SECRET_HEX.to_string());
        cfg.dc_overrides
            .insert("2".to_string(), vec![dc_addr.to_string()]);
    });
    let ip = "198.51.100.70";

    let (mut session, session_task) = silent_connection(&h, &format!("{ip}:40001"));
    session
        .write_all(&valid_mtproto_handshake(ProtoTag::Intermediate, 2))
        .await
        .unwrap();
    wait_accepted(&dc_accepted, 1).await;
    wait_pending(&h, ip, 0).await;
    assert!(
        !session_task.is_finished(),
        "the session must keep relaying"
    );

    // A second handshake from the same address is admitted, not rejected.
    let (_second, second_task) = stalled_connection(&h, &format!("{ip}:40002")).await;
    wait_pending(&h, ip, 1).await;
    assert!(!second_task.is_finished());
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 0);

    drop(session);
    dc_task.abort();
}

// Same for the masking fallback: a bad client relayed to the mask backend is
// no longer in the handshake and must not hold a slot.
#[tokio::test]
async fn masking_relay_does_not_hold_a_pending_slot() {
    let (mask_addr, mask_accepted, mask_task) = holding_backend().await;
    let h = harness_with(1, false, |cfg| {
        cfg.general.beobachten = false;
        cfg.censorship.mask = true;
        cfg.censorship.mask_unix_sock = None;
        cfg.censorship.mask_host = Some("127.0.0.1".to_string());
        cfg.censorship.mask_port = mask_addr.port();
        cfg.censorship.mask_proxy_protocol = 0;
    });
    let ip = "198.51.100.71";

    // A TLS record header with an out-of-range length goes straight to masking.
    let (mut probe, probe_task) = silent_connection(&h, &format!("{ip}:40001"));
    probe
        .write_all(&[0x16, 0x03, 0x01, 0x00, 0x10])
        .await
        .unwrap();
    wait_accepted(&mask_accepted, 1).await;
    wait_pending(&h, ip, 0).await;
    assert!(
        !probe_task.is_finished(),
        "the masking relay must stay open"
    );

    let (_second, second_task) = stalled_connection(&h, &format!("{ip}:40002")).await;
    wait_pending(&h, ip, 1).await;
    assert!(!second_task.is_finished());
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 0);

    drop(probe);
    mask_task.abort();
}

/// Counts log events at `level` whose message mentions pending handshakes.
struct PendingLimitLines {
    level: tracing::Level,
    lines: Arc<AtomicUsize>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PendingLimitLines {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Message(bool);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 |= format!("{value:?}").contains("ending handshakes");
                }
            }
        }
        if event.metadata().level() == &self.level {
            let mut message = Message(false);
            event.record(&mut message);
            if message.0 {
                self.lines.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn assert_flood_logs_one_line(dry_run: bool) {
    use tracing_subscriber::layer::SubscriberExt;

    let lines = Arc::new(AtomicUsize::new(0));
    let level = if dry_run {
        tracing::Level::INFO
    } else {
        tracing::Level::WARN
    };
    let subscriber = tracing_subscriber::registry().with(PendingLimitLines {
        level,
        lines: lines.clone(),
    });
    let _default = tracing::subscriber::set_default(subscriber);

    let h = harness(1, dry_run);
    let ip = "198.51.100.80";
    let (_first, _t1) = stalled_connection(&h, &format!("{ip}:40000")).await;
    wait_pending(&h, ip, 1).await;

    // Other tests hit the same log callsites without a subscriber; a callsite
    // registered concurrently with ours can cache "not interested". Rebuild
    // the cache so this thread-local subscriber sees the flood.
    tracing::callsite::rebuild_interest_cache();

    const FLOOD: u64 = 20;
    let mut flood = Vec::new();
    for port in 1..=FLOOD {
        flood.push(stalled_connection(&h, &format!("{ip}:{}", 40000 + port)).await);
    }
    if dry_run {
        wait_pending(&h, ip, 1 + FLOOD as u32).await;
    } else {
        for (_client, task) in flood.drain(..) {
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("rejected connection must be closed promptly")
                .unwrap()
                .unwrap();
        }
    }

    // Every event is counted by the metric, but only one line is logged.
    let counted = if dry_run {
        h.stats.get_pending_handshake_per_ip_observed_total()
    } else {
        h.stats.get_pending_handshake_per_ip_rejected_total()
    };
    assert_eq!(counted, FLOOD);
    assert_eq!(lines.load(Ordering::Relaxed), 1);
    let throttle = if dry_run {
        &h.shared.pending_handshakes.observed_log
    } else {
        &h.shared.pending_handshakes.rejected_log
    };
    // The next line, once the interval passes, reports the suppressed rest.
    let later =
        std::time::Instant::now() + crate::proxy::pending_handshake::PENDING_HANDSHAKE_LOG_INTERVAL;
    assert_eq!(throttle.note(later), Some(FLOOD - 1));
}

#[tokio::test]
async fn rejection_flood_logs_one_line_and_counts_every_rejection() {
    assert_flood_logs_one_line(false).await;
}

#[tokio::test]
async fn dry_run_flood_logs_one_line_and_counts_every_observation() {
    assert_flood_logs_one_line(true).await;
}
