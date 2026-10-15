use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::TcpListener;
use tokio::sync::watch;

use super::*;
use crate::config::{
    ProxyConfig, UpstreamConfig, UpstreamType, WebCarrier, WebRuntimeConfig, WebRuntimeProfile,
    WebSecretMode,
};
use crate::crypto::{AesCtr, sha256};
use crate::maestro::generation::{RuntimeGeneration, test_runtime_generation_with_admission};
use crate::protocol::constants::{
    DC_IDX_POS, HANDSHAKE_LEN, IV_LEN, PREKEY_LEN, PROTO_TAG_POS, ProtoTag, SKIP_LEN,
};
use crate::web::frame;
use crate::web::manager::{ManagerError, WebProcessRuntime};

struct TestRuntime {
    session: Arc<WebSession>,
    manager: Arc<WebProcessRuntime>,
    generation: Arc<RuntimeGeneration>,
    admission_tx: watch::Sender<bool>,
}

impl TestRuntime {
    fn process_frame(
        &self,
        stream_id: u32,
        sequence: u64,
        frame_type: FrameType,
        payload: &[u8],
    ) -> Result<u64, ManagerError> {
        let encoded = frame::encode(frame_type, stream_id, payload);
        match self.session.carrier() {
            WebCarrier::Https | WebCarrier::Websocket => {
                self.session.process_up(sequence, &encoded)
            }
            WebCarrier::HttpsLanes | WebCarrier::WebsocketLanes => {
                self.session.process_up_lane(stream_id, sequence, &encoded)
            }
        }
    }

    async fn shutdown(self) {
        self.session.close(super::SessionCloseReason::ApiClose);
        self.session.wait().await;
        self.manager.shutdown().await;
        self.generation.stop_sessions().await;
        self.generation.stop_background_tasks().await;
    }
}

fn test_runtime(carrier: WebCarrier, max_stream_handshakes: usize) -> TestRuntime {
    test_runtime_with_dc(carrier, max_stream_handshakes, None)
}

fn test_runtime_with_dc(
    carrier: WebCarrier,
    max_stream_handshakes: usize,
    dc_addr: Option<SocketAddr>,
) -> TestRuntime {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        public_addr: "203.0.113.10:443".parse().unwrap(),
        user: "default".to_string(),
        secret_mode: WebSecretMode::Plain,
        carrier,
        carrier_negotiation_enabled: false,
        carrier_learning: true,
        carriers: Arc::from([carrier]),
        carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
        capability: [7; 32],
        credential_id: [0; 16],
        key_fingerprint: "0000000000000000".to_string(),
        max_sessions: 4,
        max_streams: 16,
        max_streams_per_session: 4,
    });
    let mut config = ProxyConfig::default();
    config.web.enabled = true;
    config.web.carrier = carrier;
    config.web.limits.max_stream_handshakes = max_stream_handshakes;
    config.web.timeouts.stream_handshake_secs = 1;
    config.web.timeouts.shutdown_secs = 1;
    config.censorship.server_hello_delay_min_ms = 0;
    config.censorship.server_hello_delay_max_ms = 0;
    if let Some(dc_addr) = dc_addr {
        config
            .dc_overrides
            .insert("2".to_string(), vec![dc_addr.to_string()]);
        config.upstreams.push(UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
                bindtodevice: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
            ipv4: Some(true),
            ipv6: Some(false),
            prefer: Some(4),
        });
    }
    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        vhosts: BTreeMap::new(),
        profiles: vec![Arc::clone(&profile)],
        capabilities: vec![[7; 32]].into_boxed_slice(),
    }));
    config.rebuild_runtime_user_auth().unwrap();
    let limits = config.web.limits.clone();
    let timeouts = config.web.timeouts.clone();
    let (admission_tx, admission_rx) = watch::channel(true);
    let generation = test_runtime_generation_with_admission(1, config, admission_rx);
    let manager = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let session = WebSession::new(
        Arc::downgrade(&manager),
        [8; 32],
        "192.0.2.10".parse().unwrap(),
        1,
        profile,
        [7; 32],
        carrier,
        1,
        [9; 32],
        None,
        crate::web::manager::CarrierClientClass::Legacy,
        None,
        false,
        false,
        limits,
        timeouts,
        None,
    );
    TestRuntime {
        session,
        manager,
        generation,
        admission_tx,
    }
}

fn valid_plain_handshake() -> [u8; HANDSHAKE_LEN] {
    let secret = [0u8; 16];
    let mut handshake = [0x5a; HANDSHAKE_LEN];
    for (index, byte) in handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
        .iter_mut()
        .enumerate()
    {
        *byte = (index as u8).wrapping_add(1);
    }
    let dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let dec_iv_bytes = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut dec_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
    dec_key_input.extend_from_slice(dec_prekey);
    dec_key_input.extend_from_slice(&secret);
    let dec_key = sha256(&dec_key_input);
    let mut dec_iv = [0u8; IV_LEN];
    dec_iv.copy_from_slice(dec_iv_bytes);
    let mut cipher = AesCtr::new(&dec_key, u128::from_be_bytes(dec_iv));
    let keystream = cipher.encrypt(&[0u8; HANDSHAKE_LEN]);
    let mut plaintext = [0u8; HANDSHAKE_LEN];
    plaintext[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&ProtoTag::Intermediate.to_bytes());
    plaintext[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&2i16.to_le_bytes());
    for index in PROTO_TAG_POS..HANDSHAKE_LEN {
        handshake[index] = plaintext[index] ^ keystream[index];
    }
    handshake
}

async fn settle_tasks() {
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
}

fn bad_class(runtime: &TestRuntime, class: &str) -> u64 {
    runtime
        .generation
        .stats
        .get_connects_bad_class_counts()
        .into_iter()
        .find_map(|(name, total)| (name == class).then_some(total))
        .unwrap_or(0)
}

#[tokio::test(start_paused = true)]
async fn open_without_data_does_not_start_the_inner_handshake_timeout() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        let runtime = test_runtime(carrier, 1);

        assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
        settle_tasks().await;
        assert!(runtime.session.state.lock().streams.contains_key(&1));

        tokio::time::advance(Duration::from_secs(2)).await;
        settle_tasks().await;

        assert!(
            runtime.session.state.lock().streams.contains_key(&1),
            "OPEN without DATA must remain live until session cancellation or idle expiry"
        );
        runtime.shutdown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn silent_open_does_not_consume_generation_connection_capacity() {
    let runtime = test_runtime(WebCarrier::Https, 1);
    let available = runtime.generation.max_connections.available_permits();

    assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
    settle_tasks().await;

    assert_eq!(
        runtime.generation.max_connections.available_permits(),
        available
    );

    assert_eq!(runtime.process_frame(1, 2, FrameType::Data, &[0x5a]), Ok(2));
    settle_tasks().await;
    assert_eq!(
        runtime.generation.max_connections.available_permits(),
        available - 1
    );

    runtime.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn first_inner_byte_fails_closed_when_connection_capacity_is_exhausted() {
    let runtime = test_runtime(WebCarrier::Https, 1);
    let capacity = runtime.generation.max_connections.available_permits();
    let permit = runtime
        .generation
        .max_connections
        .clone()
        .try_acquire_many_owned(capacity as u32)
        .unwrap();

    assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
    settle_tasks().await;
    assert!(runtime.session.state.lock().streams.contains_key(&1));

    assert_eq!(runtime.process_frame(1, 2, FrameType::Data, &[0x5a]), Ok(2));
    settle_tasks().await;

    assert!(!runtime.session.state.lock().streams.contains_key(&1));
    assert_eq!(runtime.generation.max_connections.available_permits(), 0);

    drop(permit);
    assert_eq!(
        runtime.generation.max_connections.available_permits(),
        capacity
    );
    runtime.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn the_first_inner_byte_starts_the_handshake_timeout() {
    let runtime = test_runtime(WebCarrier::Https, 1);

    assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
    settle_tasks().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(runtime.process_frame(1, 2, FrameType::Data, &[0x5a]), Ok(2));
    settle_tasks().await;
    assert!(runtime.session.state.lock().streams.contains_key(&1));

    tokio::time::advance(Duration::from_secs(2)).await;
    settle_tasks().await;

    assert!(!runtime.session.state.lock().streams.contains_key(&1));
    assert_eq!(bad_class(&runtime, "web_mtproto_handshake_timeout"), 1);
    assert_eq!(runtime.generation.stats.get_handshake_timeouts(), 1);
    assert_eq!(
        runtime
            .generation
            .stats
            .get_handshake_failure_class_counts(),
        vec![("timeout".to_string(), 1)]
    );
    runtime.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn delayed_complete_handshake_is_classified_after_data_arrives() {
    let runtime = test_runtime(WebCarrier::Https, 1);

    assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
    settle_tasks().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        runtime.process_frame(1, 2, FrameType::Data, &[0; 64]),
        Ok(2)
    );
    settle_tasks().await;

    assert!(!runtime.session.state.lock().streams.contains_key(&1));
    assert_eq!(bad_class(&runtime, "web_mtproto_bad_client"), 1);
    assert_eq!(bad_class(&runtime, "web_mtproto_handshake_timeout"), 0);
    assert_eq!(runtime.generation.stats.get_handshake_timeouts(), 0);
    runtime.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn delayed_valid_handshake_reaches_the_authenticated_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = test_runtime_with_dc(WebCarrier::Https, 1, Some(listener.local_addr().unwrap()));

    assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
    settle_tasks().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        runtime.process_frame(1, 2, FrameType::Data, &valid_plain_handshake()),
        Ok(2)
    );

    // Keep the delayed-data scenario virtual, but wait for real TCP with real time.
    tokio::time::resume();
    let accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
    assert!(
        accepted.is_ok(),
        "valid handshake did not reach the configured upstream; bad classes: {:?}",
        runtime.generation.stats.get_connects_bad_class_counts()
    );
    let (upstream, _) = accepted.unwrap().unwrap();
    assert!(runtime.session.state.lock().streams.contains_key(&1));
    assert_eq!(runtime.generation.stats.get_connects_bad(), 0);
    assert_eq!(runtime.generation.stats.get_handshake_timeouts(), 0);

    runtime.shutdown().await;
    drop(upstream);
}

#[tokio::test]
async fn closed_generation_admission_rejects_web_stream_before_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = test_runtime_with_dc(WebCarrier::Https, 1, Some(listener.local_addr().unwrap()));
    runtime.admission_tx.send_replace(false);

    assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
    settle_tasks().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "WEB stream bypassed the closed generation admission gate"
    );
    assert!(!runtime.session.state.lock().streams.contains_key(&1));
    assert_eq!(runtime.generation.max_connections.available_permits(), 64);

    runtime.admission_tx.send_replace(true);
    assert_eq!(runtime.process_frame(2, 2, FrameType::Open, &[]), Ok(2));
    assert_eq!(
        runtime.process_frame(2, 3, FrameType::Data, &valid_plain_handshake()),
        Ok(3)
    );
    let (upstream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .expect("a new WEB stream did not start after admission reopened")
        .unwrap();
    assert_eq!(runtime.generation.max_connections.available_permits(), 63);

    runtime.shutdown().await;
    drop(upstream);
}

#[tokio::test(start_paused = true)]
async fn silent_streams_do_not_consume_active_handshake_capacity() {
    let runtime = test_runtime(WebCarrier::Https, 1);

    assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
    assert_eq!(runtime.process_frame(2, 2, FrameType::Open, &[]), Ok(2));
    settle_tasks().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    settle_tasks().await;
    {
        let state = runtime.session.state.lock();
        assert!(state.streams.contains_key(&1));
        assert!(state.streams.contains_key(&2));
    }

    assert_eq!(runtime.process_frame(1, 3, FrameType::Data, &[1]), Ok(3));
    settle_tasks().await;
    assert_eq!(runtime.process_frame(2, 4, FrameType::Data, &[2]), Ok(4));
    settle_tasks().await;

    {
        let state = runtime.session.state.lock();
        assert!(state.streams.contains_key(&1));
        assert!(!state.streams.contains_key(&2));
    }
    runtime.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn cancellation_while_waiting_for_data_releases_stream_ownership() {
    let runtime = test_runtime(WebCarrier::Https, 1);

    assert_eq!(runtime.process_frame(1, 1, FrameType::Open, &[]), Ok(1));
    settle_tasks().await;
    assert_eq!(runtime.session.tasks_live.load(Ordering::Acquire), 1);

    runtime.session.close(super::SessionCloseReason::ApiClose);
    runtime.session.wait().await;

    assert_eq!(runtime.session.tasks_live.load(Ordering::Acquire), 0);
    assert!(runtime.session.state.lock().active_peer_ports.is_empty());
    let peer_port = runtime
        .manager
        .try_acquire_stream(
            runtime.session.profile_key,
            runtime.session.profile.max_streams,
            runtime.session.client_ip,
            runtime.session.profile.public_addr,
        )
        .unwrap();
    assert_eq!(peer_port, 1);
    runtime.manager.release_stream(
        runtime.session.profile_key,
        runtime.session.client_ip,
        runtime.session.profile.public_addr,
        peer_port,
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn exhausted_stream_identity_does_not_acquire_synthetic_port_ownership() {
    let runtime = test_runtime(WebCarrier::Https, 1);
    runtime.session.state.lock().next_stream_instance = u64::MAX;

    assert_eq!(
        runtime.process_frame(1, 1, FrameType::Open, &[]),
        Err(ManagerError::Closed)
    );
    assert!(runtime.session.state.lock().active_peer_ports.is_empty());

    runtime.shutdown().await;
}
