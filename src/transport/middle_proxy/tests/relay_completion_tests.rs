use super::pool_writer_security_tests::make_pool;
use super::registry::RouteResult;
use super::{MePool, MeResponse};
use crate::config::{MeRouteNoWriterMode, ProxyConfig};
use crate::crypto::AesCtr;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::ProtoTag;
use crate::proxy::handshake::HandshakeSuccess;
use crate::proxy::middle_relay::handle_via_middle_proxy;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

struct RelayFixture {
    pool: Arc<MePool>,
    stats: Arc<Stats>,
    client: DuplexStream,
    task: AbortOnDropHandle<Result<()>>,
    cancel: CancellationToken,
    routes: RouteRuntimeController,
    conn_id: u64,
}

impl RelayFixture {
    async fn new(mode: MeRouteNoWriterMode) -> Self {
        let mut pool = make_pool().await;
        let route = Arc::get_mut(&mut Arc::get_mut(&mut pool).unwrap().route_runtime).unwrap();
        route
            .me_route_no_writer_mode
            .store(mode.as_u8(), Ordering::Relaxed);
        route.me_route_no_writer_wait = Duration::from_millis(20);
        route.me_route_hybrid_max_wait = Duration::from_millis(50);
        let stats = pool.stats.clone();
        let mut config = ProxyConfig::default();
        // The observation deadline must expire well before ordinary client idle handling.
        config.timeouts.relay_client_idle_soft_secs = 60;
        config.timeouts.relay_client_idle_hard_secs = 120;
        let routes = RouteRuntimeController::new(RelayRouteMode::Middle);
        let cancel = CancellationToken::new();
        // This isolated pool has no other registrants; reserve the preceding ID.
        let (preceding_id, _) = pool.registry.register().await;
        pool.registry.unregister(preceding_id).await;
        let conn_id = preceding_id.wrapping_add(1);
        let (server, client) = duplex(16 * 1024);
        let (reader, writer) = tokio::io::split(server);
        let success = HandshakeSuccess {
            user: "completion-test".into(),
            dc_idx: 2,
            proto_tag: ProtoTag::Intermediate,
            dec_key: [0; 32],
            dec_iv: 0,
            enc_key: [0; 32],
            enc_iv: 0,
            peer: "127.0.0.1:50000".parse().unwrap(),
            is_tls: false,
        };
        let quota = stats.current_user_quota_handle(&success.user);
        let task = AbortOnDropHandle::new(tokio::spawn(handle_via_middle_proxy(
            CryptoReader::new(reader, AesCtr::new(&[0; 32], 0)),
            CryptoWriter::new(writer, AesCtr::new(&[0; 32], 0), 64 * 1024),
            success,
            pool.clone(),
            stats.clone(),
            Arc::new(config),
            Arc::new(BufferPool::new()),
            "127.0.0.1:443".parse().unwrap(),
            pool.rng.clone(),
            routes.subscribe(),
            routes.snapshot(),
            0xB5,
            cancel.clone(),
            ProxySharedState::new(),
            quota,
        )));
        timeout(Duration::from_secs(1), async {
            loop {
                if stats.get_current_connections_me() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("relay must register its connection");
        Self {
            pool,
            stats,
            client,
            task,
            cancel,
            routes,
            conn_id,
        }
    }

    async fn send_frame(&mut self) {
        let mut frame = 2048u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&[0x42; 2048]);
        let encrypted = AesCtr::new(&[0; 32], 0).encrypt(&frame);
        self.client.write_all(&encrypted).await.unwrap();
    }

    async fn finish(&mut self) -> Result<()> {
        self.finish_with_deadline(Duration::from_secs(1)).await
    }

    async fn finish_with_deadline(&mut self, deadline: Duration) -> Result<()> {
        let result = timeout(deadline, &mut self.task)
            .await
            .expect("completed ME child must terminate relay while client remains open")
            .expect("relay must not panic or poll a completed child twice");
        assert_eq!(self.stats.get_current_connections_me(), 0);
        assert!(self.pool.registry.active_conn_ids().await.is_empty());
        assert_eq!(
            self.pool
                .registry
                .route(self.conn_id, MeResponse::Close)
                .await,
            RouteResult::NoConn,
            "the unbound route and its byte budget must be unregistered"
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            timeout(Duration::from_secs(1), self.client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(self.pool.shutdown_until(Duration::from_secs(1)).await);
        result
    }
}

#[tokio::test]
async fn no_writer_error_closes_silent_client_after_one_frame() {
    for mode in [
        MeRouteNoWriterMode::AsyncRecoveryFailfast,
        MeRouteNoWriterMode::HybridAsyncPersistent,
    ] {
        let mut fixture = RelayFixture::new(mode).await;
        fixture.send_frame().await;
        // Prove the sender has already failed, independently of parent relay completion.
        timeout(Duration::from_secs(1), async {
            while fixture.stats.get_me_no_writer_failfast_total()
                + fixture.stats.get_me_hybrid_timeout_total()
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("empty pool must reach its configured no-writer deadline");
        let error = fixture.finish().await.unwrap_err();
        assert!(
            matches!(error, ProxyError::Proxy(ref message)
            if message.contains("failfast window") || message.contains("hybrid timeout")),
            "original routing error must reach the caller: {error}"
        );
    }
}

#[tokio::test]
async fn downstream_close_terminates_silent_client() {
    let mut fixture = RelayFixture::new(MeRouteNoWriterMode::AsyncRecoveryFailfast).await;
    fixture
        .pool
        .registry
        .route(fixture.conn_id, MeResponse::Close)
        .await;
    fixture.finish().await.unwrap();
}

#[tokio::test]
async fn lost_me_route_terminates_silent_client_with_original_error() {
    let mut fixture = RelayFixture::new(MeRouteNoWriterMode::AsyncRecoveryFailfast).await;
    fixture.pool.registry.unregister(fixture.conn_id).await;
    assert!(matches!(
        fixture.finish().await,
        Err(ProxyError::MiddleConnectionLost)
    ));
}

#[tokio::test]
async fn healthy_idle_remains_open_and_client_eof_is_clean() {
    let mut fixture = RelayFixture::new(MeRouteNoWriterMode::AsyncRecoveryFailfast).await;
    assert!(
        timeout(Duration::from_millis(100), &mut fixture.task)
            .await
            .is_err()
    );
    assert_eq!(fixture.stats.get_current_connections_me(), 1);
    fixture.client.shutdown().await.unwrap();
    fixture.finish().await.unwrap();
}

#[tokio::test]
async fn user_cancellation_still_releases_relay() {
    let mut fixture = RelayFixture::new(MeRouteNoWriterMode::AsyncRecoveryFailfast).await;
    fixture.cancel.cancel();
    assert!(matches!(
        fixture.finish().await,
        Err(ProxyError::UserDisabled { .. })
    ));
}

#[tokio::test]
async fn route_cutover_still_releases_relay() {
    let mut fixture = RelayFixture::new(MeRouteNoWriterMode::AsyncRecoveryFailfast).await;
    fixture.routes.set_mode(RelayRouteMode::Direct);
    // The existing cutover stagger intentionally waits between one and two seconds.
    assert!(matches!(
        fixture.finish_with_deadline(Duration::from_secs(3)).await,
        Err(ProxyError::RouteSwitched)
    ));
}
