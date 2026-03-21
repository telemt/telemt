use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{HANDSHAKE_LEN, TLS_RECORD_APPLICATION, TLS_VERSION};
use crate::protocol::tls;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::Duration;

struct StressHarness {
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    route_runtime: Arc<RouteRuntimeController>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
}

fn new_upstream_manager(stats: Arc<Stats>) -> Arc<UpstreamManager> {
    Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats,
    ))
}

fn build_harness(mask_port: u16, secret_hex: &str) -> StressHarness {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = mask_port;
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    StressHarness {
        config,
        stats: stats.clone(),
        upstream_manager: new_upstream_manager(stats),
        replay_checker: Arc::new(ReplayChecker::new(1024, Duration::from_secs(60))),
        buffer_pool: Arc::new(BufferPool::new()),
        rng: Arc::new(SecureRandom::new()),
        route_runtime: Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        ip_tracker: Arc::new(UserIpTracker::new()),
        beobachten: Arc::new(BeobachtenStore::new()),
    }
}

fn make_valid_tls_client_hello(secret: &[u8], timestamp: u32, tls_len: usize, fill: u8) -> Vec<u8> {
    assert!(
        tls_len <= u16::MAX as usize,
        "TLS length must fit into record header"
    );

    let total_len = 5 + tls_len;
    let mut handshake = vec![fill; total_len];

    handshake[0] = 0x16;
    handshake[1] = 0x03;
    handshake[2] = 0x01;
    handshake[3..5].copy_from_slice(&(tls_len as u16).to_be_bytes());

    let session_id_len: usize = 32;
    handshake[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = session_id_len as u8;

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);
    let computed = sha256_hmac(secret, &handshake);
    let mut digest = computed;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);
    handshake
}

fn wrap_tls_application_data(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(TLS_RECORD_APPLICATION);
    record.extend_from_slice(&TLS_VERSION);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

async fn read_tls_record_body<T>(stream: &mut T, header: [u8; 5])
where
    T: tokio::io::AsyncRead + Unpin,
{
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
}

async fn run_parallel_tail_fallback_case(
    sessions: usize,
    payload_len: usize,
    write_chunk: usize,
    ts_base: u32,
    peer_port_base: u16,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut expected = std::collections::HashSet::new();
    for idx in 0..sessions {
        let payload = vec![((idx * 37) & 0xff) as u8; payload_len + idx % 3];
        expected.insert(wrap_tls_application_data(&payload));
    }

    let accept_task = tokio::spawn(async move {
        let mut remaining = expected;
        for _ in 0..sessions {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], TLS_RECORD_APPLICATION);
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut record = vec![0u8; 5 + len];
            record[..5].copy_from_slice(&header);
            stream.read_exact(&mut record[5..]).await.unwrap();
            assert!(remaining.remove(&record));
        }
        assert!(remaining.is_empty());
    });

    let mut tasks = Vec::with_capacity(sessions);

    for idx in 0..sessions {
        let harness = build_harness(backend_addr.port(), "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0");
        let hello =
            make_valid_tls_client_hello(&[0xE0; 16], ts_base + idx as u32, 600, 0x40 + (idx as u8));

        let invalid_mtproto = wrap_tls_application_data(&vec![0u8; HANDSHAKE_LEN]);
        let payload = vec![((idx * 37) & 0xff) as u8; payload_len + idx % 3];
        let trailing = wrap_tls_application_data(&payload);
        // Keep source IPs unique across stress cases so global pre-auth probe state
        // cannot contaminate unrelated sessions and make this test nondeterministic.
        let peer_ip_third = 100 + ((ts_base as u8) / 10);
        let peer_ip_fourth = (idx as u8).saturating_add(1);
        let peer: SocketAddr = format!(
            "198.51.{}.{}:{}",
            peer_ip_third,
            peer_ip_fourth,
            peer_port_base + idx as u16
        )
        .parse()
        .unwrap();

        tasks.push(tokio::spawn(async move {
            let (server_side, mut client_side) = duplex(262144);
            let handler = tokio::spawn(handle_client_stream(
                server_side,
                peer,
                harness.config,
                harness.stats,
                harness.upstream_manager,
                harness.replay_checker,
                harness.buffer_pool,
                harness.rng,
                None,
                harness.route_runtime,
                None,
                harness.ip_tracker,
                harness.beobachten,
                false,
            ));

            client_side.write_all(&hello).await.unwrap();
            let mut server_hello_head = [0u8; 5];
            client_side
                .read_exact(&mut server_hello_head)
                .await
                .unwrap();
            assert_eq!(server_hello_head[0], 0x16);
            read_tls_record_body(&mut client_side, server_hello_head).await;

            client_side.write_all(&invalid_mtproto).await.unwrap();
            for chunk in trailing.chunks(write_chunk.max(1)) {
                client_side.write_all(chunk).await.unwrap();
            }
            client_side.shutdown().await.unwrap();

            let _ = tokio::time::timeout(Duration::from_secs(4), handler)
                .await
                .unwrap()
                .unwrap();
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(8), accept_task)
        .await
        .unwrap()
        .unwrap();
}

macro_rules! stress_case {
    ($name:ident, $sessions:expr, $payload_len:expr, $chunk:expr, $ts:expr, $port:expr) => {
        #[tokio::test]
        async fn $name() {
            run_parallel_tail_fallback_case($sessions, $payload_len, $chunk, $ts, $port).await;
        }
    };
}

stress_case!(stress_masking_parallel_s01, 4, 16, 1, 1000, 57000);
stress_case!(stress_masking_parallel_s02, 5, 24, 2, 1010, 57010);
stress_case!(stress_masking_parallel_s03, 6, 32, 3, 1020, 57020);
stress_case!(stress_masking_parallel_s04, 7, 40, 4, 1030, 57030);
stress_case!(stress_masking_parallel_s05, 8, 48, 5, 1040, 57040);
stress_case!(stress_masking_parallel_s06, 9, 56, 6, 1050, 57050);
stress_case!(stress_masking_parallel_s07, 10, 64, 7, 1060, 57060);
stress_case!(stress_masking_parallel_s08, 11, 72, 8, 1070, 57070);
stress_case!(stress_masking_parallel_s09, 12, 80, 9, 1080, 57080);
stress_case!(stress_masking_parallel_s10, 13, 88, 10, 1090, 57090);
stress_case!(stress_masking_parallel_s11, 6, 128, 11, 1100, 57100);
stress_case!(stress_masking_parallel_s12, 7, 160, 12, 1110, 57110);
stress_case!(stress_masking_parallel_s13, 8, 192, 13, 1120, 57120);
stress_case!(stress_masking_parallel_s14, 9, 224, 14, 1130, 57130);
stress_case!(stress_masking_parallel_s15, 10, 256, 15, 1140, 57140);
stress_case!(stress_masking_parallel_s16, 11, 288, 16, 1150, 57150);
stress_case!(stress_masking_parallel_s17, 12, 320, 17, 1160, 57160);
stress_case!(stress_masking_parallel_s18, 13, 352, 18, 1170, 57170);
stress_case!(stress_masking_parallel_s19, 14, 384, 19, 1180, 57180);
stress_case!(stress_masking_parallel_s20, 15, 416, 20, 1190, 57190);
stress_case!(stress_masking_parallel_s21, 16, 448, 21, 1200, 57200);
stress_case!(stress_masking_parallel_s22, 17, 480, 22, 1210, 57210);
