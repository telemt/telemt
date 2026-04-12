use super::*;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tokio::time::{Duration, timeout};

struct EndlessReader {
    produced: Arc<AtomicUsize>,
}

impl AsyncRead for EndlessReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let len = buf.remaining().max(1);
        let fill = vec![0xAA; len];
        buf.put_slice(&fill);
        self.produced.fetch_add(len, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

#[test]
fn loop_guard_unspecified_bind_uses_interface_inventory() {
    let local: SocketAddr = "0.0.0.0:443".parse().unwrap();
    let resolved: SocketAddr = "192.168.44.10:443".parse().unwrap();
    let interfaces = vec!["192.168.44.10".parse().unwrap()];

    assert!(is_mask_target_local_listener_with_interfaces(
        "mask.example",
        443,
        local,
        Some(resolved),
        &interfaces,
    ));
}

#[tokio::test]
async fn consume_client_data_stops_after_byte_cap_without_eof() {
    let produced = Arc::new(AtomicUsize::new(0));
    let reader = EndlessReader {
        produced: Arc::clone(&produced),
    };
    let cap = 10_000usize;

    consume_client_data(reader, cap, MASK_RELAY_IDLE_TIMEOUT).await;

    let total = produced.load(Ordering::Relaxed);
    assert!(
        total >= cap,
        "consume path must read at least up to cap before stopping"
    );
    assert!(
        total <= cap + 8192,
        "consume path must stop within one read chunk above cap"
    );
}

#[test]
fn masking_beobachten_minutes_zero_fail_closes_to_minimum_ttl() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 0;

    let ttl = masking_beobachten_ttl(&config);
    assert_eq!(ttl, std::time::Duration::from_secs(60));
}

#[test]
fn timing_normalization_zero_floor_safety_net_defaults_to_mask_timeout() {
    let mut config = ProxyConfig::default();
    config.censorship.mask_timing_normalization_enabled = true;
    config.censorship.mask_timing_normalization_floor_ms = 0;
    config.censorship.mask_timing_normalization_ceiling_ms = 0;

    let budget = mask_outcome_target_budget(&config);
    assert_eq!(
        budget,
        Duration::from_millis(0),
        "zero floor/ceiling must produce zero extra normalization budget"
    );
}

#[tokio::test]
async fn loop_guard_blocks_self_target_before_proxy_protocol_header_growth() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let accept_task = tokio::spawn(async move {
        timeout(Duration::from_millis(120), listener.accept())
            .await
            .is_ok()
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_proxy_protocol = 2;

    let peer: SocketAddr = "203.0.113.251:55991".parse().unwrap();
    let local_addr: SocketAddr = format!("0.0.0.0:{}", backend_addr.port()).parse().unwrap();
    let beobachten = BeobachtenStore::new();

    handle_bad_client(
        tokio::io::empty(),
        tokio::io::sink(),
        b"GET / HTTP/1.1\r\n\r\n",
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let accepted = accept_task.await.unwrap();
    assert!(
        !accepted,
        "loop guard must fail closed before any recursive PROXY protocol amplification"
    );
}
