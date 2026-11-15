use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::ProxyConfig;
use crate::crypto::{SecureRandom, sha256_hmac};
use crate::error::HandshakeResult;
use crate::protocol::constants::TLS_VERSION;
use crate::protocol::tls;
use crate::proxy::handshake::{
    TlsResponseFragmentation, TlsResponseWriteOptions, handle_tls_handshake_with_shared_and_options,
};
use crate::proxy::shared_state::ProxySharedState;
use crate::stats::ReplayChecker;
use crate::transport::socket::{ListenOptions, create_listener};

const SECRET: [u8; 16] = [0x56; 16];
const SECRET_HEX: &str = "56565656565656565656565656565656";
const BULK_PAYLOAD_LEN: usize = 8192;

fn make_valid_tls_client_hello(tls_len: usize) -> Vec<u8> {
    const TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
    const TLS_EXTENSION_KEY_SHARE: u16 = 0x0033;
    const TLS_EXTENSION_PADDING: u16 = 0x0015;
    const X25519_KEY_SHARE_LEN: usize = 32;
    let fill = 0x42_u8;
    let session_id_len = 32_usize;
    let mut extensions = Vec::new();
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&tls::TLS_NAMED_GROUP_X25519.to_be_bytes());
    key_share.extend_from_slice(&(X25519_KEY_SHARE_LEN as u16).to_be_bytes());
    key_share.push(9);
    key_share.resize(key_share.len() + X25519_KEY_SHARE_LEN - 1, 0);
    let mut key_share_extension = Vec::new();
    key_share_extension.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    key_share_extension.extend_from_slice(&key_share);
    extensions.extend_from_slice(&TLS_EXTENSION_KEY_SHARE.to_be_bytes());
    extensions.extend_from_slice(&(key_share_extension.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_share_extension);
    let base_tls_len = 4
        + 2
        + 32
        + 1
        + session_id_len
        + 2
        + TLS_AES_128_GCM_SHA256.len()
        + 1
        + 1
        + 2
        + extensions.len();
    let padding_len = tls_len
        .checked_sub(base_tls_len + 4)
        .expect("wire ClientHello must leave room for padding");
    extensions.extend_from_slice(&TLS_EXTENSION_PADDING.to_be_bytes());
    extensions.extend_from_slice(&(padding_len as u16).to_be_bytes());
    extensions.resize(extensions.len() + padding_len, fill);

    let body_len = tls_len - 4;
    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(&TLS_VERSION);
    body.extend_from_slice(&[fill; 32]);
    body.push(session_id_len as u8);
    body.extend_from_slice(&[fill; 32]);
    body.extend_from_slice(&(TLS_AES_128_GCM_SHA256.len() as u16).to_be_bytes());
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = Vec::with_capacity(5 + tls_len);
    handshake.push(0x16);
    handshake.extend_from_slice(&[0x03, 0x01]);
    handshake.extend_from_slice(&(tls_len as u16).to_be_bytes());
    handshake.push(0x01);
    handshake.extend_from_slice(&(body_len as u32).to_be_bytes()[1..].as_ref());
    handshake.extend_from_slice(&body);
    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);
    let digest = sha256_hmac(&SECRET, &handshake);
    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);
    handshake
}

async fn wait_for_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("wire-test release barrier timed out");
}

async fn run_server(
    addr: SocketAddr,
    fragmentation: TlsResponseFragmentation,
    fake_cert_len: usize,
) {
    let socket = create_listener(
        addr,
        &ListenOptions {
            reuse_port: false,
            client_mss: Some(1400),
            ..Default::default()
        },
    )
    .unwrap();
    let listener = TcpListener::from_std(socket.into()).unwrap();
    let (mut server, peer) = listener.accept().await.unwrap();
    let mut header = [0_u8; 5];
    server.read_exact(&mut header).await.unwrap();
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut client_hello = Vec::with_capacity(5 + body_len);
    client_hello.extend_from_slice(&header);
    client_hello.resize(5 + body_len, 0);
    server.read_exact(&mut client_hello[5..]).await.unwrap();
    let barrier = std::env::var("TELEMT_WIRE_BARRIER").unwrap();
    let release = std::env::var("TELEMT_WIRE_RELEASE").unwrap();
    std::fs::write(&barrier, b"ready").unwrap();
    wait_for_file(Path::new(&release)).await;

    let raw_fd = server.as_raw_fd();
    let mss_before = socket2::SockRef::from(&server).tcp_mss().unwrap();
    let (read_half, write_half) = server.into_split();
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.access.ignore_time_skew = true;
    config.censorship.fake_cert_len = fake_cert_len;
    config
        .access
        .users
        .insert("wire".to_string(), SECRET_HEX.to_string());
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let shared = ProxySharedState::new();
    let (tls_reader, mut tls_writer, user) = match handle_tls_handshake_with_shared_and_options(
        &client_hello,
        read_half,
        write_half,
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        &shared,
        TlsResponseWriteOptions::tcp(raw_fd, Some(fragmentation)),
    )
    .await
    {
        HandshakeResult::Success(result) => result,
        _ => panic!("wire-test FakeTLS authentication failed"),
    };
    assert_eq!(user, "wire");
    tls_writer
        .write_all(&vec![0xA5; BULK_PAYLOAD_LEN])
        .await
        .unwrap();
    tls_writer.shutdown().await.unwrap();
    drop(tls_reader);
    // SAFETY: the write half still owns the accepted socket while it is borrowed.
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    let mss_after = socket2::SockRef::from(&borrowed_fd).tcp_mss().unwrap();
    let metadata = std::env::var("TELEMT_WIRE_SERVER_META").unwrap();
    std::fs::write(
        metadata,
        format!("configured_bulk_mss=1400\nmss_before={mss_before}\nmss_after={mss_after}\n"),
    )
    .unwrap();
}

async fn run_client(addr: SocketAddr) {
    let mut client = loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => break stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    client
        .write_all(&make_valid_tls_client_hello(600))
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let mut offset = 0;
    let mut bulk_record_start = None;
    while offset < response.len() {
        assert!(response.len() - offset >= 5, "truncated TLS record header");
        let payload_len = u16::from_be_bytes([response[offset + 3], response[offset + 4]]) as usize;
        let end = offset + 5 + payload_len;
        assert!(end <= response.len(), "truncated TLS record payload");
        if response[offset] == 0x17
            && payload_len == BULK_PAYLOAD_LEN
            && response[offset + 5..end].iter().all(|byte| *byte == 0xA5)
        {
            bulk_record_start = Some(offset);
        }
        offset = end;
    }
    let initial_response_bytes = bulk_record_start.expect("bulk TLS record missing");
    let metadata = std::env::var("TELEMT_WIRE_CLIENT_META").unwrap();
    std::fs::write(
        metadata,
        format!(
            "initial_response_bytes={initial_response_bytes}\ntotal_response_bytes={}\n",
            response.len()
        ),
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "requires privileged netns/veth packet-capture harness"]
async fn fake_tls_fragmentation_wire_role() {
    let role = std::env::var("TELEMT_WIRE_ROLE").expect("TELEMT_WIRE_ROLE is required");
    let addr = std::env::var("TELEMT_WIRE_ADDR")
        .unwrap_or_else(|_| "198.18.0.1:24443".to_string())
        .parse()
        .unwrap();
    match role.as_str() {
        "server" => {
            let fragment_size = std::env::var("TELEMT_WIRE_FRAGMENT")
                .unwrap()
                .parse()
                .unwrap();
            let fake_cert_len = std::env::var("TELEMT_WIRE_FAKE_CERT_LEN")
                .unwrap()
                .parse()
                .unwrap();
            // Optional `server.client_mss_prefix` value; omitted keeps "full".
            let server = crate::config::ServerConfig {
                client_mss_prefix: std::env::var("TELEMT_WIRE_PREFIX").ok(),
                ..Default::default()
            };
            let prefix = server
                .client_mss_prefix_value()
                .expect("TELEMT_WIRE_PREFIX must be a valid client_mss_prefix")
                .unwrap_or_default();
            let fragmentation = TlsResponseFragmentation {
                fragment_size,
                prefix,
            };
            run_server(addr, fragmentation, fake_cert_len).await;
        }
        "client" => run_client(addr).await,
        _ => panic!("TELEMT_WIRE_ROLE must be server or client"),
    }
}
