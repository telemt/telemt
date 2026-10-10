//! SOCKS transport family must not determine the ME KDF endpoint family.

use super::*;
use crate::network::probe::NetworkDecision;
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool_with_decision;
use crate::transport::socks::connect_socks5;
use tokio::net::TcpListener;

// These public tuples are simulated by the local SOCKS/ME peer; no external traffic is sent.
const V4_ME: &str = "149.154.167.50:8888";
const V4_BND: &str = "91.108.56.1:45678";
const V6_ME: &str = "[2001:67c:4e8:f002::a]:8888";
const V6_BND: &str = "[2606:4700:4700::1111]:45678";

fn socks_address(addr: SocketAddr) -> Vec<u8> {
    let mut wire = Vec::new();
    match addr.ip() {
        IpAddr::V4(ip) => {
            wire.push(1);
            wire.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            wire.push(4);
            wire.extend_from_slice(&ip.octets());
        }
    }
    wire.extend_from_slice(&addr.port().to_be_bytes());
    wire
}

async fn socks_reply(stream: &mut TcpStream, target: SocketAddr, bound: SocketAddr) {
    let mut greeting = [0u8; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut expected = vec![5, 1, 0];
    expected.extend_from_slice(&socks_address(target));
    let mut request = vec![0u8; expected.len()];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request, expected);
    let mut response = vec![5, 0, 0];
    response.extend_from_slice(&socks_address(bound));
    stream.write_all(&response).await.unwrap();
}

async fn check_socks_handshake(
    transport: &str,
    target: &str,
    bound: &str,
    policy: MeSocksKdfPolicy,
    valid: bool,
) {
    let target: SocketAddr = target.parse().unwrap();
    let mut bound: SocketAddr = bound.parse().unwrap();
    let mut pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        ..NetworkDecision::default()
    })
    .await;
    // Deliberately disagree with BND: an IP-only override must not replace its egress tuple.
    let nat = Arc::get_mut(&mut Arc::get_mut(&mut pool).unwrap().nat_runtime).unwrap();
    nat.nat_ip_cfg = Some("93.184.216.34".parse().unwrap());
    pool.transport_policy
        .me_socks_kdf_policy
        .store(policy.as_u8(), Ordering::Relaxed);
    let listener = TcpListener::bind(transport).await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let local = stream.local_addr().unwrap();
    // Avoid accidental equality with a kernel-selected ephemeral port.
    while bound.port() == local.port() || bound.port() == proxy_addr.port() {
        bound.set_port(bound.port().checked_add(1).unwrap_or(1));
    }
    let client = async {
        assert_ne!(local.port(), bound.port());
        assert_ne!(proxy_addr.port(), bound.port());
        let reply = connect_socks5(&mut stream, target, None, None)
            .await
            .unwrap();
        assert_eq!(reply.addr, bound);
        let egress = UpstreamEgressInfo {
            upstream_id: 7,
            route_kind: UpstreamRouteKind::Socks5,
            local_addr: Some(local),
            direct_bind_ip: None,
            socks_bound_addr: Some(reply.addr),
            socks_proxy_addr: Some(proxy_addr),
        };
        pool.handshake_only(stream, target, Some(egress), &pool.rng)
            .await
    };
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        socks_reply(&mut stream, target, bound).await;
        if valid {
            accept_handshake(stream, target, bound).await.is_some()
        } else {
            let mut byte = [0u8; 1];
            assert_eq!(
                stream.read(&mut byte).await.unwrap(),
                0,
                "strict rejection must precede nonce"
            );
            false
        }
    };
    let (result, accepted) = timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .expect("local SOCKS and ME handshake must finish");
    if valid {
        match result {
            Ok(_) => assert!(accepted, "ME must validate the encrypted IP and port tuple"),
            Err(error) => panic!("valid SOCKS BND must complete ME handshake: {error}"),
        }
    } else {
        assert!(
            matches!(result, Err(ProxyError::InvalidHandshake(ref message))
            if message.contains("no valid BND tuple")),
            "strict policy must reject invalid BND"
        );
    }
}

async fn accept_handshake(
    mut stream: TcpStream,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
) -> Option<TcpStream> {
    let client_port = client_addr.port();
    let server_port = server_addr.port();
    let client_ip = client_addr.ip();
    let server_ip = server_addr.ip();
    let (seq, payload) = match read_rpc_frame_plaintext(&mut stream).await {
        Ok(frame) => frame,
        // Strict policy can reject the tuple before sending any nonce.
        Err(ProxyError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return None;
        }
        Err(error) => panic!("invalid client nonce: {error}"),
    };
    assert_eq!(seq, -2);
    let (selector, _, timestamp, client_nonce) = parse_nonce_payload(&payload).unwrap();
    let server_nonce = [0x42u8; 16];
    let nonce = build_nonce_payload(selector, timestamp, &server_nonce);
    stream
        .write_all(&build_rpc_frame(-2, &nonce, RpcChecksumMode::Crc32))
        .await
        .unwrap();
    let split = |ip: IpAddr| match ip {
        IpAddr::V4(ip) => {
            let mut octets = ip.octets();
            octets.reverse();
            (Some(octets), None)
        }
        IpAddr::V6(ip) => (None, Some(ip.octets())),
    };
    let (client_v4, client_v6) = split(client_ip);
    let (server_v4, server_v6) = split(server_ip);
    let client_ip = client_v4.unwrap_or([0; 4]);
    let server_ip = server_v4.unwrap_or([0; 4]);
    let (read_key, read_iv) = derive_middleproxy_keys(
        &server_nonce,
        &client_nonce,
        &timestamp.to_le_bytes(),
        server_v4.as_ref().map(|ip| ip.as_slice()),
        &client_port.to_le_bytes(),
        b"CLIENT",
        client_v4.as_ref().map(|ip| ip.as_slice()),
        &server_port.to_le_bytes(),
        &[1u8; 32],
        client_v6.as_ref(),
        server_v6.as_ref(),
    );
    let (write_key, write_iv) = derive_middleproxy_keys(
        &server_nonce,
        &client_nonce,
        &timestamp.to_le_bytes(),
        server_v4.as_ref().map(|ip| ip.as_slice()),
        &client_port.to_le_bytes(),
        b"SERVER",
        client_v4.as_ref().map(|ip| ip.as_slice()),
        &server_port.to_le_bytes(),
        &[1u8; 32],
        client_v6.as_ref(),
        server_v6.as_ref(),
    );
    let mut encrypted = [0u8; 48];
    stream.read_exact(&mut encrypted).await.unwrap();
    cbc_decrypt_inplace(&read_key, &read_iv, &mut encrypted).unwrap();
    assert_eq!(u32::from_le_bytes(encrypted[..4].try_into().unwrap()), 44);
    assert_eq!(i32::from_le_bytes(encrypted[4..8].try_into().unwrap()), -1);
    assert_eq!(
        u32::from_le_bytes(encrypted[40..44].try_into().unwrap()),
        rpc_crc(RpcChecksumMode::Crc32, &encrypted[..40])
    );
    parse_handshake_flags(&encrypted[8..40]).unwrap();
    assert_eq!(&encrypted[16..20], &client_ip);
    assert_eq!(
        u16::from_le_bytes(encrypted[20..22].try_into().unwrap()),
        client_port
    );
    assert_eq!(
        u16::from_le_bytes(encrypted[32..34].try_into().unwrap()),
        server_port
    );
    let reply = build_handshake_payload(server_ip, server_port, client_ip, client_port, 0);
    let (encrypted, _) = cbc_encrypt_padded(
        &write_key,
        &write_iv,
        &build_rpc_frame(-1, &reply, RpcChecksumMode::Crc32),
    )
    .unwrap();
    stream.write_all(&encrypted).await.unwrap();
    Some(stream)
}

#[tokio::test]
async fn ipv6_socks_transport_to_ipv4_me_strict() {
    check_socks_handshake("[::1]:0", V4_ME, V4_BND, MeSocksKdfPolicy::Strict, true).await;
}

#[tokio::test]
async fn ipv6_socks_transport_to_ipv4_me_compat() {
    check_socks_handshake("[::1]:0", V4_ME, V4_BND, MeSocksKdfPolicy::Compat, true).await;
}

#[tokio::test]
async fn ipv4_socks_transport_to_ipv6_me_strict() {
    check_socks_handshake("127.0.0.1:0", V6_ME, V6_BND, MeSocksKdfPolicy::Strict, true).await;
}

#[tokio::test]
async fn ipv4_socks_transport_to_ipv6_me_compat() {
    check_socks_handshake("127.0.0.1:0", V6_ME, V6_BND, MeSocksKdfPolicy::Compat, true).await;
}

#[tokio::test]
async fn same_family_socks_keeps_bnd_ip_and_port_over_configured_nat() {
    for policy in [MeSocksKdfPolicy::Strict, MeSocksKdfPolicy::Compat] {
        check_socks_handshake("127.0.0.1:0", V4_ME, V4_BND, policy, true).await;
        check_socks_handshake("[::1]:0", V6_ME, V6_BND, policy, true).await;
    }
}

#[tokio::test]
async fn strict_socks_rejects_wrong_me_family_and_incomplete_bnd() {
    for (transport, target, bound) in [
        ("[::1]:0", V4_ME, V6_BND),
        ("127.0.0.1:0", V6_ME, V4_BND),
        ("[::1]:0", V4_ME, "10.0.0.1:45678"),
        ("[::1]:0", V4_ME, "0.0.0.0:45678"),
        ("[::1]:0", V4_ME, "91.108.56.1:0"),
        ("127.0.0.1:0", V6_ME, "[::]:45678"),
        ("127.0.0.1:0", V6_ME, "[2606:4700:4700::1111]:0"),
    ] {
        check_socks_handshake(transport, target, bound, MeSocksKdfPolicy::Strict, false).await;
    }
}
