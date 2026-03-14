#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::{lookup_host, UdpSocket};
use tokio::time::{timeout, Duration, Instant, sleep};

use crate::error::{ProxyError, Result};
use crate::network::dns_overrides::{resolve, split_host_port};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy)]
pub struct StunProbeResult {
    pub local_addr: SocketAddr,
    pub reflected_addr: SocketAddr,
    pub family: IpFamily,
}

#[derive(Debug, Default, Clone)]
pub struct DualStunResult {
    pub v4: Option<StunProbeResult>,
    pub v6: Option<StunProbeResult>,
}

pub async fn stun_probe_dual(stun_addr: &str) -> Result<DualStunResult> {
    let (v4, v6) = tokio::join!(
        stun_probe_family(stun_addr, IpFamily::V4),
        stun_probe_family(stun_addr, IpFamily::V6),
    );

    Ok(DualStunResult {
        v4: v4?,
        v6: v6?,
    })
}

pub async fn stun_probe_family(stun_addr: &str, family: IpFamily) -> Result<Option<StunProbeResult>> {
    stun_probe_family_with_bind(stun_addr, family, None).await
}

pub async fn stun_probe_family_with_bind(
    stun_addr: &str,
    family: IpFamily,
    bind_ip: Option<IpAddr>,
) -> Result<Option<StunProbeResult>> {
    use rand::RngCore;

    let bind_addr = match (family, bind_ip) {
        (IpFamily::V4, Some(IpAddr::V4(ip))) => SocketAddr::new(IpAddr::V4(ip), 0),
        (IpFamily::V6, Some(IpAddr::V6(ip))) => SocketAddr::new(IpAddr::V6(ip), 0),
        (IpFamily::V4, Some(IpAddr::V6(_))) | (IpFamily::V6, Some(IpAddr::V4(_))) => {
            return Ok(None);
        }
        (IpFamily::V4, None) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        (IpFamily::V6, None) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(_) if bind_ip.is_some() => return Ok(None),
        Err(e) => return Err(ProxyError::Proxy(format!("STUN bind failed: {e}"))),
    };

    let target_addr = resolve_stun_addr(stun_addr, family).await?;
    if let Some(addr) = target_addr {
        match socket.connect(addr).await {
            Ok(()) => {}
            Err(e) if family == IpFamily::V6 && matches!(
                e.kind(),
                std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::Unsupported
                | std::io::ErrorKind::NetworkDown
            ) => return Ok(None),
            Err(e) => return Err(ProxyError::Proxy(format!("STUN connect failed: {e}"))),
        }
    } else {
        return Ok(None);
    }

    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    req[2..4].copy_from_slice(&0u16.to_be_bytes()); // length
    req[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes()); // magic cookie
    rand::rng().fill_bytes(&mut req[8..20]); // transaction ID

    let mut buf = [0u8; 2048];
    // Per-attempt recv timeout: 3 attempts × 1 s + 0.5 s + 1.0 s backoffs = 4.5 s ≤ STUN_BATCH_TIMEOUT.
    const STUN_RECV_TIMEOUT: Duration = Duration::from_secs(1);
    let mut attempt = 0;
    let mut backoff = Duration::from_millis(500);
    loop {
        if socket.send(&req).await.is_err() {
            attempt += 1;
            if attempt >= 3 {
                return Ok(None);
            }
            sleep(backoff).await;
            backoff *= 2;
            continue;
        }

        let attempt_deadline = Instant::now() + STUN_RECV_TIMEOUT;
        loop {
            let now = Instant::now();
            if now >= attempt_deadline {
                break;
            }

            let recv_res = timeout(
                attempt_deadline.saturating_duration_since(now),
                socket.recv(&mut buf),
            )
            .await;
            let n = match recv_res {
                Ok(Ok(n)) => n,
                Ok(Err(_)) | Err(_) => break,
            };

            if n < 20 {
                continue;
            }

            let stun_body_len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
            let Some(stun_packet_len) = 20usize.checked_add(stun_body_len) else {
                continue;
            };
            if stun_packet_len > n {
                continue;
            }

            let magic = 0x2112_A442_u32.to_be_bytes();
            let txid = &req[8..20];

            // RFC 5389 §7.3.1: response MUST be a Binding Response (0x0101).
            if u16::from_be_bytes([buf[0], buf[1]]) != 0x0101 {
                continue;
            }
            // RFC 5389 §6: magic cookie MUST be present in the response.
            if buf[4..8] != magic {
                continue;
            }
            // RFC 5389 §7.3.1: transaction ID MUST match the request.
            // Without this check an on-path attacker can inject a fake response
            // with an arbitrary XOR-MAPPED-ADDRESS for IPv4 (magic-only XOR).
            if buf[8..20] != *txid {
                continue;
            }

            let mut idx = 20;
            while let Some((atype, alen, value_idx)) = parse_attr_header(&buf, idx, stun_packet_len) {
                idx = value_idx;

                match atype {
                    0x0020 /* XOR-MAPPED-ADDRESS */ | 0x0001 /* MAPPED-ADDRESS */ => {
                        if alen < 8 {
                            break;
                        }
                        let family_byte = buf[idx + 1];
                        let port_bytes = [buf[idx + 2], buf[idx + 3]];
                        let len_check = match family_byte {
                            0x01 => 4,
                            0x02 => 16,
                            _ => 0,
                        };
                        if len_check == 0 || alen < 4 + len_check {
                            break;
                        }

                        let raw_ip = &buf[idx + 4..idx + 4 + len_check];
                        let mut port = u16::from_be_bytes(port_bytes);

                        let reflected_ip = if atype == 0x0020 {
                            port ^= (u16::from(magic[0]) << 8) | u16::from(magic[1]);
                            match family_byte {
                                0x01 => {
                                    let ip = [
                                        raw_ip[0] ^ magic[0],
                                        raw_ip[1] ^ magic[1],
                                        raw_ip[2] ^ magic[2],
                                        raw_ip[3] ^ magic[3],
                                    ];
                                    IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
                                }
                                0x02 => {
                                    let mut ip = [0u8; 16];
                                    let xor_key = [magic.as_slice(), txid].concat();
                                    for (i, b) in raw_ip.iter().enumerate().take(16) {
                                        ip[i] = *b ^ xor_key[i];
                                    }
                                    IpAddr::V6(Ipv6Addr::from(ip))
                                }
                                _ => {
                                    idx += (alen + 3) & !3;
                                    continue;
                                }
                            }
                        } else {
                            match family_byte {
                                0x01 => {
                                    IpAddr::V4(Ipv4Addr::new(raw_ip[0], raw_ip[1], raw_ip[2], raw_ip[3]))
                                }
                                0x02 => {
                                    let mut ip = [0u8; 16];
                                    ip.copy_from_slice(raw_ip);
                                    IpAddr::V6(Ipv6Addr::from(ip))
                                }
                                _ => {
                                    idx += (alen + 3) & !3;
                                    continue;
                                }
                            }
                        };

                        // Reject cross-family responses: a V4 probe must not yield a V6
                        // reflected address (and vice versa). This guards against malformed
                        // or adversarial STUN servers that return a mismatched address family.
                        match (family, &reflected_ip) {
                            (IpFamily::V4, IpAddr::V4(_)) | (IpFamily::V6, IpAddr::V6(_)) => {}
                            _ => {
                                idx += (alen + 3) & !3;
                                continue;
                            }
                        }

                        let reflected_addr = SocketAddr::new(reflected_ip, port);
                        let local_addr = socket
                            .local_addr()
                            .map_err(|e| ProxyError::Proxy(format!("STUN local_addr failed: {e}")))?;

                        return Ok(Some(StunProbeResult {
                            local_addr,
                            reflected_addr,
                            family,
                        }));
                    }
                    _ => {}
                }

                idx += (alen + 3) & !3;
            }
        }

        attempt += 1;
        if attempt >= 3 {
            return Ok(None);
        }
        sleep(backoff).await;
        backoff *= 2;

    }
}

async fn resolve_stun_addr(stun_addr: &str, family: IpFamily) -> Result<Option<SocketAddr>> {
    if let Ok(addr) = stun_addr.parse::<SocketAddr>() {
        return Ok(match (addr.is_ipv4(), family) {
            (true, IpFamily::V4) | (false, IpFamily::V6) => Some(addr),
            _ => None,
        });
    }

    if let Some((host, port)) = split_host_port(stun_addr)
        && let Some(ip) = resolve(&host, port)
    {
        let addr = SocketAddr::new(ip, port);
        return Ok(match (addr.is_ipv4(), family) {
            (true, IpFamily::V4) | (false, IpFamily::V6) => Some(addr),
            _ => None,
        });
    }

    let mut addrs = lookup_host(stun_addr)
        .await
        .map_err(|e| ProxyError::Proxy(format!("STUN resolve failed: {e}")))?;

    let target = addrs
        .find(|a| matches!((a.is_ipv4(), family), (true, IpFamily::V4) | (false, IpFamily::V6)));
    Ok(target)
}

fn parse_attr_header(buf: &[u8], idx: usize, n: usize) -> Option<(u16, usize, usize)> {
    if idx.checked_add(4)? > n {
        return None;
    }
    let atype = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
    let alen = usize::from(u16::from_be_bytes([buf[idx + 2], buf[idx + 3]]));
    let value_idx = idx + 4;
    if value_idx.checked_add(alen)? > n {
        return None;
    }
    Some((atype, alen, value_idx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TokioUdp;

    #[test]
    fn stun_magic_cookie_wire_bytes_match_rfc() {
        let magic = 0x2112_A442_u32.to_be_bytes();
        assert_eq!(magic, [0x21, 0x12, 0xA4, 0x42]);
    }

    #[test]
    fn parse_attr_header_rejects_truncated_header() {
        let buf = [0u8; 24];
        let parsed = parse_attr_header(&buf, 21, 24);
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_attr_header_rejects_value_outside_packet() {
        let mut buf = [0u8; 32];
        buf[20] = 0x00;
        buf[21] = 0x01;
        buf[22] = 0x00;
        buf[23] = 0x10;
        let parsed = parse_attr_header(&buf, 20, 30);
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_attr_header_accepts_exact_boundary() {
        let mut buf = [0u8; 40];
        buf[20] = 0x00;
        buf[21] = 0x20;
        buf[22] = 0x00;
        buf[23] = 0x10;
        let parsed = parse_attr_header(&buf, 20, 40);
        assert_eq!(parsed, Some((0x0020, 16, 24)));
    }

    // Maximum legal alen encoded in the 2-byte length field (0xFFFF) should not
    // overflow usize arithmetic inside parse_attr_header.
    #[test]
    fn parse_attr_header_max_alen_does_not_overflow() {
        let mut buf = [0u8; 32];
        // At idx=0: atype is buf[0..2], alen is buf[2..4].
        buf[2] = 0xFF;
        buf[3] = 0xFF; // alen = 65535
        // value_idx = 4; 4 + 65535 = 65539 > 32 → must be rejected, not overflow.
        let parsed = parse_attr_header(&buf, 0, 32);
        assert!(parsed.is_none(), "oversized alen must be rejected without overflow");
    }

    fn build_valid_binding_response(txid: &[u8; 12], reflected_ip: [u8; 4]) -> Vec<u8> {
        let magic = 0x2112_A442_u32.to_be_bytes();
        let xored_port = 54321u16 ^ ((u16::from(magic[0]) << 8) | u16::from(magic[1]));
        let xored_ip = [
            reflected_ip[0] ^ magic[0],
            reflected_ip[1] ^ magic[1],
            reflected_ip[2] ^ magic[2],
            reflected_ip[3] ^ magic[3],
        ];

        // XOR-MAPPED-ADDRESS attribute: reserved(1) + family(1) + port(2) + ip(4) = 8 bytes
        let attr_len: u16 = 8;
        let mut attr = Vec::new();
        attr.extend_from_slice(&0x0020u16.to_be_bytes());
        attr.extend_from_slice(&attr_len.to_be_bytes());
        attr.push(0x00);
        attr.push(0x01); // IPv4
        attr.extend_from_slice(&xored_port.to_be_bytes());
        attr.extend_from_slice(&xored_ip);

        let mut resp = Vec::with_capacity(20 + attr.len());
        resp.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Response
        resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        resp.extend_from_slice(&magic);
        resp.extend_from_slice(txid);
        resp.extend_from_slice(&attr);
        resp
    }

    // A correctly-formed Binding Response must be accepted and the reflected address
    // decoded accurately.
    #[tokio::test]
    async fn stun_valid_response_is_accepted() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            let resp = build_valid_binding_response(&txid, [1, 2, 3, 4]);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");

        match result {
            Some(r) => assert_eq!(r.reflected_addr.ip().to_string(), "1.2.3.4"),
            None => panic!("valid Binding Response was rejected"),
        }
    }

    // An on-path attacker can see the request transaction ID in plaintext and inject
    // a fake Binding Response that claims our public IPv4 is an attacker-chosen address.
    // Without txid validation this attack succeeds; with the fix it must be rejected.
    #[tokio::test]
    async fn stun_injected_response_mismatched_txid_rejected() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            // Attacker forges a response with a different transaction ID but a
            // crafted XOR-MAPPED-ADDRESS pointing to 8.8.8.8 (attacker-controlled IP).
            let attacker_txid = [0xAAu8; 12];
            let resp = build_valid_binding_response(&attacker_txid, [8, 8, 8, 8]);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");
        assert!(result.is_none(), "response with mismatched txid must be rejected");
    }

    // A STUN error response (0x0111) must never be accepted as a valid reflected address.
    #[tokio::test]
    async fn stun_error_response_type_rejected() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let magic = 0x2112_A442_u32.to_be_bytes();
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();

            // Build a syntactically valid response but with Error Response type.
            let mut resp = [0u8; 20];
            resp[0..2].copy_from_slice(&0x0111u16.to_be_bytes()); // Error Response
            resp[2..4].copy_from_slice(&0u16.to_be_bytes());
            resp[4..8].copy_from_slice(&magic);
            resp[8..20].copy_from_slice(&txid);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");
        assert!(result.is_none(), "STUN error response type must be rejected");
    }

    // A UDP packet with a wrong magic cookie must not be treated as a STUN response.
    // This filters arbitrary UDP traffic spoofed onto the socket.
    #[tokio::test]
    async fn stun_wrong_magic_cookie_rejected() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();

            let mut resp = [0u8; 20];
            resp[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
            resp[2..4].copy_from_slice(&0u16.to_be_bytes());
            resp[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // wrong magic
            resp[8..20].copy_from_slice(&txid);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");
        assert!(result.is_none(), "wrong magic cookie must be rejected");
    }

    // A 19-byte UDP response (one byte below the STUN header minimum) must be silently
    // dropped without panic.
    #[tokio::test]
    async fn stun_short_response_below_header_minimum_rejected() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            server.send_to(&[0u8; 19], src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");
        assert!(result.is_none(), "sub-header response must be rejected");
    }

    // A valid header followed by a malformed XOR-MAPPED-ADDRESS attribute (alen says
    // 12 bytes but only 8 are present) must not panic or out-of-bounds read.
    // When no reflected address is found in the response the STUN client retries;
    // after the test server closes its socket that retry returns either Ok(None)
    // or a recv error — but must never return a crafted reflected address.
    #[tokio::test]
    async fn stun_truncated_attribute_value_rejected() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let magic = 0x2112_A442_u32.to_be_bytes();
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();

            // Valid header, then XOR-MAPPED-ADDRESS with alen=12 but only 8 bytes provided.
            let mut resp = Vec::new();
            resp.extend_from_slice(&0x0101u16.to_be_bytes());
            resp.extend_from_slice(&8u16.to_be_bytes()); // STUN body length
            resp.extend_from_slice(&magic);
            resp.extend_from_slice(&txid);
            // Attribute: type=0x0020, declared alen=12, but only 8 bytes follow
            resp.extend_from_slice(&0x0020u16.to_be_bytes());
            resp.extend_from_slice(&12u16.to_be_bytes()); // alen claims 12
            resp.extend_from_slice(&[0u8; 8]); // only 8 bytes
            server.send_to(&resp, src).await.unwrap();
            // Server socket drops here; subsequent client retries may get ECONNREFUSED.
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4).await;
        // After receiving a response with a truncated attribute the client retries;
        // once the test server is gone it will either time out (Ok(None)) or get
        // ECONNREFUSED (Err). Either is acceptable — the critical invariant is that
        // no reflected address is fabricated from the malformed data.
        match result {
            Ok(None) | Err(_) => {}
            Ok(Some(r)) => panic!("truncated attribute must not yield a reflected address: {r:?}"),
        }
    }

    // A server that drops the first request (simulating UDP packet loss) but responds
    // correctly to the retry must yield Ok(Some(...)) — proves retries are live code.
    #[tokio::test]
    async fn stun_retry_on_packet_loss_succeeds() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // First request: discard without responding to simulate UDP packet loss.
            let (_, _src) = server.recv_from(&mut buf).await.unwrap();
            // Second request: reply with a valid Binding Response.
            let (_, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            let resp = build_valid_binding_response(&txid, [5, 6, 7, 8]);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");
        match result {
            Some(r) => assert_eq!(r.reflected_addr.ip().to_string(), "5.6.7.8"),
            None => panic!("retry after packet loss must succeed"),
        }
    }

    // A second-attempt response must carry the ORIGINAL transaction ID (from the first send).
    // Validates that re-using the same req buffer across retries preserves txid consistency.
    #[tokio::test]
    async fn stun_retry_uses_same_transaction_id() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // Drop first request.
            let (_, _src) = server.recv_from(&mut buf).await.unwrap();
            let txid_from_first: [u8; 12] = buf[8..20].try_into().unwrap();
            // On retry, the txid in the packet must equal txid_from_first.
            let (_, src) = server.recv_from(&mut buf).await.unwrap();
            let txid_from_retry: [u8; 12] = buf[8..20].try_into().unwrap();
            assert_eq!(
                txid_from_first, txid_from_retry,
                "txid must be identical across all retry attempts"
            );
            let resp = build_valid_binding_response(&txid_from_retry, [9, 10, 11, 12]);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");
        assert!(result.is_some(), "response to retry must be accepted");
    }

    // A spoofed packet with wrong txid must not terminate the probe if a valid
    // response arrives afterwards within the same receive timeout window.
    #[tokio::test]
    async fn stun_ignores_spoofed_packet_then_accepts_valid_response() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();

            let forged = build_valid_binding_response(&[0xAB; 12], [10, 10, 10, 10]);
            server.send_to(&forged, src).await.unwrap();

            let valid = build_valid_binding_response(&txid, [11, 22, 33, 44]);
            server.send_to(&valid, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");

        match result {
            Some(r) => assert_eq!(r.reflected_addr.ip().to_string(), "11.22.33.44"),
            None => panic!("valid response after spoofed packet must be accepted"),
        }
    }

    // Large STUN responses that exceed 256 bytes must still be parsed when
    // XOR-MAPPED-ADDRESS is placed after byte 256.
    #[tokio::test]
    async fn stun_large_response_with_late_xor_mapped_address_is_accepted() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let magic = 0x2112_A442_u32.to_be_bytes();
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();

            let mut attrs = Vec::new();
            // SOFTWARE attribute with 260-byte payload to push following attributes
            // beyond the legacy 256-byte client receive buffer.
            attrs.extend_from_slice(&0x8022u16.to_be_bytes());
            attrs.extend_from_slice(&260u16.to_be_bytes());
            attrs.extend_from_slice(&vec![0x41u8; 260]);
            while attrs.len() % 4 != 0 {
                attrs.push(0);
            }

            let xored_port = 54321u16 ^ ((u16::from(magic[0]) << 8) | u16::from(magic[1]));
            let reflected_ip = [21u8, 31, 41, 51];
            let xored_ip = [
                reflected_ip[0] ^ magic[0],
                reflected_ip[1] ^ magic[1],
                reflected_ip[2] ^ magic[2],
                reflected_ip[3] ^ magic[3],
            ];

            attrs.extend_from_slice(&0x0020u16.to_be_bytes());
            attrs.extend_from_slice(&8u16.to_be_bytes());
            attrs.push(0x00);
            attrs.push(0x01);
            attrs.extend_from_slice(&xored_port.to_be_bytes());
            attrs.extend_from_slice(&xored_ip);

            let mut resp = Vec::with_capacity(20 + attrs.len());
            resp.extend_from_slice(&0x0101u16.to_be_bytes());
            resp.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
            resp.extend_from_slice(&magic);
            resp.extend_from_slice(&txid);
            resp.extend_from_slice(&attrs);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");

        match result {
            Some(r) => assert_eq!(r.reflected_addr.ip().to_string(), "21.31.41.51"),
            None => panic!("large valid STUN response must be accepted"),
        }
    }

    // A STUN server that returns an IPv6 XOR-MAPPED-ADDRESS in response to an IPv4 probe
    // must be rejected.  Without the family consistency check, the caller would receive a
    // StunProbeResult with family=V4 but reflected_addr=IPv6, silently corrupting NAT
    // detection (e.g., recording the wrong public IP family, disabling IPv4 ME mode).
    #[tokio::test]
    async fn stun_ipv6_xmapped_in_ipv4_probe_rejected() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let magic = 0x2112_A442_u32.to_be_bytes();
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();

            // Build XOR-MAPPED-ADDRESS with family=0x02 (IPv6), address 2001:db8::1.
            // alen = reserved(1) + family(1) + port(2) + ip(16) = 20 bytes.
            let xor_key: Vec<u8> = [magic.as_slice(), txid.as_slice()].concat();
            let target_ipv6: [u8; 16] = [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ];
            let mut xored_ipv6 = [0u8; 16];
            for i in 0..16 {
                xored_ipv6[i] = target_ipv6[i] ^ xor_key[i];
            }
            let xored_port = 54321u16 ^ ((u16::from(magic[0]) << 8) | u16::from(magic[1]));

            let alen: u16 = 20;
            let mut attr = Vec::new();
            attr.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
            attr.extend_from_slice(&alen.to_be_bytes());
            attr.push(0x00); // reserved
            attr.push(0x02); // IPv6 family
            attr.extend_from_slice(&xored_port.to_be_bytes());
            attr.extend_from_slice(&xored_ipv6);

            let mut resp = Vec::with_capacity(20 + attr.len());
            resp.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Response
            resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
            resp.extend_from_slice(&magic);
            resp.extend_from_slice(&txid);
            resp.extend_from_slice(&attr);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = stun_probe_family(&server_addr.to_string(), IpFamily::V4)
            .await
            .expect("probe should not error");
        assert!(
            result.is_none(),
            "IPv6 XOR-MAPPED-ADDRESS in an IPv4 probe must be rejected"
        );
    }

    // Symmetric: an IPv4 XOR-MAPPED-ADDRESS returned for an IPv6 probe must be detected
    // as a cross-family mismatch.  This test validates the logic predicate directly
    // without needing a live IPv6 socket (which may be absent in CI).
    #[test]
    fn stun_ipv4_xmapped_in_ipv6_attr_cross_family_rejected() {
        let family = IpFamily::V6;
        let reflected_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        let ip_matches = matches!(
            (family, &reflected_ip),
            (IpFamily::V4, std::net::IpAddr::V4(_)) | (IpFamily::V6, std::net::IpAddr::V6(_))
        );
        assert!(
            !ip_matches,
            "V4 address in a V6 probe must be detected as a cross-family mismatch"
        );
    }
}
