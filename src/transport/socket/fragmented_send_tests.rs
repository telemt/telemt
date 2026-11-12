use super::*;

use crate::transport::socket::{ListenOptions, create_listener};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

const HANDSHAKE_MSS: usize = 92;
const BULK_MSS: u16 = 1400;
const RESPONSE_LEN: usize = 4096;

fn tls_record(record_type: u8, body_len: usize, fill: u8) -> Vec<u8> {
    let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + body_len);
    record.push(record_type);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(body_len as u16).to_be_bytes());
    record.resize(TLS_RECORD_HEADER_LEN + body_len, fill);
    record
}

/// ServerHello record (`hello_body_len` bytes of body) followed by
/// ApplicationData up to [`RESPONSE_LEN`] bytes.
fn initial_response(hello_body_len: usize) -> Vec<u8> {
    let mut response = tls_record(TLS_RECORD_HANDSHAKE, hello_body_len, 0x5A);
    let rest = RESPONSE_LEN - response.len() - TLS_RECORD_HEADER_LEN;
    response.extend_from_slice(&tls_record(0x17, rest, 0xA5));
    assert_eq!(response.len(), RESPONSE_LEN);
    response
}

#[test]
fn full_prefix_covers_whole_response() {
    let response = initial_response(122);
    assert_eq!(
        chunked_prefix_len(&response, ClientMssPrefix::Full),
        RESPONSE_LEN
    );
}

#[test]
fn server_hello_prefix_ends_at_first_record() {
    let response = initial_response(122);
    assert_eq!(
        chunked_prefix_len(&response, ClientMssPrefix::ServerHello),
        127
    );
}

#[test]
fn server_hello_prefix_covers_hybrid_key_share_record() {
    let response = initial_response(1211);
    assert_eq!(
        chunked_prefix_len(&response, ClientMssPrefix::ServerHello),
        1216
    );
}

#[test]
fn server_hello_prefix_is_capped() {
    let mut response = tls_record(TLS_RECORD_HANDSHAKE, 3000, 0x5A);
    response.extend_from_slice(&tls_record(0x17, 100, 0xA5));
    assert_eq!(
        chunked_prefix_len(&response, ClientMssPrefix::ServerHello),
        SERVER_HELLO_PREFIX_MAX
    );
}

#[test]
fn server_hello_prefix_falls_back_to_full_on_unexpected_input() {
    let not_handshake = tls_record(0x17, 200, 0xA5);
    assert_eq!(
        chunked_prefix_len(&not_handshake, ClientMssPrefix::ServerHello),
        not_handshake.len()
    );

    let mut truncated = tls_record(TLS_RECORD_HANDSHAKE, 200, 0x5A);
    truncated.truncate(100);
    assert_eq!(
        chunked_prefix_len(&truncated, ClientMssPrefix::ServerHello),
        100
    );

    let short = [TLS_RECORD_HANDSHAKE, 0x03, 0x03];
    assert_eq!(chunked_prefix_len(&short, ClientMssPrefix::ServerHello), 3);
    assert_eq!(chunked_prefix_len(&[], ClientMssPrefix::ServerHello), 0);
}

#[test]
fn byte_prefix_is_bounded_by_response_len() {
    let response = initial_response(122);
    assert_eq!(
        chunked_prefix_len(&response, ClientMssPrefix::Bytes(200)),
        200
    );
    assert_eq!(
        chunked_prefix_len(&response, ClientMssPrefix::Bytes(u16::MAX)),
        RESPONSE_LEN
    );
}

#[test]
fn chunk_payload_subtracts_negotiated_timestamps() {
    assert_eq!(chunk_payload_len(92, TCPI_OPT_TIMESTAMPS, 1388), 80);
    assert_eq!(chunk_payload_len(92, 0, 1400), 92);
}

#[test]
fn chunk_payload_never_exceeds_send_mss() {
    assert_eq!(chunk_payload_len(256, 0, 100), 100);
    assert_eq!(chunk_payload_len(256, TCPI_OPT_TIMESTAMPS, 100), 100);
    // An unknown send MSS leaves the requested value.
    assert_eq!(chunk_payload_len(92, 0, 0), 92);
}

#[test]
fn chunk_payload_is_never_zero() {
    assert_eq!(chunk_payload_len(8, TCPI_OPT_TIMESTAMPS, 1388), 1);
    assert_eq!(chunk_payload_len(1, 0, 0), 1);
}

/// Accepted server socket on a listener at the bulk MSS, plus its client.
async fn bulk_pair() -> Option<(TcpStream, TcpStream)> {
    let options = ListenOptions {
        reuse_port: false,
        client_mss: Some(BULK_MSS),
        ..Default::default()
    };
    let socket = match create_listener("127.0.0.1:0".parse().unwrap(), &options) {
        Ok(socket) => socket,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("create_listener failed: {error}"),
    };
    let listener = TcpListener::from_std(socket.into()).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    Some((server, client))
}

/// Sends `response` and returns the bytes the client received.
async fn send_and_receive(
    server: &TcpStream,
    client: TcpStream,
    response: &[u8],
    prefix: ClientMssPrefix,
) -> Vec<u8> {
    let expected_len = response.len();
    let reader = tokio::spawn(async move {
        let mut client = client;
        let mut received = vec![0; expected_len];
        client.read_exact(&mut received).await.unwrap();
        received
    });
    send_tcp_fragmented_fd(server.as_raw_fd(), response, HANDSHAKE_MSS, prefix)
        .await
        .unwrap();
    reader.await.unwrap()
}

#[cfg(target_env = "gnu")]
async fn wait_all_acked(server: &TcpStream) -> libc::tcp_info {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let info = tcp_info(server.as_raw_fd()).unwrap();
            if info.tcpi_notsent_bytes == 0 && info.tcpi_unacked == 0 {
                return info;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("sent data was not acknowledged")
}

/// Counts data segments with `tcpi_data_segs_out`; needs no privileges.
#[cfg(target_env = "gnu")]
async fn data_segments_for(prefix: ClientMssPrefix, response: &[u8]) -> Option<(u32, usize, u32)> {
    let (server, client) = bulk_pair().await?;
    let before = wait_all_acked(&server).await;
    let chunk = chunk_payload_len(HANDSHAKE_MSS, before.tcpi_options, before.tcpi_snd_mss);
    let received = send_and_receive(&server, client, response, prefix).await;
    assert_eq!(
        received, response,
        "chunked send must preserve the byte stream"
    );
    let after = wait_all_acked(&server).await;
    Some((
        after.tcpi_data_segs_out - before.tcpi_data_segs_out,
        chunk,
        after.tcpi_snd_mss,
    ))
}

#[cfg(target_env = "gnu")]
#[tokio::test]
async fn server_hello_prefix_chunks_only_first_record() {
    let response = initial_response(122);
    let prefix_len = chunked_prefix_len(&response, ClientMssPrefix::ServerHello);
    let Some((segments, chunk, snd_mss)) =
        data_segments_for(ClientMssPrefix::ServerHello, &response).await
    else {
        return;
    };
    let head = prefix_len.div_ceil(chunk) as u32;
    let tail = (RESPONSE_LEN - prefix_len).div_ceil(snd_mss as usize) as u32;
    assert!(snd_mss >= 1000, "listener must run at the bulk MSS");
    assert!(
        segments > head,
        "ServerHello must leave in chunks of {chunk} bytes: {segments} segments"
    );
    assert!(
        segments <= head + tail + 1,
        "the rest must leave at the bulk MSS {snd_mss}: {segments} segments, want <= {}",
        head + tail + 1
    );
}

#[cfg(target_env = "gnu")]
#[tokio::test]
async fn full_prefix_chunks_whole_response() {
    let response = initial_response(122);
    let Some((segments, chunk, _)) = data_segments_for(ClientMssPrefix::Full, &response).await
    else {
        return;
    };
    let want = RESPONSE_LEN.div_ceil(chunk) as u32;
    assert!(
        segments >= want,
        "whole response must leave in chunks of {chunk} bytes: {segments} segments, want >= {want}"
    );
}

/// Outgoing TCP payload sizes from `port` captured on the loopback interface.
struct LoopbackCapture {
    fd: std::os::fd::OwnedFd,
}

impl LoopbackCapture {
    /// Opens an AF_PACKET socket on `lo`; `None` without CAP_NET_RAW.
    fn open() -> Option<Self> {
        use std::os::fd::FromRawFd;

        // Outgoing packets reach only ETH_P_ALL taps.
        let protocol = (libc::ETH_P_ALL as u16).to_be();
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                i32::from(protocol),
            )
        };
        if raw < 0 {
            let error = Error::last_os_error();
            assert!(
                matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)),
                "AF_PACKET socket failed: {error}"
            );
            return None;
        }
        // SAFETY: raw is a freshly created descriptor owned by nobody else.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(ifindex, 0, "loopback interface is missing");
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = protocol;
        address.sll_ifindex = ifindex as i32;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &address as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "AF_PACKET bind failed: {}", Error::last_os_error());
        Some(Self { fd })
    }

    /// Drains captured packets and returns TCP payload sizes sent from `port`.
    fn payloads_from(&self, port: u16) -> Vec<usize> {
        let mut payloads = Vec::new();
        let mut packet = vec![0_u8; 65_536];
        loop {
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut address_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let received = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    packet.as_mut_ptr().cast::<libc::c_void>(),
                    packet.len(),
                    0,
                    &mut address as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut address_len,
                )
            };
            if received < 0 {
                let error = Error::last_os_error();
                assert_eq!(error.kind(), ErrorKind::WouldBlock, "recvfrom: {error}");
                return payloads;
            }
            // Loopback shows every packet twice; keep the outgoing copy.
            if address.sll_pkttype != libc::PACKET_OUTGOING {
                continue;
            }
            let ip = &packet[..received as usize];
            if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != libc::IPPROTO_TCP as u8 {
                continue;
            }
            let ip_header_len = usize::from(ip[0] & 0x0F) * 4;
            let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            let tcp = &ip[ip_header_len..];
            if u16::from_be_bytes([tcp[0], tcp[1]]) != port {
                continue;
            }
            let tcp_header_len = usize::from(tcp[12] >> 4) * 4;
            let payload = total_len - ip_header_len - tcp_header_len;
            if payload > 0 {
                payloads.push(payload);
            }
        }
    }
}

/// Checks segment sizes on the wire. Skipped without CAP_NET_RAW; on `lo` the
/// bulk part may appear as one GSO packet, which is larger still.
#[tokio::test]
async fn server_hello_prefix_wire_segments() {
    let Some(capture) = LoopbackCapture::open() else {
        return;
    };
    let Some((server, client)) = bulk_pair().await else {
        return;
    };
    let port = server.local_addr().unwrap().port();
    let info = tcp_info(server.as_raw_fd()).unwrap();
    let chunk = chunk_payload_len(HANDSHAKE_MSS, info.tcpi_options, info.tcpi_snd_mss);
    let response = initial_response(122);
    let prefix_len = chunked_prefix_len(&response, ClientMssPrefix::ServerHello);

    let received = send_and_receive(&server, client, &response, ClientMssPrefix::ServerHello).await;
    assert_eq!(received, response);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let payloads = capture.payloads_from(port);
    assert_eq!(
        payloads.iter().sum::<usize>(),
        RESPONSE_LEN,
        "capture must see the whole response once: {payloads:?}"
    );
    let mut offset = 0;
    let mut head_segments = 0;
    for payload in &payloads {
        if offset < prefix_len {
            assert!(
                *payload <= chunk,
                "prefix segment of {payload} bytes exceeds {chunk}: {payloads:?}"
            );
            head_segments += 1;
        } else {
            assert!(
                *payload > HANDSHAKE_MSS,
                "segment of {payload} bytes after the prefix is not bulk: {payloads:?}"
            );
        }
        offset += payload;
    }
    assert_eq!(head_segments, prefix_len.div_ceil(chunk), "{payloads:?}");
    assert!(
        payloads.len() > head_segments,
        "the rest must follow the prefix: {payloads:?}"
    );
}
