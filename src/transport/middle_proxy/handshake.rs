use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use socket2::{SockRef, TcpKeepalive};
#[cfg(target_os = "linux")]
use libc;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::raw::c_int;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::crypto::{SecureRandom, build_middleproxy_prekey, derive_middleproxy_keys, sha256};
use crate::error::{ProxyError, Result};
use crate::network::IpFamily;
use crate::protocol::constants::{
    ME_CONNECT_TIMEOUT_SECS, ME_HANDSHAKE_TIMEOUT_SECS, RPC_CRYPTO_AES_U32, RPC_HANDSHAKE_ERROR_U32,
    RPC_HANDSHAKE_U32, RPC_PING_U32, RPC_PONG_U32, RPC_NONCE_U32,
};

use super::codec::{
    build_handshake_payload, build_nonce_payload, build_rpc_frame, cbc_decrypt_inplace,
    cbc_encrypt_padded, parse_nonce_payload, read_rpc_frame_plaintext,
};
use super::wire::{extract_ip_material, IpMaterial};
use super::MePool;

/// Result of a successful ME handshake with timings.
pub(crate) struct HandshakeOutput {
    pub rd: ReadHalf<TcpStream>,
    pub wr: WriteHalf<TcpStream>,
    pub read_key: [u8; 32],
    pub read_iv: [u8; 16],
    pub write_key: [u8; 32],
    pub write_iv: [u8; 16],
    pub handshake_ms: f64,
}

impl MePool {
    /// TCP connect with timeout + return RTT in milliseconds.
    pub(crate) async fn connect_tcp(&self, addr: SocketAddr) -> Result<(TcpStream, f64)> {
        let start = Instant::now();
        let stream = timeout(Duration::from_secs(ME_CONNECT_TIMEOUT_SECS), TcpStream::connect(addr))
            .await
            .map_err(|_| ProxyError::ConnectionTimeout { addr: addr.to_string() })??;
        let connect_ms = start.elapsed().as_secs_f64() * 1000.0;
        stream.set_nodelay(true).ok();
        if let Err(e) = Self::configure_keepalive(&stream) {
            warn!(error = %e, "ME keepalive setup failed");
        }
        #[cfg(target_os = "linux")]
        if let Err(e) = Self::configure_user_timeout(stream.as_raw_fd()) {
            warn!(error = %e, "ME TCP_USER_TIMEOUT setup failed");
        }
        Ok((stream, connect_ms))
    }

    fn configure_keepalive(stream: &TcpStream) -> std::io::Result<()> {
        let sock = SockRef::from(stream);
        let ka = TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10))
            .with_retries(3);
        sock.set_tcp_keepalive(&ka)?;
        sock.set_keepalive(true)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn configure_user_timeout(fd: RawFd) -> std::io::Result<()> {
        let timeout_ms: c_int = 30_000;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &timeout_ms as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout_ms) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Perform full ME RPC handshake on an established TCP stream.
    /// Returns cipher keys/ivs and split halves; does not register writer.
    pub(crate) async fn handshake_only(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        rng: &SecureRandom,
    ) -> Result<HandshakeOutput> {
        let hs_start = Instant::now();

        let local_addr = stream.local_addr().map_err(ProxyError::Io)?;
        let peer_addr = stream.peer_addr().map_err(ProxyError::Io)?;

        let _ = self.maybe_detect_nat_ip(local_addr.ip()).await;
        let family = if local_addr.ip().is_ipv4() {
            IpFamily::V4
        } else {
            IpFamily::V6
        };
        let reflected = if self.nat_probe {
            self.maybe_reflect_public_addr(family).await
        } else {
            None
        };

        let local_addr_nat = self.translate_our_addr_with_reflection(local_addr, reflected);
        let peer_addr_nat = SocketAddr::new(self.translate_ip_for_nat(peer_addr.ip()), peer_addr.port());
        let (mut rd, mut wr) = tokio::io::split(stream);

        let my_nonce: [u8; 16] = rng.bytes(16).try_into().unwrap();
        let crypto_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let ks = self.key_selector().await;
        let nonce_payload = build_nonce_payload(ks, crypto_ts, &my_nonce);
        let nonce_frame = build_rpc_frame(-2, &nonce_payload);
        let dump = hex_dump(&nonce_frame[..nonce_frame.len().min(44)]);
        info!(
            key_selector = format_args!("0x{ks:08x}"),
            crypto_ts,
            frame_len = nonce_frame.len(),
            nonce_frame_hex = %dump,
            "Sending ME nonce frame"
        );
        wr.write_all(&nonce_frame).await.map_err(ProxyError::Io)?;
        wr.flush().await.map_err(ProxyError::Io)?;

        let (srv_seq, srv_nonce_payload) = timeout(
            Duration::from_secs(ME_HANDSHAKE_TIMEOUT_SECS),
            read_rpc_frame_plaintext(&mut rd),
        )
        .await
        .map_err(|_| ProxyError::TgHandshakeTimeout)??;

        if srv_seq != -2 {
            return Err(ProxyError::InvalidHandshake(format!("Expected seq=-2, got {srv_seq}")));
        }

        let (srv_key_select, schema, srv_ts, srv_nonce) = parse_nonce_payload(&srv_nonce_payload)?;
        if schema != RPC_CRYPTO_AES_U32 {
            warn!(schema = format_args!("0x{schema:08x}"), "Unsupported ME crypto schema");
            return Err(ProxyError::InvalidHandshake(format!(
                "Unsupported crypto schema: 0x{schema:x}"
            )));
        }

        if srv_key_select != ks {
            return Err(ProxyError::InvalidHandshake(format!(
                "Server key_select 0x{srv_key_select:08x} != client 0x{ks:08x}"
            )));
        }

        let skew = crypto_ts.abs_diff(srv_ts);
        if skew > 30 {
            return Err(ProxyError::InvalidHandshake(format!(
                "nonce crypto_ts skew too large: client={crypto_ts}, server={srv_ts}, skew={skew}s"
            )));
        }

        info!(
            %local_addr,
            %local_addr_nat,
            reflected_ip = reflected.map(|r| r.ip()).as_ref().map(ToString::to_string),
            %peer_addr,
            %peer_addr_nat,
            key_selector = format_args!("0x{ks:08x}"),
            crypto_schema = format_args!("0x{schema:08x}"),
            skew_secs = skew,
            "ME key derivation parameters"
        );

        let ts_bytes = crypto_ts.to_le_bytes();
        let server_port_bytes = peer_addr_nat.port().to_le_bytes();
        let client_port_bytes = local_addr_nat.port().to_le_bytes();

        let server_ip = extract_ip_material(peer_addr_nat);
        let client_ip = extract_ip_material(local_addr_nat);

        let (srv_ip_opt, clt_ip_opt, clt_v6_opt, srv_v6_opt, hs_our_ip, hs_peer_ip) = match (server_ip, client_ip) {
            (IpMaterial::V4(mut srv), IpMaterial::V4(mut clt)) => {
                srv.reverse();
                clt.reverse();
                (Some(srv), Some(clt), None, None, clt, srv)
            }
            (IpMaterial::V6(srv), IpMaterial::V6(clt)) => {
                let zero = [0u8; 4];
                (None, None, Some(clt), Some(srv), zero, zero)
            }
            _ => {
                return Err(ProxyError::InvalidHandshake(
                    "mixed IPv4/IPv6 endpoints are not supported for ME key derivation".to_string(),
                ));
            }
        };

        let diag_level: u8 = std::env::var("ME_DIAG").ok().and_then(|v| v.parse().ok()).unwrap_or(0);

        let secret: Vec<u8> = self.proxy_secret.read().await.clone();

        let prekey_client = build_middleproxy_prekey(
            &srv_nonce,
            &my_nonce,
            &ts_bytes,
            srv_ip_opt.as_ref().map(|x| &x[..]),
            &client_port_bytes,
            b"CLIENT",
            clt_ip_opt.as_ref().map(|x| &x[..]),
            &server_port_bytes,
            &secret,
            clt_v6_opt.as_ref(),
            srv_v6_opt.as_ref(),
        );
        let prekey_server = build_middleproxy_prekey(
            &srv_nonce,
            &my_nonce,
            &ts_bytes,
            srv_ip_opt.as_ref().map(|x| &x[..]),
            &client_port_bytes,
            b"SERVER",
            clt_ip_opt.as_ref().map(|x| &x[..]),
            &server_port_bytes,
            &secret,
            clt_v6_opt.as_ref(),
            srv_v6_opt.as_ref(),
        );

        let (wk, wi) = derive_middleproxy_keys(
            &srv_nonce,
            &my_nonce,
            &ts_bytes,
            srv_ip_opt.as_ref().map(|x| &x[..]),
            &client_port_bytes,
            b"CLIENT",
            clt_ip_opt.as_ref().map(|x| &x[..]),
            &server_port_bytes,
            &secret,
            clt_v6_opt.as_ref(),
            srv_v6_opt.as_ref(),
        );
        let (rk, ri) = derive_middleproxy_keys(
            &srv_nonce,
            &my_nonce,
            &ts_bytes,
            srv_ip_opt.as_ref().map(|x| &x[..]),
            &client_port_bytes,
            b"SERVER",
            clt_ip_opt.as_ref().map(|x| &x[..]),
            &server_port_bytes,
            &secret,
            clt_v6_opt.as_ref(),
            srv_v6_opt.as_ref(),
        );

        let hs_payload = build_handshake_payload(hs_our_ip, local_addr.port(), hs_peer_ip, peer_addr.port());
        let hs_frame = build_rpc_frame(-1, &hs_payload);
        if diag_level >= 1 {
            info!(
                write_key = %hex_dump(&wk),
                write_iv = %hex_dump(&wi),
                read_key = %hex_dump(&rk),
                read_iv = %hex_dump(&ri),
                srv_ip = %srv_ip_opt.map(|ip| hex_dump(&ip)).unwrap_or_default(),
                clt_ip = %clt_ip_opt.map(|ip| hex_dump(&ip)).unwrap_or_default(),
                srv_port = %hex_dump(&server_port_bytes),
                clt_port = %hex_dump(&client_port_bytes),
                crypto_ts = %hex_dump(&ts_bytes),
                nonce_srv = %hex_dump(&srv_nonce),
                nonce_clt = %hex_dump(&my_nonce),
                prekey_sha256_client = %hex_dump(&sha256(&prekey_client)),
                prekey_sha256_server = %hex_dump(&sha256(&prekey_server)),
                hs_plain = %hex_dump(&hs_frame),
                proxy_secret_sha256 = %hex_dump(&sha256(&secret)),
                "ME diag: derived keys and handshake plaintext"
            );
        }
        if diag_level >= 2 {
            info!(
                prekey_client = %hex_dump(&prekey_client),
                prekey_server = %hex_dump(&prekey_server),
                "ME diag: full prekey buffers"
            );
        }

        let (encrypted_hs, mut write_iv) = cbc_encrypt_padded(&wk, &wi, &hs_frame)?;
        if diag_level >= 1 {
            info!(
                hs_cipher = %hex_dump(&encrypted_hs),
                "ME diag: handshake ciphertext"
            );
        }
        wr.write_all(&encrypted_hs).await.map_err(ProxyError::Io)?;
        wr.flush().await.map_err(ProxyError::Io)?;

        let deadline = Instant::now() + Duration::from_secs(ME_HANDSHAKE_TIMEOUT_SECS);
        let mut enc_buf = BytesMut::with_capacity(256);
        let mut dec_buf = BytesMut::with_capacity(256);
        let mut read_iv = ri;
        let mut handshake_ok = false;

        while Instant::now() < deadline && !handshake_ok {
            let remaining = deadline - Instant::now();
            let mut tmp = [0u8; 256];
            let n = match timeout(remaining, rd.read(&mut tmp)).await {
                Ok(Ok(0)) => {
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "ME closed during handshake",
                    )));
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(ProxyError::Io(e)),
                Err(_) => return Err(ProxyError::TgHandshakeTimeout),
            };

            enc_buf.extend_from_slice(&tmp[..n]);

            let blocks = enc_buf.len() / 16 * 16;
            if blocks > 0 {
                let mut chunk = vec![0u8; blocks];
                chunk.copy_from_slice(&enc_buf[..blocks]);
                read_iv = cbc_decrypt_inplace(&rk, &read_iv, &mut chunk)?;
                dec_buf.extend_from_slice(&chunk);
                let _ = enc_buf.split_to(blocks);
            }

            while dec_buf.len() >= 4 {
                let fl = u32::from_le_bytes(dec_buf[0..4].try_into().unwrap()) as usize;

                if fl == 4 {
                    let _ = dec_buf.split_to(4);
                    continue;
                }
                if !(12..=(1 << 24)).contains(&fl) {
                    return Err(ProxyError::InvalidHandshake(format!(
                        "Bad HS response frame len: {fl}"
                    )));
                }
                if dec_buf.len() < fl {
                    break;
                }

                let frame = dec_buf.split_to(fl);
                let pe = fl - 4;
                let ec = u32::from_le_bytes(frame[pe..pe + 4].try_into().unwrap());
                let ac = crate::crypto::crc32(&frame[..pe]);
                if ec != ac {
                    return Err(ProxyError::InvalidHandshake(format!(
                        "HS CRC mismatch: 0x{ec:08x} vs 0x{ac:08x}"
                    )));
                }

                let hs_type = u32::from_le_bytes(frame[8..12].try_into().unwrap());
                if hs_type == RPC_HANDSHAKE_ERROR_U32 {
                    let err_code = if frame.len() >= 16 {
                        i32::from_le_bytes(frame[12..16].try_into().unwrap())
                    } else {
                        -1
                    };
                    return Err(ProxyError::InvalidHandshake(format!(
                        "ME rejected handshake (error={err_code})"
                    )));
                }
                if hs_type != RPC_HANDSHAKE_U32 {
                    return Err(ProxyError::InvalidHandshake(format!(
                        "Expected HANDSHAKE 0x{RPC_HANDSHAKE_U32:08x}, got 0x{hs_type:08x}"
                    )));
                }

                handshake_ok = true;
                break;
            }
        }

        if !handshake_ok {
            return Err(ProxyError::TgHandshakeTimeout);
        }

        let handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;
        info!(%addr, "RPC handshake OK");

        Ok(HandshakeOutput {
            rd,
            wr,
            read_key: rk,
            read_iv,
            write_key: wk,
            write_iv,
            handshake_ms,
        })
    }
}

fn hex_dump(data: &[u8]) -> String {
    const MAX: usize = 64;
    let mut out = String::with_capacity(data.len() * 2 + 3);
    for (i, b) in data.iter().take(MAX).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02x}"));
    }
    if data.len() > MAX {
        out.push_str(" …");
    }
    out
}
