use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64};
use std::time::Duration;

use bytes::BytesMut;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Instant, timeout};
use tracing::{debug, info, warn};

use crate::crypto::{SecureRandom, build_middleproxy_prekey, derive_middleproxy_keys, sha256};
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;

use super::ConnRegistry;
use super::codec::{
    RpcWriter, build_handshake_payload, build_nonce_payload, build_rpc_frame, cbc_decrypt_inplace,
    cbc_encrypt_padded, parse_nonce_payload, read_rpc_frame_plaintext,
};
use super::reader::reader_loop;
use super::wire::{IpMaterial, extract_ip_material};

const ME_ACTIVE_PING_SECS: u64 = 25;
const ME_ACTIVE_PING_JITTER_SECS: i64 = 5;

pub struct MePool {
    pub(super) registry: Arc<ConnRegistry>,
    pub(super) writers: Arc<RwLock<Vec<(SocketAddr, Arc<Mutex<RpcWriter>>)>>> ,
    pub(super) rr: AtomicU64,
    pub(super) proxy_tag: Option<Vec<u8>>,
    pub(super) proxy_secret: Arc<RwLock<Vec<u8>>>,
    pub(super) nat_ip_cfg: Option<IpAddr>,
    pub(super) nat_ip_detected: Arc<RwLock<Option<IpAddr>>>,
    pub(super) nat_probe: bool,
    pub(super) nat_stun: Option<String>,
    pub(super) proxy_map_v4: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) proxy_map_v6: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) default_dc: AtomicI32,
    pool_size: usize,
}

impl MePool {
    pub fn new(
        proxy_tag: Option<Vec<u8>>,
        proxy_secret: Vec<u8>,
        nat_ip: Option<IpAddr>,
        nat_probe: bool,
        nat_stun: Option<String>,
        proxy_map_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        proxy_map_v6: HashMap<i32, Vec<(IpAddr, u16)>>,
        default_dc: Option<i32>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry: Arc::new(ConnRegistry::new()),
            writers: Arc::new(RwLock::new(Vec::new())),
            rr: AtomicU64::new(0),
            proxy_tag,
            proxy_secret: Arc::new(RwLock::new(proxy_secret)),
            nat_ip_cfg: nat_ip,
            nat_ip_detected: Arc::new(RwLock::new(None)),
            nat_probe,
            nat_stun,
            pool_size: 2,
            proxy_map_v4: Arc::new(RwLock::new(proxy_map_v4)),
            proxy_map_v6: Arc::new(RwLock::new(proxy_map_v6)),
            default_dc: AtomicI32::new(default_dc.unwrap_or(0)),
        })
    }

    pub fn has_proxy_tag(&self) -> bool {
        self.proxy_tag.is_some()
    }

    pub fn translate_our_addr(&self, addr: SocketAddr) -> SocketAddr {
        let ip = self.translate_ip_for_nat(addr.ip());
        SocketAddr::new(ip, addr.port())
    }

    pub fn registry(&self) -> &Arc<ConnRegistry> {
        &self.registry
    }

    fn writers_arc(&self) -> Arc<RwLock<Vec<(SocketAddr, Arc<Mutex<RpcWriter>>)>>>
    {
        self.writers.clone()
    }

    pub async fn update_proxy_maps(
        &self,
        new_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        new_v6: Option<HashMap<i32, Vec<(IpAddr, u16)>>>,
    ) -> bool {
        let mut changed = false;
        {
            let mut guard = self.proxy_map_v4.write().await;
            if !new_v4.is_empty() && *guard != new_v4 {
                *guard = new_v4;
                changed = true;
            }
        }
        if let Some(v6) = new_v6 {
            let mut guard = self.proxy_map_v6.write().await;
            if !v6.is_empty() && *guard != v6 {
                *guard = v6;
            }
        }
        changed
    }

    pub async fn update_secret(&self, new_secret: Vec<u8>) -> bool {
        if new_secret.len() < 32 {
            warn!(len = new_secret.len(), "proxy-secret update ignored (too short)");
            return false;
        }
        let mut guard = self.proxy_secret.write().await;
        if *guard != new_secret {
            *guard = new_secret;
            drop(guard);
            self.reconnect_all().await;
            return true;
        }
        false
    }

    pub async fn reconnect_all(&self) {
        let mut ws = self.writers.write().await;
        ws.clear();
    }

    async fn key_selector(&self) -> u32 {
        let secret = self.proxy_secret.read().await;
        if secret.len() >= 4 {
            u32::from_le_bytes([secret[0], secret[1], secret[2], secret[3]])
        } else {
            0
        }
    }

    pub async fn init(self: &Arc<Self>, pool_size: usize, rng: &SecureRandom) -> Result<()> {
        let map = self.proxy_map_v4.read().await;
        let ks = self.key_selector().await;
        info!(
            me_servers = map.len(),
            pool_size,
            key_selector = format_args!("0x{ks:08x}"),
            secret_len = self.proxy_secret.read().await.len(),
            "Initializing ME pool"
        );

        // Ensure at least one connection per DC
        for (dc, addrs) in map.iter() {
            if addrs.is_empty() {
                continue;
            }
            // round-robin first address
            let &(ip, port) = addrs.get(0).unwrap();
            let addr = SocketAddr::new(ip, port);
            match self.connect_one(addr, rng).await {
                Ok(()) => info!(%addr, dc = %dc, "ME connected"),
                Err(e) => warn!(%addr, dc = %dc, error = %e, "ME connect failed"),
            }
        }

        // Additional connections up to pool_size total
        for (dc, addrs) in map.iter() {
            for (i, (ip, port)) in addrs.iter().enumerate().skip(1) {
                if self.connection_count() >= pool_size {
                    break;
                }
                let addr = SocketAddr::new(*ip, *port);
                match self.connect_one(addr, rng).await {
                    Ok(()) => info!(%addr, dc = %dc, idx = i, "ME connected"),
                    Err(e) => warn!(%addr, dc = %dc, idx = i, error = %e, "ME connect failed"),
                }
            }
            if self.connection_count() >= pool_size {
                break;
            }
        }

        if self.writers.read().await.is_empty() {
            return Err(ProxyError::Proxy("No ME connections".into()));
        }
        Ok(())
    }

    pub(crate) async fn connect_one(
        self: &Arc<Self>,
        addr: SocketAddr,
        rng: &SecureRandom,
    ) -> Result<()> {
        let secret_guard = self.proxy_secret.read().await;
        let secret: Vec<u8> = secret_guard.clone();
        if secret.len() < 32 {
            return Err(ProxyError::Proxy(
                "proxy-secret too short for ME auth".into(),
            ));
        }

        let stream = timeout(
            Duration::from_secs(ME_CONNECT_TIMEOUT_SECS),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| ProxyError::ConnectionTimeout {
            addr: addr.to_string(),
        })?
        .map_err(ProxyError::Io)?;
        stream.set_nodelay(true).ok();

        let local_addr = stream.local_addr().map_err(ProxyError::Io)?;
        let peer_addr = stream.peer_addr().map_err(ProxyError::Io)?;
        let _ = self.maybe_detect_nat_ip(local_addr.ip()).await;
        let reflected = if self.nat_probe {
            self.maybe_reflect_public_addr().await
        } else {
            None
        };
        let local_addr_nat = self.translate_our_addr_with_reflection(local_addr, reflected);
        let peer_addr_nat =
            SocketAddr::new(self.translate_ip_for_nat(peer_addr.ip()), peer_addr.port());
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
            return Err(ProxyError::InvalidHandshake(format!(
                "Expected seq=-2, got {srv_seq}"
            )));
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

        let (srv_ip_opt, clt_ip_opt, clt_v6_opt, srv_v6_opt, hs_our_ip, hs_peer_ip) =
            match (server_ip, client_ip) {
                // IPv4: reverse byte order for KDF (Python/C reference behavior)
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
                        "mixed IPv4/IPv6 endpoints are not supported for ME key derivation"
                            .to_string(),
                    ));
                }
            };

        let diag_level: u8 = std::env::var("ME_DIAG")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

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

        let hs_payload =
            build_handshake_payload(hs_our_ip, local_addr.port(), hs_peer_ip, peer_addr.port());
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

        let (encrypted_hs, write_iv) = cbc_encrypt_padded(&wk, &wi, &hs_frame)?;
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

        info!(%addr, "RPC handshake OK");

        let rpc_w = Arc::new(Mutex::new(RpcWriter {
            writer: wr,
            key: wk,
            iv: write_iv,
            seq_no: 0,
        }));
        self.writers.write().await.push((addr, rpc_w.clone()));

        let reg = self.registry.clone();
        let w_pong = rpc_w.clone();
        let w_pool = self.writers_arc();
        let w_ping = rpc_w.clone();
        let w_pool_ping = self.writers_arc();
        tokio::spawn(async move {
            if let Err(e) =
                reader_loop(rd, rk, read_iv, reg, enc_buf, dec_buf, w_pong.clone()).await
            {
                warn!(error = %e, "ME reader ended");
            }
            let mut ws = w_pool.write().await;
            ws.retain(|(_, w)| !Arc::ptr_eq(w, &w_pong));
            info!(remaining = ws.len(), "Dead ME writer removed from pool");
        });
        tokio::spawn(async move {
            let mut ping_id: i64 = rand::random::<i64>();
            loop {
                let jitter = rand::rng()
                    .random_range(-ME_ACTIVE_PING_JITTER_SECS..=ME_ACTIVE_PING_JITTER_SECS);
                let wait = (ME_ACTIVE_PING_SECS as i64 + jitter).max(5) as u64;
                tokio::time::sleep(Duration::from_secs(wait)).await;
                let mut p = Vec::with_capacity(12);
                p.extend_from_slice(&RPC_PING_U32.to_le_bytes());
                p.extend_from_slice(&ping_id.to_le_bytes());
                ping_id = ping_id.wrapping_add(1);
                if let Err(e) = w_ping.lock().await.send(&p).await {
                    debug!(error = %e, "Active ME ping failed, removing dead writer");
                    let mut ws = w_pool_ping.write().await;
                    ws.retain(|(_, w)| !Arc::ptr_eq(w, &w_ping));
                    break;
                }
            }
        });

        Ok(())
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
