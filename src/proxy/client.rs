//! Client Handler

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;

use tracing::{debug, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{HandshakeResult, ProxyError, Result};
use crate::ip_tracker::UserIpTracker;
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::middle_proxy::MePool;
use crate::transport::{configure_client_socket, UpstreamManager};

use crate::proxy::direct_relay::handle_via_direct;
use crate::proxy::handshake::{
    handle_mtproto_handshake, handle_tls_handshake, HandshakeSuccess,
};
use crate::proxy::masking::handle_bad_client;
use crate::proxy::middle_relay::handle_via_middle_proxy;


///
/// Generic client handler (TCP, Unix socket, etc)
///
pub async fn handle_client_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
    ip_tracker: Arc<UserIpTracker>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    stats.increment_connects_all();

    debug!(peer = %peer, "New connection (generic stream)");

    let handshake_timeout =
        Duration::from_secs(config.timeouts.client_handshake);

    let stats_for_timeout = stats.clone();

    let local_addr: SocketAddr = format!("0.0.0.0:{}", config.server.port)
        .parse()
        .unwrap_or_else(|_| "0.0.0.0:443".parse().unwrap());

    let result = timeout(handshake_timeout, async {

        let mut first_bytes = [0u8; 5];
        stream.read_exact(&mut first_bytes).await?;

        let is_tls = tls::is_tls_handshake(&first_bytes[..3]);

        debug!(
            peer = %peer,
            is_tls = is_tls,
            "Handshake type detected"
        );

        if is_tls {

            let tls_len =
                u16::from_be_bytes([first_bytes[3], first_bytes[4]])
                    as usize;

            if tls_len < 512 {

                stats.increment_connects_bad();

                let (reader, writer) =
                    tokio::io::split(stream);

                handle_bad_client(
                    reader,
                    writer,
                    &first_bytes,
                    &config,
                ).await;

                return Ok(());
            }

            let mut handshake =
                vec![0u8; 5 + tls_len];

            handshake[..5]
                .copy_from_slice(&first_bytes);

            stream.read_exact(
                &mut handshake[5..],
            ).await?;

            let (read_half, write_half) =
                tokio::io::split(stream);

            let (
                mut tls_reader,
                tls_writer,
                _tls_user,
            ) =
                match handle_tls_handshake(
                    &handshake,
                    read_half,
                    write_half,
                    peer,
                    &config,
                    &replay_checker,
                    &rng,
                ).await {

                    HandshakeResult::Success(x) => x,

                    HandshakeResult::BadClient {
                        reader,
                        writer,
                    } => {

                        stats.increment_connects_bad();

                        handle_bad_client(
                            reader,
                            writer,
                            &handshake,
                            &config,
                        ).await;

                        return Ok(());
                    }

                    HandshakeResult::Error(e) =>
                        return Err(e),
                };

            let mtproto_data =
                tls_reader.read_exact(
                    HANDSHAKE_LEN,
                ).await?;

            let mtproto_handshake:
                [u8; HANDSHAKE_LEN] =
                mtproto_data[..]
                    .try_into()
                    .map_err(|_| {
                        ProxyError::InvalidHandshake(
                            "Short MTProto handshake".into()
                        )
                    })?;

            let (
                crypto_reader,
                crypto_writer,
                success,
            ) =
                match handle_mtproto_handshake(
                    &mtproto_handshake,
                    tls_reader,
                    tls_writer,
                    peer,
                    &config,
                    &replay_checker,
                    true,
                ).await {

                    HandshakeResult::Success(x) => x,

                    HandshakeResult::BadClient {
                        reader: _,
                        writer: _,
                    } => {

                        stats.increment_connects_bad();

                        return Ok(());
                    }

                    HandshakeResult::Error(e) =>
                        return Err(e),
                };

            RunningClientHandler::handle_authenticated_static(
                crypto_reader,
                crypto_writer,
                success,
                upstream_manager,
                stats,
                config,
                buffer_pool,
                rng,
                me_pool,
                local_addr,
                peer,
                ip_tracker.clone(),
            ).await

        } else {

            if !config.general.modes.classic
                && !config.general.modes.secure
            {

                stats.increment_connects_bad();

                let (reader, writer) =
                    tokio::io::split(stream);

                handle_bad_client(
                    reader,
                    writer,
                    &first_bytes,
                    &config,
                ).await;

                return Ok(());
            }

            let mut handshake =
                [0u8; HANDSHAKE_LEN];

            handshake[..5]
                .copy_from_slice(&first_bytes);

            stream.read_exact(
                &mut handshake[5..],
            ).await?;

            let (read_half, write_half) =
                tokio::io::split(stream);

            let (
                crypto_reader,
                crypto_writer,
                success,
            ) =
                match handle_mtproto_handshake(
                    &handshake,
                    read_half,
                    write_half,
                    peer,
                    &config,
                    &replay_checker,
                    false,
                ).await {

                    HandshakeResult::Success(x) => x,

                    HandshakeResult::BadClient {
                        reader,
                        writer,
                    } => {

                        stats.increment_connects_bad();

                        handle_bad_client(
                            reader,
                            writer,
                            &handshake,
                            &config,
                        ).await;

                        return Ok(());
                    }

                    HandshakeResult::Error(e) =>
                        return Err(e),
                };

            RunningClientHandler::handle_authenticated_static(
                crypto_reader,
                crypto_writer,
                success,
                upstream_manager,
                stats,
                config,
                buffer_pool,
                rng,
                me_pool,
                local_addr,
                peer,
                ip_tracker.clone(),
            ).await
        }

    }).await;

    match result {

        Ok(Ok(())) => Ok(()),

        Ok(Err(e)) => Err(e),

        Err(_) => {

            stats_for_timeout
                .increment_handshake_timeouts();

            Err(
                ProxyError::TgHandshakeTimeout
            )
        }
    }
}


///
/// TCP-specific handler
///
pub struct ClientHandler;

pub struct RunningClientHandler {

    stream: TcpStream,
    peer: SocketAddr,

    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    replay_checker: Arc<ReplayChecker>,
    upstream_manager: Arc<UpstreamManager>,

    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,

    me_pool: Option<Arc<MePool>>,
    ip_tracker: Arc<UserIpTracker>,
}


impl ClientHandler {

    pub fn new(
        stream: TcpStream,
        peer: SocketAddr,

        config: Arc<ProxyConfig>,
        stats: Arc<Stats>,
        upstream_manager: Arc<UpstreamManager>,
        replay_checker: Arc<ReplayChecker>,

        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,

        me_pool: Option<Arc<MePool>>,
        ip_tracker: Arc<UserIpTracker>,
    ) -> RunningClientHandler {

        RunningClientHandler {

            stream,
            peer,

            config,
            stats,
            replay_checker,
            upstream_manager,

            buffer_pool,
            rng,

            me_pool,
            ip_tracker,
        }
    }
}


impl RunningClientHandler {

    pub async fn run(mut self) -> Result<()> {

        self.stats.increment_connects_all();

        if let Err(e) = configure_client_socket(
            &self.stream,
            self.config.timeouts.client_keepalive,
            self.config.timeouts.client_ack,
        ) {

            debug!(error = %e);
        }

        let timeout_dur =
            Duration::from_secs(
                self.config.timeouts.client_handshake
            );

        timeout(
            timeout_dur,
            self.do_handshake()
        ).await?
    }


    async fn do_handshake(mut self) -> Result<()> {

        let mut first_bytes = [0u8; 5];

        self.stream.read_exact(
            &mut first_bytes
        ).await?;

        let is_tls =
            tls::is_tls_handshake(
                &first_bytes[..3]
            );

        if is_tls {

            self.handle_tls_client(
                first_bytes
            ).await

        } else {

            self.handle_direct_client(
                first_bytes
            ).await
        }
    }


    async fn handle_tls_client(
        mut self,
        first_bytes: [u8; 5]
    ) -> Result<()> {

        let tls_len =
            u16::from_be_bytes(
                [first_bytes[3],
                 first_bytes[4]]
            ) as usize;

        if tls_len < 512 {

            self.stats.increment_connects_bad();

            let (r,w) =
                self.stream.into_split();

            handle_bad_client(
                r,
                w,
                &first_bytes,
                &self.config
            ).await;

            return Ok(())
        }

        let mut handshake =
            vec![0u8;5+tls_len];

        handshake[..5]
            .copy_from_slice(
                &first_bytes
            );

        self.stream.read_exact(
            &mut handshake[5..]
        ).await?;

        let local_addr =
            self.stream.local_addr()?;

        let (r,w) =
            self.stream.into_split();

        let (
            mut tls_reader,
            tls_writer,
            _
        ) =
            match handle_tls_handshake(
                &handshake,
                r,w,
                self.peer,
                &self.config,
                &self.replay_checker,
                &self.rng
            ).await {

                HandshakeResult::Success(x)=>x,

                HandshakeResult::BadClient{reader,writer}=>{
                    handle_bad_client(
                        reader,writer,
                        &handshake,
                        &self.config
                    ).await;

                    return Ok(())
                }

                HandshakeResult::Error(e)=>return Err(e)
            };

        let mt =
            tls_reader.read_exact(
                HANDSHAKE_LEN
            ).await?;

        let mt:
            [u8;HANDSHAKE_LEN] =
            mt.try_into().unwrap();

        let (
            cr,
            cw,
            success
        ) =
            match handle_mtproto_handshake(
                &mt,
                tls_reader,
                tls_writer,
                self.peer,
                &self.config,
                &self.replay_checker,
                true
            ).await {

                HandshakeResult::Success(x)=>x,

                HandshakeResult::BadClient{..}=>{
                    return Ok(())
                }

                HandshakeResult::Error(e)=>return Err(e)
            };

        Self::handle_authenticated_static(
            cr,cw,success,
            self.upstream_manager,
            self.stats,
            self.config,
            self.buffer_pool,
            self.rng,
            self.me_pool,
            local_addr,
            self.peer,
            self.ip_tracker
        ).await
    }


    async fn handle_direct_client(
        mut self,
        first_bytes:[u8;5]
    )->Result<()>{

        let mut handshake=
            [0u8;HANDSHAKE_LEN];

        handshake[..5]
            .copy_from_slice(
                &first_bytes
            );

        self.stream.read_exact(
            &mut handshake[5..]
        ).await?;

        let local_addr=
            self.stream.local_addr()?;

        let (r,w)=
            self.stream.into_split();

        let (
            cr,
            cw,
            success
        )=
            handle_mtproto_handshake(
                &handshake,
                r,w,
                self.peer,
                &self.config,
                &self.replay_checker,
                false
            ).await?
            .into_success()?;


        Self::handle_authenticated_static(
            cr,cw,success,
            self.upstream_manager,
            self.stats,
            self.config,
            self.buffer_pool,
            self.rng,
            self.me_pool,
            local_addr,
            self.peer,
            self.ip_tracker
        ).await
    }


    pub(crate)
    async fn handle_authenticated_static<R,W>(
        client_reader:CryptoReader<R>,
        client_writer:CryptoWriter<W>,
        success:HandshakeSuccess,

        upstream_manager:Arc<UpstreamManager>,
        stats:Arc<Stats>,
        config:Arc<ProxyConfig>,

        buffer_pool:Arc<BufferPool>,
        rng:Arc<SecureRandom>,
        me_pool:Option<Arc<MePool>>,

        local_addr:SocketAddr,
        peer_addr:SocketAddr,

        ip_tracker:Arc<UserIpTracker>,
    )->Result<()>
    where
        R:AsyncRead+Unpin+Send+'static,
        W:AsyncWrite+Unpin+Send+'static,
    {

        let user=&success.user;

        ip_tracker.check_and_add(
            user,
            peer_addr.ip()
        ).await?;


        if config.general.use_middle_proxy {

            if let Some(pool)=me_pool{

                return handle_via_middle_proxy(
                    client_reader,
                    client_writer,
                    success,
                    pool,
                    stats,
                    config,
                    buffer_pool,
                    local_addr
                ).await
            }
        }

        handle_via_direct(
            client_reader,
            client_writer,
            success,
            upstream_manager,
            stats,
            config,
            buffer_pool,
            rng
        ).await
    }

}
