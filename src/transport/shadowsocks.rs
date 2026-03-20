use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use shadowsocks::{
    ProxyClientStream,
    config::{ServerConfig, ServerType},
    context::Context,
    net::ConnectOpts,
};

use crate::error::{ProxyError, Result};

pub(crate) type ShadowsocksStream = ProxyClientStream<shadowsocks::net::TcpStream>;

fn parse_server_config(url: &str, connect_timeout: Duration) -> Result<ServerConfig> {
    let mut config = ServerConfig::from_url(url)
        .map_err(|error| ProxyError::Config(format!("invalid shadowsocks url: {error}")))?;

    if config.plugin().is_some() {
        return Err(ProxyError::Config(
            "shadowsocks plugins are not supported".to_string(),
        ));
    }

    config.set_timeout(connect_timeout);
    Ok(config)
}

pub(crate) fn sanitize_shadowsocks_url(url: &str) -> Result<String> {
    Ok(parse_server_config(url, Duration::from_secs(1))?
        .addr()
        .to_string())
}

fn connect_opts_for_interface(interface: &Option<String>) -> ConnectOpts {
    let mut opts = ConnectOpts::default();
    if let Some(interface) = interface {
        if let Ok(ip) = interface.parse::<IpAddr>() {
            opts.bind_local_addr = Some(SocketAddr::new(ip, 0));
        } else {
            opts.bind_interface = Some(interface.clone());
        }
    }
    opts
}

pub(crate) async fn connect_shadowsocks(
    url: &str,
    interface: &Option<String>,
    target: SocketAddr,
    connect_timeout: Duration,
) -> Result<ShadowsocksStream> {
    let config = parse_server_config(url, connect_timeout)?;
    let context = Context::new_shared(ServerType::Local);
    let opts = connect_opts_for_interface(interface);

    ProxyClientStream::connect_with_opts(context, &config, target, &opts)
        .await
        .map_err(ProxyError::Io)
}
