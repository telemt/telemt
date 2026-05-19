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

#[cfg(test)]
mod tests {
    use super::*;

    mod connect_opts_for_interface_tests {
        use super::*;

        #[test]
        fn none_yields_default() {
            let opts = connect_opts_for_interface(&None);
            assert!(opts.bind_local_addr.is_none());
            assert!(opts.bind_interface.is_none());
        }

        #[test]
        fn ipv4_literal_binds_local_addr() {
            let iface = Some("192.168.1.1".to_string());
            let opts = connect_opts_for_interface(&iface);
            assert!(opts.bind_local_addr.is_some());
            assert!(opts.bind_interface.is_none());
            let addr = opts.bind_local_addr.unwrap();
            assert_eq!(addr.ip().to_string(), "192.168.1.1");
            assert_eq!(addr.port(), 0);
        }

        #[test]
        fn ipv6_literal_binds_local_addr() {
            let iface = Some("::1".to_string());
            let opts = connect_opts_for_interface(&iface);
            assert!(opts.bind_local_addr.is_some());
            assert!(opts.bind_interface.is_none());
        }

        #[test]
        fn interface_name_sets_bind_interface() {
            let iface = Some("eth0".to_string());
            let opts = connect_opts_for_interface(&iface);
            assert!(opts.bind_local_addr.is_none());
            assert_eq!(opts.bind_interface.as_deref(), Some("eth0"));
        }
    }

    mod parse_server_config_tests {
        use super::*;

        #[test]
        fn invalid_url_returns_err() {
            let err = parse_server_config("not a url", Duration::from_secs(1));
            assert!(err.is_err());
            let msg = format!("{}", err.unwrap_err());
            assert!(msg.contains("invalid shadowsocks url"));
        }

        #[test]
        fn sanitize_invalid_url_returns_err() {
            assert!(sanitize_shadowsocks_url("definitely not a ss url").is_err());
        }
    }
}
