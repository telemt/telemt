//! TCP Socket Configuration

use std::io::Result;
use std::net::{SocketAddr, IpAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use socket2::{Socket, TcpKeepalive, Domain, Type, Protocol};
use tracing::debug;

/// Configure TCP socket with recommended settings for proxy use
pub fn configure_tcp_socket(
    stream: &TcpStream,
    keepalive: bool,
    keepalive_interval: Duration,
) -> Result<()> {
    let socket = socket2::SockRef::from(stream);
    
    // Disable Nagle's algorithm for lower latency
    socket.set_nodelay(true)?;
    
    // Set keepalive if enabled
    if keepalive {
        let keepalive = TcpKeepalive::new()
            .with_time(keepalive_interval);
        
        // Platform-specific keepalive settings
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
        let keepalive = keepalive.with_interval(keepalive_interval);
        
        socket.set_tcp_keepalive(&keepalive)?;
    }
    
    // CHANGED: Removed manual buffer size setting (was 256KB).
    // Allowing the OS kernel to handle TCP window scaling (Autotuning) is critical
    // for mobile clients to avoid bufferbloat and stalled connections during uploads.
    
    Ok(())
}

/// Configure socket for accepting client connections
pub fn configure_client_socket(
    stream: &TcpStream,
    keepalive_secs: u64,
    ack_timeout_secs: u64,
) -> Result<()> {
    let socket = socket2::SockRef::from(stream);
    
    // Disable Nagle's algorithm
    socket.set_nodelay(true)?;
    
    // Set keepalive
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(keepalive_secs));
    
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
    let keepalive = keepalive.with_interval(Duration::from_secs(keepalive_secs));
    
    socket.set_tcp_keepalive(&keepalive)?;
    
    // Set TCP user timeout (Linux only)
    // NOTE: iOS does not support TCP_USER_TIMEOUT - application-level timeout 
    // is implemented in relay_bidirectional instead
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let timeout_ms = (ack_timeout_secs * 1000) as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &timeout_ms as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    
    Ok(())
}

/// Set socket to send RST on close (for masking)
pub fn set_linger_zero(stream: &TcpStream) -> Result<()> {
    let socket = socket2::SockRef::from(stream);
    socket.set_linger(Some(Duration::ZERO))?;
    Ok(())
}

/// Create a new TCP socket for outgoing connections
pub fn create_outgoing_socket(addr: SocketAddr) -> Result<Socket> {
    create_outgoing_socket_bound(addr, None)
}

/// Create a new TCP socket for outgoing connections, optionally bound to a specific interface
pub fn create_outgoing_socket_bound(addr: SocketAddr, bind_addr: Option<IpAddr>) -> Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    
    // Set non-blocking
    socket.set_nonblocking(true)?;
    
    // Disable Nagle
    socket.set_nodelay(true)?;

    if let Some(bind_ip) = bind_addr {
        let bind_sock_addr = SocketAddr::new(bind_ip, 0);
        socket.bind(&bind_sock_addr.into())?;
        debug!("Bound outgoing socket to {}", bind_ip);
    }
    
    Ok(socket)
}


/// Get local address of a socket
pub fn get_local_addr(stream: &TcpStream) -> Option<SocketAddr> {
    stream.local_addr().ok()
}

/// Get peer address of a socket
pub fn get_peer_addr(stream: &TcpStream) -> Option<SocketAddr> {
    stream.peer_addr().ok()
}

/// Check if address is IPv6
pub fn is_ipv6(addr: &SocketAddr) -> bool {
    addr.is_ipv6()
}

/// Parse IPv4-mapped IPv6 address to IPv4
pub fn normalize_ip(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}

/// Socket options for server listening
#[derive(Debug, Clone)]
pub struct ListenOptions {
    /// Enable SO_REUSEADDR
    pub reuse_addr: bool,
    /// Enable SO_REUSEPORT (Linux/BSD)
    pub reuse_port: bool,
    /// Backlog size
    pub backlog: u32,
    /// IPv6 only (disable dual-stack)
    pub ipv6_only: bool,
}

impl Default for ListenOptions {
    fn default() -> Self {
        Self {
            reuse_addr: true,
            reuse_port: true,
            backlog: 1024,
            ipv6_only: false,
        }
    }
}

/// Create a listening socket with the specified options
pub fn create_listener(addr: SocketAddr, options: &ListenOptions) -> Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    
    if options.reuse_addr {
        socket.set_reuse_address(true)?;
    }
    
    #[cfg(unix)]
    if options.reuse_port {
        socket.set_reuse_port(true)?;
    }
    
    if addr.is_ipv6() && options.ipv6_only {
        socket.set_only_v6(true)?;
    }
    
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(options.backlog as i32)?;
    
    debug!(addr = %addr, "Created listening socket");
    
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    
    #[tokio::test]
    async fn test_configure_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let stream = TcpStream::connect(addr).await.unwrap();
        configure_tcp_socket(&stream, true, Duration::from_secs(30)).unwrap();
    }
    
    #[test]
    fn test_normalize_ip() {
        // IPv4 stays IPv4
        let v4: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        assert_eq!(normalize_ip(v4), v4);
        
        // Pure IPv6 stays IPv6
        let v6: SocketAddr = "[::1]:8080".parse().unwrap();
        assert_eq!(normalize_ip(v6), v6);
    }
    
    #[test]
    fn test_listen_options_default() {
        let opts = ListenOptions::default();
        assert!(opts.reuse_addr);
        assert!(opts.reuse_port);
        assert_eq!(opts.backlog, 1024);
    }
}