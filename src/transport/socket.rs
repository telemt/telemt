//! TCP Socket Configuration

use std::collections::HashSet;
use std::fs;
use std::io::Result;
use std::net::{SocketAddr, IpAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use socket2::{Socket, TcpKeepalive, Domain, Type, Protocol};
use tracing::debug;

/// Configure TCP socket with recommended settings for proxy use
#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn set_linger_zero(stream: &TcpStream) -> Result<()> {
    let socket = socket2::SockRef::from(stream);
    socket.set_linger(Some(Duration::ZERO))?;
    Ok(())
}

/// Create a new TCP socket for outgoing connections
#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn get_local_addr(stream: &TcpStream) -> Option<SocketAddr> {
    stream.local_addr().ok()
}

/// Resolve primary IP address of a network interface by name.
/// Returns the first address matching the requested family (IPv4/IPv6).
#[cfg(unix)]
pub fn resolve_interface_ip(name: &str, want_ipv6: bool) -> Option<IpAddr> {
    use nix::ifaddrs::getifaddrs;

    if let Ok(addrs) = getifaddrs() {
        for iface in addrs {
            if iface.interface_name == name
                && let Some(address) = iface.address
            {
                if let Some(v4) = address.as_sockaddr_in() {
                    if !want_ipv6 {
                        return Some(IpAddr::V4(v4.ip()));
                    }
                } else if let Some(v6) = address.as_sockaddr_in6()
                    && want_ipv6
                {
                    return Some(IpAddr::V6(v6.ip()));
                }
            }
        }
    }
    None
}

/// Stub for non-Unix platforms: interface name resolution unsupported.
#[cfg(not(unix))]
pub fn resolve_interface_ip(_name: &str, _want_ipv6: bool) -> Option<IpAddr> {
    None
}

/// Get peer address of a socket
#[allow(dead_code)]
pub fn get_peer_addr(stream: &TcpStream) -> Option<SocketAddr> {
    stream.peer_addr().ok()
}

/// Check if address is IPv6
#[allow(dead_code)]
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

/// Best-effort process list for listeners occupying the same local TCP port.
#[derive(Debug, Clone)]
pub struct ListenerProcessInfo {
    pub pid: u32,
    pub process: String,
}

/// Find processes currently listening on the local TCP port of `addr`.
/// Returns an empty list when unsupported or when no owners can be resolved.
pub fn find_listener_processes(addr: SocketAddr) -> Vec<ListenerProcessInfo> {
    #[cfg(target_os = "linux")]
    {
        find_listener_processes_linux(addr)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = addr;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn find_listener_processes_linux(addr: SocketAddr) -> Vec<ListenerProcessInfo> {
    let inodes = listening_inodes_for_port(addr);
    if inodes.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    let proc_entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return out,
    };

    for entry in proc_entries.flatten() {
        let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let fd_dir = entry.path().join("fd");
        let fd_entries = match fs::read_dir(fd_dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        let mut matched = false;
        for fd in fd_entries.flatten() {
            let link_target = match fs::read_link(fd.path()) {
                Ok(link) => link,
                Err(_) => continue,
            };

            let link_str = link_target.to_string_lossy();
            let Some(rest) = link_str.strip_prefix("socket:[") else {
                continue;
            };
            let Some(inode_str) = rest.strip_suffix(']') else {
                continue;
            };
            let Ok(inode) = inode_str.parse::<u64>() else {
                continue;
            };

            if inodes.contains(&inode) {
                matched = true;
                break;
            }
        }

        if matched {
            let process = fs::read_to_string(entry.path().join("comm"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown".to_string());
            out.push(ListenerProcessInfo { pid, process });
        }
    }

    out.sort_by_key(|p| p.pid);
    out.dedup_by_key(|p| p.pid);
    out
}

#[cfg(target_os = "linux")]
fn listening_inodes_for_port(addr: SocketAddr) -> HashSet<u64> {
    let path = match addr {
        SocketAddr::V4(_) => "/proc/net/tcp",
        SocketAddr::V6(_) => "/proc/net/tcp6",
    };

    let mut inodes = HashSet::new();
    let Ok(data) = fs::read_to_string(path) else {
        return inodes;
    };

    for line in data.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }

        // LISTEN state in /proc/net/tcp*
        if cols[3] != "0A" {
            continue;
        }

        let Some(port_hex) = cols[1].split(':').nth(1) else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port != addr.port() {
            continue;
        }

        if let Ok(inode) = cols[9].parse::<u64>() {
            inodes.insert(inode);
        }
    }

    inodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tokio::net::TcpListener;
    
    #[tokio::test]
    async fn test_configure_socket() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        
        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("connect failed: {e}"),
        };
        if let Err(e) = configure_tcp_socket(&stream, true, Duration::from_secs(30)) {
            if e.kind() == ErrorKind::PermissionDenied {
                return;
            }
            panic!("configure_tcp_socket failed: {e}");
        }
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
