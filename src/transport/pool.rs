//! Connection Pool

#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use parking_lot::RwLock;
use tracing::debug;
use crate::error::{ProxyError, Result};
use super::socket::configure_tcp_socket;

/// A pooled connection with metadata
struct PooledConnection {
    stream: TcpStream,
    created_at: Instant,
}

/// Internal pool state for a single endpoint
struct PoolInner {
    /// Available connections
    connections: Vec<PooledConnection>,
    /// Number of connections being established
    pending: usize,
}

impl PoolInner {
    const fn new() -> Self {
        Self {
            connections: Vec::new(),
            pending: 0,
        }
    }
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per endpoint
    pub max_connections: usize,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Maximum idle time before connection is dropped
    pub max_idle_time: Duration,
    /// Enable TCP keepalive
    pub keepalive: bool,
    /// Keepalive interval
    pub keepalive_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 64,
            connect_timeout: Duration::from_secs(10),
            max_idle_time: Duration::from_secs(60),
            keepalive: true,
            keepalive_interval: Duration::from_secs(40),
        }
    }
}

/// Thread-safe connection pool
pub struct ConnectionPool {
    /// Per-endpoint pools
    pools: RwLock<HashMap<SocketAddr, Arc<Mutex<PoolInner>>>>,
    /// Configuration
    config: PoolConfig,
}

impl ConnectionPool {
    /// Create new connection pool with default config
    pub fn new() -> Self {
        Self::with_config(PoolConfig::default())
    }
    
    /// Create connection pool with custom config
    pub fn with_config(config: PoolConfig) -> Self {
        Self {
            pools: RwLock::new(HashMap::new()),
            config,
        }
    }
    
    /// Get or create pool for an endpoint
    fn get_or_create_pool(&self, addr: SocketAddr) -> Arc<Mutex<PoolInner>> {
        // Fast path with read lock
        {
            let pools = self.pools.read();
            if let Some(pool) = pools.get(&addr) {
                return Arc::clone(pool);
            }
        }
        
        // Slow path with write lock
        let mut pools = self.pools.write();
        pools.entry(addr)
            .or_insert_with(|| Arc::new(Mutex::new(PoolInner::new())))
            .clone()
    }
    
    /// Get a connection to the specified address
    pub async fn get(&self, addr: SocketAddr) -> Result<TcpStream> {
        let pool = self.get_or_create_pool(addr);
        
        // Try to get an existing connection
        {
            let mut inner = pool.lock().await;
            
            // Remove stale connections
            let now = Instant::now();
            inner.connections.retain(|c| {
                now.duration_since(c.created_at) < self.config.max_idle_time
            });
            
            // Try to find a usable connection
            while let Some(conn) = inner.connections.pop() {
                // Check if connection is still alive
                if is_connection_alive(&conn.stream) {
                    debug!(addr = %addr, "Reusing pooled connection");
                    return Ok(conn.stream);
                }
                debug!(addr = %addr, "Discarding dead pooled connection");
            }
            
            // Check if we can create a new connection
            let total = inner.connections.len() + inner.pending;
            if total >= self.config.max_connections {
                return Err(ProxyError::ConnectionTimeout { 
                    addr: addr.to_string() 
                });
            }
            
            inner.pending += 1;
        }
        
        // Create new connection
        debug!(addr = %addr, "Creating new connection");
        let result = self.create_connection(addr).await;
        
        // Decrement pending count
        {
            let mut inner = pool.lock().await;
            inner.pending = inner.pending.saturating_sub(1);
        }
        
        result
    }
    
    /// Create a new connection to the address
    async fn create_connection(&self, addr: SocketAddr) -> Result<TcpStream> {
        let connect_future = TcpStream::connect(addr);
        
        let stream = timeout(self.config.connect_timeout, connect_future)
            .await
            .map_err(|_| ProxyError::ConnectionTimeout { 
                addr: addr.to_string() 
            })?
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    ProxyError::ConnectionRefused { addr: addr.to_string() }
                } else {
                    ProxyError::Io(e)
                }
            })?;
        
        // Configure socket
        configure_tcp_socket(
            &stream,
            self.config.keepalive,
            self.config.keepalive_interval,
        )?;
        
        Ok(stream)
    }
    
    /// Return a connection to the pool
    pub async fn put(&self, addr: SocketAddr, stream: TcpStream) {
        let pool = self.get_or_create_pool(addr);
        let mut inner = pool.lock().await;
        
        if inner.connections.len() < self.config.max_connections {
            inner.connections.push(PooledConnection {
                stream,
                created_at: Instant::now(),
            });
            debug!(addr = %addr, pool_size = inner.connections.len(), "Returned connection to pool");
        } else {
            debug!(addr = %addr, "Pool full, dropping connection");
        }
    }
    
    /// Close all pooled connections
    pub async fn close_all(&self) {
        let pools: Vec<(SocketAddr, Arc<Mutex<PoolInner>>)> = {
            let guard = self.pools.read();
            guard
                .iter()
                .map(|(addr, pool)| (*addr, Arc::clone(pool)))
                .collect()
        };

        for (addr, pool) in pools {
            let mut inner = pool.lock().await;
            let count = inner.connections.len();
            inner.connections.clear();
            debug!(addr = %addr, count = count, "Closed pooled connections");
        }
    }
    
    /// Get pool statistics
    pub async fn stats(&self) -> PoolStats {
        let pools: Vec<Arc<Mutex<PoolInner>>> = {
            let guard = self.pools.read();
            guard.values().cloned().collect()
        };
        let mut total_connections = 0;
        let mut total_pending = 0;
        let mut endpoints = 0;
        
        for pool in pools {
            let inner = pool.lock().await;
            total_connections += inner.connections.len();
            total_pending += inner.pending;
            endpoints += 1;
        }
        
        PoolStats {
            endpoints,
            total_connections,
            total_pending,
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub endpoints: usize,
    pub total_connections: usize,
    pub total_pending: usize,
}

/// Check if a TCP connection is still alive (non-blocking, without consuming data).
///
/// On Unix, MSG_PEEK inspects the receive buffer without consuming any bytes,
/// preventing silent data loss if the server pushed unsolicited bytes while the
/// connection was idle. On non-Unix platforms, try_read is used as a fallback.
#[cfg(unix)]
#[allow(unsafe_code)]
fn is_connection_alive(stream: &TcpStream) -> bool {
    use std::io::ErrorKind;
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut buf = [0u8; 1];

    // EINTR can fire on any syscall when a signal is delivered to the thread.
    // Treating it as a dead connection causes spurious reconnects; retry instead.
    const MAX_RECV_RETRIES: usize = 3;

    for _ in 0..MAX_RECV_RETRIES {
        // SAFETY: `stream` owns this fd for the full duration of the call.
        // MSG_PEEK + MSG_DONTWAIT: inspect the receive buffer without consuming bytes.
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };

        if n > 0 {
            return true;
        } else if n == 0 {
            return false;
        } else {
            match std::io::Error::last_os_error().kind() {
                ErrorKind::Interrupted => continue,
                ErrorKind::WouldBlock => return true,
                _ => return false,
            }
        }
    }

    // After MAX_RECV_RETRIES consecutive EINTR, assume the connection is alive
    // rather than triggering a false reconnect.
    true
}

#[cfg(not(unix))]
fn is_connection_alive(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        Ok(0) => false,
        Ok(_) => true,
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

/// Connection pool with custom initialization
pub struct InitializingPool<F> {
    pool: ConnectionPool,
    init_fn: F,
}

impl<F, Fut> InitializingPool<F>
where
    F: Fn(TcpStream, SocketAddr) -> Fut + Send + Sync,
    Fut: Future<Output = Result<TcpStream>> + Send,
{
    /// Create pool with initialization function
    pub fn new(config: PoolConfig, init_fn: F) -> Self {
        Self {
            pool: ConnectionPool::with_config(config),
            init_fn,
        }
    }
    
    /// Get an initialized connection
    pub async fn get(&self, addr: SocketAddr) -> Result<TcpStream> {
        let stream = self.pool.get(addr).await?;
        (self.init_fn)(stream, addr).await
    }
    
    /// Return connection to pool
    pub async fn put(&self, addr: SocketAddr, stream: TcpStream) {
        self.pool.put(addr, stream).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tokio::net::TcpListener;
    
    #[tokio::test]
    async fn test_pool_basic() {
        // Start a test server
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        
        // Accept connections in background
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        
        let pool = ConnectionPool::new();
        
        // Get a connection
        let conn1 = match pool.get(addr).await {
            Ok(c) => c,
            Err(ProxyError::Io(e)) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("connect failed: {e}"),
        };
        
        // Return it to pool
        pool.put(addr, conn1).await;
        
        // Get again (should reuse)
        let _conn2 = pool.get(addr).await.unwrap();
        
        let stats = pool.stats().await;
        assert_eq!(stats.endpoints, 1);
    }
    
    #[tokio::test]
    async fn test_pool_connection_refused() {
        let pool = ConnectionPool::with_config(PoolConfig {
            connect_timeout: Duration::from_millis(100),
            ..Default::default()
        });
        
        // Try to connect to a port that's not listening
        let result = pool.get("127.0.0.1:1".parse().unwrap()).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_pool_stats() {
        let pool = ConnectionPool::new();
        
        let stats = pool.stats().await;
        assert_eq!(stats.endpoints, 0);
        assert_eq!(stats.total_connections, 0);
    }

    // ===== T-3: is_connection_alive MSG_PEEK tests (Unix only) =====

    /// Verify that is_connection_alive returns true when the server has pushed data
    /// AND that the pushed byte is still readable afterwards — i.e. it was not consumed.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_is_connection_alive_peek_does_not_consume_server_data() {
        use tokio::io::AsyncWriteExt;

        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut accepted, _) = listener.accept().await.expect("accept");
            accepted.write_all(&[0xAB]).await.expect("server write");
            // Hold the connection open while the client peeks.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("connect failed: {e}"),
        };

        // Allow the server's byte to arrive in the kernel receive buffer.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            is_connection_alive(&stream),
            "connection with buffered server data must be alive"
        );

        // The byte must still be readable — MSG_PEEK must not have consumed it.
        let mut buf = [0u8; 1];
        let n = stream.try_read(&mut buf).expect("try_read after peek");
        assert_eq!(n, 1, "byte must still be present after peek");
        assert_eq!(buf[0], 0xAB, "byte value must be unchanged after peek");

        drop(server);
    }

    /// Verify that is_connection_alive returns false after the server closes the connection.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_is_connection_alive_returns_false_for_closed_connection() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (accepted, _) = listener.accept().await.expect("accept");
            drop(accepted); // Immediately close → sends FIN to client.
        });

        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("connect failed: {e}"),
        };

        server_handle.await.expect("server join");

        // Allow FIN to propagate through the network stack.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            !is_connection_alive(&stream),
            "closed connection must not be reported as alive"
        );
    }

    /// Verify that an idle open connection (no server data) is reported as alive.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_is_connection_alive_idle_open_connection_returns_true() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("connect failed: {e}"),
        };

        // No data from server → MSG_PEEK returns EAGAIN/EWOULDBLOCK → alive.
        assert!(
            is_connection_alive(&stream),
            "idle open connection must be reported as alive"
        );
    }

    /// Verify that consecutive peek calls do not change the connection state.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_is_connection_alive_idempotent_on_idle_connection() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("connect failed: {e}"),
        };

        for _ in 0..5 {
            assert!(is_connection_alive(&stream));
        }
    }

    // ── EINTR retry-logic unit tests ──────────────────────────────────────────

    // The non-unix fallback path must correctly classify WouldBlock as alive
    // and any other error as dead, mirroring the unix semantics.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn test_is_connection_alive_non_unix_open_connection() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        });
        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("connect failed: {e}"),
        };
        assert!(is_connection_alive(&stream), "open idle connection must be alive (non-unix)");
    }

    // Verify the unix path: calling is_connection_alive many times on an active
    // connection never spuriously returns false (guards against the pre-fix bug
    // where EINTR would flip the result on a single call).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_is_connection_alive_never_returns_false_spuriously_on_open_connection() {
        use tokio::io::AsyncWriteExt;
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            s.write_all(&[0xBEu8]).await.expect("write");
            tokio::time::sleep(Duration::from_millis(500)).await;
        });
        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("connect failed: {e}"),
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        // Call is_connection_alive 20 times; all must return true.
        for i in 0..20 {
            assert!(
                is_connection_alive(&stream),
                "is_connection_alive must be true on call {i} (connection is open with buffered data)"
            );
        }
        drop(server);
    }
}
