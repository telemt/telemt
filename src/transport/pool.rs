//! Connection Pool

#![allow(dead_code)]

use std::collections::HashMap;
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
    fn new() -> Self {
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
        let pools = self.pools.read();
        for (addr, pool) in pools.iter() {
            let mut inner = pool.lock().await;
            let count = inner.connections.len();
            inner.connections.clear();
            debug!(addr = %addr, count = count, "Closed pooled connections");
        }
    }
    
    /// Get pool statistics
    pub async fn stats(&self) -> PoolStats {
        let pools = self.pools.read();
        let mut total_connections = 0;
        let mut total_pending = 0;
        let mut endpoints = 0;
        
        for pool in pools.values() {
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

/// Check if a TCP connection is still alive (non-blocking)
fn is_connection_alive(stream: &TcpStream) -> bool {
    // Try a non-blocking read to check connection state
    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        Ok(0) => false, // Connection closed
        Ok(_) => true,  // Data available (shouldn't happen, but connection is alive)
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // No data, but alive
        Err(_) => false, // Some error, assume dead
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
    Fut: std::future::Future<Output = Result<TcpStream>> + Send,
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
}
