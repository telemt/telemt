//! Error Types

#![allow(dead_code)]

use std::fmt;
use std::net::SocketAddr;
use thiserror::Error;

// ============= Stream Errors =============

/// Errors specific to stream I/O operations
#[derive(Debug)]
pub enum StreamError {
    /// Partial read: got fewer bytes than expected
    PartialRead {
        expected: usize,
        got: usize,
    },
    /// Partial write: wrote fewer bytes than expected
    PartialWrite {
        expected: usize,
        written: usize,
    },
    /// Stream is in poisoned state and cannot be used
    Poisoned {
        reason: String,
    },
    /// Buffer overflow: attempted to buffer more than allowed
    BufferOverflow {
        limit: usize,
        attempted: usize,
    },
    /// Invalid frame format
    InvalidFrame {
        details: String,
    },
    /// Unexpected end of stream
    UnexpectedEof,
    /// Underlying I/O error
    Io(std::io::Error),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartialRead { expected, got } => {
                write!(f, "partial read: expected {} bytes, got {}", expected, got)
            }
            Self::PartialWrite { expected, written } => {
                write!(f, "partial write: expected {} bytes, wrote {}", expected, written)
            }
            Self::Poisoned { reason } => {
                write!(f, "stream poisoned: {}", reason)
            }
            Self::BufferOverflow { limit, attempted } => {
                write!(f, "buffer overflow: limit {}, attempted {}", limit, attempted)
            }
            Self::InvalidFrame { details } => {
                write!(f, "invalid frame: {}", details)
            }
            Self::UnexpectedEof => {
                write!(f, "unexpected end of stream")
            }
            Self::Io(e) => {
                write!(f, "I/O error: {}", e)
            }
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StreamError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<StreamError> for std::io::Error {
    fn from(err: StreamError) -> Self {
        match err {
            StreamError::Io(e) => e,
            StreamError::UnexpectedEof => {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, err)
            }
            StreamError::Poisoned { .. } => {
                std::io::Error::other(err)
            }
            StreamError::BufferOverflow { .. } => {
                std::io::Error::new(std::io::ErrorKind::OutOfMemory, err)
            }
            StreamError::InvalidFrame { .. } => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, err)
            }
            StreamError::PartialRead { .. } | StreamError::PartialWrite { .. } => {
                std::io::Error::other(err)
            }
        }
    }
}

// ============= Recoverable Trait =============

/// Trait for errors that may be recoverable
pub trait Recoverable {
    /// Check if error is recoverable (can retry operation)
    fn is_recoverable(&self) -> bool;
    
    /// Check if connection can continue after this error
    fn can_continue(&self) -> bool;
}

impl Recoverable for StreamError {
    fn is_recoverable(&self) -> bool {
        match self {
            Self::PartialRead { .. } | Self::PartialWrite { .. } => true,
            Self::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock 
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::TimedOut
            ),
            Self::Poisoned { .. } 
            | Self::BufferOverflow { .. }
            | Self::InvalidFrame { .. }
            | Self::UnexpectedEof => false,
        }
    }
    
    fn can_continue(&self) -> bool {
        !matches!(self, Self::Poisoned { .. } | Self::UnexpectedEof | Self::BufferOverflow { .. })
    }
}

impl Recoverable for std::io::Error {
    fn is_recoverable(&self) -> bool {
        matches!(
            self.kind(),
            std::io::ErrorKind::WouldBlock 
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::TimedOut
        )
    }
    
    fn can_continue(&self) -> bool {
        !matches!(
            self.kind(),
            std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
        )
    }
}

// ============= Main Proxy Errors =============

#[derive(Error, Debug)]
pub enum ProxyError {
    // ============= Crypto Errors =============
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    
    // ============= Stream Errors =============
    
    #[error("Stream error: {0}")]
    Stream(#[from] StreamError),
    
    // ============= Protocol Errors =============
    
    #[error("Invalid handshake: {0}")]
    InvalidHandshake(String),
    
    #[error("Invalid protocol tag: {0:02x?}")]
    InvalidProtoTag([u8; 4]),
    
    #[error("Invalid TLS record: type={record_type}, version={version:02x?}")]
    InvalidTlsRecord { record_type: u8, version: [u8; 2] },
    
    #[error("Replay attack detected from {addr}")]
    ReplayAttack { addr: SocketAddr },
    
    #[error("Time skew detected: client={client_time}, server={server_time}")]
    TimeSkew { client_time: u32, server_time: u32 },
    
    #[error("Invalid message length: {len} (min={min}, max={max})")]
    InvalidMessageLength { len: usize, min: usize, max: usize },
    
    #[error("Checksum mismatch: expected={expected:08x}, got={got:08x}")]
    ChecksumMismatch { expected: u32, got: u32 },
    
    #[error("Sequence number mismatch: expected={expected}, got={got}")]
    SeqNoMismatch { expected: i32, got: i32 },
    
    #[error("TLS handshake failed: {reason}")]
    TlsHandshakeFailed { reason: String },
    
    #[error("Telegram handshake timeout")]
    TgHandshakeTimeout,
    
    // ============= Network Errors =============
    
    #[error("Connection timeout to {addr}")]
    ConnectionTimeout { addr: String },
    
    #[error("Connection refused by {addr}")]
    ConnectionRefused { addr: String },
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    // ============= Proxy Protocol Errors =============
    
    #[error("Invalid proxy protocol header")]
    InvalidProxyProtocol,
    
    #[error("Proxy error: {0}")]
    Proxy(String),
    
    // ============= Config Errors =============
    
    #[error("Config error: {0}")]
    Config(String),
    
    #[error("Invalid secret for user {user}: {reason}")]
    InvalidSecret { user: String, reason: String },
    
    // ============= User Errors =============
    
    #[error("User {user} expired")]
    UserExpired { user: String },
    
    #[error("User {user} exceeded connection limit")]
    ConnectionLimitExceeded { user: String },
    
    #[error("User {user} exceeded data quota")]
    DataQuotaExceeded { user: String },
    
    #[error("Unknown user")]
    UnknownUser,
    
    #[error("Rate limited")]
    RateLimited,
    
    // ============= General Errors =============
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Recoverable for ProxyError {
    fn is_recoverable(&self) -> bool {
        match self {
            Self::Stream(e) => e.is_recoverable(),
            Self::Io(e) => e.is_recoverable(),
            Self::ConnectionTimeout { .. } => true,
            Self::RateLimited => true,
            _ => false,
        }
    }
    
    fn can_continue(&self) -> bool {
        match self {
            Self::Stream(e) => e.can_continue(),
            Self::Io(e) => e.can_continue(),
            _ => false,
        }
    }
}

/// Convenient Result type alias
pub type Result<T> = std::result::Result<T, ProxyError>;

/// Result type for stream operations
pub type StreamResult<T> = std::result::Result<T, StreamError>;

/// Result with optional bad client handling
#[derive(Debug)]
pub enum HandshakeResult<T, R, W> {
    /// Handshake succeeded
    Success(T),
    /// Client failed validation, needs masking. Returns ownership of streams.
    BadClient { reader: R, writer: W },
    /// Error occurred
    Error(ProxyError),
}

impl<T, R, W> HandshakeResult<T, R, W> {
    /// Check if successful
    pub fn is_success(&self) -> bool {
        matches!(self, HandshakeResult::Success(_))
    }
    
    /// Check if bad client
    pub fn is_bad_client(&self) -> bool {
        matches!(self, HandshakeResult::BadClient { .. })
    }
    
    /// Map the success value
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> HandshakeResult<U, R, W> {
        match self {
            HandshakeResult::Success(v) => HandshakeResult::Success(f(v)),
            HandshakeResult::BadClient { reader, writer } => HandshakeResult::BadClient { reader, writer },
            HandshakeResult::Error(e) => HandshakeResult::Error(e),
        }
    }
}

impl<T, R, W> From<ProxyError> for HandshakeResult<T, R, W> {
    fn from(err: ProxyError) -> Self {
        HandshakeResult::Error(err)
    }
}

impl<T, R, W> From<std::io::Error> for HandshakeResult<T, R, W> {
    fn from(err: std::io::Error) -> Self {
        HandshakeResult::Error(ProxyError::Io(err))
    }
}

impl<T, R, W> From<StreamError> for HandshakeResult<T, R, W> {
    fn from(err: StreamError) -> Self {
        HandshakeResult::Error(ProxyError::Stream(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stream_error_display() {
        let err = StreamError::PartialRead { expected: 100, got: 50 };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));
        
        let err = StreamError::Poisoned { reason: "test".into() };
        assert!(err.to_string().contains("test"));
    }
    
    #[test]
    fn test_stream_error_recoverable() {
        assert!(StreamError::PartialRead { expected: 10, got: 5 }.is_recoverable());
        assert!(StreamError::PartialWrite { expected: 10, written: 5 }.is_recoverable());
        assert!(!StreamError::Poisoned { reason: "x".into() }.is_recoverable());
        assert!(!StreamError::UnexpectedEof.is_recoverable());
    }
    
    #[test]
    fn test_stream_error_can_continue() {
        assert!(!StreamError::Poisoned { reason: "x".into() }.can_continue());
        assert!(!StreamError::UnexpectedEof.can_continue());
        assert!(StreamError::PartialRead { expected: 10, got: 5 }.can_continue());
    }
    
    #[test]
    fn test_stream_error_to_io_error() {
        let stream_err = StreamError::UnexpectedEof;
        let io_err: std::io::Error = stream_err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
    
    #[test]
    fn test_handshake_result() {
        let success: HandshakeResult<i32, (), ()> = HandshakeResult::Success(42);
        assert!(success.is_success());
        assert!(!success.is_bad_client());
        
        let bad: HandshakeResult<i32, (), ()> = HandshakeResult::BadClient { reader: (), writer: () };
        assert!(!bad.is_success());
        assert!(bad.is_bad_client());
    }
    
    #[test]
    fn test_handshake_result_map() {
        let success: HandshakeResult<i32, (), ()> = HandshakeResult::Success(42);
        let mapped = success.map(|x| x * 2);
        
        match mapped {
            HandshakeResult::Success(v) => assert_eq!(v, 84),
            _ => panic!("Expected success"),
        }
    }
    
    #[test]
    fn test_proxy_error_recoverable() {
        let err = ProxyError::RateLimited;
        assert!(err.is_recoverable());
        
        let err = ProxyError::InvalidHandshake("bad".into());
        assert!(!err.is_recoverable());
    }
    
    #[test]
    fn test_error_display() {
        let err = ProxyError::ConnectionTimeout { addr: "1.2.3.4:443".into() };
        assert!(err.to_string().contains("1.2.3.4:443"));
        
        let err = ProxyError::InvalidProxyProtocol;
        assert!(err.to_string().contains("proxy protocol"));
    }
}