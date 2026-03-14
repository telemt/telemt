//! Error Types

#![allow(dead_code)]

use std::fmt;
use std::net::SocketAddr;
use thiserror::Error;

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
                Self::new(std::io::ErrorKind::UnexpectedEof, err)
            }
            StreamError::Poisoned { .. } => {
                Self::other(err)
            }
            StreamError::BufferOverflow { .. } => {
                Self::new(std::io::ErrorKind::OutOfMemory, err)
            }
            StreamError::InvalidFrame { .. } => {
                Self::new(std::io::ErrorKind::InvalidData, err)
            }
            StreamError::PartialRead { .. } | StreamError::PartialWrite { .. } => {
                Self::other(err)
            }
        }
    }
}

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

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    
    #[error("Stream error: {0}")]
    Stream(#[from] StreamError),
    
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
    
    #[error("Connection timeout to {addr}")]
    ConnectionTimeout { addr: String },
    
    #[error("Connection refused by {addr}")]
    ConnectionRefused { addr: String },
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Invalid proxy protocol header")]
    InvalidProxyProtocol,
    
    #[error("Proxy error: {0}")]
    Proxy(String),
    
    #[error("Config error: {0}")]
    Config(String),
    
    #[error("Invalid secret for user {user}: {reason}")]
    InvalidSecret { user: String, reason: String },
    
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
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }
    
    /// Check if bad client
    pub const fn is_bad_client(&self) -> bool {
        matches!(self, Self::BadClient { .. })
    }
    
    /// Map the success value
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> HandshakeResult<U, R, W> {
        match self {
            Self::Success(v) => HandshakeResult::Success(f(v)),
            Self::BadClient { reader, writer } => HandshakeResult::BadClient { reader, writer },
            Self::Error(e) => HandshakeResult::Error(e),
        }
    }
}

impl<T, R, W> From<ProxyError> for HandshakeResult<T, R, W> {
    fn from(err: ProxyError) -> Self {
        Self::Error(err)
    }
}

impl<T, R, W> From<std::io::Error> for HandshakeResult<T, R, W> {
    fn from(err: std::io::Error) -> Self {
        Self::Error(ProxyError::Io(err))
    }
}

impl<T, R, W> From<StreamError> for HandshakeResult<T, R, W> {
    fn from(err: StreamError) -> Self {
        Self::Error(ProxyError::Stream(err))
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

    #[test]
    fn stream_error_source_chain_tracks_io_error() {
        use std::error::Error;
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let stream_err: StreamError = io_err.into();
        assert!(stream_err.source().is_some(),
            "StreamError::Io must propagate source to the inner io::Error");

        let partial = StreamError::PartialRead { expected: 10, got: 5 };
        assert!(partial.source().is_none(),
            "PartialRead must have no chained source error");
    }

    #[test]
    fn all_stream_error_variants_have_non_empty_display() {
        let cases: &[(&str, &dyn std::fmt::Display)] = &[
            ("PartialRead",    &StreamError::PartialRead { expected: 100, got: 1 }),
            ("PartialWrite",   &StreamError::PartialWrite { expected: 200, written: 0 }),
            ("Poisoned",       &StreamError::Poisoned { reason: "corrupted".into() }),
            ("BufferOverflow", &StreamError::BufferOverflow { limit: 4096, attempted: 8192 }),
            ("InvalidFrame",   &StreamError::InvalidFrame { details: "bad magic byte".into() }),
            ("UnexpectedEof",  &StreamError::UnexpectedEof),
        ];
        for (name, v) in cases {
            assert!(!v.to_string().is_empty(),
                "StreamError::{name} must have a non-empty Display");
        }
    }

    #[test]
    fn recoverable_trait_all_stream_error_variants() {
        // Transient OS-level conditions that the caller may retry.
        assert!(StreamError::Io(
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "")
        ).is_recoverable(), "WouldBlock must be recoverable");
        assert!(StreamError::Io(
            std::io::Error::new(std::io::ErrorKind::Interrupted, "")
        ).is_recoverable(), "Interrupted must be recoverable");

        // Terminal conditions — stream is dead, retrying would be incorrect.
        assert!(!StreamError::Io(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "")
        ).is_recoverable(), "BrokenPipe must not be recoverable");
        assert!(!StreamError::Poisoned { reason: "x".into() }.is_recoverable());
        assert!(!StreamError::BufferOverflow { limit: 0, attempted: 1 }.is_recoverable());
        assert!(!StreamError::UnexpectedEof.is_recoverable());
        assert!(!StreamError::InvalidFrame { details: "x".into() }.is_recoverable());
    }

    #[test]
    fn can_continue_reflects_stream_liveness() {
        // Poisoned and Eof mean the stream can never be used again.
        assert!(!StreamError::Poisoned { reason: "x".into() }.can_continue());
        assert!(!StreamError::UnexpectedEof.can_continue());
        assert!(!StreamError::BufferOverflow { limit: 0, attempted: 1 }.can_continue());

        // These do not necessarily kill the stream.
        assert!(StreamError::InvalidFrame { details: "x".into() }.can_continue());
        assert!(StreamError::PartialRead { expected: 1, got: 0 }.can_continue());
        assert!(StreamError::PartialWrite { expected: 1, written: 0 }.can_continue());
    }

    #[test]
    fn stream_error_to_io_error_covers_all_variants() {
        // Every variant must map to the appropriate io::ErrorKind
        // so upstream callers using io::Error matching behave correctly.
        let eof: std::io::Error = StreamError::UnexpectedEof.into();
        assert_eq!(eof.kind(), std::io::ErrorKind::UnexpectedEof);

        let overflow: std::io::Error =
            StreamError::BufferOverflow { limit: 0, attempted: 1 }.into();
        assert_eq!(overflow.kind(), std::io::ErrorKind::OutOfMemory);

        let invalid: std::io::Error =
            StreamError::InvalidFrame { details: "x".into() }.into();
        assert_eq!(invalid.kind(), std::io::ErrorKind::InvalidData);

        // These must convert without panic; exact kind is implementation-defined.
        let _: std::io::Error = StreamError::PartialRead { expected: 1, got: 0 }.into();
        let _: std::io::Error = StreamError::PartialWrite { expected: 1, written: 0 }.into();
        let _: std::io::Error = StreamError::Poisoned { reason: "x".into() }.into();
    }

    #[test]
    fn handshake_result_map_preserves_all_variants() {
        let s: HandshakeResult<i32, (), ()> = HandshakeResult::Success(10);
        assert!(matches!(s.map(|v| v * 5), HandshakeResult::Success(50)));

        let b: HandshakeResult<i32, &str, &str> =
            HandshakeResult::BadClient { reader: "r", writer: "w" };
        assert!(matches!(b.map(|v: i32| v + 1), HandshakeResult::BadClient { .. }));

        let e: HandshakeResult<i32, (), ()> =
            HandshakeResult::Error(ProxyError::Internal("test".into()));
        assert!(matches!(e.map(|v| v + 1), HandshakeResult::Error(_)));
    }

    #[test]
    fn proxy_error_recoverable_reflects_security_intent() {
        // Transient network conditions — a retry is valid.
        assert!(
            ProxyError::ConnectionTimeout { addr: "1.2.3.4:443".into() }.is_recoverable(),
            "ConnectionTimeout is a transient network event"
        );
        assert!(ProxyError::RateLimited.is_recoverable(),
            "RateLimited implies a future retry is valid");

        // Security violations must NEVER be retried. Accepting the same
        // replayed packet again would constitute a vulnerability.
        let addr: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert!(!ProxyError::ReplayAttack { addr }.is_recoverable(),
            "ReplayAttack must not be recoverable — retrying would accept the attack");

        // Protocol and authentication errors are always final.
        assert!(!ProxyError::InvalidHandshake("bad".into()).is_recoverable());
        assert!(!ProxyError::UnknownUser.is_recoverable());
        assert!(!ProxyError::UserExpired { user: "x".into() }.is_recoverable());
    }

    #[test]
    fn proxy_error_display_contains_contextual_fields() {
        // Structured error fields must appear in Display output so that
        // log messages carry enough context for incident investigation.
        let err = ProxyError::InvalidKeyLength { expected: 32, got: 16 };
        let s = err.to_string();
        assert!(s.contains("32") && s.contains("16"),
            "InvalidKeyLength display must include both expected and got values");

        let err = ProxyError::TimeSkew { client_time: 1000, server_time: 9999 };
        let s = err.to_string();
        assert!(s.contains("1000") && s.contains("9999"),
            "TimeSkew display must include both timestamps");

        let addr: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let err = ProxyError::ReplayAttack { addr };
        assert!(err.to_string().contains("10.0.0.1"),
            "ReplayAttack display must include the source address");
    }
}