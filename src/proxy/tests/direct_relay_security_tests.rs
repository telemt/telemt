use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::{AesCtr, SecureRandom};
use crate::protocol::constants::ProtoTag;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration as TokioDuration, timeout};

fn make_crypto_reader<R>(reader: R) -> CryptoReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

fn nonempty_line_count(text: &str) -> usize {
    text.lines().filter(|line| !line.trim().is_empty()).count()
}

// Unknown-DC deduplication and path validation.
#[path = "direct_relay_security_tests/unknown_paths.rs"]
mod unknown_paths;
// No-follow file opening and target-swap defenses.
#[path = "direct_relay_security_tests/nofollow.rs"]
mod nofollow;
// Directory-anchored append and descriptor integrity.
#[path = "direct_relay_security_tests/anchored.rs"]
mod anchored;
// Asynchronous unknown-DC logging integration.
#[path = "direct_relay_security_tests/logging_integration.rs"]
mod logging_integration;
// Direct relay cancellation and cutover lifecycle.
#[path = "direct_relay_security_tests/relay_lifecycle.rs"]
mod relay_lifecycle;
// DC override routing and negative connection paths.
#[path = "direct_relay_security_tests/routing.rs"]
mod routing;
