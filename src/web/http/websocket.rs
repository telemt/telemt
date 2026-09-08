use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode};
use ipnetwork::IpNetwork;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;

use super::body::RequestBody;
use super::decoy::serve_decoy;
use super::request::client_ip;
use super::response::{full_response, insert_header};
use super::{HttpResponse, request_trace, set_trace_route};
use crate::config::{WebCarrier, WebClientIpSource, WebRuntimeVhost};
use crate::web::manager::{TokenHash, WebProcessRuntime, WebSocketKind};
use crate::web::trace::TraceRoute;

// Codec buffers and fixed driver state are charged before HTTP 101 commits.
const BASE_BUDGET_BYTES: usize = 132 * 1024;
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Accepted connection IO retains the process HTTP slot after an upgrade.
pub(super) struct ConnectionIo {
    stream: TcpStream,
    _connection_permit: OwnedSemaphorePermit,
    websocket_read: Option<WebSocketReadBoundary>,
}

impl ConnectionIo {
    pub(super) fn new(stream: TcpStream, connection_permit: OwnedSemaphorePermit) -> Self {
        Self {
            stream,
            _connection_permit: connection_permit,
            websocket_read: None,
        }
    }

    async fn readable(&self) -> std::io::Result<()> {
        if self
            .websocket_read
            .as_ref()
            .is_some_and(WebSocketReadBoundary::has_buffered)
        {
            return Ok(());
        }
        // Readiness can remain set after a complete frame is drained. Confirm
        // actual input without consuming it before reserving a message budget.
        let mut byte = [0u8; 1];
        self.stream.peek(&mut byte).await.map(|_| ())
    }

    fn enable_websocket(&mut self, buffered: Bytes) {
        self.websocket_read = Some(WebSocketReadBoundary::new(buffered));
    }

    fn websocket_fragmented_message(&self) -> bool {
        self.websocket_read
            .as_ref()
            .is_some_and(WebSocketReadBoundary::fragmented_message)
    }
}

// Frame-boundary reads keep the kernel readiness gate authoritative even when
// Hyper read-ahead or one TCP packet contains several WebSocket messages.
enum WebSocketReadState {
    Header {
        bytes: [u8; 14],
        filled: usize,
        target: usize,
    },
    Payload {
        remaining: usize,
    },
}

struct WebSocketReadBoundary {
    buffered: Bytes,
    state: WebSocketReadState,
    fragmented_message: bool,
}

impl WebSocketReadBoundary {
    fn new(buffered: Bytes) -> Self {
        Self {
            buffered,
            state: Self::new_header(),
            fragmented_message: false,
        }
    }

    fn has_buffered(&self) -> bool {
        !self.buffered.is_empty()
    }

    fn fragmented_message(&self) -> bool {
        self.fragmented_message
    }

    fn maximum_read(&self, requested: usize) -> usize {
        let boundary = match self.state {
            WebSocketReadState::Header { filled, target, .. } => target.saturating_sub(filled),
            WebSocketReadState::Payload { remaining } => remaining,
        };
        requested.min(boundary)
    }

    fn observe(&mut self, bytes: &[u8]) {
        match &mut self.state {
            WebSocketReadState::Header {
                bytes: header,
                filled,
                target,
            } => {
                debug_assert!(bytes.len() <= target.saturating_sub(*filled));
                header[*filled..*filled + bytes.len()].copy_from_slice(bytes);
                *filled += bytes.len();
                if *filled == 2 && *target == 2 {
                    let extended = match header[1] & 0x7f {
                        126 => 2,
                        127 => 8,
                        _ => 0,
                    };
                    let mask = usize::from(header[1] & 0x80 != 0) * 4;
                    *target = 2 + extended + mask;
                }
                if *filled == *target {
                    let finished = header[0] & 0x80 != 0;
                    match header[0] & 0x0f {
                        0 if finished => self.fragmented_message = false,
                        1 | 2 if !finished => self.fragmented_message = true,
                        _ => {}
                    }
                    let payload = match header[1] & 0x7f {
                        value @ 0..=125 => usize::from(value),
                        126 => usize::from(u16::from_be_bytes([header[2], header[3]])),
                        127 => usize::try_from(u64::from_be_bytes([
                            header[2], header[3], header[4], header[5], header[6], header[7],
                            header[8], header[9],
                        ]))
                        .unwrap_or(usize::MAX),
                        _ => unreachable!(),
                    };
                    self.state = if payload == 0 {
                        Self::new_header()
                    } else {
                        WebSocketReadState::Payload { remaining: payload }
                    };
                }
            }
            WebSocketReadState::Payload { remaining } => {
                debug_assert!(bytes.len() <= *remaining);
                *remaining -= bytes.len();
                if *remaining == 0 {
                    self.state = Self::new_header();
                }
            }
        }
    }

    fn new_header() -> WebSocketReadState {
        WebSocketReadState::Header {
            bytes: [0; 14],
            filled: 0,
            target: 2,
        }
    }
}

impl AsyncRead for ConnectionIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let Some(boundary) = this.websocket_read.as_mut() else {
            return Pin::new(&mut this.stream).poll_read(context, buffer);
        };
        let maximum = boundary.maximum_read(buffer.remaining());
        if maximum == 0 {
            return Poll::Ready(Ok(()));
        }
        if !boundary.buffered.is_empty() {
            let bytes = boundary
                .buffered
                .split_to(maximum.min(boundary.buffered.len()));
            boundary.observe(&bytes);
            buffer.put_slice(&bytes);
            return Poll::Ready(Ok(()));
        }
        let unfilled = buffer.initialize_unfilled_to(maximum);
        let mut limited = ReadBuf::new(unfilled);
        match Pin::new(&mut this.stream).poll_read(context, &mut limited) {
            Poll::Ready(Ok(())) => {
                let filled = limited.filled().len();
                boundary.observe(limited.filled());
                buffer.advance(filled);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ConnectionIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

enum ParsedCarrier {
    Multiplex,
    Lane(u32),
}

struct ParsedUpgrade {
    token_hash: TokenHash,
    protocol: String,
    accept: String,
    carrier: ParsedCarrier,
    acknowledge_commit: bool,
}

pub(super) async fn handle(
    mut request: Request<RequestBody>,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
) -> HttpResponse {
    let request_deadline = super::request_deadline(&request);
    let Some(parsed) = parse_upgrade(&request) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if !request.body_mut().finish_empty() {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let Some(effective_ip) = client_ip(&request, peer, client_ip_source, trusted_proxy_cidrs)
    else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    let Ok(session) = runtime.get_session(parsed.token_hash, &vhost.host) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    let kind = match (parsed.carrier, session.carrier()) {
        (ParsedCarrier::Multiplex, WebCarrier::Websocket) => WebSocketKind::Multiplex,
        (ParsedCarrier::Lane(lane_id), WebCarrier::WebsocketLanes) => WebSocketKind::Lane(lane_id),
        _ => return serve_decoy(request, vhost, true, &runtime).await,
    };
    let mut probe_reservation = match session.reserve_websocket_probe(parsed.acknowledge_commit) {
        Ok(reservation) => reservation,
        Err(_) => return serve_decoy(request, vhost, true, &runtime).await,
    };
    let mut lane_reservation = match kind {
        WebSocketKind::Multiplex => None,
        WebSocketKind::Lane(lane_id) => match session.reserve_websocket_lane(lane_id) {
            Ok(reservation) => Some(reservation),
            Err(_) => return serve_decoy(request, vhost, true, &runtime).await,
        },
    };
    let timeouts = session.timeouts().clone();
    let admission_lease = match request_deadline.as_ref() {
        Some(deadline) => {
            match deadline.lease_for(Duration::from_secs(timeouts.websocket_eviction_secs)) {
                Some(lease) => Some(lease),
                None => return serve_decoy(request, vhost, true, &runtime).await,
            }
        }
        None => None,
    };
    let admitted = runtime
        .admit_websocket(
            session.profile_key(),
            session.trace_session_id(),
            session.token_hash(),
            effective_ip,
            kind,
            BASE_BUDGET_BYTES,
            Duration::from_secs(timeouts.long_poll_secs),
            Duration::from_secs(timeouts.websocket_eviction_secs),
            session.carrier_cancellation(),
        )
        .await;
    drop(admission_lease);
    let connection = match admitted {
        Ok(connection) => connection,
        Err(_) => return serve_decoy(request, vhost, true, &runtime).await,
    };
    if let Some(reservation) = lane_reservation.as_mut()
        && reservation.bind(connection.id()).is_err()
    {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    if let Some(reservation) = probe_reservation.as_mut()
        && reservation.bind(connection.id()).is_err()
    {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let trace_context = runtime.trace().websocket_context(
        &request,
        peer.ip(),
        effective_ip,
        connection.id(),
        match kind {
            WebSocketKind::Multiplex => None,
            WebSocketKind::Lane(lane_id) => Some(lane_id),
        },
        || session.trace_identity(),
    );
    if let Some(trace) = request_trace(&request) {
        trace.set_effective_ip(effective_ip);
        trace.set_route(TraceRoute::Websocket);
        trace.bind_identity(session.trace_identity());
        trace.register_redaction(parsed.protocol.as_bytes());
    }
    let upgrade_deadline = match request_deadline.as_ref() {
        Some(deadline) => {
            let Some(until) = tokio::time::Instant::now()
                .checked_add(Duration::from_secs(timeouts.websocket_upgrade_secs))
            else {
                return serve_decoy(request, vhost, true, &runtime).await;
            };
            match deadline.upgrade_until(until) {
                Some(lease) => Some(lease),
                None => return serve_decoy(request, vhost, true, &runtime).await,
            }
        }
        None => None,
    };
    let on_upgrade = hyper::upgrade::on(&mut request);
    let protocol = parsed.protocol;
    let accept = parsed.accept;
    let driver_runtime = Arc::clone(&runtime);
    let driver_session = Arc::clone(&session);
    runtime.spawn_auxiliary(async move {
        driver::run_upgraded(
            on_upgrade,
            upgrade_deadline,
            driver_runtime,
            driver_session,
            connection,
            lane_reservation.take(),
            probe_reservation.take(),
            trace_context,
            parsed.acknowledge_commit,
        )
        .await;
    });
    set_trace_route(&request, TraceRoute::Websocket);
    let mut response = full_response(StatusCode::SWITCHING_PROTOCOLS, Bytes::new());
    response.headers_mut().remove(header::CONTENT_LENGTH);
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    response
        .headers_mut()
        .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    insert_header(
        &mut response,
        HeaderName::from_static("sec-websocket-accept"),
        &accept,
    );
    insert_header(
        &mut response,
        HeaderName::from_static("sec-websocket-protocol"),
        &protocol,
    );
    response
}

fn parse_upgrade<B>(request: &Request<B>) -> Option<ParsedUpgrade> {
    if request.method() != Method::GET
        || request.uri().query().is_some()
        || request.headers().contains_key(header::AUTHORIZATION)
        || request.headers().contains_key(header::CONTENT_LENGTH)
        || request.headers().contains_key(header::TRANSFER_ENCODING)
        || !single_header_eq(request, header::UPGRADE, "websocket")
        || !single_header_eq(request, "sec-websocket-version", "13")
        || !header_has_token(request, header::CONNECTION, "upgrade")
    {
        return None;
    }
    let key = single_header(request, "sec-websocket-key")?;
    let decoded_key = base64::engine::general_purpose::STANDARD.decode(key).ok()?;
    if decoded_key.len() != 16
        || base64::engine::general_purpose::STANDARD.encode(&decoded_key) != key
    {
        return None;
    }
    let protocol = single_header(request, "sec-websocket-protocol")?;
    if protocol
        .bytes()
        .any(|value| value == b',' || value.is_ascii_whitespace())
    {
        return None;
    }
    let (token, carrier, acknowledge_commit) =
        if let Some(token) = protocol.strip_prefix("tproxy-auto-v1.") {
            (token, ParsedCarrier::Multiplex, true)
        } else if let Some(lane) = protocol.strip_prefix("tproxy-auto-lane-v1.") {
            let (token, lane_id) = parse_lane_protocol(lane)?;
            (token, ParsedCarrier::Lane(lane_id), true)
        } else if let Some(token) = protocol.strip_prefix("tproxy-v1.") {
            (token, ParsedCarrier::Multiplex, false)
        } else if let Some(lane) = protocol.strip_prefix("tproxy-lane-v1.") {
            let (token, lane_id) = parse_lane_protocol(lane)?;
            (token, ParsedCarrier::Lane(lane_id), false)
        } else {
            return None;
        };
    let raw_token = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .ok()?;
    if raw_token.len() != 32
        || token.len() != 43
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw_token) != token
    {
        return None;
    }
    let token_hash = Sha256::digest(&raw_token).into();
    let mut accept = Sha1::new();
    accept.update(key.as_bytes());
    accept.update(WEBSOCKET_GUID);
    Some(ParsedUpgrade {
        token_hash,
        protocol: protocol.to_string(),
        accept: base64::engine::general_purpose::STANDARD.encode(accept.finalize()),
        carrier,
        acknowledge_commit,
    })
}

fn parse_lane_protocol(value: &str) -> Option<(&str, u32)> {
    let (token, lane_id) = value.split_once('.')?;
    if lane_id.is_empty()
        || lane_id.starts_with('+')
        || (lane_id.len() > 1 && lane_id.starts_with('0'))
    {
        return None;
    }
    let lane_id = lane_id
        .parse::<u32>()
        .ok()
        .filter(|value| (1..=crate::web::frame::MAX_STREAM_ID).contains(value))?;
    Some((token, lane_id))
}

fn single_header<B>(request: &Request<B>, name: impl hyper::header::AsHeaderName) -> Option<&str> {
    let mut values = request.headers().get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

fn single_header_eq<B>(
    request: &Request<B>,
    name: impl hyper::header::AsHeaderName,
    expected: &str,
) -> bool {
    single_header(request, name).is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn header_has_token<B>(
    request: &Request<B>,
    name: impl hyper::header::AsHeaderName,
    expected: &str,
) -> bool {
    let mut found = false;
    for value in request.headers().get_all(name) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for token in value.split(',').map(str::trim) {
            if token.eq_ignore_ascii_case(expected) {
                if found {
                    return false;
                }
                found = true;
            }
        }
    }
    found
}

// Ordered WebSocket message relay and deadlines are isolated from handshake parsing.
mod driver;

#[cfg(test)]
mod tests;
