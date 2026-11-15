use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_util::sync::CancellationToken;

use super::ConnectionIo;
use crate::web::http::activity::UpgradeDeadlineLease;
use crate::web::manager::{WebProcessRuntime, WebSocketBudgetLease, WebSocketConnection};
use crate::web::session::{
    SessionCloseReason, WebSession, WebSocketLaneReservation, WebSocketProbeReservation,
};
use crate::web::trace::{TraceDirection, TraceWebSocketContext};

const READ_BUFFER_BYTES: usize = 64 * 1024;
const WRITE_BUFFER_BYTES: usize = 64 * 1024;

// Cancellation-safe message I/O and budget retries remain separate from carrier loops.
mod io;
mod resume;
// Per-lane carrier state remains isolated from the multiplexed driver.
mod lane;
use io::{flush, process_multiplex, read_message, record_message, reserve_data, send};
use lane::run_lane;

// Upgrade ownership remains explicit across cancellation and reservation boundaries.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_upgraded(
    on_upgrade: hyper::upgrade::OnUpgrade,
    upgrade_deadline: Option<UpgradeDeadlineLease>,
    runtime: Arc<WebProcessRuntime>,
    session: Arc<WebSession>,
    connection: WebSocketConnection,
    mut lane_reservation: Option<WebSocketLaneReservation>,
    _probe_reservation: Option<WebSocketProbeReservation>,
    trace: Option<TraceWebSocketContext>,
    acknowledge_commit: bool,
) {
    let cancellation = connection.cancellation();
    let timeouts = session.timeouts().clone();
    let deadline = upgrade_deadline.as_ref().map_or_else(
        || tokio::time::Instant::now() + Duration::from_secs(timeouts.websocket_upgrade_secs),
        UpgradeDeadlineLease::deadline,
    );
    let upgraded = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout_at(deadline, on_upgrade) => result,
    };
    drop(upgrade_deadline);
    let Ok(Ok(upgraded)) = upgraded else {
        return;
    };
    let Ok(parts) = upgraded.downcast::<TokioIo<ConnectionIo>>() else {
        return;
    };
    let mut io = parts.io.into_inner();
    io.enable_websocket(parts.read_buf);
    let limits = session.limits().clone();
    let config = WebSocketConfig::default()
        .read_buffer_size(READ_BUFFER_BYTES)
        .write_buffer_size(WRITE_BUFFER_BYTES)
        .max_write_buffer_size(
            WRITE_BUFFER_BYTES
                .saturating_add(limits.carrier_batch_bytes)
                .saturating_add(1024),
        )
        .max_message_size(Some(limits.carrier_batch_bytes))
        .max_frame_size(Some(limits.carrier_batch_bytes));
    let mut socket = WebSocketStream::from_raw_socket(io, Role::Server, Some(config)).await;
    if !connection.mark_opened() {
        return;
    }
    if let Some(reservation) = lane_reservation.as_mut() {
        let _ = run_lane(
            &mut socket,
            &runtime,
            &session,
            &connection,
            reservation,
            cancellation.clone(),
            trace.as_ref(),
            acknowledge_commit,
        )
        .await;
    } else {
        let _ = run_multiplex(
            &mut socket,
            &runtime,
            &session,
            &connection,
            cancellation.clone(),
            trace.as_ref(),
            acknowledge_commit,
        )
        .await;
    }
    let eviction = Duration::from_secs(timeouts.websocket_eviction_secs);
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {}
        _ = tokio::time::timeout(eviction, socket.close(None)) => {}
    }
    if let Some(reservation) = lane_reservation {
        session.close_websocket_lane(reservation);
    } else if !acknowledge_commit || session.is_carrier_committed() {
        session.close(SessionCloseReason::WebSocketEnded);
    }
}

type CarrierSocket = WebSocketStream<ConnectionIo>;

enum DataPlaneEvent<I, D> {
    Incoming(I),
    Down(D),
}

#[derive(Default)]
struct FairDataSelector {
    prefer_down: bool,
}

impl FairDataSelector {
    async fn select<I, D>(&mut self, incoming: I, down: D) -> DataPlaneEvent<I::Output, D::Output>
    where
        I: Future,
        D: Future,
    {
        let event = if self.prefer_down {
            tokio::select! {
                biased;
                down = down => DataPlaneEvent::Down(down),
                incoming = incoming => DataPlaneEvent::Incoming(incoming),
            }
        } else {
            tokio::select! {
                biased;
                incoming = incoming => DataPlaneEvent::Incoming(incoming),
                down = down => DataPlaneEvent::Down(down),
            }
        };
        self.prefer_down = matches!(event, DataPlaneEvent::Incoming(_));
        event
    }
}

async fn run_multiplex(
    socket: &mut CarrierSocket,
    runtime: &Arc<WebProcessRuntime>,
    session: &Arc<WebSession>,
    connection: &WebSocketConnection,
    cancellation: CancellationToken,
    trace: Option<&TraceWebSocketContext>,
    acknowledge_commit: bool,
) -> Result<(), ()> {
    let mut sequence = 1u64;
    let mut cursor = 0u64;
    // The lease survives cancelled select branches and control frames interleaved
    // inside one fragmented data message.
    let mut read_budget = None;
    let liveness_interval = connection.liveness_interval();
    let mut next_ping = Instant::now() + liveness_interval;
    let open_deadline =
        Instant::now() + Duration::from_secs(session.timeouts().websocket_open_secs);
    let backpressure_timeout = Duration::from_secs(session.timeouts().websocket_backpressure_secs);
    let write_timeout = Duration::from_secs(session.timeouts().websocket_write_secs);
    let maximum_message = session.limits().carrier_batch_bytes;
    let mut active = false;
    let mut data_selector = FairDataSelector::default();
    loop {
        let down = session.poll_down_websocket(cursor);
        let event = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(()),
            _ = tokio::time::sleep_until(open_deadline.into()), if !active => return Err(()),
            _ = tokio::time::sleep_until(next_ping.into()) => DriverEvent::Liveness,
            data = data_selector.select(
                read_message(
                    socket,
                    runtime,
                    session.profile_key(),
                    &cancellation,
                    &mut read_budget,
                    maximum_message,
                    backpressure_timeout,
                ),
                down,
            ) => {
                match data {
                    DataPlaneEvent::Incoming(incoming) => DriverEvent::Incoming(incoming?),
                    DataPlaneEvent::Down(down) => DriverEvent::Down(down.map_err(|_| ())?),
                }
            }
        };
        match event {
            DriverEvent::Incoming((message, _budget)) => match message {
                Message::Binary(body) => {
                    if resume::respond_multiplex(
                        &body,
                        active,
                        socket,
                        session,
                        connection,
                        &cancellation,
                    )
                    .await?
                    {
                        next_ping = Instant::now() + liveness_interval;
                        continue;
                    }
                    let started = Instant::now();
                    let result = process_multiplex(
                        runtime,
                        session,
                        sequence,
                        &body,
                        &cancellation,
                        backpressure_timeout,
                    )
                    .await;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "binary",
                        &body,
                        started,
                    );
                    let progressed = result?;
                    if acknowledge_commit && sequence == 1 {
                        if !session.needs_websocket_commit_ack(connection.id()) {
                            return Err(());
                        }
                        let started = Instant::now();
                        send(
                            socket,
                            Message::Binary(Bytes::new()),
                            &cancellation,
                            write_timeout,
                        )
                        .await?;
                        record_message(
                            runtime,
                            trace,
                            TraceDirection::Response,
                            "carrier-ack",
                            &[],
                            started,
                        );
                        if !session.websocket_commit_ack_written(connection.id()) {
                            session.close(SessionCloseReason::Protocol);
                            return Err(());
                        }
                    } else if acknowledge_commit
                        && sequence > 1
                        && progressed
                        && !session.websocket_peer_after_commit_ack(connection.id())
                    {
                        return Err(());
                    }
                    if !active && progressed {
                        if !connection.mark_active() {
                            return Err(());
                        }
                        active = true;
                    }
                    sequence = sequence.checked_add(1).ok_or(())?;
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Pong(payload) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "pong",
                        &payload,
                        Instant::now(),
                    );
                    if !session.record_websocket_peer_activity() {
                        return Err(());
                    }
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Ping(payload) => {
                    let started = Instant::now();
                    flush(socket, &cancellation, write_timeout).await?;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "ping",
                        &payload,
                        started,
                    );
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Response,
                        "pong",
                        &payload,
                        started,
                    );
                    if !session.record_websocket_peer_activity() {
                        return Err(());
                    }
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Close(_) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "close",
                        &[],
                        Instant::now(),
                    );
                    return Ok(());
                }
                Message::Text(text) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "text",
                        text.as_bytes(),
                        Instant::now(),
                    );
                    return Err(());
                }
                Message::Frame(_) => return Err(()),
            },
            DriverEvent::Down(result) => {
                if result.body.is_empty() {
                    let started = Instant::now();
                    send(
                        socket,
                        Message::Ping(Bytes::new()),
                        &cancellation,
                        write_timeout,
                    )
                    .await?;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Response,
                        "ping",
                        &[],
                        started,
                    );
                    next_ping = Instant::now() + liveness_interval;
                } else {
                    let _budget = reserve_data(
                        runtime,
                        session.profile_key(),
                        result.body.len(),
                        &cancellation,
                        backpressure_timeout,
                    )
                    .await?;
                    let body = result.body;
                    let started = Instant::now();
                    if trace.is_some() {
                        send(
                            socket,
                            Message::Binary(body.clone()),
                            &cancellation,
                            write_timeout,
                        )
                        .await?;
                        record_message(
                            runtime,
                            trace,
                            TraceDirection::Response,
                            "binary",
                            &body,
                            started,
                        );
                    } else {
                        send(socket, Message::Binary(body), &cancellation, write_timeout).await?;
                    }
                    connection.mark_progress();
                }
                cursor = result.next_cursor;
            }
            DriverEvent::Liveness => {
                let started = Instant::now();
                send(
                    socket,
                    Message::Ping(Bytes::new()),
                    &cancellation,
                    write_timeout,
                )
                .await?;
                record_message(
                    runtime,
                    trace,
                    TraceDirection::Response,
                    "ping",
                    &[],
                    started,
                );
                next_ping = Instant::now() + liveness_interval;
            }
        }
    }
}

enum DriverEvent {
    Incoming((Message, Option<WebSocketBudgetLease>)),
    Down(crate::web::session::PollResult),
    Liveness,
}

#[cfg(test)]
mod fairness_tests {
    use super::*;

    #[tokio::test]
    async fn continuously_ready_directions_alternate() {
        let mut selector = FairDataSelector::default();
        for expected_incoming in [true, false, true, false] {
            let event = selector
                .select(std::future::ready("incoming"), std::future::ready("down"))
                .await;
            assert_eq!(
                matches!(event, DataPlaneEvent::Incoming(_)),
                expected_incoming
            );
        }
    }
}
