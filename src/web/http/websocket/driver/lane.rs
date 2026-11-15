use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_util::sync::CancellationToken;

use super::io::{flush, process_lane, read_message, record_message, reserve_data, send};
use super::{CarrierSocket, DataPlaneEvent, DriverEvent, FairDataSelector};
use crate::web::manager::{WebProcessRuntime, WebSocketConnection};
use crate::web::session::{SessionCloseReason, WebSession, WebSocketLaneReservation};
use crate::web::trace::{TraceDirection, TraceWebSocketContext};

#[allow(clippy::too_many_arguments)]
/// Drives one exact WebSocket lane until its isolated failure boundary closes.
pub(super) async fn run_lane(
    socket: &mut CarrierSocket,
    runtime: &Arc<WebProcessRuntime>,
    session: &Arc<WebSession>,
    connection: &WebSocketConnection,
    reservation: &mut WebSocketLaneReservation,
    cancellation: CancellationToken,
    trace: Option<&TraceWebSocketContext>,
    acknowledge_commit: bool,
) -> Result<(), ()> {
    let mut sequence = 1u64;
    let mut cursor = 0u64;
    // Lane reads use the same cancellation-safe fragmented-message ownership.
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
        let down = session.poll_down_websocket_lane(reservation.lane_identity(), cursor);
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
                    if super::resume::respond_lane(
                        &body,
                        active,
                        socket,
                        session,
                        connection,
                        reservation,
                        &cancellation,
                    )
                    .await?
                    {
                        next_ping = Instant::now() + liveness_interval;
                        continue;
                    }
                    let started = Instant::now();
                    let result = process_lane(
                        runtime,
                        session,
                        reservation,
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
                        if send(
                            socket,
                            Message::Binary(Bytes::new()),
                            &cancellation,
                            write_timeout,
                        )
                        .await
                        .is_err()
                        {
                            session.close(SessionCloseReason::Protocol);
                            return Err(());
                        }
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
                if result.lane_closed {
                    return Ok(());
                }
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
