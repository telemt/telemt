use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_util::sync::CancellationToken;

use super::CarrierSocket;
use crate::web::manager::{ManagerError, WebProcessRuntime, WebSocketBudgetLease};
use crate::web::session::{WebSession, WebSocketLaneReservation};
use crate::web::trace::{TraceDirection, TraceWebSocketContext};

pub(super) async fn read_message(
    socket: &mut CarrierSocket,
    runtime: &Arc<WebProcessRuntime>,
    owner: crate::web::manager::ProfileKey,
    cancellation: &CancellationToken,
    retained_budget: &mut Option<WebSocketBudgetLease>,
    maximum: usize,
    backpressure_timeout: Duration,
) -> Result<(Message, Option<WebSocketBudgetLease>), ()> {
    tokio::select! {
        _ = cancellation.cancelled() => return Err(()),
        ready = socket.get_ref().readable() => ready.map_err(|_| ())?,
    }
    if retained_budget.is_none() {
        *retained_budget =
            Some(reserve_data(runtime, owner, maximum, cancellation, backpressure_timeout).await?);
    }
    let message = tokio::select! {
        _ = cancellation.cancelled() => return Err(()),
        message = socket.next() => message.ok_or(())?.map_err(|_| ())?,
    };
    if socket.get_ref().websocket_fragmented_message() {
        return Ok((message, None));
    }
    let mut budget = retained_budget.take().ok_or(())?;
    budget.shrink_to(message.len());
    Ok((message, Some(budget)))
}

pub(super) async fn reserve_data(
    runtime: &Arc<WebProcessRuntime>,
    owner: crate::web::manager::ProfileKey,
    bytes: usize,
    cancellation: &CancellationToken,
    timeout: Duration,
) -> Result<WebSocketBudgetLease, ()> {
    match tokio::time::timeout(timeout, async {
        loop {
            if cancellation.is_cancelled() {
                return Err(());
            }
            let notify = runtime.budget_notify();
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(budget) = runtime.try_websocket_data_budget(owner, bytes.max(1)) {
                return Ok(budget);
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Err(()),
                _ = notified => {}
            }
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => {
            runtime.telemetry().record_rejection(
                crate::web::telemetry::WebRejectionReason::WebSocketBytesCapacity,
            );
            Err(())
        }
    }
}

pub(super) async fn process_multiplex(
    runtime: &Arc<WebProcessRuntime>,
    session: &Arc<WebSession>,
    sequence: u64,
    body: &[u8],
    cancellation: &CancellationToken,
    timeout: Duration,
) -> Result<bool, ()> {
    retry_backpressure(runtime, cancellation, timeout, || {
        session.process_websocket_multiplex(sequence, body)
    })
    .await
}

pub(super) async fn process_lane(
    runtime: &Arc<WebProcessRuntime>,
    session: &Arc<WebSession>,
    reservation: &mut WebSocketLaneReservation,
    sequence: u64,
    body: &[u8],
    cancellation: &CancellationToken,
    timeout: Duration,
) -> Result<bool, ()> {
    tokio::time::timeout(timeout, async {
        loop {
            if cancellation.is_cancelled() {
                return Err(());
            }
            let notify = runtime.budget_notify();
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match session.process_websocket_lane(reservation, sequence, body) {
                Ok(progressed) => return Ok(progressed),
                Err(ManagerError::Backpressure) => {}
                Err(_) => return Err(()),
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Err(()),
                _ = notified => {}
            }
        }
    })
    .await
    .map_err(|_| ())?
}

async fn retry_backpressure<F, T>(
    runtime: &Arc<WebProcessRuntime>,
    cancellation: &CancellationToken,
    timeout: Duration,
    mut operation: F,
) -> Result<T, ()>
where
    F: FnMut() -> Result<T, ManagerError>,
{
    tokio::time::timeout(timeout, async {
        loop {
            if cancellation.is_cancelled() {
                return Err(());
            }
            let notify = runtime.budget_notify();
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match operation() {
                Ok(value) => return Ok(value),
                Err(ManagerError::Backpressure) => {}
                Err(_) => return Err(()),
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Err(()),
                _ = notified => {}
            }
        }
    })
    .await
    .map_err(|_| ())?
}

pub(super) async fn send(
    socket: &mut CarrierSocket,
    message: Message,
    cancellation: &CancellationToken,
    timeout: Duration,
) -> Result<(), ()> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(()),
        result = tokio::time::timeout(timeout, socket.send(message)) => {
            result.map_err(|_| ())?.map_err(|_| ())
        }
    }
}

pub(super) async fn flush(
    socket: &mut CarrierSocket,
    cancellation: &CancellationToken,
    timeout: Duration,
) -> Result<(), ()> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(()),
        result = tokio::time::timeout(timeout, socket.flush()) => {
            result.map_err(|_| ())?.map_err(|_| ())
        }
    }
}

pub(super) fn record_message(
    runtime: &WebProcessRuntime,
    trace: Option<&TraceWebSocketContext>,
    direction: TraceDirection,
    message_type: &'static str,
    payload: &[u8],
    started: Instant,
) {
    let Some(trace) = trace else {
        return;
    };
    runtime.trace().record_websocket_message(
        trace,
        direction,
        message_type,
        payload,
        started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
    );
}
