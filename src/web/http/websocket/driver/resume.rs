use std::time::Duration;

use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_util::sync::CancellationToken;

use super::CarrierSocket;
use super::io::send;
use crate::web::manager::{WebSocketConnection, WebSocketKind};
use crate::web::session::{WebSession, WebSocketLaneReservation};

// The challenge and reply are fixed-size and use the existing per-socket write budget.
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);

fn decode_challenge(body: &[u8]) -> Option<[u8; 16]> {
    if body.len() != 24 || body[0] != 5 || body[1..4] != [0, 0, 0] || body[4..8] != [0, 0, 0, 16] {
        return None;
    }
    body[8..].try_into().ok()
}

pub(super) async fn respond_multiplex(
    body: &[u8],
    active: bool,
    socket: &mut CarrierSocket,
    session: &WebSession,
    connection: &WebSocketConnection,
    cancellation: &CancellationToken,
) -> Result<bool, ()> {
    let Some(nonce) = decode_challenge(body) else {
        return Ok(false);
    };
    if !active || !connection.is_current_resume_owner(session, WebSocketKind::Multiplex) {
        return Err(());
    }
    let reply = crate::web::frame::encode(crate::web::frame::FrameType::Pong, 0, &nonce);
    send(socket, Message::Binary(reply), cancellation, WRITE_TIMEOUT).await?;
    if !connection.is_current_resume_owner(session, WebSocketKind::Multiplex)
        || !session.record_websocket_peer_activity()
    {
        return Err(());
    }
    connection.mark_peer_activity();
    Ok(true)
}

pub(super) async fn respond_lane(
    body: &[u8],
    active: bool,
    socket: &mut CarrierSocket,
    session: &WebSession,
    connection: &WebSocketConnection,
    reservation: &WebSocketLaneReservation,
    cancellation: &CancellationToken,
) -> Result<bool, ()> {
    let Some(nonce) = decode_challenge(body) else {
        return Ok(false);
    };
    let kind = WebSocketKind::Lane(reservation.lane_id());
    if !active
        || !connection.is_current_resume_owner(session, kind)
        || !reservation.is_current_resume_lane(connection.id())
    {
        return Err(());
    }
    let reply = crate::web::frame::encode(crate::web::frame::FrameType::Pong, 0, &nonce);
    send(socket, Message::Binary(reply), cancellation, WRITE_TIMEOUT).await?;
    if !connection.is_current_resume_owner(session, kind)
        || !reservation.is_current_resume_lane(connection.id())
        || !session.record_websocket_peer_activity()
    {
        return Err(());
    }
    connection.mark_peer_activity();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::decode_challenge;
    use crate::web::frame::{self, FrameType};

    #[test]
    fn accepts_only_one_exact_stream_zero_nonce_challenge() {
        let nonce = [0xA5; 16];
        assert_eq!(
            decode_challenge(&frame::encode(FrameType::Ping, 0, &nonce)),
            Some(nonce)
        );
        assert!(decode_challenge(&frame::encode(FrameType::Ping, 1, &nonce)).is_none());
        assert!(decode_challenge(&frame::encode(FrameType::Ping, 0, &[1; 15])).is_none());
        assert!(decode_challenge(&frame::encode(FrameType::Ping, 0, &[1; 17])).is_none());
        assert!(decode_challenge(&frame::encode(FrameType::Pong, 0, &nonce)).is_none());
        let mut mixed = frame::encode(FrameType::Ping, 0, &nonce).to_vec();
        mixed.extend_from_slice(&frame::encode(FrameType::Data, 7, &[1]));
        assert!(decode_challenge(&mixed).is_none());
    }
}
