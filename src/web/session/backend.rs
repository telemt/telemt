use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::proxy::shared_state::ConntrackClosePolicy;
use crate::web::frame::FrameType;
use crate::web::stream::WebLogicalStream;

use super::{StreamIdentity, WebSession, inbound_queue_cost};

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;

impl WebSession {
    /// Starts one owned inner handshake and relay task for an admitted stream.
    pub(super) fn spawn_stream(
        self: &Arc<Self>,
        completion: StreamCompletion,
        retain_reservation_on_reject: bool,
    ) -> bool {
        let stream = completion.stream;
        let peer_port = completion.peer_port;
        let Some(manager) = self.manager.upgrade() else {
            completion
                .retain_rejected
                .store(retain_reservation_on_reject, Ordering::Release);
            drop(completion);
            return false;
        };
        let generation = manager.active_generation();
        if !*generation.admission_rx.borrow() {
            manager.record_stream_rejected_reason(
                crate::web::telemetry::WebRejectionReason::GenerationAdmissionClosed,
            );
            self.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::StreamRejected,
                Some(stream.id),
                Some("admission_closed"),
            );
            completion
                .retain_rejected
                .store(retain_reservation_on_reject, Ordering::Release);
            drop(completion);
            return false;
        }
        let connection_permits = Arc::clone(&generation.max_connections);
        let deps = generation.client_runtime_deps();
        let replay_checker = Arc::clone(&generation.replay_checker);
        let session = Arc::clone(self);
        let cancel = self.cancel.clone();
        let retain_rejected = Arc::clone(&completion.retain_rejected);
        let future = async move {
            let _completion = completion;
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::StreamAdmitted,
                Some(stream.id),
                None,
            );
            let logical_stream = WebLogicalStream::new(Arc::clone(&session), stream);
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = run_stream(
                    Arc::clone(&session),
                    stream,
                    logical_stream,
                    deps,
                    replay_checker,
                    connection_permits,
                    peer_port,
                ) => {}
            }
        };
        if let Err(future) = generation.try_spawn_session(future) {
            manager.record_stream_rejected_reason(
                crate::web::telemetry::WebRejectionReason::GenerationScopeClosed,
            );
            retain_rejected.store(retain_reservation_on_reject, Ordering::Release);
            self.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::StreamRejected,
                Some(stream.id),
                Some("generation_closed"),
            );
            drop(future);
            return false;
        }
        true
    }

    fn stream_rejected_before_spawn(
        &self,
        stream: StreamIdentity,
        peer_port: u16,
        retain_reservation: bool,
    ) {
        if !retain_reservation {
            self.stream_finished(stream, peer_port);
            return;
        }
        let queued = {
            let mut state = self.state.lock();
            if state.closing_streams.get(&stream.id) == Some(&stream.instance) {
                state.closing_streams.remove(&stream.id);
                self.remember_closed_locked(&mut state, stream.id);
            }
            state
                .streams
                .get(&stream.id)
                .filter(|state| state.instance == stream.instance)
                .is_some()
                .then(|| state.streams.remove(&stream.id))
                .flatten()
                .map(|stream_state| {
                    let (bytes, items) = inbound_queue_cost(&stream_state.inbound);
                    self.release_locked(&mut state, bytes, items, false);
                    self.remember_closed_locked(&mut state, stream.id);
                    self.queue_control_locked(&mut state, FrameType::Close, stream.id, &[])
                })
        };
        if queued.is_some_and(|queued| !queued) {
            self.close();
        }
    }

    fn stream_finished(&self, stream: StreamIdentity, peer_port: u16) {
        let (queued, reserved) = {
            let mut state = self.state.lock();
            let reserved = state.active_peer_ports.remove(&peer_port);
            let current = state
                .streams
                .get(&stream.id)
                .is_some_and(|state| state.instance == stream.instance);
            let queued = current
                .then(|| state.streams.remove(&stream.id))
                .flatten()
                .map(|stream_state| {
                    let (bytes, items) = inbound_queue_cost(&stream_state.inbound);
                    self.release_locked(&mut state, bytes, items, false);
                    self.remember_closed_locked(&mut state, stream.id);
                    self.queue_control_locked(&mut state, FrameType::Close, stream.id, &[])
                });
            if state.closing_streams.get(&stream.id) == Some(&stream.instance) {
                state.closing_streams.remove(&stream.id);
                self.remember_closed_locked(&mut state, stream.id);
            }
            (queued, reserved)
        };
        if reserved && let Some(manager) = self.manager.upgrade() {
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                peer_port,
            );
        }
        if let Some(queued) = queued {
            if !queued {
                self.close();
            }
            if self.carrier().is_multiplexed() {
                self.down_notify.notify_waiters();
            }
        }
    }
}

pub(super) struct StreamCompletion {
    session: Arc<WebSession>,
    pub(super) stream: StreamIdentity,
    pub(super) peer_port: u16,
    retain_rejected: Arc<AtomicBool>,
}

impl WebSession {
    pub(super) fn own_stream_task(
        self: &Arc<Self>,
        stream: StreamIdentity,
        peer_port: u16,
    ) -> StreamCompletion {
        self.tasks_live.fetch_add(1, Ordering::AcqRel);
        StreamCompletion {
            session: Arc::clone(self),
            stream,
            peer_port,
            retain_rejected: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Drop for StreamCompletion {
    fn drop(&mut self) {
        self.session.trace_lifecycle(
            crate::web::trace::TraceLifecycleEvent::StreamClosed,
            Some(self.stream.id),
            None,
        );
        if self.retain_rejected.load(Ordering::Acquire) {
            self.session
                .stream_rejected_before_spawn(self.stream, self.peer_port, true);
        } else {
            self.session.stream_finished(self.stream, self.peer_port);
        }
        if self.session.tasks_live.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.session.tasks_done.notify_waiters();
        }
    }
}

async fn run_stream(
    session: Arc<WebSession>,
    stream_identity: StreamIdentity,
    stream: WebLogicalStream,
    deps: crate::proxy::authenticated::ClientRuntimeDeps,
    replay_checker: Arc<crate::stats::ReplayChecker>,
    connection_permits: Arc<tokio::sync::Semaphore>,
    peer_port: u16,
) {
    use tokio::io::AsyncReadExt;

    use crate::protocol::constants::HANDSHAKE_LEN;
    use crate::proxy::authenticated::run_authenticated;
    use crate::proxy::handshake::handle_mtproto_handshake_for_web_user;

    let (mut reader, writer) = tokio::io::split(stream);
    let mut handshake = [0u8; HANDSHAKE_LEN];
    let peer = std::net::SocketAddr::new(session.client_ip, peer_port);
    deps.stats.increment_connects_all();

    // Silent OPEN ownership has a separate absolute deadline so it cannot
    // consume stream and tuple quotas indefinitely before handshake admission.
    let first_byte = tokio::time::timeout(
        Duration::from_secs(session.timeouts.stream_first_byte_secs),
        reader.read_exact(&mut handshake[..1]),
    )
    .await;
    if first_byte.is_err() {
        session.trace_lifecycle(
            crate::web::trace::TraceLifecycleEvent::HandshakeTimeout,
            Some(stream_identity.id),
            Some("first_byte_timeout"),
        );
        deps.stats
            .increment_connects_bad_with_class("web_mtproto_first_byte_timeout");
        return;
    }
    if first_byte.is_ok_and(|result| result.is_err()) {
        session.trace_lifecycle(
            crate::web::trace::TraceLifecycleEvent::HandshakeIo,
            Some(stream_identity.id),
            Some("first_byte_io"),
        );
        deps.stats
            .increment_connects_bad_with_class("web_mtproto_handshake_io");
        return;
    }
    session.trace_lifecycle(
        crate::web::trace::TraceLifecycleEvent::StreamFirstByte,
        Some(stream_identity.id),
        None,
    );
    let Some(manager) = session.manager.upgrade() else {
        return;
    };
    let Ok(_connection_permit) = connection_permits.try_acquire_owned() else {
        manager.record_stream_rejected_reason(
            crate::web::telemetry::WebRejectionReason::GenerationConnectionCapacity,
        );
        session.trace_lifecycle(
            crate::web::trace::TraceLifecycleEvent::StreamRejected,
            Some(stream_identity.id),
            Some("connection_limit_after_first_byte"),
        );
        return;
    };
    let Some(handshake_permit) = manager.try_stream_handshake() else {
        session.trace_lifecycle(
            crate::web::trace::TraceLifecycleEvent::StreamRejected,
            Some(stream_identity.id),
            Some("handshake_limit"),
        );
        return;
    };
    let handshake_result = tokio::time::timeout(
        Duration::from_secs(session.timeouts.stream_handshake_secs),
        async {
            reader.read_exact(&mut handshake[1..]).await?;
            Ok::<_, io::Error>(
                handle_mtproto_handshake_for_web_user(
                    &handshake,
                    reader,
                    writer,
                    peer,
                    &deps.config,
                    &replay_checker,
                    &session.profile.user,
                    session.profile.secret_mode,
                    &deps.shared,
                )
                .await,
            )
        },
    )
    .await;
    drop(handshake_permit);
    let (reader, writer, success) = match handshake_result {
        Err(_) => {
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::HandshakeTimeout,
                Some(stream_identity.id),
                Some("timeout"),
            );
            deps.stats
                .increment_connects_bad_with_class("web_mtproto_handshake_timeout");
            deps.stats.increment_handshake_timeouts();
            deps.stats.increment_handshake_failure_class("timeout");
            return;
        }
        Ok(Err(_)) => {
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::HandshakeIo,
                Some(stream_identity.id),
                Some("io"),
            );
            deps.stats
                .increment_connects_bad_with_class("web_mtproto_handshake_io");
            return;
        }
        Ok(Ok(crate::error::HandshakeResult::Success((reader, writer, success)))) => {
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::HandshakeSucceeded,
                Some(stream_identity.id),
                None,
            );
            (reader, writer, success)
        }
        Ok(Ok(_)) => {
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::HandshakeRejected,
                Some(stream_identity.id),
                Some("bad_client"),
            );
            deps.stats
                .increment_connects_bad_with_class("web_mtproto_bad_client");
            return;
        }
    };
    session.trace_lifecycle(
        crate::web::trace::TraceLifecycleEvent::RelayStarted,
        Some(stream_identity.id),
        None,
    );
    let relay_result = run_authenticated(
        reader,
        writer,
        success,
        deps,
        session.profile.public_addr,
        peer,
        ConntrackClosePolicy::Suppress,
    )
    .await;
    session.trace_lifecycle(
        crate::web::trace::TraceLifecycleEvent::RelayEnded,
        Some(stream_identity.id),
        Some(if relay_result.is_ok() {
            "completed"
        } else {
            "error"
        }),
    );
}
