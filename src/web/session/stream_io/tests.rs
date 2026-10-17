use std::collections::VecDeque;
use std::mem::ManuallyDrop;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Weak};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use bytes::Bytes;
use tokio::io::ReadBuf;

use super::super::{InboundChunk, StreamIdentity, StreamState, WebSession};
use crate::config::{
    WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig,
};
use crate::web::frame;
use crate::web::frame::FrameType;
use crate::web::manager::WebProcessRuntime;

const CLONE_ACTION_NONE: u8 = 0;
const CLONE_ACTION_INSERT_DATA: u8 = 1;

struct CallbackProbe {
    session: Weak<WebSession>,
    stream: StreamIdentity,
    clone_action: AtomicU8,
    clones: AtomicUsize,
    drops: AtomicUsize,
    wakes: AtomicUsize,
    clone_while_locked: AtomicBool,
    drop_while_locked: AtomicBool,
    wake_while_locked: AtomicBool,
}

struct WakeCounter(AtomicUsize);

impl std::task::Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

impl CallbackProbe {
    fn new(session: &Arc<WebSession>, stream: StreamIdentity, clone_action: u8) -> Arc<Self> {
        Arc::new(Self {
            session: Arc::downgrade(session),
            stream,
            clone_action: AtomicU8::new(clone_action),
            clones: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
            clone_while_locked: AtomicBool::new(false),
            drop_while_locked: AtomicBool::new(false),
            wake_while_locked: AtomicBool::new(false),
        })
    }

    fn on_clone(&self) {
        self.clones.fetch_add(1, Ordering::AcqRel);
        let Some(session) = self.session.upgrade() else {
            return;
        };
        let Some(mut state) = session.state.try_lock() else {
            self.clone_while_locked.store(true, Ordering::Release);
            return;
        };
        if self.clone_action.swap(CLONE_ACTION_NONE, Ordering::AcqRel) == CLONE_ACTION_INSERT_DATA
            && let Some(stream) = state
                .streams
                .get_mut(&self.stream.id)
                .filter(|stream| stream.instance == self.stream.instance)
        {
            stream.inbound.push_back(InboundChunk {
                bytes: Bytes::from_static(b"x"),
                offset: 0,
            });
        }
    }

    fn on_drop(&self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
        if let Some(session) = self.session.upgrade()
            && session.state.try_lock().is_none()
        {
            self.drop_while_locked.store(true, Ordering::Release);
        }
    }

    fn on_wake(&self) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
        if let Some(session) = self.session.upgrade()
            && session.state.try_lock().is_none()
        {
            self.wake_while_locked.store(true, Ordering::Release);
        }
    }
}

unsafe fn clone_probe(data: *const ()) -> RawWaker {
    // SAFETY: every probe RawWaker originates from Arc::into_raw with this exact type.
    let probe = unsafe { Arc::<CallbackProbe>::from_raw(data.cast()) };
    probe.on_clone();
    let clone = Arc::clone(&probe);
    let _ = Arc::into_raw(probe);
    RawWaker::new(Arc::into_raw(clone).cast(), &PROBE_VTABLE)
}

unsafe fn wake_probe(data: *const ()) {
    // SAFETY: consuming wake reconstructs and consumes the RawWaker-owned Arc exactly once.
    let probe = unsafe { Arc::<CallbackProbe>::from_raw(data.cast()) };
    probe.on_wake();
}

unsafe fn wake_probe_by_ref(data: *const ()) {
    // SAFETY: by-reference wake reconstructs the Arc without consuming its raw ownership.
    let probe = ManuallyDrop::new(unsafe { Arc::<CallbackProbe>::from_raw(data.cast()) });
    probe.on_wake();
}

unsafe fn drop_probe(data: *const ()) {
    // SAFETY: dropping reconstructs and consumes the RawWaker-owned Arc exactly once.
    let probe = unsafe { Arc::<CallbackProbe>::from_raw(data.cast()) };
    probe.on_drop();
}

static PROBE_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_probe, wake_probe, wake_probe_by_ref, drop_probe);

fn probe_waker(probe: Arc<CallbackProbe>) -> Waker {
    let raw = RawWaker::new(Arc::into_raw(probe).cast(), &PROBE_VTABLE);
    // SAFETY: PROBE_VTABLE preserves the Arc ownership contract for every operation.
    unsafe { Waker::from_raw(raw) }
}

fn session() -> Arc<WebSession> {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        capability: [0; 32],
        shared: Arc::new(crate::config::WebRuntimeProfileShared {
            derivation_context: [0; 32],
            public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
            user: "alice".to_string(),
            secret_mode: WebSecretMode::Plain,
            carrier: WebCarrier::Https,
            carrier_negotiation_enabled: false,
            carrier_learning: false,
            carriers: Arc::from([WebCarrier::Https]),
            carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
            credential_id: [0; 16],
            key_fingerprint: "0000000000000000".to_string(),
            max_sessions: 1,
            max_streams: 1,
            max_streams_per_session: 1,
        }),
    });
    WebSession::new(
        Weak::<WebProcessRuntime>::new(),
        [1; 32],
        "192.0.2.10".parse().unwrap(),
        1,
        profile,
        [2; 32],
        WebCarrier::Https,
        1,
        [3; 32],
        None,
        crate::web::manager::CarrierClientClass::Legacy,
        None,
        false,
        false,
        WebLimitsConfig::default(),
        WebTimeoutsConfig::default(),
        None,
    )
}

fn insert_stream(session: &WebSession, stream: StreamIdentity, send_credit: u64) {
    session.state.lock().streams.insert(
        stream.id,
        StreamState {
            instance: stream.instance,
            inbound: VecDeque::new(),
            receive_window: frame::INITIAL_STREAM_WINDOW,
            send_credit,
            read_waker: None,
            write_waker: None,
        },
    );
}

#[test]
fn read_rechecks_after_unlocked_waker_clone() {
    let session = session();
    let stream = StreamIdentity { id: 1, instance: 1 };
    insert_stream(&session, stream, u64::from(frame::INITIAL_STREAM_WINDOW));
    let probe = CallbackProbe::new(&session, stream, CLONE_ACTION_INSERT_DATA);
    let waker = probe_waker(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut output = [];
    let mut read = ReadBuf::new(&mut output);

    assert!(matches!(
        session.poll_read(stream, &mut context, &mut read),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(probe.clones.load(Ordering::Acquire), 1);
    assert!(!probe.clone_while_locked.load(Ordering::Acquire));
    assert!(probe.drops.load(Ordering::Acquire) >= 1);
    assert!(!probe.drop_while_locked.load(Ordering::Acquire));
}

#[test]
fn replacing_registered_waker_drops_the_previous_handle_after_unlock() {
    let session = session();
    let stream = StreamIdentity { id: 1, instance: 1 };
    insert_stream(&session, stream, u64::from(frame::INITIAL_STREAM_WINDOW));
    let first_probe = CallbackProbe::new(&session, stream, CLONE_ACTION_NONE);
    let first_waker = probe_waker(Arc::clone(&first_probe));
    let mut first_context = Context::from_waker(&first_waker);
    let mut first_output = [0u8; 1];
    let mut first_read = ReadBuf::new(&mut first_output);
    assert!(matches!(
        session.poll_read(stream, &mut first_context, &mut first_read),
        Poll::Pending
    ));
    let drops_before_replace = first_probe.drops.load(Ordering::Acquire);

    let second_probe = CallbackProbe::new(&session, stream, CLONE_ACTION_NONE);
    let second_waker = probe_waker(Arc::clone(&second_probe));
    let mut second_context = Context::from_waker(&second_waker);
    let mut second_output = [0u8; 1];
    let mut second_read = ReadBuf::new(&mut second_output);
    assert!(matches!(
        session.poll_read(stream, &mut second_context, &mut second_read),
        Poll::Pending
    ));

    assert!(first_probe.drops.load(Ordering::Acquire) > drops_before_replace);
    assert!(!first_probe.drop_while_locked.load(Ordering::Acquire));
    assert!(!second_probe.clone_while_locked.load(Ordering::Acquire));
}

#[test]
fn write_clones_waker_only_after_releasing_session_lock() {
    let session = session();
    let stream = StreamIdentity { id: 1, instance: 1 };
    insert_stream(&session, stream, 0);
    let probe = CallbackProbe::new(&session, stream, CLONE_ACTION_NONE);
    let waker = probe_waker(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);

    assert!(matches!(
        session.poll_write(stream, &mut context, b"x"),
        Poll::Pending
    ));
    assert_eq!(probe.clones.load(Ordering::Acquire), 1);
    assert!(!probe.clone_while_locked.load(Ordering::Acquire));
    assert!(!probe.drop_while_locked.load(Ordering::Acquire));
}

#[test]
fn concurrent_read_registration_and_data_publication_never_lose_readiness() {
    const ATTEMPTS: usize = 10_000;

    let session = session();
    let stream = StreamIdentity { id: 1, instance: 1 };
    insert_stream(&session, stream, u64::from(frame::INITIAL_STREAM_WINDOW));
    let barrier = Arc::new(Barrier::new(3));
    let outcome = Arc::new(AtomicU8::new(0));
    let wakes = Arc::new(WakeCounter(AtomicUsize::new(0)));

    std::thread::scope(|scope| {
        let poll_session = Arc::clone(&session);
        let poll_barrier = Arc::clone(&barrier);
        let poll_outcome = Arc::clone(&outcome);
        let poll_wakes = Arc::clone(&wakes);
        scope.spawn(move || {
            for _ in 0..ATTEMPTS {
                poll_barrier.wait();
                let waker = Waker::from(Arc::clone(&poll_wakes));
                let mut context = Context::from_waker(&waker);
                let mut output = [];
                let mut read = ReadBuf::new(&mut output);
                let value = match poll_session.poll_read(stream, &mut context, &mut read) {
                    Poll::Pending => 1,
                    Poll::Ready(Ok(())) => 2,
                    Poll::Ready(Err(error)) => panic!("unexpected read failure: {error}"),
                };
                poll_outcome.store(value, Ordering::Release);
                poll_barrier.wait();
            }
        });

        let data_session = Arc::clone(&session);
        let data_barrier = Arc::clone(&barrier);
        scope.spawn(move || {
            let body = frame::encode(FrameType::Data, stream.id, b"x");
            for _ in 0..ATTEMPTS {
                data_barrier.wait();
                let frames = frame::parse_all(&body, &data_session.limits).unwrap();
                let mut opened = Vec::new();
                let mut unused_bytes = body.len().saturating_add(super::super::QUEUE_ITEM_COST);
                let mut unused_items = 1;
                let mut progress = super::super::uplink::AppliedProgress::default();
                data_session.with_state_effects(|state, effects| {
                    assert!(data_session.apply_batch_locked(
                        state,
                        &frames,
                        effects,
                        &mut opened,
                        &mut None,
                        &mut unused_bytes,
                        &mut unused_items,
                        &mut progress,
                    ));
                });
                data_barrier.wait();
            }
        });

        for _ in 0..ATTEMPTS {
            outcome.store(0, Ordering::Release);
            wakes.0.store(0, Ordering::Release);
            barrier.wait();
            barrier.wait();
            let observed = outcome.load(Ordering::Acquire);
            assert!(observed == 2 || wakes.0.load(Ordering::Acquire) != 0);
            let mut state = session.state.lock();
            let stream_state = state.streams.get_mut(&stream.id).unwrap();
            stream_state.inbound.clear();
            assert!(stream_state.read_waker.is_none());
        }
    });
}
