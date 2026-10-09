use super::*;

#[test]
fn socket_wakeup_drains_both_encrypted_layers_while_source_stays_pending() {
    let payload: Vec<_> = (0..65536).map(|i| (i % 251) as u8).collect();
    let mut reader = AdaptiveBufReader::new(
        BurstReader {
            bytes: payload.clone(),
            pos: 0,
            eof: false,
        },
        AdaptiveBufferState::new(payload.len()),
    );
    let sink = SinkState::new(13, 7);
    let mut writer = CryptoWriter::new(
        FakeTlsWriter::new(Sink(Arc::clone(&sink))),
        AesCtr::new(&[7; 32], 9),
        65536,
    );
    let wake = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut cx = Context::from_waker(&waker);
    let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
    for _ in 0..3 {
        assert!(copy.as_mut().poll(&mut cx).is_pending());
        assert_eq!(sink.lock().unwrap().bytes.len(), 13);
    }
    assert_eq!(
        wake.0.load(Ordering::Relaxed),
        0,
        "blocked copy must not spin or self-wake"
    );
    let wake_writer = {
        let mut state = sink.lock().unwrap();
        state.allowance = usize::MAX;
        state
            .waker
            .take()
            .expect("blocked sink must register readiness")
    };
    wake_writer.wake();
    assert_eq!(wake.0.load(Ordering::Relaxed), 1);
    assert!(copy.as_mut().poll(&mut cx).is_pending());
    assert_eq!(plaintext(&sink.lock().unwrap().bytes), payload);
    drop(copy);
    assert!(!writer.has_pending());
    assert!(!writer.get_ref().has_pending());
}

#[test]
fn writer_pending_preserves_unconsumed_reader_bytes_and_reservation() {
    let state = AdaptiveBufferState::new(64);
    let payload = vec![42; 64];
    let mut reader = AdaptiveBufReader::new(
        BurstReader {
            bytes: payload.clone(),
            pos: 0,
            eof: true,
        },
        Arc::clone(&state),
    );
    let sink = SinkState::new(0, 3);
    let mut writer = Sink(Arc::clone(&sink));
    let mut cx = Context::from_waker(Waker::noop());
    let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
    assert!(copy.as_mut().poll(&mut cx).is_pending());
    drop(copy);
    assert_eq!(reader.pos, 0);
    assert_eq!(reader.cap, payload.len());
    assert!(sink.lock().unwrap().bytes.is_empty());
    state.desired_bytes.store(8, Ordering::Release);
    sink.lock().unwrap().allowance = usize::MAX;
    let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
    assert!(matches!(copy.as_mut().poll(&mut cx), Poll::Ready(Ok(64))));
    drop(copy);
    assert_eq!(sink.lock().unwrap().bytes, payload);
    assert_eq!(state.actual_bytes.load(Ordering::Acquire), 8);
}

#[test]
fn eof_flushes_complete_ciphertext_and_reports_plaintext_count() {
    for len in [
        0,
        1,
        MAX_TLS_CIPHERTEXT_SIZE,
        MAX_TLS_CIPHERTEXT_SIZE + 1,
        65536,
    ] {
        let payload = vec![17; len];
        let mut reader = AdaptiveBufReader::new(
            BurstReader {
                bytes: payload.clone(),
                pos: 0,
                eof: true,
            },
            AdaptiveBufferState::new(65536),
        );
        let sink = SinkState::new(usize::MAX, 113);
        let mut writer = CryptoWriter::new(
            FakeTlsWriter::new(Sink(Arc::clone(&sink))),
            AesCtr::new(&[7; 32], 9),
            65536,
        );
        let mut cx = Context::from_waker(Waker::noop());
        let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
        assert!(matches!(copy.as_mut().poll(&mut cx), Poll::Ready(Ok(n)) if n == len as u64));
        assert_eq!(plaintext(&sink.lock().unwrap().bytes), payload);
    }
}

struct FlushGate {
    accepted: usize,
    polls: Arc<AtomicUsize>,
    blocked: Arc<AtomicBool>,
    error: Option<io::ErrorKind>,
}

impl AsyncWrite for FlushGate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.accepted += bytes.len();
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        if self.blocked.load(Ordering::Relaxed) {
            return Poll::Pending;
        }
        Poll::Ready(self.error.map_or(Ok(()), |kind| Err(kind.into())))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("copy must leave shutdown to its caller")
    }
}

#[test]
fn pending_flush_is_retried_and_successful_idle_flush_is_not_repeated() {
    let mut reader = AdaptiveBufReader::new(
        BurstReader {
            bytes: vec![3; 128],
            pos: 0,
            eof: false,
        },
        AdaptiveBufferState::new(256),
    );
    let polls = Arc::new(AtomicUsize::new(0));
    let blocked = Arc::new(AtomicBool::new(true));
    let mut writer = FlushGate {
        accepted: 0,
        polls: Arc::clone(&polls),
        blocked: Arc::clone(&blocked),
        error: None,
    };
    let mut cx = Context::from_waker(Waker::noop());
    let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
    assert!(copy.as_mut().poll(&mut cx).is_pending());
    assert_eq!(polls.load(Ordering::Relaxed), 1);
    blocked.store(false, Ordering::Relaxed);
    assert!(copy.as_mut().poll(&mut cx).is_pending());
    assert_eq!(polls.load(Ordering::Relaxed), 2);
    for _ in 0..8 {
        assert!(copy.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(polls.load(Ordering::Relaxed), 2);
    drop(copy);
    assert_eq!(writer.accepted, 128);
}

#[test]
fn source_pending_before_any_write_does_not_flush() {
    let mut reader = AdaptiveBufReader::new(
        BurstReader {
            bytes: Vec::new(),
            pos: 0,
            eof: false,
        },
        AdaptiveBufferState::new(64),
    );
    let sink = SinkState::new(usize::MAX, usize::MAX);
    let mut writer = Sink(Arc::clone(&sink));
    let mut cx = Context::from_waker(Waker::noop());
    let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
    for _ in 0..8 {
        assert!(copy.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(sink.lock().unwrap().flushes, 0);
}

#[test]
fn flush_errors_propagate_on_source_pending_and_eof() {
    for eof in [false, true] {
        let mut reader = AdaptiveBufReader::new(
            BurstReader {
                bytes: vec![3; 128],
                pos: 0,
                eof,
            },
            AdaptiveBufferState::new(256),
        );
        let mut writer = FlushGate {
            accepted: 0,
            polls: Arc::new(AtomicUsize::new(0)),
            blocked: Arc::new(AtomicBool::new(false)),
            error: Some(io::ErrorKind::ConnectionReset),
        };
        let mut cx = Context::from_waker(Waker::noop());
        let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
        assert!(
            matches!(copy.as_mut().poll(&mut cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset)
        );
    }
}

struct ErrorIo;

impl AsyncRead for ErrorIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
    }
}

impl AsyncWrite for ErrorIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("copy must not flush after a read/write error")
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("copy must leave shutdown to its caller")
    }
}

#[test]
fn read_write_and_write_zero_errors_preserve_their_categories() {
    let mut cx = Context::from_waker(Waker::noop());
    let mut reader = AdaptiveBufReader::new(ErrorIo, AdaptiveBufferState::new(8));
    let mut writer = ErrorIo;
    let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
    assert!(
        matches!(copy.as_mut().poll(&mut cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
    drop(copy);

    let mut reader = AdaptiveBufReader::new(&b"abc"[..], AdaptiveBufferState::new(8));
    let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
    assert!(
        matches!(copy.as_mut().poll(&mut cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe)
    );
    drop(copy);
    assert_eq!(reader.pos, 0);

    let mut writer = Sink(SinkState::new(usize::MAX, 0));
    let mut copy = Box::pin(copy_with_flush(&mut reader, &mut writer));
    assert!(
        matches!(copy.as_mut().poll(&mut cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::WriteZero)
    );
    drop(copy);
    assert_eq!(reader.pos, 0);
}
