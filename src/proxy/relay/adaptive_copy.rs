use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, copy_buf};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::error::{ProxyError, Result};
use crate::proxy::adaptive_buffers::{
    AdaptiveTier, RelaySignalSample, SessionAdaptiveController, TierTransitionReason,
    direct_copy_buffers_for_tier_with_ceilings,
};
use crate::proxy::direct_buffer_budget::{
    DIRECT_BASE_C2S_BYTES, DIRECT_BASE_S2C_BYTES, DirectBufferBudget, DirectBufferLease,
};
use crate::proxy::traffic_limiter::TrafficLease;
use crate::stats::Stats;

use super::WATCHDOG_INTERVAL;
use super::io::{SharedCounters, StatsIo, is_quota_io_error};
use super::watchdog_delta;

mod write_pressure;

use self::write_pressure::WritePressureIo;

struct AdaptiveBufferState {
    desired_bytes: AtomicUsize,
    actual_bytes: AtomicUsize,
}

impl AdaptiveBufferState {
    fn new(bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            desired_bytes: AtomicUsize::new(bytes.max(1)),
            actual_bytes: AtomicUsize::new(bytes.max(1)),
        })
    }
}

struct AdaptiveBufReader<R> {
    inner: R,
    buffer: Box<[u8]>,
    pos: usize,
    cap: usize,
    state: Arc<AdaptiveBufferState>,
}

impl<R> AdaptiveBufReader<R> {
    fn new(inner: R, state: Arc<AdaptiveBufferState>) -> Self {
        let bytes = state.actual_bytes.load(Ordering::Relaxed).max(1);
        Self {
            inner,
            buffer: vec![0; bytes].into_boxed_slice(),
            pos: 0,
            cap: 0,
            state,
        }
    }

    fn resize_if_drained(&mut self) {
        if self.pos != self.cap {
            return;
        }
        let desired = self.state.desired_bytes.load(Ordering::Acquire).max(1);
        if desired == self.buffer.len() {
            return;
        }
        self.buffer = vec![0; desired].into_boxed_slice();
        self.pos = 0;
        self.cap = 0;
        self.state.actual_bytes.store(desired, Ordering::Release);
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AdaptiveBufReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.cap {
            let available = &this.buffer[this.pos..this.cap];
            let copied = available.len().min(output.remaining());
            output.put_slice(&available[..copied]);
            this.pos += copied;
            return Poll::Ready(Ok(()));
        }
        this.resize_if_drained();
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for AdaptiveBufReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.pos < this.cap {
            return Poll::Ready(Ok(&this.buffer[this.pos..this.cap]));
        }

        this.resize_if_drained();
        let mut read_buf = ReadBuf::new(&mut this.buffer);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                this.pos = 0;
                this.cap = read_buf.filled().len();
                Poll::Ready(Ok(&this.buffer[..this.cap]))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.pos = this.pos.saturating_add(amount).min(this.cap);
    }
}

enum AdaptiveRelayOutcome {
    Copy(io::Result<(u64, u64)>),
    ActivityTimeout,
    UserDisabled,
}

#[allow(clippy::too_many_arguments)]
/// Relays one Direct session with independently resizable directional buffers.
pub(crate) async fn relay_direct_adaptive<CR, CW, SR, SW>(
    client_reader: CR,
    client_writer: CW,
    server_reader: SR,
    server_writer: SW,
    ceiling_c2s_bytes: usize,
    ceiling_s2c_bytes: usize,
    max_connections: u32,
    user: &str,
    stats: Arc<Stats>,
    quota_limit: Option<u64>,
    traffic_lease: Option<Arc<TrafficLease>>,
    activity_timeout: Duration,
    session_cancel: CancellationToken,
    budget: Arc<DirectBufferBudget>,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    let activity_timeout = activity_timeout.max(Duration::from_secs(1));
    let epoch = Instant::now();
    let counters = Arc::new(SharedCounters::new());
    let quota_exceeded = Arc::new(AtomicBool::new(false));
    let user_owned = user.to_string();

    let (base_c2s, base_s2c) = initial_base_sizes(
        ceiling_c2s_bytes,
        ceiling_s2c_bytes,
        max_connections,
        budget.target_bytes(),
    );
    let base_total = base_c2s.saturating_add(base_s2c);
    let mut lease = match budget.try_reserve(base_total, false) {
        Some(lease) => lease,
        None => {
            let minimum_total = DIRECT_BASE_C2S_BYTES + DIRECT_BASE_S2C_BYTES;
            match budget.try_reserve(minimum_total, true) {
                Some(lease) => {
                    budget.increment_minimum_fallback();
                    lease
                }
                None => {
                    budget.increment_admission_rejected();
                    return Err(ProxyError::Proxy(
                        "Direct relay buffer pressure: budget exhausted".to_string(),
                    ));
                }
            }
        }
    };

    let effective_base = if lease.reserved_bytes() < base_total {
        (DIRECT_BASE_C2S_BYTES, DIRECT_BASE_S2C_BYTES)
    } else {
        (base_c2s, base_s2c)
    };
    let c2s_state = AdaptiveBufferState::new(effective_base.0);
    let s2c_state = AdaptiveBufferState::new(effective_base.1);

    let mut controller = SessionAdaptiveController::new(AdaptiveTier::Base);

    let c2s_client = StatsIo::new_with_traffic_lease(
        client_reader,
        Arc::clone(&counters),
        Arc::clone(&stats),
        user_owned.clone(),
        traffic_lease.clone(),
        quota_limit,
        Arc::clone(&quota_exceeded),
        epoch,
    );
    let client_writer = StatsIo::new_with_traffic_lease(
        client_writer,
        Arc::clone(&counters),
        Arc::clone(&stats),
        user_owned.clone(),
        traffic_lease,
        quota_limit,
        Arc::clone(&quota_exceeded),
        epoch,
    );
    let mut client_writer = WritePressureIo::new(client_writer, Arc::clone(&counters));
    let mut c2s_reader = AdaptiveBufReader::new(c2s_client, Arc::clone(&c2s_state));
    let mut s2c_reader = AdaptiveBufReader::new(server_reader, Arc::clone(&s2c_state));
    let mut server_writer = server_writer;
    let mut pressure_rx = budget.subscribe_pressure();

    let relay_outcome = {
        let copy = async {
            let c2s = async {
                let copied = copy_buf(&mut c2s_reader, &mut server_writer).await?;
                server_writer.shutdown().await?;
                Ok::<u64, io::Error>(copied)
            };
            let s2c = async {
                let copied = copy_buf(&mut s2c_reader, &mut client_writer).await?;
                client_writer.shutdown().await?;
                Ok::<u64, io::Error>(copied)
            };
            tokio::try_join!(c2s, s2c)
        };
        tokio::pin!(copy);

        let mut interval = tokio::time::interval(WATCHDOG_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        let mut previous = RelaySignalSample::default();
        let mut previous_log_c2s = 0u64;
        let mut previous_log_s2c = 0u64;
        let mut previous_sample_at = epoch;

        loop {
            tokio::select! {
                result = &mut copy => break AdaptiveRelayOutcome::Copy(result),
                _ = session_cancel.cancelled() => break AdaptiveRelayOutcome::UserDisabled,
                changed = pressure_rx.changed() => {
                    if changed.is_ok() {
                        apply_global_pressure_demotion(
                            &mut controller,
                            &mut lease,
                            &c2s_state,
                            &s2c_state,
                            effective_base,
                            (ceiling_c2s_bytes, ceiling_s2c_bytes),
                            budget.as_ref(),
                        );
                        reconcile_reservation(&mut lease, &c2s_state, &s2c_state);
                    }
                }
                _ = interval.tick() => {
                    let now = Instant::now();
                    let idle = counters.idle_duration(now, epoch);
                    if quota_exceeded.load(Ordering::Acquire) {
                        warn!(user = %user_owned, "User data quota reached, closing relay");
                        break AdaptiveRelayOutcome::ActivityTimeout;
                    }
                    if idle >= activity_timeout {
                        warn!(
                            user = %user_owned,
                            c2s_bytes = counters.c2s_bytes.load(Ordering::Relaxed),
                            s2c_bytes = counters.s2c_bytes.load(Ordering::Relaxed),
                            idle_secs = idle.as_secs(),
                            "Activity timeout"
                        );
                        break AdaptiveRelayOutcome::ActivityTimeout;
                    }

                    let sample = current_sample(counters.as_ref());
                    let c2s_delta = watchdog_delta(sample.c2s_bytes, previous_log_c2s);
                    let s2c_delta = watchdog_delta(sample.s2c_written_bytes, previous_log_s2c);
                    if c2s_delta > 0 || s2c_delta > 0 {
                        let secs = now.saturating_duration_since(previous_sample_at).as_secs_f64();
                        debug!(
                            user = %user_owned,
                            c2s_kbps = (c2s_delta as f64 / secs / 1024.0) as u64,
                            s2c_kbps = (s2c_delta as f64 / secs / 1024.0) as u64,
                            c2s_total = sample.c2s_bytes,
                            s2c_total = sample.s2c_written_bytes,
                            "Relay active"
                        );
                    }

                    let delta = sample_delta(sample, previous);
                    let tick_secs = now.saturating_duration_since(previous_sample_at).as_secs_f64();
                    if let Some(transition) = controller.observe(delta, tick_secs) {
                        apply_controller_transition(
                            transition,
                            &mut controller,
                            &mut lease,
                            &c2s_state,
                            &s2c_state,
                            effective_base,
                            (ceiling_c2s_bytes, ceiling_s2c_bytes),
                            budget.as_ref(),
                        );
                    }
                    reconcile_reservation(&mut lease, &c2s_state, &s2c_state);
                    previous = sample;
                    previous_log_c2s = sample.c2s_bytes;
                    previous_log_s2c = sample.s2c_written_bytes;
                    previous_sample_at = now;
                }
            }
        }
    };

    let _ = client_writer.shutdown().await;
    let _ = server_writer.shutdown().await;
    let c2s_ops = counters.c2s_ops.load(Ordering::Relaxed);
    let s2c_ops = counters.s2c_ops.load(Ordering::Relaxed);
    let duration = epoch.elapsed();
    match relay_outcome {
        AdaptiveRelayOutcome::Copy(Ok((c2s, s2c))) => {
            debug!(
                user = %user_owned,
                c2s_bytes = c2s,
                s2c_bytes = s2c,
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                "Relay finished"
            );
            Ok(())
        }
        AdaptiveRelayOutcome::Copy(Err(error)) if is_quota_io_error(&error) => {
            warn!(
                user = %user_owned,
                c2s_bytes = counters.c2s_bytes.load(Ordering::Relaxed),
                s2c_bytes = counters.s2c_bytes.load(Ordering::Relaxed),
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                "Data quota reached, closing relay"
            );
            Err(ProxyError::DataQuotaExceeded { user: user_owned })
        }
        AdaptiveRelayOutcome::Copy(Err(error)) => {
            debug!(
                user = %user_owned,
                c2s_bytes = counters.c2s_bytes.load(Ordering::Relaxed),
                s2c_bytes = counters.s2c_bytes.load(Ordering::Relaxed),
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                error = %error,
                "Relay error"
            );
            Err(error.into())
        }
        AdaptiveRelayOutcome::ActivityTimeout => {
            debug!(
                user = %user_owned,
                c2s_bytes = counters.c2s_bytes.load(Ordering::Relaxed),
                s2c_bytes = counters.s2c_bytes.load(Ordering::Relaxed),
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                "Relay finished (activity timeout)"
            );
            Ok(())
        }
        AdaptiveRelayOutcome::UserDisabled => {
            debug!(
                user = %user_owned,
                c2s_bytes = counters.c2s_bytes.load(Ordering::Relaxed),
                s2c_bytes = counters.s2c_bytes.load(Ordering::Relaxed),
                c2s_msgs = c2s_ops,
                s2c_msgs = s2c_ops,
                duration_secs = duration.as_secs(),
                "Relay finished (user disabled)"
            );
            Err(ProxyError::UserDisabled { user: user_owned })
        }
    }
}

fn initial_base_sizes(
    ceiling_c2s: usize,
    ceiling_s2c: usize,
    max_connections: u32,
    target_bytes: usize,
) -> (usize, usize) {
    let configured_total = ceiling_c2s.saturating_add(ceiling_s2c);
    let configured_worst_case = configured_total.saturating_mul(max_connections as usize);
    if max_connections != 0 && configured_worst_case <= target_bytes {
        return (ceiling_c2s, ceiling_s2c);
    }
    (
        DIRECT_BASE_C2S_BYTES.min(ceiling_c2s),
        DIRECT_BASE_S2C_BYTES.min(ceiling_s2c),
    )
}

fn current_sample(counters: &SharedCounters) -> RelaySignalSample {
    RelaySignalSample {
        c2s_bytes: counters.c2s_bytes.load(Ordering::Relaxed),
        s2c_requested_bytes: counters.s2c_requested_bytes.load(Ordering::Relaxed),
        s2c_written_bytes: counters.s2c_bytes.load(Ordering::Relaxed),
        s2c_write_ops: counters.s2c_ops.load(Ordering::Relaxed),
        s2c_partial_writes: counters.s2c_partial_writes.load(Ordering::Relaxed),
        s2c_consecutive_pending_writes: counters
            .s2c_consecutive_pending_writes
            .load(Ordering::Relaxed),
    }
}

fn sample_delta(current: RelaySignalSample, previous: RelaySignalSample) -> RelaySignalSample {
    RelaySignalSample {
        c2s_bytes: current.c2s_bytes.saturating_sub(previous.c2s_bytes),
        s2c_requested_bytes: current
            .s2c_requested_bytes
            .saturating_sub(previous.s2c_requested_bytes),
        s2c_written_bytes: current
            .s2c_written_bytes
            .saturating_sub(previous.s2c_written_bytes),
        s2c_write_ops: current.s2c_write_ops.saturating_sub(previous.s2c_write_ops),
        s2c_partial_writes: current
            .s2c_partial_writes
            .saturating_sub(previous.s2c_partial_writes),
        s2c_consecutive_pending_writes: current.s2c_consecutive_pending_writes,
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_controller_transition(
    transition: crate::proxy::adaptive_buffers::TierTransition,
    controller: &mut SessionAdaptiveController,
    lease: &mut DirectBufferLease,
    c2s_state: &AdaptiveBufferState,
    s2c_state: &AdaptiveBufferState,
    base: (usize, usize),
    ceilings: (usize, usize),
    budget: &DirectBufferBudget,
) {
    let sizes = direct_copy_buffers_for_tier_with_ceilings(
        transition.to,
        base.0,
        base.1,
        ceilings.0,
        ceilings.1,
    );
    if transition.to > transition.from {
        if !lease.try_grow_to(sizes.0.saturating_add(sizes.1)) {
            *controller = SessionAdaptiveController::new(transition.from);
            return;
        }
    } else {
        match transition.reason {
            TierTransitionReason::QuietDemotion => budget.increment_quiet_demotion(),
            TierTransitionReason::SustainedWritePressure => {
                budget.increment_write_pressure_demotion();
            }
            TierTransitionReason::SoftConfirmed | TierTransitionReason::HardPressure => {}
        }
    }
    set_desired_sizes(c2s_state, s2c_state, sizes);
    lease.set_tier(transition.to.as_u8() as usize);
}

fn apply_global_pressure_demotion(
    controller: &mut SessionAdaptiveController,
    lease: &mut DirectBufferLease,
    c2s_state: &AdaptiveBufferState,
    s2c_state: &AdaptiveBufferState,
    base: (usize, usize),
    ceilings: (usize, usize),
    budget: &DirectBufferBudget,
) {
    let current = controller.tier();
    let target = current.demote();
    if target == current {
        return;
    }
    *controller = SessionAdaptiveController::new(target);
    let sizes =
        direct_copy_buffers_for_tier_with_ceilings(target, base.0, base.1, ceilings.0, ceilings.1);
    set_desired_sizes(c2s_state, s2c_state, sizes);
    lease.set_tier(target.as_u8() as usize);
    budget.increment_global_pressure_demotion();
}

fn set_desired_sizes(
    c2s_state: &AdaptiveBufferState,
    s2c_state: &AdaptiveBufferState,
    sizes: (usize, usize),
) {
    c2s_state
        .desired_bytes
        .store(sizes.0.max(1), Ordering::Release);
    s2c_state
        .desired_bytes
        .store(sizes.1.max(1), Ordering::Release);
}

fn reconcile_reservation(
    lease: &mut DirectBufferLease,
    c2s_state: &AdaptiveBufferState,
    s2c_state: &AdaptiveBufferState,
) {
    // Promotion reserves the desired allocation before either reader grows.
    // Demotion keeps the actual allocation covered until its buffered bytes drain.
    let covered_c2s = c2s_state
        .actual_bytes
        .load(Ordering::Acquire)
        .max(c2s_state.desired_bytes.load(Ordering::Acquire));
    let covered_s2c = s2c_state
        .actual_bytes
        .load(Ordering::Acquire)
        .max(s2c_state.desired_bytes.load(Ordering::Acquire));
    lease.shrink_to(covered_c2s.saturating_add(covered_s2c));
}
