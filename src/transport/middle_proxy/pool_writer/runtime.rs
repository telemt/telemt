use super::*;

impl MePool {
    pub(crate) async fn prune_closed_writers(self: &Arc<Self>) {
        let closed_writer_ids: Vec<u64> = {
            let ws = self.writers.read().await;
            ws.iter()
                .filter(|w| w.tx.is_closed())
                .map(|w| w.id)
                .collect()
        };
        if closed_writer_ids.is_empty() {
            return;
        }

        for writer_id in closed_writer_ids {
            let _ = self.remove_writer_and_close_clients(writer_id).await;
        }
    }

    pub(crate) async fn connect_one_for_dc(
        self: &Arc<Self>,
        addr: SocketAddr,
        writer_dc: i32,
        rng: &SecureRandom,
    ) -> Result<()> {
        self.connect_one_with_generation_contour(
            addr,
            rng,
            self.current_generation(),
            WriterContour::Active,
            writer_dc,
        )
        .await
    }

    pub(in crate::transport::middle_proxy) async fn connect_one_with_generation_contour(
        self: &Arc<Self>,
        addr: SocketAddr,
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        writer_dc: i32,
    ) -> Result<()> {
        self.connect_one_with_generation_contour_for_dc(addr, rng, generation, contour, writer_dc)
            .await
    }

    pub(in crate::transport::middle_proxy) async fn connect_one_with_generation_contour_for_dc(
        self: &Arc<Self>,
        addr: SocketAddr,
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        writer_dc: i32,
    ) -> Result<()> {
        self.connect_one_with_generation_contour_for_dc_with_cap_policy(
            addr, rng, generation, contour, writer_dc, false,
        )
        .await
    }

    pub(in crate::transport::middle_proxy) async fn connect_one_with_generation_contour_for_dc_with_cap_policy(
        self: &Arc<Self>,
        addr: SocketAddr,
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        writer_dc: i32,
        allow_coverage_override: bool,
    ) -> Result<()> {
        let Some(_writer_open_reservation) = self
            .reserve_writer_open(contour, allow_coverage_override, writer_dc)
            .await
        else {
            return Err(ProxyError::Proxy(format!(
                "ME {contour:?} writer cap reached"
            )));
        };

        let secret_len = self.proxy_secret.read().await.secret.len();
        if secret_len < 32 {
            return Err(ProxyError::Proxy(
                "proxy-secret too short for ME auth".into(),
            ));
        }

        let dc_idx = i16::try_from(writer_dc).ok();
        let (stream, _connect_ms, upstream_egress) = self.connect_tcp(addr, dc_idx).await?;
        let hs = self
            .handshake_only(stream, addr, upstream_egress, rng)
            .await?;
        let Some(task_registration) = self.lifecycle.try_register() else {
            return Err(ProxyError::Proxy("ME pool lifecycle closed".into()));
        };

        let writer_id = self.next_writer_id.fetch_add(1, Ordering::Relaxed);
        let contour = Arc::new(AtomicU8::new(contour.as_u8()));
        let cancel = CancellationToken::new();
        let degraded = Arc::new(AtomicBool::new(false));
        let rtt_ema_ms_x10 = Arc::new(AtomicU32::new(0));
        let draining = Arc::new(AtomicBool::new(false));
        let draining_started_at_epoch_secs = Arc::new(AtomicU64::new(0));
        let drain_deadline_epoch_secs = Arc::new(AtomicU64::new(0));
        let allow_drain_fallback = Arc::new(AtomicBool::new(false));
        let byte_budget = self.new_writer_byte_budget();
        let (tx, rx) =
            mpsc::channel::<WriterCommand>(self.writer_lifecycle.writer_cmd_channel_capacity);
        let rpc_writer = RpcWriter {
            writer: hs.wr,
            key: hs.write_key,
            iv: hs.write_iv,
            seq_no: 0,
            crc_mode: hs.crc_mode,
            frame_buf: Vec::new(),
        };
        let writer = MeWriter {
            id: writer_id,
            addr,
            source_ip: hs.source_ip,
            writer_dc,
            generation,
            contour: contour.clone(),
            created_at: Instant::now(),
            tx: tx.clone(),
            byte_budget: byte_budget.clone(),
            cancel: cancel.clone(),
            degraded: degraded.clone(),
            rtt_ema_ms_x10: rtt_ema_ms_x10.clone(),
            draining: draining.clone(),
            draining_started_at_epoch_secs: draining_started_at_epoch_secs.clone(),
            drain_deadline_epoch_secs: drain_deadline_epoch_secs.clone(),
            allow_drain_fallback: allow_drain_fallback.clone(),
        };
        self.writers
            .update(|writers| writers.push(writer.clone()))
            .await;
        self.registry
            .register_writer(writer_id, tx.clone(), byte_budget)
            .await;
        self.registry.mark_writer_idle(writer_id).await;
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        self.notify_writer_epoch();

        let reg = self.registry.clone();
        let writers_arc = self.writers_arc();
        let ping_tracker = Arc::new(tokio::sync::Mutex::new(HashMap::<i64, Instant>::new()));
        let ping_tracker_reader = ping_tracker.clone();
        let ping_tracker_ping = ping_tracker.clone();
        let rtt_stats = self.rtt_stats.clone();
        let stats_reader = self.stats.clone();
        let stats_reader_close = self.stats.clone();
        let stats_ping = self.stats.clone();
        let stats_signal = self.stats.clone();
        let pool_lifecycle = Arc::downgrade(self);
        let pool_ping = Arc::downgrade(self);
        let pool_signal = Arc::downgrade(self);
        let tx_reader = tx.clone();
        let tx_ping = tx.clone();
        let tx_signal = tx.clone();
        let keepalive_enabled = self.writer_lifecycle.me_keepalive_enabled;
        let keepalive_interval = self.writer_lifecycle.me_keepalive_interval;
        let keepalive_jitter = self.writer_lifecycle.me_keepalive_jitter;
        let keepalive_jitter_signal = self.writer_lifecycle.me_keepalive_jitter;
        let rpc_proxy_req_every_secs = self
            .writer_lifecycle
            .rpc_proxy_req_every_secs
            .load(Ordering::Relaxed);
        let cancel_reader = cancel.clone();
        let cancel_writer = cancel.clone();
        let cancel_ping = cancel.clone();
        let cancel_signal = cancel.clone();
        let cancel_select = cancel.clone();
        let cancel_cleanup = cancel.clone();
        let route_backpressure_enabled =
            self.transport_policy.me_route_backpressure_enabled.clone();
        let route_fairshare_enabled = self.transport_policy.me_route_fairshare_enabled.clone();
        let reader_route_data_wait_ms = self.transport_policy.me_reader_route_data_wait_ms.clone();

        self.lifecycle
            .spawn_registered_writer(task_registration, async move {
                // Reader MUST be the first branch in biased select! to avoid read starvation.
                let exit = tokio::select! {
                    biased;

                    reader_res = reader_loop(
                        hs.rd,
                        hs.read_key,
                        hs.read_iv,
                        hs.crc_mode,
                        reg.clone(),
                        BytesMut::new(),
                        BytesMut::new(),
                        tx_reader,
                        ping_tracker_reader,
                        rtt_stats,
                        stats_reader,
                        writer_id,
                        degraded,
                        rtt_ema_ms_x10,
                        route_backpressure_enabled,
                        route_fairshare_enabled,
                        reader_route_data_wait_ms,
                        cancel_reader,
                    ) => WriterLifecycleExit::Reader(reader_res),
                    writer_res = writer_command_loop(rx, rpc_writer, cancel_writer) => {
                        WriterLifecycleExit::Writer(writer_res)
                    }
                    _ = ping_loop(
                        pool_ping,
                        writer_id,
                        tx_ping,
                        ping_tracker_ping,
                        stats_ping,
                        keepalive_enabled,
                        keepalive_interval,
                        keepalive_jitter,
                        cancel_ping,
                    ) => WriterLifecycleExit::Ping,
                    _ = rpc_proxy_req_signal_loop(
                        pool_signal,
                        writer_id,
                        tx_signal,
                        stats_signal,
                        cancel_signal,
                        keepalive_jitter_signal,
                        rpc_proxy_req_every_secs,
                    ) => WriterLifecycleExit::Signal,
                    _ = cancel_select.cancelled() => WriterLifecycleExit::Cancelled,
                };

                match exit {
                    WriterLifecycleExit::Reader(res) => {
                        let idle_close_by_peer = if let Err(e) = res.as_ref() {
                            is_me_peer_closed_error(e) && reg.is_writer_empty(writer_id).await
                        } else {
                            false
                        };
                        if idle_close_by_peer {
                            stats_reader_close.increment_me_idle_close_by_peer_total();
                            info!(writer_id, "ME socket closed by peer on idle writer");
                        }
                        if let Err(e) = res
                            && !idle_close_by_peer
                        {
                            warn!(error = %e, "ME reader ended");
                        }
                    }
                    WriterLifecycleExit::Writer(res) => {
                        if let Err(e) = res {
                            warn!(error = %e, "ME writer command loop ended");
                        }
                    }
                    WriterLifecycleExit::Ping => {
                        debug!(writer_id, "ME ping loop finished");
                    }
                    WriterLifecycleExit::Signal => {
                        debug!(writer_id, "ME rpc_proxy_req signal loop finished");
                    }
                    WriterLifecycleExit::Cancelled => {}
                }

                if let Some(pool) = pool_lifecycle.upgrade() {
                    pool.remove_writer_and_close_clients(writer_id).await;
                } else {
                    // Fallback for shutdown races: make lifecycle exit observable by prune.
                    cancel_cleanup.cancel();
                }

                let remaining = writers_arc.read().await.len();
                debug!(writer_id, remaining, "ME writer lifecycle task finished");
            });

        Ok(())
    }

    pub(crate) async fn remove_writer_and_close_clients(self: &Arc<Self>, writer_id: u64) {
        // Full client cleanup now happens inside `registry.writer_lost` to keep
        // writer reap/remove paths strictly non-blocking per connection.
        let _ = self
            .remove_writer_with_mode(writer_id, WriterTeardownMode::Any)
            .await;
    }

    pub(in crate::transport::middle_proxy) async fn remove_draining_writer_hard_detach(
        self: &Arc<Self>,
        writer_id: u64,
    ) -> bool {
        self.remove_writer_with_mode(writer_id, WriterTeardownMode::DrainingOnly)
            .await
    }

    #[allow(dead_code)]
    async fn remove_writer_only(self: &Arc<Self>, writer_id: u64) -> bool {
        self.remove_writer_with_mode(writer_id, WriterTeardownMode::Any)
            .await
    }

    // Authoritative teardown primitive shared by normal cleanup and watchdog path.
    // Lock-order invariant:
    // 1) mutate `writers` under pool write lock,
    // 2) release pool lock,
    // 3) run registry/metrics/refill side effects.
    // `registry.writer_lost` must never run while `writers` lock is held.
    async fn remove_writer_with_mode(
        self: &Arc<Self>,
        writer_id: u64,
        mode: WriterTeardownMode,
    ) -> bool {
        let mut close_tx: Option<mpsc::Sender<WriterCommand>> = None;
        let mut removed_addr: Option<SocketAddr> = None;
        let mut removed_dc: Option<i32> = None;
        let mut removed_uptime: Option<Duration> = None;
        let mut trigger_refill = false;
        let mut removed = false;
        {
            let mut ws = self.writers.write().await;
            if let Some(pos) = ws.iter().position(|w| w.id == writer_id) {
                if matches!(mode, WriterTeardownMode::DrainingOnly)
                    && !ws[pos].draining.load(Ordering::Relaxed)
                {
                    return false;
                }
                let w = ws.remove(pos);
                let was_draining = w.draining.load(Ordering::Relaxed);
                if was_draining {
                    self.stats.decrement_pool_drain_active();
                    self.decrement_draining_active_runtime();
                }
                self.stats.increment_me_writer_removed_total();
                w.cancel.cancel();
                removed_addr = Some(w.addr);
                removed_dc = Some(w.writer_dc);
                removed_uptime = Some(w.created_at.elapsed());
                trigger_refill = !was_draining;
                if trigger_refill {
                    self.stats.increment_me_writer_removed_unexpected_total();
                }
                close_tx = Some(w.tx.clone());
                self.conn_count.fetch_sub(1, Ordering::Relaxed);
                removed = true;
            }
        }
        // State invariant:
        // - writer is removed from `self.writers` (pool visibility),
        // - writer is removed from registry routing/binding maps via `writer_lost`.
        // The close command below is only a best-effort accelerator for task shutdown.
        // Cleanup progress must never depend on command-channel availability.
        let _ = self.registry.writer_lost(writer_id).await;
        self.rtt_stats.lock().await.remove(&writer_id);
        if let Some(tx) = close_tx {
            // Keep teardown critical path non-blocking: close is best-effort only.
            let _ = tx.try_send(WriterCommand::Close);
        }
        if let Some(addr) = removed_addr {
            if let Some(uptime) = removed_uptime {
                // Quarantine contract: only unexpected removals are considered endpoint flap.
                if trigger_refill {
                    self.stats
                        .increment_me_endpoint_quarantine_unexpected_total();
                    self.maybe_quarantine_flapping_endpoint(addr, uptime, "unexpected")
                        .await;
                } else {
                    self.stats
                        .increment_me_endpoint_quarantine_draining_suppressed_total();
                    debug!(
                        %addr,
                        uptime_ms = uptime.as_millis(),
                        "Skipping endpoint quarantine for draining writer removal"
                    );
                }
            }
            if trigger_refill && let Some(writer_dc) = removed_dc {
                self.trigger_immediate_refill_for_dc(addr, writer_dc);
            }
        }
        if removed {
            self.notify_writer_epoch();
        }
        removed
    }

    pub(crate) async fn mark_writer_draining_with_timeout(
        self: &Arc<Self>,
        writer_id: u64,
        timeout: Option<Duration>,
        allow_drain_fallback: bool,
    ) {
        let timeout = timeout.filter(|d| !d.is_zero());
        let found = {
            let mut ws = self.writers.write().await;
            if let Some(w) = ws.iter_mut().find(|w| w.id == writer_id) {
                let already_draining = w.draining.swap(true, Ordering::Relaxed);
                w.allow_drain_fallback
                    .store(allow_drain_fallback, Ordering::Relaxed);
                let now_epoch_secs = Self::now_epoch_secs();
                w.draining_started_at_epoch_secs
                    .store(now_epoch_secs, Ordering::Relaxed);
                let drain_deadline_epoch_secs = timeout
                    .map(|duration| now_epoch_secs.saturating_add(duration.as_secs()))
                    .unwrap_or(0);
                w.drain_deadline_epoch_secs
                    .store(drain_deadline_epoch_secs, Ordering::Relaxed);
                if !already_draining {
                    self.stats.increment_pool_drain_active();
                    self.increment_draining_active_runtime();
                }
                w.contour
                    .store(WriterContour::Draining.as_u8(), Ordering::Relaxed);
                w.draining.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        };

        if !found {
            return;
        }

        let timeout_secs = timeout.map(|d| d.as_secs()).unwrap_or(0);
        debug!(
            writer_id,
            timeout_secs, allow_drain_fallback, "ME writer marked draining"
        );
    }

    pub(crate) async fn mark_writer_draining(self: &Arc<Self>, writer_id: u64) {
        self.mark_writer_draining_with_timeout(writer_id, Some(Duration::from_secs(300)), false)
            .await;
    }

    pub(in crate::transport::middle_proxy) fn writer_accepts_new_binding(
        &self,
        writer: &MeWriter,
    ) -> bool {
        if !writer.draining.load(Ordering::Relaxed) {
            return true;
        }
        if !writer.allow_drain_fallback.load(Ordering::Relaxed) {
            return false;
        }

        match self.bind_stale_mode() {
            MeBindStaleMode::Never => false,
            MeBindStaleMode::Always => true,
            MeBindStaleMode::Ttl => {
                let ttl_secs = self
                    .binding_policy
                    .me_bind_stale_ttl_secs
                    .load(Ordering::Relaxed);
                if ttl_secs == 0 {
                    return true;
                }

                let started = writer
                    .draining_started_at_epoch_secs
                    .load(Ordering::Relaxed);
                if started == 0 {
                    return false;
                }

                Self::now_epoch_secs().saturating_sub(started) <= ttl_secs
            }
        }
    }
}
