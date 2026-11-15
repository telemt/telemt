use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rand::RngExt;
use rand::seq::SliceRandom;
use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};

use super::pool::{MePool, WriterOpenIntent};

impl MePool {
    pub async fn init(self: &Arc<Self>, pool_size: usize, rng: &Arc<SecureRandom>) -> Result<()> {
        let family_order = self.family_order();
        let connect_concurrency = self
            .reconnect_runtime
            .me_reconnect_max_concurrent_per_dc
            .max(1) as usize;
        let ks = self.key_selector().await;
        let me_servers = self.endpoint_snapshot.load().map_v4.len();
        let secret_len = self.proxy_secret.read().await.secret.len();
        info!(
            me_servers,
            pool_size,
            connect_concurrency,
            key_selector = format_args!("0x{ks:08x}"),
            secret_len,
            "Initializing ME pool"
        );

        let mut missing_dc_groups = Vec::new();
        for family in family_order {
            let map = self.proxy_map_for_family(family).await;
            let mut dc_addrs: Vec<(i32, Vec<(IpAddr, u16)>)> = map
                .into_iter()
                .map(|(dc, mut addrs)| {
                    addrs.sort_unstable();
                    addrs.dedup();
                    (dc, addrs)
                })
                .filter(|(_, addrs)| !addrs.is_empty())
                .collect();
            dc_addrs.sort_unstable_by_key(|(dc, _)| *dc);
            dc_addrs.sort_by_key(|(_, addrs)| (addrs.len() != 1, addrs.len()));

            // Stage 1: build base coverage for conditional-cast.
            // Single-endpoint DCs are prefilled first; multi-endpoint DCs require one live writer.
            let mut join = tokio::task::JoinSet::new();
            for (dc, addrs) in dc_addrs.iter().cloned() {
                if addrs.is_empty() {
                    continue;
                }
                let target_writers = if addrs.len() == 1 {
                    self.required_writers_for_dc_with_floor_mode(addrs.len(), false)
                } else {
                    1usize
                };
                let endpoints: HashSet<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if self
                    .active_usable_writer_count_for_dc_endpoints(dc, &endpoints)
                    .await
                    >= target_writers
                {
                    continue;
                }
                let pool = Arc::clone(self);
                let rng_clone = Arc::clone(rng);
                join.spawn(async move {
                    pool.connect_primary_for_dc(
                        dc,
                        addrs,
                        target_writers,
                        rng_clone,
                        connect_concurrency,
                        WriterOpenIntent::Coverage,
                    )
                    .await
                });
            }
            while join.join_next().await.is_some() {}

            let mut missing_dcs = Vec::new();
            for (dc, addrs) in &dc_addrs {
                let endpoints: HashSet<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if self
                    .active_usable_writer_count_for_dc_endpoints(*dc, &endpoints)
                    .await
                    == 0
                {
                    missing_dcs.push(*dc);
                }
            }
            if !missing_dcs.is_empty() {
                missing_dc_groups.extend(missing_dcs.iter().copied());
            }

            // Stage 2: continue saturating multi-endpoint DC groups in background.
            let pool = Arc::clone(self);
            let rng_clone = Arc::clone(rng);
            let dc_addrs_bg = dc_addrs.clone();
            let saturation = async move {
                let mut join_bg = tokio::task::JoinSet::new();
                for (dc, addrs) in dc_addrs_bg {
                    if addrs.len() <= 1 {
                        continue;
                    }
                    let target_writers =
                        pool.required_writers_for_dc_with_floor_mode(addrs.len(), false);
                    let pool_clone = Arc::clone(&pool);
                    let rng_clone_local = Arc::clone(&rng_clone);
                    join_bg.spawn(async move {
                        pool_clone
                            .connect_primary_for_dc(
                                dc,
                                addrs,
                                target_writers,
                                rng_clone_local,
                                connect_concurrency,
                                WriterOpenIntent::Normal,
                            )
                            .await
                    });
                }
                while join_bg.join_next().await.is_some() {}
                debug!(
                    current_pool_size = pool.connection_count(),
                    "Background ME saturation warmup finished"
                );
            };
            if self.lifecycle.spawn_producer(saturation).is_err() {
                debug!("Background ME saturation skipped: pool lifecycle closed");
            }

            if !self.decision.effective_multipath && self.admission_ready_conditional_cast().await {
                break;
            }
        }

        missing_dc_groups.sort_unstable();
        missing_dc_groups.dedup();
        if !self.admission_ready_conditional_cast().await {
            if self.writers.read().await.is_empty() {
                return Err(ProxyError::Proxy("No ME connections".into()));
            }
            return Err(ProxyError::Proxy(format!(
                "ME init incomplete: no live writers for DC groups {missing_dc_groups:?}"
            )));
        }
        if !missing_dc_groups.is_empty() {
            warn!(
                missing_dcs = ?missing_dc_groups,
                "ME started with partial coverage; missing DCs recover in background"
            );
        }
        info!(
            active_writers = self.connection_count(),
            "ME primary pool ready; reserve warmup continues in background"
        );
        Ok(())
    }

    async fn connect_primary_for_dc(
        self: Arc<Self>,
        dc: i32,
        mut addrs: Vec<(IpAddr, u16)>,
        target_writers: usize,
        rng: Arc<SecureRandom>,
        connect_concurrency: usize,
        intent: WriterOpenIntent,
    ) -> bool {
        if addrs.is_empty() {
            return false;
        }
        let target_writers = target_writers.max(1);
        addrs.shuffle(&mut rand::rng());
        let endpoints: Vec<SocketAddr> = addrs
            .iter()
            .map(|(ip, port)| SocketAddr::new(*ip, *port))
            .collect();
        let endpoint_set: HashSet<SocketAddr> = endpoints.iter().copied().collect();

        loop {
            let alive = self
                .active_usable_writer_count_for_dc_endpoints(dc, &endpoint_set)
                .await;
            if alive >= target_writers {
                info!(
                    dc = %dc,
                    alive,
                    target_writers,
                    "ME connected"
                );
                return true;
            }

            let missing = target_writers.saturating_sub(alive).max(1);
            let concurrency = connect_concurrency.max(1).min(missing);
            let mut join = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                let pool = Arc::clone(&self);
                let rng_clone = Arc::clone(&rng);
                let endpoints_clone = endpoints.clone();
                let generation = self.current_generation();
                join.spawn(async move {
                    pool.connect_endpoints_round_robin_with_generation_contour(
                        dc,
                        &endpoints_clone,
                        rng_clone.as_ref(),
                        generation,
                        super::pool::WriterContour::Active,
                        intent,
                    )
                    .await
                });
            }

            let mut progress = false;
            while let Some(res) = join.join_next().await {
                match res {
                    Ok(true) => {
                        progress = true;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(dc = %dc, error = %e, "ME connect task failed");
                    }
                }
            }

            let alive_after = self
                .active_usable_writer_count_for_dc_endpoints(dc, &endpoint_set)
                .await;
            if alive_after >= target_writers {
                info!(
                    dc = %dc,
                    alive = alive_after,
                    target_writers,
                    "ME connected"
                );
                return true;
            }
            if !progress {
                let active_writers_current = self.active_contour_writer_count_total().await;
                let active_cap_configured = self.adaptive_floor_active_cap_configured_total();
                if intent != WriterOpenIntent::Coverage
                    && active_writers_current >= active_cap_configured
                {
                    info!(
                        dc = %dc,
                        alive = alive_after,
                        target_writers,
                        active_writers_current,
                        active_cap_configured,
                        "ME init saturation stopped by active writer cap"
                    );
                } else {
                    warn!(
                        dc = %dc,
                        alive = alive_after,
                        target_writers,
                        "All ME servers for DC failed at init"
                    );
                }
                return false;
            }

            if self.reconnect_runtime.me_warmup_stagger_enabled {
                let jitter = rand::rng().random_range(
                    0..=self.reconnect_runtime.me_warmup_step_jitter.as_millis() as u64,
                );
                let delay_ms =
                    self.reconnect_runtime.me_warmup_step_delay.as_millis() as u64 + jitter;
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    async fn active_usable_writer_count_for_dc_endpoints(
        &self,
        dc: i32,
        endpoints: &HashSet<SocketAddr>,
    ) -> usize {
        let generation = self.current_generation();
        self.writers
            .read()
            .await
            .iter()
            .filter(|writer| !writer.draining.load(std::sync::atomic::Ordering::Acquire))
            .filter(|writer| !writer.tx.is_closed() && !writer.cancel.is_cancelled())
            .filter(|writer| writer.generation == generation)
            .filter(|writer| {
                super::pool::WriterContour::from_u8(
                    writer.contour.load(std::sync::atomic::Ordering::Acquire),
                ) == super::pool::WriterContour::Active
            })
            .filter(|writer| writer.writer_dc == dc && endpoints.contains(&writer.addr))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecureRandom;
    use crate::network::probe::NetworkDecision;
    use crate::transport::middle_proxy::codec::WriterCommand;
    use crate::transport::middle_proxy::pool::{MeWriter, WriterContour};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64};
    use std::time::Instant;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use crate::transport::middle_proxy::pool_writer_security_tests::make_pool_with_decision;

    fn writer(
        pool: &Arc<MePool>,
        id: u64,
        dc: i32,
        addr: SocketAddr,
    ) -> (MeWriter, mpsc::Receiver<WriterCommand>) {
        let (tx, rx) = mpsc::channel::<WriterCommand>(8);
        (
            MeWriter {
                id,
                addr,
                source_ip: addr.ip(),
                writer_dc: dc,
                generation: pool.current_generation(),
                contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
                created_at: Instant::now(),
                tx,
                byte_budget: pool.new_writer_byte_budget(),
                cancel: CancellationToken::new(),
                degraded: Arc::new(AtomicBool::new(false)),
                rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
                draining: Arc::new(AtomicBool::new(false)),
                draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
                drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
                allow_drain_fallback: Arc::new(AtomicBool::new(false)),
            },
            rx,
        )
    }

    #[tokio::test]
    async fn init_coverage_ignores_closed_or_cancelled_writers() {
        let pool = make_pool_with_decision(NetworkDecision {
            ipv4_me: true,
            effective_prefer: 4,
            ..NetworkDecision::default()
        })
        .await;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let endpoints = HashSet::from([addr]);

        let (closed, receiver) = writer(&pool, 1, 2, addr);
        pool.writers.write().await.push(closed);
        assert_eq!(
            pool.active_usable_writer_count_for_dc_endpoints(2, &endpoints)
                .await,
            1
        );
        drop(receiver);
        assert_eq!(
            pool.active_usable_writer_count_for_dc_endpoints(2, &endpoints)
                .await,
            0
        );

        pool.writers.write().await.clear();
        let (cancelled, _receiver) = writer(&pool, 2, 2, addr);
        cancelled.cancel.cancel();
        pool.writers.write().await.push(cancelled);
        assert_eq!(
            pool.active_usable_writer_count_for_dc_endpoints(2, &endpoints)
                .await,
            0
        );
    }

    #[tokio::test]
    async fn init_dials_when_target_coverage_is_only_a_closed_writer() {
        let pool = make_pool_with_decision(NetworkDecision {
            ipv4_me: true,
            effective_prefer: 4,
            ..NetworkDecision::default()
        })
        .await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (attempt_tx, attempt_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = attempt_tx.send(());
                drop(stream);
            }
        });
        pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
            .await;
        let (closed, receiver) = writer(&pool, 1, 2, addr);
        drop(receiver);
        pool.writers.write().await.push(closed);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pool.init(1, &Arc::new(SecureRandom::new())),
        )
        .await
        .expect("local handshake failure must stay bounded");
        assert!(result.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(1), attempt_rx)
            .await
            .expect("closed writer must not satisfy startup coverage")
            .expect("init must dial its configured endpoint");
    }

    #[tokio::test]
    async fn init_keeps_missing_dc_and_admits_a_live_dc_with_partial_coverage() {
        let pool = make_pool_with_decision(NetworkDecision {
            ipv4_me: true,
            effective_prefer: 4,
            ..NetworkDecision::default()
        })
        .await;
        let dc2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 2, 2)), 443);
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dc5 = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            probe.local_addr().unwrap().port(),
        );
        drop(probe);
        pool.update_proxy_maps(
            HashMap::from([
                (2, vec![(dc2.ip(), dc2.port())]),
                (5, vec![(dc5.ip(), dc5.port())]),
            ]),
            None,
        )
        .await;
        let (writer, _writer_rx) = writer(&pool, 1, 2, dc2);
        pool.writers.write().await.push(writer);

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pool.init(1, &Arc::new(SecureRandom::new())),
        )
        .await
        .expect("closed-port failure must stay bounded")
        .expect("the live DC2 route admits partial startup");

        assert!(pool.admission_ready_conditional_cast().await);
        assert!(!pool.admission_ready_full_floor().await);
        assert!(
            pool.endpoint_snapshot
                .load()
                .map_v4
                .get(&5)
                .is_some_and(|endpoints| endpoints.contains(&(dc5.ip(), dc5.port())))
        );
        assert_eq!(
            pool.api_status_snapshot()
                .await
                .dcs
                .iter()
                .find(|dc| dc.dc == 5)
                .expect("missing DC5 remains visible")
                .alive_writers,
            0
        );
    }

    #[tokio::test]
    async fn init_attempts_alternate_enabled_family_before_failing() {
        let pool = make_pool_with_decision(NetworkDecision {
            ipv4_me: true,
            ipv6_me: true,
            effective_prefer: 4,
            ..NetworkDecision::default()
        })
        .await;
        let v4_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let v4 = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            v4_probe.local_addr().unwrap().port(),
        );
        drop(v4_probe);
        let v6_listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let v6 = v6_listener.local_addr().unwrap();
        let (attempt_tx, attempt_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((stream, _)) = v6_listener.accept().await {
                let _ = attempt_tx.send(());
                drop(stream);
            }
        });
        pool.update_proxy_maps(
            HashMap::from([(2, vec![(v4.ip(), v4.port())])]),
            Some(HashMap::from([(5, vec![(v6.ip(), v6.port())])])),
        )
        .await;
        pool.conn_count
            .store(1, std::sync::atomic::Ordering::Relaxed);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            pool.init(1, &Arc::new(SecureRandom::new())),
        )
        .await
        .expect("local route failures must stay bounded");
        assert!(result.is_err(), "neither endpoint completed a ME handshake");
        tokio::time::timeout(std::time::Duration::from_secs(1), attempt_rx)
            .await
            .expect("init must try enabled IPv6 after IPv4 fails")
            .expect("the local listener must observe the IPv6 TCP attempt");
    }

    #[tokio::test]
    async fn init_still_fails_when_every_configured_route_is_unavailable() {
        let pool = make_pool_with_decision(NetworkDecision {
            ipv4_me: true,
            effective_prefer: 4,
            ..NetworkDecision::default()
        })
        .await;
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            probe.local_addr().unwrap().port(),
        );
        drop(probe);
        pool.update_proxy_maps(HashMap::from([(5, vec![(addr.ip(), addr.port())])]), None)
            .await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pool.init(1, &Arc::new(SecureRandom::new())),
        )
        .await
        .expect("closed-port failure must stay bounded");
        assert!(result.is_err());
        assert!(!pool.admission_ready_conditional_cast().await);
    }
}
