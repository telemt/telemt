use super::*;

impl MePool {
    pub(crate) async fn admission_ready_conditional_cast(&self) -> bool {
        let mut endpoints_by_dc = BTreeMap::<i16, BTreeSet<SocketAddr>>::new();
        let endpoint_snapshot = self.endpoint_snapshot.load_full();
        if self.decision.ipv4_me {
            let map = endpoint_snapshot.map_v4.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }
        if self.decision.ipv6_me {
            let map = endpoint_snapshot.map_v6.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }

        if endpoints_by_dc.is_empty() {
            return false;
        }

        let active_generation = self.reinit.status.load().active_generation;
        let writers = self.writers.read().await.clone();
        let mut live_writers_by_dc = HashMap::<i16, usize>::new();
        for writer in writers.iter() {
            if writer.draining.load(Ordering::Relaxed)
                || writer.generation != active_generation
                || WriterContour::from_u8(writer.contour.load(Ordering::Relaxed))
                    != WriterContour::Active
            {
                continue;
            }
            if let Ok(dc) = i16::try_from(writer.writer_dc) {
                *live_writers_by_dc.entry(dc).or_insert(0) += 1;
            }
        }

        // A missing DC must not close healthy routes or force a global cutover.
        // The send path still requires a writer for the exact requested DC.
        endpoints_by_dc
            .keys()
            .any(|dc| live_writers_by_dc.get(dc).copied().unwrap_or(0) > 0)
    }

    #[allow(dead_code)]
    pub(crate) async fn admission_ready_full_floor(&self) -> bool {
        let mut endpoints_by_dc = BTreeMap::<i16, BTreeSet<SocketAddr>>::new();
        let endpoint_snapshot = self.endpoint_snapshot.load_full();
        if self.decision.ipv4_me {
            let map = endpoint_snapshot.map_v4.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }
        if self.decision.ipv6_me {
            let map = endpoint_snapshot.map_v6.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }

        if endpoints_by_dc.is_empty() {
            return false;
        }

        let active_generation = self.reinit.status.load().active_generation;
        let writers = self.writers.read().await.clone();
        let mut live_writers_by_group = HashMap::<(i16, bool), usize>::new();
        for writer in writers.iter() {
            if writer.draining.load(Ordering::Relaxed)
                || writer.generation != active_generation
                || WriterContour::from_u8(writer.contour.load(Ordering::Relaxed))
                    != WriterContour::Active
            {
                continue;
            }
            if let Ok(dc) = i16::try_from(writer.writer_dc) {
                *live_writers_by_group
                    .entry((dc, writer.addr.is_ipv4()))
                    .or_insert(0) += 1;
            }
        }

        for (dc, endpoints) in endpoints_by_dc {
            for (ipv4, endpoint_count) in endpoint_family_counts(&endpoints) {
                if endpoint_count == 0 {
                    continue;
                }
                let required = self.required_writers_for_dc_with_floor_mode(endpoint_count, false);
                let alive = live_writers_by_group.get(&(dc, ipv4)).copied().unwrap_or(0);
                if alive < required {
                    return false;
                }
            }
        }

        true
    }

    pub(crate) async fn api_status_snapshot(&self) -> MeApiStatusSnapshot {
        let reinit = self.reinit.status.load_full();
        self.api_status_snapshot_for_reinit(reinit.as_ref()).await
    }

    pub(super) async fn api_status_snapshot_for_reinit(
        &self,
        reinit: &ReinitStatusSnapshot,
    ) -> MeApiStatusSnapshot {
        let now_epoch_secs = Self::now_epoch_secs();
        let active_generation = reinit.active_generation;
        let drain_ttl_secs = self
            .drain_runtime
            .me_pool_drain_ttl_secs
            .load(Ordering::Relaxed);

        let mut endpoints_by_dc = BTreeMap::<i16, BTreeSet<SocketAddr>>::new();
        let endpoint_snapshot = self.endpoint_snapshot.load_full();
        if self.decision.ipv4_me {
            let map = endpoint_snapshot.map_v4.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }
        if self.decision.ipv6_me {
            let map = endpoint_snapshot.map_v6.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }

        let configured_dc_groups = endpoints_by_dc.len();
        let configured_endpoints = endpoints_by_dc.values().map(BTreeSet::len).sum();

        let required_writers = endpoints_by_dc
            .values()
            .map(|endpoints| {
                endpoint_family_counts(endpoints)
                    .into_iter()
                    .map(|(_, count)| self.required_writers_for_dc_with_floor_mode(count, false))
                    .sum::<usize>()
            })
            .sum();

        let idle_since = self.registry.writer_idle_since_snapshot().await;
        let activity = self.registry.writer_activity_snapshot().await;
        let rtt = self.rtt_stats.lock().await.clone();
        let writers = self.writers.read().await.clone();

        let mut live_writers_by_dc_endpoint = HashMap::<(i16, SocketAddr), usize>::new();
        let mut live_writers_by_dc = HashMap::<i16, usize>::new();
        let mut fresh_writers_by_dc = HashMap::<i16, usize>::new();
        let mut dc_rtt_agg = HashMap::<i16, (f64, u64)>::new();
        let mut writer_rows = Vec::<MeApiWriterStatusSnapshot>::with_capacity(writers.len());

        for writer in writers.iter() {
            let endpoint = writer.addr;
            let dc = i16::try_from(writer.writer_dc).ok();
            let draining = writer.draining.load(Ordering::Acquire);
            let degraded = writer.degraded.load(Ordering::Relaxed);
            let matches_active_generation = writer.generation == active_generation;
            let in_desired_map = dc
                .and_then(|dc_idx| endpoints_by_dc.get(&dc_idx))
                .is_some_and(|endpoints| endpoints.contains(&endpoint));
            let bound_clients = activity
                .bound_clients_by_writer
                .get(&writer.id)
                .copied()
                .unwrap_or(0);
            let idle_for_secs = idle_since
                .get(&writer.id)
                .map(|idle_ts| now_epoch_secs.saturating_sub(*idle_ts));
            let rtt_ema_ms = rtt.get(&writer.id).map(|(_, ema)| *ema);
            let allow_drain_fallback = writer.allow_drain_fallback.load(Ordering::Relaxed);
            let drain_started_at_epoch_secs = writer
                .draining_started_at_epoch_secs
                .load(Ordering::Relaxed);
            let drain_deadline_epoch_secs =
                writer.drain_deadline_epoch_secs.load(Ordering::Relaxed);
            let drain_started_at_epoch_secs =
                (drain_started_at_epoch_secs != 0).then_some(drain_started_at_epoch_secs);
            let drain_deadline_epoch_secs =
                (drain_deadline_epoch_secs != 0).then_some(drain_deadline_epoch_secs);
            let drain_over_ttl = draining
                && drain_ttl_secs > 0
                && drain_started_at_epoch_secs
                    .is_some_and(|started| now_epoch_secs.saturating_sub(started) > drain_ttl_secs);
            let contour = WriterContour::from_u8(writer.contour.load(Ordering::Relaxed));
            let state = match contour {
                WriterContour::Warm => "warm",
                WriterContour::Active => "active",
                WriterContour::Draining => "draining",
            };

            let authoritative_active = !draining
                && contour == WriterContour::Active
                && matches_active_generation
                && in_desired_map;
            if authoritative_active && let Some(dc_idx) = dc {
                *live_writers_by_dc_endpoint
                    .entry((dc_idx, endpoint))
                    .or_insert(0) += 1;
                *live_writers_by_dc.entry(dc_idx).or_insert(0) += 1;
                if let Some(ema_ms) = rtt_ema_ms {
                    let entry = dc_rtt_agg.entry(dc_idx).or_insert((0.0, 0));
                    entry.0 += ema_ms;
                    entry.1 += 1;
                }
                *fresh_writers_by_dc.entry(dc_idx).or_insert(0) += 1;
            }

            writer_rows.push(MeApiWriterStatusSnapshot {
                writer_id: writer.id,
                dc,
                endpoint,
                generation: writer.generation,
                state,
                draining,
                degraded,
                bound_clients,
                idle_for_secs,
                rtt_ema_ms,
                matches_active_generation,
                in_desired_map,
                allow_drain_fallback,
                drain_started_at_epoch_secs,
                drain_deadline_epoch_secs,
                drain_over_ttl,
            });
        }

        writer_rows.sort_by_key(|row| (row.dc.unwrap_or(i16::MAX), row.endpoint, row.writer_id));

        let mut dcs = Vec::<MeApiDcStatusSnapshot>::with_capacity(endpoints_by_dc.len());
        let mut available_endpoints = 0usize;
        let mut alive_writers = 0usize;
        let mut fresh_alive_writers = 0usize;
        let floor_mode = self.floor_mode();
        let adaptive_cpu_cores = (self
            .floor_runtime
            .me_adaptive_floor_cpu_cores_effective
            .load(Ordering::Relaxed) as usize)
            .max(1);
        for (dc, endpoints) in endpoints_by_dc {
            let endpoint_count = endpoints.len();
            let family_counts = endpoint_family_counts(&endpoints);
            let dc_available_endpoints = endpoints
                .iter()
                .filter(|endpoint| live_writers_by_dc_endpoint.contains_key(&(dc, **endpoint)))
                .count();
            let base_required = family_counts
                .iter()
                .filter(|(_, count)| *count > 0)
                .map(|(_, count)| self.required_writers_for_dc(*count))
                .sum::<usize>();
            let dc_required_writers = family_counts
                .iter()
                .filter(|(_, count)| *count > 0)
                .map(|(_, count)| self.required_writers_for_dc_with_floor_mode(*count, false))
                .sum::<usize>();
            let floor_min = family_counts
                .iter()
                .filter(|(_, count)| *count > 0)
                .map(|(_, count)| {
                    let family_base = self.required_writers_for_dc(*count);
                    let configured = if *count <= 1 {
                        self.floor_runtime
                            .me_adaptive_floor_min_writers_single_endpoint
                            .load(Ordering::Relaxed) as usize
                    } else {
                        self.floor_runtime
                            .me_adaptive_floor_min_writers_multi_endpoint
                            .load(Ordering::Relaxed) as usize
                    };
                    configured.max(1).min(family_base.max(1))
                })
                .sum::<usize>();
            let floor_max = family_counts
                .iter()
                .filter(|(_, count)| *count > 0)
                .map(|(_, count)| {
                    let family_base = self.required_writers_for_dc(*count);
                    let extra_per_core = if *count <= 1 {
                        self.floor_runtime
                            .me_adaptive_floor_max_extra_writers_single_per_core
                            .load(Ordering::Relaxed) as usize
                    } else {
                        self.floor_runtime
                            .me_adaptive_floor_max_extra_writers_multi_per_core
                            .load(Ordering::Relaxed) as usize
                    };
                    family_base.saturating_add(adaptive_cpu_cores.saturating_mul(extra_per_core))
                })
                .sum::<usize>();
            let floor_capped =
                matches!(floor_mode, MeFloorMode::Adaptive) && dc_required_writers < base_required;
            let dc_alive_writers = live_writers_by_dc.get(&dc).copied().unwrap_or(0);
            let dc_fresh_alive_writers = fresh_writers_by_dc.get(&dc).copied().unwrap_or(0);
            let dc_load = activity
                .active_sessions_by_target_dc
                .get(&dc)
                .copied()
                .unwrap_or(0);
            let dc_rtt_ms = dc_rtt_agg
                .get(&dc)
                .and_then(|(sum, count)| (*count > 0).then_some(*sum / (*count as f64)));

            available_endpoints += dc_available_endpoints;
            alive_writers += dc_alive_writers;
            fresh_alive_writers += dc_fresh_alive_writers;

            dcs.push(MeApiDcStatusSnapshot {
                dc,
                endpoint_writers: endpoints
                    .iter()
                    .map(|endpoint| MeApiDcEndpointWriterSnapshot {
                        endpoint: *endpoint,
                        active_writers: live_writers_by_dc_endpoint
                            .get(&(dc, *endpoint))
                            .copied()
                            .unwrap_or(0),
                    })
                    .collect(),
                endpoints: endpoints.into_iter().collect(),
                available_endpoints: dc_available_endpoints,
                available_pct: ratio_pct(dc_available_endpoints, endpoint_count),
                required_writers: dc_required_writers,
                floor_min,
                floor_target: dc_required_writers,
                floor_max,
                floor_capped,
                alive_writers: dc_alive_writers,
                coverage_pct: ratio_pct(dc_alive_writers, dc_required_writers),
                fresh_alive_writers: dc_fresh_alive_writers,
                fresh_coverage_pct: ratio_pct(dc_fresh_alive_writers, dc_required_writers),
                rtt_ms: dc_rtt_ms,
                load: dc_load,
            });
        }

        MeApiStatusSnapshot {
            generated_at_epoch_secs: now_epoch_secs,
            configured_dc_groups,
            configured_endpoints,
            available_endpoints,
            available_pct: ratio_pct(available_endpoints, configured_endpoints),
            required_writers,
            alive_writers,
            coverage_pct: ratio_pct(alive_writers, required_writers),
            fresh_alive_writers,
            fresh_coverage_pct: ratio_pct(fresh_alive_writers, required_writers),
            writers: writer_rows,
            dcs,
        }
    }
}

fn endpoint_family_counts(endpoints: &BTreeSet<SocketAddr>) -> [(bool, usize); 2] {
    let ipv4 = endpoints
        .iter()
        .filter(|endpoint| endpoint.is_ipv4())
        .count();
    [(true, ipv4), (false, endpoints.len().saturating_sub(ipv4))]
}
