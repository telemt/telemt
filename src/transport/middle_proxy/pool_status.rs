use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::pool::{MePool, MeWriter, WriterContour};
use crate::config::{MeBindStaleMode, MeFloorMode, MeSocksKdfPolicy};
use crate::network::IpFamily;
use crate::transport::upstream::IpPreference;

#[derive(Clone, Debug)]
pub(crate) struct MeApiWriterStatusSnapshot {
    pub writer_id: u64,
    pub dc: Option<i16>,
    pub endpoint: SocketAddr,
    pub generation: u64,
    pub state: &'static str,
    pub draining: bool,
    pub degraded: bool,
    pub bound_clients: usize,
    pub idle_for_secs: Option<u64>,
    pub rtt_ema_ms: Option<f64>,
    pub matches_active_generation: bool,
    pub in_desired_map: bool,
    pub allow_drain_fallback: bool,
    pub drain_started_at_epoch_secs: Option<u64>,
    pub drain_deadline_epoch_secs: Option<u64>,
    pub drain_over_ttl: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiDcStatusSnapshot {
    pub dc: i16,
    pub endpoints: Vec<SocketAddr>,
    pub endpoint_writers: Vec<MeApiDcEndpointWriterSnapshot>,
    pub available_endpoints: usize,
    pub available_pct: f64,
    pub required_writers: usize,
    pub floor_min: usize,
    pub floor_target: usize,
    pub floor_max: usize,
    pub floor_capped: bool,
    pub alive_writers: usize,
    pub coverage_pct: f64,
    pub fresh_alive_writers: usize,
    pub fresh_coverage_pct: f64,
    pub rtt_ms: Option<f64>,
    pub load: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiDcEndpointWriterSnapshot {
    pub endpoint: SocketAddr,
    pub active_writers: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiStatusSnapshot {
    pub generated_at_epoch_secs: u64,
    pub configured_dc_groups: usize,
    pub configured_endpoints: usize,
    pub available_endpoints: usize,
    pub available_pct: f64,
    pub required_writers: usize,
    pub alive_writers: usize,
    pub coverage_pct: f64,
    pub fresh_alive_writers: usize,
    pub fresh_coverage_pct: f64,
    pub writers: Vec<MeApiWriterStatusSnapshot>,
    pub dcs: Vec<MeApiDcStatusSnapshot>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiQuarantinedEndpointSnapshot {
    pub endpoint: SocketAddr,
    pub remaining_ms: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiDcPathSnapshot {
    pub dc: i16,
    pub ip_preference: Option<&'static str>,
    pub selected_addr_v4: Option<SocketAddr>,
    pub selected_addr_v6: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiRuntimeSnapshot {
    pub active_generation: u64,
    pub warm_generation: u64,
    pub pending_hardswap_generation: u64,
    pub pending_hardswap_age_secs: Option<u64>,
    pub hardswap_enabled: bool,
    pub floor_mode: &'static str,
    pub adaptive_floor_idle_secs: u64,
    pub adaptive_floor_min_writers_single_endpoint: u8,
    pub adaptive_floor_min_writers_multi_endpoint: u8,
    pub adaptive_floor_recover_grace_secs: u64,
    pub adaptive_floor_writers_per_core_total: u16,
    pub adaptive_floor_cpu_cores_override: u16,
    pub adaptive_floor_max_extra_writers_single_per_core: u16,
    pub adaptive_floor_max_extra_writers_multi_per_core: u16,
    pub adaptive_floor_max_active_writers_per_core: u16,
    pub adaptive_floor_max_warm_writers_per_core: u16,
    pub adaptive_floor_max_active_writers_global: u32,
    pub adaptive_floor_max_warm_writers_global: u32,
    pub adaptive_floor_cpu_cores_detected: u32,
    pub adaptive_floor_cpu_cores_effective: u32,
    pub adaptive_floor_global_cap_raw: u64,
    pub adaptive_floor_global_cap_effective: u64,
    pub adaptive_floor_target_writers_total: u64,
    pub adaptive_floor_active_cap_configured: u64,
    pub adaptive_floor_active_cap_effective: u64,
    pub adaptive_floor_warm_cap_configured: u64,
    pub adaptive_floor_warm_cap_effective: u64,
    pub adaptive_floor_active_writers_current: u64,
    pub adaptive_floor_warm_writers_current: u64,
    pub me_keepalive_enabled: bool,
    pub me_keepalive_interval_secs: u64,
    pub me_keepalive_jitter_secs: u64,
    pub me_keepalive_payload_random: bool,
    pub rpc_proxy_req_every_secs: u64,
    pub me_reconnect_max_concurrent_per_dc: u32,
    pub me_reconnect_backoff_base_ms: u64,
    pub me_reconnect_backoff_cap_ms: u64,
    pub me_reconnect_fast_retry_count: u32,
    pub me_pool_drain_ttl_secs: u64,
    pub me_pool_force_close_secs: u64,
    pub me_pool_min_fresh_ratio: f32,
    pub me_bind_stale_mode: &'static str,
    pub me_bind_stale_ttl_secs: u64,
    pub me_single_endpoint_shadow_writers: u8,
    pub me_single_endpoint_outage_mode_enabled: bool,
    pub me_single_endpoint_outage_disable_quarantine: bool,
    pub me_single_endpoint_outage_backoff_min_ms: u64,
    pub me_single_endpoint_outage_backoff_max_ms: u64,
    pub me_single_endpoint_shadow_rotate_every_secs: u64,
    pub me_deterministic_writer_sort: bool,
    pub me_writer_pick_mode: &'static str,
    pub me_writer_pick_sample_size: u8,
    pub me_socks_kdf_policy: &'static str,
    pub quarantined_endpoints: Vec<MeApiQuarantinedEndpointSnapshot>,
    pub network_path: Vec<MeApiDcPathSnapshot>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MeAdmissionCoverageSnapshot {
    pub configured_dcs: BTreeSet<i16>,
    pub ready_dcs: BTreeSet<i16>,
}

fn writer_ip_family(writer: &MeWriter) -> IpFamily {
    if writer.addr.is_ipv6() {
        IpFamily::V6
    } else {
        IpFamily::V4
    }
}

fn family_configured_for_admission(pool: &MePool, family: IpFamily) -> bool {
    match family {
        IpFamily::V4 => pool.decision.ipv4_me,
        IpFamily::V6 => pool.decision.ipv6_me,
    }
}

impl MePool {
    pub(crate) async fn admission_coverage_snapshot(&self) -> MeAdmissionCoverageSnapshot {
        let mut configured_dcs = BTreeSet::<i16>::new();
        let mut configured_families_by_dc = HashMap::<i16, HashSet<IpFamily>>::new();

        if family_configured_for_admission(self, IpFamily::V4) {
            let map = self.proxy_map_v4.read().await;
            for (dc, _) in map.iter().filter(|(_, endpoints)| !endpoints.is_empty()) {
                if let Ok(dc) = i16::try_from(*dc) {
                    configured_dcs.insert(dc);
                    configured_families_by_dc
                        .entry(dc)
                        .or_default()
                        .insert(IpFamily::V4);
                }
            }
        }
        if family_configured_for_admission(self, IpFamily::V6) {
            let map = self.proxy_map_v6.read().await;
            for (dc, _) in map.iter().filter(|(_, endpoints)| !endpoints.is_empty()) {
                if let Ok(dc) = i16::try_from(*dc) {
                    configured_dcs.insert(dc);
                    configured_families_by_dc
                        .entry(dc)
                        .or_default()
                        .insert(IpFamily::V6);
                }
            }
        }

        let writers = self.writers.read().await.clone();
        let mut ready_dcs = BTreeSet::<i16>::new();
        for writer in writers.iter() {
            if writer.draining.load(Ordering::Relaxed) {
                continue;
            }
            if let Ok(dc) = i16::try_from(writer.writer_dc)
                && configured_families_by_dc
                    .get(&dc)
                    .is_some_and(|families| families.contains(&writer_ip_family(writer)))
            {
                ready_dcs.insert(dc);
            }
        }

        MeAdmissionCoverageSnapshot {
            configured_dcs,
            ready_dcs,
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn admission_ready_partial_cast(&self) -> bool {
        let snapshot = self.admission_coverage_snapshot().await;
        !snapshot.configured_dcs.is_empty() && !snapshot.ready_dcs.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) async fn admission_ready_conditional_cast(&self) -> bool {
        let snapshot = self.admission_coverage_snapshot().await;
        !snapshot.configured_dcs.is_empty() && snapshot.ready_dcs == snapshot.configured_dcs
    }

    pub(crate) async fn admission_ready_for_target_dc(&self, target_dc: i16) -> bool {
        let (routed_dc, _) = self.resolve_target_dc_for_routing(target_dc as i32).await;
        let mut configured_families = HashSet::<IpFamily>::new();

        if family_configured_for_admission(self, IpFamily::V4) {
            let map = self.proxy_map_v4.read().await;
            if map.get(&routed_dc).is_some_and(|endpoints| !endpoints.is_empty()) {
                configured_families.insert(IpFamily::V4);
            }
        }
        if family_configured_for_admission(self, IpFamily::V6) {
            let map = self.proxy_map_v6.read().await;
            if map.get(&routed_dc).is_some_and(|endpoints| !endpoints.is_empty()) {
                configured_families.insert(IpFamily::V6);
            }
        }

        if configured_families.is_empty() {
            return false;
        }

        let writers = self.writers.read().await.clone();
        writers.iter().any(|writer| {
            !writer.draining.load(Ordering::Relaxed)
                && writer.writer_dc == routed_dc
                && configured_families.contains(&writer_ip_family(writer))
        })
    }

    #[allow(dead_code)]
    pub(crate) async fn admission_ready_full_floor(&self) -> bool {
        let mut endpoints_by_dc = BTreeMap::<i16, BTreeSet<SocketAddr>>::new();
        let now_epoch_secs = Self::now_epoch_secs();
        if self.family_enabled_for_drain_coverage(IpFamily::V4, now_epoch_secs) {
            let map = self.proxy_map_v4.read().await.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }
        if self.family_enabled_for_drain_coverage(IpFamily::V6, now_epoch_secs) {
            let map = self.proxy_map_v6.read().await.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }

        if endpoints_by_dc.is_empty() {
            return false;
        }

        let writers = self.writers.read().await.clone();
        let mut live_writers_by_dc_family = HashMap::<(i16, IpFamily), usize>::new();
        for writer in writers.iter() {
            if writer.draining.load(Ordering::Relaxed) {
                continue;
            }
            if let Ok(dc) = i16::try_from(writer.writer_dc) {
                *live_writers_by_dc_family
                    .entry((dc, writer_ip_family(writer)))
                    .or_insert(0) += 1;
            }
        }

        for (dc, endpoints) in endpoints_by_dc {
            let endpoint_count = endpoints.len();
            if endpoint_count == 0 {
                return false;
            }
            let required = self.required_writers_for_dc_with_floor_mode(endpoint_count, false);
            let alive = endpoints.iter().fold(0usize, |acc, endpoint| {
                let family = if endpoint.is_ipv6() {
                    IpFamily::V6
                } else {
                    IpFamily::V4
                };
                acc.saturating_add(
                    live_writers_by_dc_family
                        .get(&(dc, family))
                        .copied()
                        .unwrap_or(0),
                )
            });
            if alive < required {
                return false;
            }
        }

        true
    }

    pub(crate) async fn api_status_snapshot(&self) -> MeApiStatusSnapshot {
        let now_epoch_secs = Self::now_epoch_secs();
        let active_generation = self.current_generation();
        let drain_ttl_secs = self
            .drain_runtime
            .me_pool_drain_ttl_secs
            .load(Ordering::Relaxed);

        let mut endpoints_by_dc = BTreeMap::<i16, BTreeSet<SocketAddr>>::new();
        if self.decision.ipv4_me {
            let map = self.proxy_map_v4.read().await.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }
        if self.decision.ipv6_me {
            let map = self.proxy_map_v6.read().await.clone();
            extend_signed_endpoints(&mut endpoints_by_dc, map);
        }

        let configured_dc_groups = endpoints_by_dc.len();
        let configured_endpoints = endpoints_by_dc.values().map(BTreeSet::len).sum();

        let required_writers = endpoints_by_dc
            .values()
            .map(|endpoints| self.required_writers_for_dc_with_floor_mode(endpoints.len(), false))
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
            let draining = writer.draining.load(Ordering::Relaxed);
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
            let state = match WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) {
                WriterContour::Warm => "warm",
                WriterContour::Active => "active",
                WriterContour::Draining => "draining",
            };

            if !draining && let Some(dc_idx) = dc {
                *live_writers_by_dc_endpoint
                    .entry((dc_idx, endpoint))
                    .or_insert(0) += 1;
                *live_writers_by_dc.entry(dc_idx).or_insert(0) += 1;
                if let Some(ema_ms) = rtt_ema_ms {
                    let entry = dc_rtt_agg.entry(dc_idx).or_insert((0.0, 0));
                    entry.0 += ema_ms;
                    entry.1 += 1;
                }
                if matches_active_generation && in_desired_map {
                    *fresh_writers_by_dc.entry(dc_idx).or_insert(0) += 1;
                }
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
            let dc_available_endpoints = endpoints
                .iter()
                .filter(|endpoint| live_writers_by_dc_endpoint.contains_key(&(dc, **endpoint)))
                .count();
            let base_required = self.required_writers_for_dc(endpoint_count);
            let dc_required_writers =
                self.required_writers_for_dc_with_floor_mode(endpoint_count, false);
            let floor_min = if endpoint_count <= 1 {
                (self
                    .floor_runtime
                    .me_adaptive_floor_min_writers_single_endpoint
                    .load(Ordering::Relaxed) as usize)
                    .max(1)
                    .min(base_required.max(1))
            } else {
                (self
                    .floor_runtime
                    .me_adaptive_floor_min_writers_multi_endpoint
                    .load(Ordering::Relaxed) as usize)
                    .max(1)
                    .min(base_required.max(1))
            };
            let extra_per_core = if endpoint_count <= 1 {
                self.floor_runtime
                    .me_adaptive_floor_max_extra_writers_single_per_core
                    .load(Ordering::Relaxed) as usize
            } else {
                self.floor_runtime
                    .me_adaptive_floor_max_extra_writers_multi_per_core
                    .load(Ordering::Relaxed) as usize
            };
            let floor_max =
                base_required.saturating_add(adaptive_cpu_cores.saturating_mul(extra_per_core));
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

    pub(crate) async fn api_runtime_snapshot(&self) -> MeApiRuntimeSnapshot {
        let now = Instant::now();
        let now_epoch_secs = Self::now_epoch_secs();
        let pending_started_at = self
            .reinit
            .pending_hardswap_started_at_epoch_secs
            .load(Ordering::Relaxed);
        let pending_hardswap_age_secs =
            (pending_started_at > 0).then_some(now_epoch_secs.saturating_sub(pending_started_at));

        let mut quarantined_endpoints = Vec::<MeApiQuarantinedEndpointSnapshot>::new();
        {
            let guard = self.endpoint_quarantine.lock().await;
            for (endpoint, expires_at) in guard.iter() {
                if *expires_at <= now {
                    continue;
                }
                let remaining_ms = expires_at.duration_since(now).as_millis() as u64;
                quarantined_endpoints.push(MeApiQuarantinedEndpointSnapshot {
                    endpoint: *endpoint,
                    remaining_ms,
                });
            }
        }
        quarantined_endpoints.sort_by_key(|entry| entry.endpoint);

        let mut network_path = Vec::<MeApiDcPathSnapshot>::new();
        if let Some(upstream) = &self.upstream {
            for dc in 1..=5 {
                let dc_idx = dc as i16;
                let ip_preference = upstream
                    .get_dc_ip_preference(dc_idx)
                    .await
                    .map(ip_preference_label);
                let selected_addr_v4 = upstream.get_dc_addr(dc_idx, false).await;
                let selected_addr_v6 = upstream.get_dc_addr(dc_idx, true).await;
                network_path.push(MeApiDcPathSnapshot {
                    dc: dc_idx,
                    ip_preference,
                    selected_addr_v4,
                    selected_addr_v6,
                });
            }
        }

        MeApiRuntimeSnapshot {
            active_generation: self.reinit.active_generation.load(Ordering::Relaxed),
            warm_generation: self.reinit.warm_generation.load(Ordering::Relaxed),
            pending_hardswap_generation: self
                .reinit
                .pending_hardswap_generation
                .load(Ordering::Relaxed),
            pending_hardswap_age_secs,
            hardswap_enabled: self.reinit.hardswap.load(Ordering::Relaxed),
            floor_mode: floor_mode_label(self.floor_mode()),
            adaptive_floor_idle_secs: self
                .floor_runtime
                .me_adaptive_floor_idle_secs
                .load(Ordering::Relaxed),
            adaptive_floor_min_writers_single_endpoint: self
                .floor_runtime
                .me_adaptive_floor_min_writers_single_endpoint
                .load(Ordering::Relaxed),
            adaptive_floor_min_writers_multi_endpoint: self
                .floor_runtime
                .me_adaptive_floor_min_writers_multi_endpoint
                .load(Ordering::Relaxed),
            adaptive_floor_recover_grace_secs: self
                .floor_runtime
                .me_adaptive_floor_recover_grace_secs
                .load(Ordering::Relaxed),
            adaptive_floor_writers_per_core_total: self
                .floor_runtime
                .me_adaptive_floor_writers_per_core_total
                .load(Ordering::Relaxed) as u16,
            adaptive_floor_cpu_cores_override: self
                .floor_runtime
                .me_adaptive_floor_cpu_cores_override
                .load(Ordering::Relaxed) as u16,
            adaptive_floor_max_extra_writers_single_per_core: self
                .floor_runtime
                .me_adaptive_floor_max_extra_writers_single_per_core
                .load(Ordering::Relaxed)
                as u16,
            adaptive_floor_max_extra_writers_multi_per_core: self
                .floor_runtime
                .me_adaptive_floor_max_extra_writers_multi_per_core
                .load(Ordering::Relaxed)
                as u16,
            adaptive_floor_max_active_writers_per_core: self
                .floor_runtime
                .me_adaptive_floor_max_active_writers_per_core
                .load(Ordering::Relaxed)
                as u16,
            adaptive_floor_max_warm_writers_per_core: self
                .floor_runtime
                .me_adaptive_floor_max_warm_writers_per_core
                .load(Ordering::Relaxed)
                as u16,
            adaptive_floor_max_active_writers_global: self
                .floor_runtime
                .me_adaptive_floor_max_active_writers_global
                .load(Ordering::Relaxed),
            adaptive_floor_max_warm_writers_global: self
                .floor_runtime
                .me_adaptive_floor_max_warm_writers_global
                .load(Ordering::Relaxed),
            adaptive_floor_cpu_cores_detected: self
                .floor_runtime
                .me_adaptive_floor_cpu_cores_detected
                .load(Ordering::Relaxed),
            adaptive_floor_cpu_cores_effective: self
                .floor_runtime
                .me_adaptive_floor_cpu_cores_effective
                .load(Ordering::Relaxed),
            adaptive_floor_global_cap_raw: self
                .floor_runtime
                .me_adaptive_floor_global_cap_raw
                .load(Ordering::Relaxed),
            adaptive_floor_global_cap_effective: self
                .floor_runtime
                .me_adaptive_floor_global_cap_effective
                .load(Ordering::Relaxed),
            adaptive_floor_target_writers_total: self
                .floor_runtime
                .me_adaptive_floor_target_writers_total
                .load(Ordering::Relaxed),
            adaptive_floor_active_cap_configured: self
                .floor_runtime
                .me_adaptive_floor_active_cap_configured
                .load(Ordering::Relaxed),
            adaptive_floor_active_cap_effective: self
                .floor_runtime
                .me_adaptive_floor_active_cap_effective
                .load(Ordering::Relaxed),
            adaptive_floor_warm_cap_configured: self
                .floor_runtime
                .me_adaptive_floor_warm_cap_configured
                .load(Ordering::Relaxed),
            adaptive_floor_warm_cap_effective: self
                .floor_runtime
                .me_adaptive_floor_warm_cap_effective
                .load(Ordering::Relaxed),
            adaptive_floor_active_writers_current: self
                .floor_runtime
                .me_adaptive_floor_active_writers_current
                .load(Ordering::Relaxed),
            adaptive_floor_warm_writers_current: self
                .floor_runtime
                .me_adaptive_floor_warm_writers_current
                .load(Ordering::Relaxed),
            me_keepalive_enabled: self.writer_lifecycle.me_keepalive_enabled,
            me_keepalive_interval_secs: self.writer_lifecycle.me_keepalive_interval.as_secs(),
            me_keepalive_jitter_secs: self.writer_lifecycle.me_keepalive_jitter.as_secs(),
            me_keepalive_payload_random: self.writer_lifecycle.me_keepalive_payload_random,
            rpc_proxy_req_every_secs: self
                .writer_lifecycle
                .rpc_proxy_req_every_secs
                .load(Ordering::Relaxed),
            me_reconnect_max_concurrent_per_dc: self
                .reconnect_runtime
                .me_reconnect_max_concurrent_per_dc,
            me_reconnect_backoff_base_ms: self
                .reconnect_runtime
                .me_reconnect_backoff_base
                .as_millis() as u64,
            me_reconnect_backoff_cap_ms: self.reconnect_runtime.me_reconnect_backoff_cap.as_millis()
                as u64,
            me_reconnect_fast_retry_count: self.reconnect_runtime.me_reconnect_fast_retry_count,
            me_pool_drain_ttl_secs: self
                .drain_runtime
                .me_pool_drain_ttl_secs
                .load(Ordering::Relaxed),
            me_pool_force_close_secs: self
                .drain_runtime
                .me_pool_force_close_secs
                .load(Ordering::Relaxed),
            me_pool_min_fresh_ratio: Self::permille_to_ratio(
                self.drain_runtime
                    .me_pool_min_fresh_ratio_permille
                    .load(Ordering::Relaxed),
            ),
            me_bind_stale_mode: bind_stale_mode_label(self.bind_stale_mode()),
            me_bind_stale_ttl_secs: self
                .binding_policy
                .me_bind_stale_ttl_secs
                .load(Ordering::Relaxed),
            me_single_endpoint_shadow_writers: self
                .single_endpoint_runtime
                .me_single_endpoint_shadow_writers
                .load(Ordering::Relaxed),
            me_single_endpoint_outage_mode_enabled: self
                .single_endpoint_runtime
                .me_single_endpoint_outage_mode_enabled
                .load(Ordering::Relaxed),
            me_single_endpoint_outage_disable_quarantine: self
                .single_endpoint_runtime
                .me_single_endpoint_outage_disable_quarantine
                .load(Ordering::Relaxed),
            me_single_endpoint_outage_backoff_min_ms: self
                .single_endpoint_runtime
                .me_single_endpoint_outage_backoff_min_ms
                .load(Ordering::Relaxed),
            me_single_endpoint_outage_backoff_max_ms: self
                .single_endpoint_runtime
                .me_single_endpoint_outage_backoff_max_ms
                .load(Ordering::Relaxed),
            me_single_endpoint_shadow_rotate_every_secs: self
                .single_endpoint_runtime
                .me_single_endpoint_shadow_rotate_every_secs
                .load(Ordering::Relaxed),
            me_deterministic_writer_sort: self
                .writer_selection_policy
                .me_deterministic_writer_sort
                .load(Ordering::Relaxed),
            me_writer_pick_mode: writer_pick_mode_label(self.writer_pick_mode()),
            me_writer_pick_sample_size: self.writer_pick_sample_size() as u8,
            me_socks_kdf_policy: socks_kdf_policy_label(self.socks_kdf_policy()),
            quarantined_endpoints,
            network_path,
        }
    }
}

fn ratio_pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let pct = ((part as f64) / (total as f64)) * 100.0;
    pct.clamp(0.0, 100.0)
}

fn extend_signed_endpoints(
    endpoints_by_dc: &mut BTreeMap<i16, BTreeSet<SocketAddr>>,
    map: HashMap<i32, Vec<(IpAddr, u16)>>,
) {
    for (dc, addrs) in map {
        if dc == 0 {
            continue;
        }
        let Ok(dc_idx) = i16::try_from(dc) else {
            continue;
        };
        let entry = endpoints_by_dc.entry(dc_idx).or_default();
        for (ip, port) in addrs {
            entry.insert(SocketAddr::new(ip, port));
        }
    }
}

fn floor_mode_label(mode: MeFloorMode) -> &'static str {
    match mode {
        MeFloorMode::Static => "static",
        MeFloorMode::Adaptive => "adaptive",
    }
}

fn bind_stale_mode_label(mode: MeBindStaleMode) -> &'static str {
    match mode {
        MeBindStaleMode::Never => "never",
        MeBindStaleMode::Ttl => "ttl",
        MeBindStaleMode::Always => "always",
    }
}

fn writer_pick_mode_label(mode: crate::config::MeWriterPickMode) -> &'static str {
    match mode {
        crate::config::MeWriterPickMode::SortedRr => "sorted_rr",
        crate::config::MeWriterPickMode::P2c => "p2c",
    }
}

fn socks_kdf_policy_label(policy: MeSocksKdfPolicy) -> &'static str {
    match policy {
        MeSocksKdfPolicy::Strict => "strict",
        MeSocksKdfPolicy::Compat => "compat",
    }
}

fn ip_preference_label(preference: IpPreference) -> &'static str {
    match preference {
        IpPreference::Unknown => "unknown",
        IpPreference::PreferV6 => "prefer_v6",
        IpPreference::PreferV4 => "prefer_v4",
        IpPreference::BothWork => "both",
        IpPreference::Unavailable => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
    use std::time::Instant;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::ratio_pct;
    use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeWriterPickMode};
    use crate::crypto::SecureRandom;
    use crate::network::IpFamily;
    use crate::network::probe::NetworkDecision;
    use crate::stats::Stats;
    use crate::transport::middle_proxy::codec::WriterCommand;
    use crate::transport::middle_proxy::pool::{MePool, MeWriter, WriterContour};

    #[test]
    fn ratio_pct_is_zero_when_denominator_is_zero() {
        assert_eq!(ratio_pct(1, 0), 0.0);
    }

    #[test]
    fn ratio_pct_is_capped_at_100() {
        assert_eq!(ratio_pct(7, 3), 100.0);
    }

    #[test]
    fn ratio_pct_reports_expected_value() {
        assert_eq!(ratio_pct(1, 4), 25.0);
    }

    async fn make_pool() -> Arc<MePool> {
        let general = GeneralConfig::default();
        let mut proxy_map_v4 = HashMap::new();
        proxy_map_v4.insert(2, vec![(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443)]);
        proxy_map_v4.insert(3, vec![(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)), 443)]);
        let decision = NetworkDecision {
            ipv4_me: true,
            ..NetworkDecision::default()
        };
        MePool::new(
            None,
            vec![1u8; 32],
            None,
            false,
            None,
            Vec::new(),
            1,
            None,
            12,
            1200,
            proxy_map_v4,
            HashMap::new(),
            None,
            decision,
            None,
            Arc::new(SecureRandom::new()),
            Arc::new(Stats::default()),
            general.me_keepalive_enabled,
            general.me_keepalive_interval_secs,
            general.me_keepalive_jitter_secs,
            general.me_keepalive_payload_random,
            general.rpc_proxy_req_every,
            general.me_warmup_stagger_enabled,
            general.me_warmup_step_delay_ms,
            general.me_warmup_step_jitter_ms,
            general.me_reconnect_max_concurrent_per_dc,
            general.me_reconnect_backoff_base_ms,
            general.me_reconnect_backoff_cap_ms,
            general.me_reconnect_fast_retry_count,
            general.me_single_endpoint_shadow_writers,
            general.me_single_endpoint_outage_mode_enabled,
            general.me_single_endpoint_outage_disable_quarantine,
            general.me_single_endpoint_outage_backoff_min_ms,
            general.me_single_endpoint_outage_backoff_max_ms,
            general.me_single_endpoint_shadow_rotate_every_secs,
            general.me_floor_mode,
            general.me_adaptive_floor_idle_secs,
            general.me_adaptive_floor_min_writers_single_endpoint,
            general.me_adaptive_floor_min_writers_multi_endpoint,
            general.me_adaptive_floor_recover_grace_secs,
            general.me_adaptive_floor_writers_per_core_total,
            general.me_adaptive_floor_cpu_cores_override,
            general.me_adaptive_floor_max_extra_writers_single_per_core,
            general.me_adaptive_floor_max_extra_writers_multi_per_core,
            general.me_adaptive_floor_max_active_writers_per_core,
            general.me_adaptive_floor_max_warm_writers_per_core,
            general.me_adaptive_floor_max_active_writers_global,
            general.me_adaptive_floor_max_warm_writers_global,
            general.hardswap,
            general.me_pool_drain_ttl_secs,
            general.me_instadrain,
            general.me_pool_drain_threshold,
            general.me_pool_drain_soft_evict_enabled,
            general.me_pool_drain_soft_evict_grace_secs,
            general.me_pool_drain_soft_evict_per_writer,
            general.me_pool_drain_soft_evict_budget_per_core,
            general.me_pool_drain_soft_evict_cooldown_ms,
            general.effective_me_pool_force_close_secs(),
            general.me_pool_min_fresh_ratio,
            general.me_hardswap_warmup_delay_min_ms,
            general.me_hardswap_warmup_delay_max_ms,
            general.me_hardswap_warmup_extra_passes,
            general.me_hardswap_warmup_pass_backoff_base_ms,
            general.me_bind_stale_mode,
            general.me_bind_stale_ttl_secs,
            general.me_secret_atomic_snapshot,
            general.me_deterministic_writer_sort,
            MeWriterPickMode::default(),
            general.me_writer_pick_sample_size,
            crate::config::MeSocksKdfPolicy::default(),
            general.me_writer_cmd_channel_capacity,
            general.me_route_channel_capacity,
            general.me_route_backpressure_enabled,
            general.me_route_fairshare_enabled,
            general.me_route_backpressure_base_timeout_ms,
            general.me_route_backpressure_high_timeout_ms,
            general.me_route_backpressure_high_watermark_pct,
            general.me_reader_route_data_wait_ms,
            general.me_health_interval_ms_unhealthy,
            general.me_health_interval_ms_healthy,
            general.me_warn_rate_limit_ms,
            MeRouteNoWriterMode::default(),
            general.me_route_no_writer_wait_ms,
            general.me_route_hybrid_max_wait_ms,
            general.me_route_blocking_send_timeout_ms,
            general.me_route_inline_recovery_attempts,
            general.me_route_inline_recovery_wait_ms,
        )
    }

    async fn insert_live_writer(
        pool: &Arc<MePool>,
        writer_id: u64,
        writer_dc: i32,
        endpoint: SocketAddr,
    ) {
        let (tx, _writer_rx) = mpsc::channel::<WriterCommand>(8);
        let writer = MeWriter {
            id: writer_id,
            addr: endpoint,
            source_ip: endpoint.ip(),
            writer_dc,
            generation: 1,
            contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
            created_at: Instant::now(),
            tx: tx.clone(),
            cancel: CancellationToken::new(),
            degraded: Arc::new(AtomicBool::new(false)),
            rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
            draining: Arc::new(AtomicBool::new(false)),
            draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
            drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
            allow_drain_fallback: Arc::new(AtomicBool::new(false)),
        };
        pool.writers.write().await.push(writer);
        pool.registry.register_writer(writer_id, tx).await;
        pool.conn_count.fetch_add(1, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn admission_ready_partial_cast_accepts_partial_dc_coverage() {
        let pool = make_pool().await;
        insert_live_writer(
            &pool,
            1,
            2,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21)), 4001),
        )
        .await;

        assert!(pool.admission_ready_partial_cast().await);
        assert!(!pool.admission_ready_conditional_cast().await);
    }

    #[tokio::test]
    async fn admission_ready_for_target_dc_checks_requested_dc() {
        let pool = make_pool().await;
        insert_live_writer(
            &pool,
            1,
            2,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21)), 4001),
        )
        .await;

        assert!(pool.admission_ready_for_target_dc(2).await);
        assert!(!pool.admission_ready_for_target_dc(3).await);
    }

    #[tokio::test]
    async fn admission_ready_for_target_dc_ignores_writer_from_uncovered_family() {
        let pool = make_pool().await;
        pool.proxy_map_v4.write().await.remove(&2);
        pool.proxy_map_v6.write().await.insert(
            2,
            vec![(IpAddr::V6("2001:db8::10".parse().unwrap()), 443)],
        );

        insert_live_writer(
            &pool,
            1,
            2,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21)), 4001),
        )
        .await;

        assert!(!pool.admission_ready_for_target_dc(2).await);
        assert!(!pool.admission_ready_partial_cast().await);
        assert!(!pool.admission_ready_conditional_cast().await);
    }

    #[tokio::test]
    async fn admission_snapshot_keeps_configured_family_during_runtime_suppression() {
        let pool = make_pool().await;
        pool.set_family_runtime_state(
            IpFamily::V4,
            crate::transport::middle_proxy::pool::MeFamilyRuntimeState::Suppressed,
            1,
            u64::MAX,
            5,
            0,
        );

        insert_live_writer(
            &pool,
            1,
            3,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31)), 4001),
        )
        .await;

        let snapshot = pool.admission_coverage_snapshot().await;
        assert!(snapshot.configured_dcs.contains(&2));
        assert!(snapshot.configured_dcs.contains(&3));
        assert!(snapshot.ready_dcs.contains(&3));
        assert!(!pool.admission_ready_for_target_dc(2).await);
        assert!(pool.admission_ready_for_target_dc(3).await);
        assert!(pool.admission_ready_partial_cast().await);
    }
}
