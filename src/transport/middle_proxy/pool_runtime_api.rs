use std::collections::HashMap;
use std::time::Instant;

use super::pool::{MeDrainGateReason, MePool, RefillDcKey};
use crate::network::IpFamily;

#[derive(Clone, Debug)]
pub(crate) struct MeApiRefillDcSnapshot {
    pub dc: i16,
    pub family: &'static str,
    pub inflight: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiRefillSnapshot {
    pub inflight_endpoints_total: usize,
    pub inflight_dc_total: usize,
    pub by_dc: Vec<MeApiRefillDcSnapshot>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiNatReflectionSnapshot {
    pub addr: std::net::SocketAddr,
    pub age_secs: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiNatStunSnapshot {
    pub nat_probe_enabled: bool,
    pub nat_probe_disabled_runtime: bool,
    pub nat_probe_attempts: u8,
    pub configured_servers: Vec<String>,
    pub live_servers: Vec<String>,
    pub reflection_v4: Option<MeApiNatReflectionSnapshot>,
    pub reflection_v6: Option<MeApiNatReflectionSnapshot>,
    pub stun_backoff_remaining_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiFamilyStateSnapshot {
    pub family: &'static str,
    pub state: &'static str,
    pub state_since_epoch_secs: u64,
    pub suppressed_until_epoch_secs: Option<u64>,
    pub fail_streak: u32,
    pub recover_success_streak: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiDrainGateSnapshot {
    pub route_quorum_ok: bool,
    pub redundancy_ok: bool,
    pub block_reason: &'static str,
    pub updated_at_epoch_secs: u64,
}

impl MePool {
    pub(crate) async fn api_refill_snapshot(&self) -> MeApiRefillSnapshot {
        let inflight_endpoints_total = self.refill_inflight.lock().await.len();
        let inflight_dc_keys = self
            .refill_inflight_dc
            .lock()
            .await
            .iter()
            .copied()
            .collect::<Vec<RefillDcKey>>();

        let mut by_dc_map = HashMap::<(i16, &'static str), usize>::new();
        for key in inflight_dc_keys {
            let family = match key.family {
                IpFamily::V4 => "v4",
                IpFamily::V6 => "v6",
            };
            let dc = key.dc as i16;
            *by_dc_map.entry((dc, family)).or_insert(0) += 1;
        }

        let mut by_dc = by_dc_map
            .into_iter()
            .map(|((dc, family), inflight)| MeApiRefillDcSnapshot {
                dc,
                family,
                inflight,
            })
            .collect::<Vec<_>>();
        by_dc.sort_by_key(|entry| (entry.dc, entry.family));

        MeApiRefillSnapshot {
            inflight_endpoints_total,
            inflight_dc_total: by_dc.len(),
            by_dc,
        }
    }

    pub(crate) async fn api_nat_stun_snapshot(&self) -> MeApiNatStunSnapshot {
        let now = Instant::now();
        let mut configured_servers = if !self.nat_runtime.nat_stun_servers.is_empty() {
            self.nat_runtime.nat_stun_servers.clone()
        } else if let Some(stun) = &self.nat_runtime.nat_stun {
            if stun.trim().is_empty() {
                Vec::new()
            } else {
                vec![stun.clone()]
            }
        } else {
            Vec::new()
        };
        configured_servers.sort();
        configured_servers.dedup();

        let mut live_servers = self.nat_runtime.nat_stun_live_servers.read().await.clone();
        live_servers.sort();
        live_servers.dedup();

        let reflection = self.nat_runtime.nat_reflection_cache.lock().await;
        let reflection_v4 = reflection.v4.map(|(ts, addr)| MeApiNatReflectionSnapshot {
            addr,
            age_secs: now.saturating_duration_since(ts).as_secs(),
        });
        let reflection_v6 = reflection.v6.map(|(ts, addr)| MeApiNatReflectionSnapshot {
            addr,
            age_secs: now.saturating_duration_since(ts).as_secs(),
        });
        drop(reflection);

        let backoff_until = *self.nat_runtime.stun_backoff_until.read().await;
        let stun_backoff_remaining_ms = backoff_until.and_then(|until| {
            (until > now).then_some(until.duration_since(now).as_millis() as u64)
        });

        MeApiNatStunSnapshot {
            nat_probe_enabled: self.nat_runtime.nat_probe,
            nat_probe_disabled_runtime: self
                .nat_runtime
                .nat_probe_disabled
                .load(std::sync::atomic::Ordering::Relaxed),
            nat_probe_attempts: self
                .nat_runtime
                .nat_probe_attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            configured_servers,
            live_servers,
            reflection_v4,
            reflection_v6,
            stun_backoff_remaining_ms,
        }
    }

    pub(crate) fn api_family_state_snapshot(&self) -> Vec<MeApiFamilyStateSnapshot> {
        [IpFamily::V4, IpFamily::V6]
            .into_iter()
            .map(|family| {
                let state = self.family_runtime_state(family);
                let suppressed_until = self.family_suppressed_until_epoch_secs(family);
                MeApiFamilyStateSnapshot {
                    family: match family {
                        IpFamily::V4 => "v4",
                        IpFamily::V6 => "v6",
                    },
                    state: state.as_str(),
                    state_since_epoch_secs: self.family_runtime_state_since_epoch_secs(family),
                    suppressed_until_epoch_secs: (suppressed_until != 0)
                        .then_some(suppressed_until),
                    fail_streak: self.family_fail_streak(family),
                    recover_success_streak: self.family_recover_success_streak(family),
                }
            })
            .collect()
    }

    pub(crate) fn api_drain_gate_snapshot(&self) -> MeApiDrainGateSnapshot {
        let reason: MeDrainGateReason = self.last_drain_gate_block_reason();
        MeApiDrainGateSnapshot {
            route_quorum_ok: self.last_drain_gate_route_quorum_ok(),
            redundancy_ok: self.last_drain_gate_redundancy_ok(),
            block_reason: reason.as_str(),
            updated_at_epoch_secs: self.last_drain_gate_updated_at_epoch_secs(),
        }
    }
}
