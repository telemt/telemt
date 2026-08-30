use super::*;

pub(in crate::api) async fn build_runtime_nat_stun_data(shared: &ApiShared) -> RuntimeNatStunData {
    let now_epoch_secs = now_epoch_secs();
    let Some(pool) = shared.me_pool.read().await.clone() else {
        return RuntimeNatStunData {
            enabled: false,
            reason: Some(SOURCE_UNAVAILABLE_REASON),
            generated_at_epoch_secs: now_epoch_secs,
            data: None,
        };
    };

    let snapshot = pool.api_nat_stun_snapshot().await;
    RuntimeNatStunData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs: now_epoch_secs,
        data: Some(RuntimeNatStunPayload {
            flags: RuntimeNatStunFlagsData {
                nat_probe_enabled: snapshot.nat_probe_enabled,
                nat_probe_disabled_runtime: snapshot.nat_probe_disabled_runtime,
                nat_probe_attempts: snapshot.nat_probe_attempts,
            },
            servers: RuntimeNatStunServersData {
                configured: snapshot.configured_servers,
                live: snapshot.live_servers.clone(),
                live_total: snapshot.live_servers.len(),
            },
            reflection: RuntimeNatStunReflectionBlockData {
                v4: snapshot
                    .reflection_v4
                    .map(|entry| RuntimeNatStunReflectionData {
                        addr: entry.addr.to_string(),
                        age_secs: entry.age_secs,
                    }),
                v6: snapshot
                    .reflection_v6
                    .map(|entry| RuntimeNatStunReflectionData {
                        addr: entry.addr.to_string(),
                        age_secs: entry.age_secs,
                    }),
            },
            stun_backoff_remaining_ms: snapshot.stun_backoff_remaining_ms,
        }),
    }
}

pub(super) fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
