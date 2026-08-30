use super::*;

pub(crate) struct AuthProbeState {
    pub(super) fail_streak: u32,
    pub(super) blocked_until: Instant,
    pub(super) last_seen: Instant,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthProbeSaturationState {
    pub(super) fail_streak: u32,
    pub(super) blocked_until: Instant,
    pub(super) last_seen: Instant,
}
pub(super) fn unknown_sni_warn_state_lock_in(
    shared: &ProxySharedState,
) -> std::sync::MutexGuard<'_, Option<Instant>> {
    shared
        .handshake
        .unknown_sni_warn_next_allowed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn should_emit_unknown_sni_warn_in(shared: &ProxySharedState, now: Instant) -> bool {
    let mut guard = unknown_sni_warn_state_lock_in(shared);
    if let Some(next_allowed) = *guard
        && now < next_allowed
    {
        return false;
    }
    *guard = Some(now + Duration::from_secs(UNKNOWN_SNI_WARN_COOLDOWN_SECS));
    true
}

pub(super) fn normalize_auth_probe_ip(peer_ip: IpAddr) -> IpAddr {
    match peer_ip {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => {
            let [a, b, c, d, _, _, _, _] = ip.segments();
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
    }
}

pub(super) fn auth_probe_backoff(fail_streak: u32) -> Duration {
    if fail_streak < AUTH_PROBE_BACKOFF_START_FAILS {
        return Duration::ZERO;
    }
    let shift = (fail_streak - AUTH_PROBE_BACKOFF_START_FAILS).min(10);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let ms = AUTH_PROBE_BACKOFF_BASE_MS
        .saturating_mul(multiplier)
        .min(AUTH_PROBE_BACKOFF_MAX_MS);
    Duration::from_millis(ms)
}

pub(super) fn auth_probe_state_expired(state: &AuthProbeState, now: Instant) -> bool {
    let retention = Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS);
    now.duration_since(state.last_seen) > retention
}

pub(super) fn auth_probe_eviction_offset_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) -> usize {
    let hasher_state = &shared.handshake.auth_probe_eviction_hasher;
    let mut hasher = hasher_state.build_hasher();
    peer_ip.hash(&mut hasher);
    now.hash(&mut hasher);
    hasher.finish() as usize
}

pub(super) fn auth_probe_scan_start_offset_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
    state_len: usize,
    scan_limit: usize,
) -> usize {
    if state_len == 0 || scan_limit == 0 {
        return 0;
    }

    auth_probe_eviction_offset_in(shared, peer_ip, now) % state_len
}

pub(super) fn auth_probe_is_throttled_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) -> bool {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = &shared.handshake.auth_probe;
    let Some(entry) = state.get(&peer_ip) else {
        return false;
    };
    if auth_probe_state_expired(&entry, now) {
        drop(entry);
        state.remove_if(&peer_ip, |_, current| {
            auth_probe_state_expired(current, now)
        });
        return false;
    }
    now < entry.blocked_until
}

pub(super) fn auth_probe_saturation_grace_exhausted_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) -> bool {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = &shared.handshake.auth_probe;
    let Some(entry) = state.get(&peer_ip) else {
        return false;
    };
    if auth_probe_state_expired(&entry, now) {
        drop(entry);
        state.remove_if(&peer_ip, |_, current| {
            auth_probe_state_expired(current, now)
        });
        return false;
    }

    entry.fail_streak >= AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS
}

pub(super) fn auth_probe_should_apply_preauth_throttle_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) -> bool {
    if !auth_probe_is_throttled_in(shared, peer_ip, now) {
        return false;
    }

    if !auth_probe_saturation_is_throttled_in(shared, now) {
        return true;
    }

    auth_probe_saturation_grace_exhausted_in(shared, peer_ip, now)
}

pub(super) fn auth_probe_saturation_is_throttled_in(
    shared: &ProxySharedState,
    now: Instant,
) -> bool {
    let mut guard = shared
        .handshake
        .auth_probe_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let Some(state) = guard.as_mut() else {
        return false;
    };

    if now.duration_since(state.last_seen) > Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS) {
        *guard = None;
        return false;
    }

    if now < state.blocked_until {
        return true;
    }

    false
}

pub(super) fn auth_probe_note_saturation_in(shared: &ProxySharedState, now: Instant) {
    let mut guard = shared
        .handshake
        .auth_probe_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    match guard.as_mut() {
        Some(state)
            if now.duration_since(state.last_seen)
                <= Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS) =>
        {
            state.fail_streak = state.fail_streak.saturating_add(1);
            state.last_seen = now;
            state.blocked_until = now + auth_probe_backoff(state.fail_streak);
        }
        _ => {
            let fail_streak = AUTH_PROBE_BACKOFF_START_FAILS;
            *guard = Some(AuthProbeSaturationState {
                fail_streak,
                blocked_until: now + auth_probe_backoff(fail_streak),
                last_seen: now,
            });
        }
    }
}

pub(super) fn auth_probe_note_expensive_invalid_scan_in(
    shared: &ProxySharedState,
    now: Instant,
    validation_checks: usize,
    overload: bool,
) {
    if overload || validation_checks < EXPENSIVE_INVALID_SCAN_SATURATION_THRESHOLD {
        return;
    }

    auth_probe_note_saturation_in(shared, now);
}

pub(super) fn auth_probe_record_failure_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = &shared.handshake.auth_probe;
    auth_probe_record_failure_with_state_in(shared, state, peer_ip, now);
}

pub(super) fn auth_probe_record_failure_with_state_in(
    shared: &ProxySharedState,
    state: &DashMap<IpAddr, AuthProbeState>,
    peer_ip: IpAddr,
    now: Instant,
) {
    let make_new_state = || AuthProbeState {
        fail_streak: 1,
        blocked_until: now + auth_probe_backoff(1),
        last_seen: now,
    };

    let update_existing = |entry: &mut AuthProbeState| {
        if auth_probe_state_expired(entry, now) {
            *entry = make_new_state();
        } else {
            entry.fail_streak = entry.fail_streak.saturating_add(1);
            entry.last_seen = now;
            entry.blocked_until = now + auth_probe_backoff(entry.fail_streak);
        }
    };

    match state.entry(peer_ip) {
        Entry::Occupied(mut entry) => {
            update_existing(entry.get_mut());
            return;
        }
        Entry::Vacant(_) => {}
    }

    if state.len() >= AUTH_PROBE_TRACK_MAX_ENTRIES {
        let mut rounds = 0usize;
        while state.len() >= AUTH_PROBE_TRACK_MAX_ENTRIES {
            rounds += 1;
            if rounds > 8 {
                auth_probe_note_saturation_in(shared, now);
                let mut eviction_candidate: Option<(IpAddr, u32, Instant)> = None;
                for entry in state.iter().take(AUTH_PROBE_PRUNE_SCAN_LIMIT) {
                    let key = *entry.key();
                    let fail_streak = entry.value().fail_streak;
                    let last_seen = entry.value().last_seen;
                    match eviction_candidate {
                        Some((_, current_fail, current_seen))
                            if fail_streak > current_fail
                                || (fail_streak == current_fail && last_seen >= current_seen) => {}
                        _ => eviction_candidate = Some((key, fail_streak, last_seen)),
                    }
                }

                let Some((evict_key, evict_fail_streak, evict_last_seen)) = eviction_candidate
                else {
                    return;
                };
                if state
                    .remove_if(&evict_key, |_, current| {
                        current.fail_streak == evict_fail_streak
                            && current.last_seen == evict_last_seen
                    })
                    .is_some()
                {
                    break;
                }
                continue;
            }

            let mut stale_keys = Vec::new();
            let mut eviction_candidate: Option<(IpAddr, u32, Instant)> = None;
            let state_len = state.len();
            let scan_limit = state_len.min(AUTH_PROBE_PRUNE_SCAN_LIMIT);

            if state_len <= AUTH_PROBE_PRUNE_SCAN_LIMIT {
                for entry in state.iter() {
                    let key = *entry.key();
                    let fail_streak = entry.value().fail_streak;
                    let last_seen = entry.value().last_seen;
                    match eviction_candidate {
                        Some((_, current_fail, current_seen))
                            if fail_streak > current_fail
                                || (fail_streak == current_fail && last_seen >= current_seen) => {}
                        _ => eviction_candidate = Some((key, fail_streak, last_seen)),
                    }
                    if auth_probe_state_expired(entry.value(), now) {
                        stale_keys.push(key);
                    }
                }
            } else {
                let start_offset =
                    auth_probe_scan_start_offset_in(shared, peer_ip, now, state_len, scan_limit);
                let mut scanned = 0usize;
                for entry in state.iter().skip(start_offset) {
                    let key = *entry.key();
                    let fail_streak = entry.value().fail_streak;
                    let last_seen = entry.value().last_seen;
                    match eviction_candidate {
                        Some((_, current_fail, current_seen))
                            if fail_streak > current_fail
                                || (fail_streak == current_fail && last_seen >= current_seen) => {}
                        _ => eviction_candidate = Some((key, fail_streak, last_seen)),
                    }
                    if auth_probe_state_expired(entry.value(), now) {
                        stale_keys.push(key);
                    }
                    scanned += 1;
                    if scanned >= scan_limit {
                        break;
                    }
                }

                if scanned < scan_limit {
                    for entry in state.iter().take(scan_limit - scanned) {
                        let key = *entry.key();
                        let fail_streak = entry.value().fail_streak;
                        let last_seen = entry.value().last_seen;
                        match eviction_candidate {
                            Some((_, current_fail, current_seen))
                                if fail_streak > current_fail
                                    || (fail_streak == current_fail
                                        && last_seen >= current_seen) => {}
                            _ => eviction_candidate = Some((key, fail_streak, last_seen)),
                        }
                        if auth_probe_state_expired(entry.value(), now) {
                            stale_keys.push(key);
                        }
                    }
                }
            }

            for stale_key in stale_keys {
                state.remove_if(&stale_key, |_, current| {
                    auth_probe_state_expired(current, now)
                });
            }

            if state.len() < AUTH_PROBE_TRACK_MAX_ENTRIES {
                break;
            }

            let Some((evict_key, evict_fail_streak, evict_last_seen)) = eviction_candidate else {
                auth_probe_note_saturation_in(shared, now);
                return;
            };
            state.remove_if(&evict_key, |_, current| {
                current.fail_streak == evict_fail_streak && current.last_seen == evict_last_seen
            });
            auth_probe_note_saturation_in(shared, now);
        }
    }

    match state.entry(peer_ip) {
        Entry::Occupied(mut entry) => {
            update_existing(entry.get_mut());
        }
        Entry::Vacant(entry) => {
            entry.insert(make_new_state());
        }
    }
}

pub(super) fn auth_probe_record_success_in(shared: &ProxySharedState, peer_ip: IpAddr) {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let state = &shared.handshake.auth_probe;
    state.remove(&peer_ip);
}

#[cfg(test)]
pub(crate) fn auth_probe_record_failure_for_testing(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) {
    auth_probe_record_failure_in(shared, peer_ip, now);
}

#[cfg(test)]
pub(crate) fn auth_probe_fail_streak_for_testing_in_shared(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
) -> Option<u32> {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    shared
        .handshake
        .auth_probe
        .get(&peer_ip)
        .map(|entry| entry.fail_streak)
}

#[cfg(test)]
pub(crate) fn clear_auth_probe_state_for_testing_in_shared(shared: &ProxySharedState) {
    shared.handshake.auth_probe.clear();
    match shared.handshake.auth_probe_saturation.lock() {
        Ok(mut saturation) => {
            *saturation = None;
        }
        Err(poisoned) => {
            let mut saturation = poisoned.into_inner();
            *saturation = None;
            shared.handshake.auth_probe_saturation.clear_poison();
        }
    }
}

#[cfg(test)]
pub(crate) fn auth_probe_state_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &DashMap<IpAddr, AuthProbeState> {
    &shared.handshake.auth_probe
}

#[cfg(test)]
pub(crate) fn auth_probe_saturation_state_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &Mutex<Option<AuthProbeSaturationState>> {
    &shared.handshake.auth_probe_saturation
}

#[cfg(test)]
pub(crate) fn auth_probe_saturation_state_lock_for_testing_in_shared(
    shared: &ProxySharedState,
) -> std::sync::MutexGuard<'_, Option<AuthProbeSaturationState>> {
    shared
        .handshake
        .auth_probe_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub(crate) fn clear_unknown_sni_warn_state_for_testing_in_shared(shared: &ProxySharedState) {
    let mut guard = shared
        .handshake
        .unknown_sni_warn_next_allowed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = None;
}

#[cfg(test)]
pub(crate) fn should_emit_unknown_sni_warn_for_testing_in_shared(
    shared: &ProxySharedState,
    now: Instant,
) -> bool {
    should_emit_unknown_sni_warn_in(shared, now)
}

#[cfg(test)]
pub(crate) fn clear_warned_secrets_for_testing_in_shared(shared: &ProxySharedState) {
    if let Ok(mut guard) = shared.handshake.invalid_secret_warned.lock() {
        guard.clear();
    }
}

#[cfg(test)]
pub(crate) fn warned_secrets_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &Mutex<HashSet<(String, String)>> {
    &shared.handshake.invalid_secret_warned
}

#[cfg(test)]
pub(crate) fn auth_probe_is_throttled_for_testing_in_shared(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
) -> bool {
    auth_probe_is_throttled_in(shared, peer_ip, Instant::now())
}

#[cfg(test)]
pub(crate) fn auth_probe_saturation_is_throttled_for_testing_in_shared(
    shared: &ProxySharedState,
) -> bool {
    auth_probe_saturation_is_throttled_in(shared, Instant::now())
}

#[cfg(test)]
pub(crate) fn auth_probe_saturation_is_throttled_at_for_testing_in_shared(
    shared: &ProxySharedState,
    now: Instant,
) -> bool {
    auth_probe_saturation_is_throttled_in(shared, now)
}

#[inline]
pub(super) fn find_matching_tls_domain<'a>(config: &'a ProxyConfig, sni: &str) -> Option<&'a str> {
    if config.censorship.tls_domain.eq_ignore_ascii_case(sni) {
        return Some(config.censorship.tls_domain.as_str());
    }

    for domain in &config.censorship.tls_domains {
        if domain.eq_ignore_ascii_case(sni) {
            return Some(domain.as_str());
        }
    }

    None
}

pub(super) async fn maybe_apply_server_hello_delay(config: &ProxyConfig) {
    if config.censorship.server_hello_delay_max_ms == 0 {
        return;
    }

    let min = config.censorship.server_hello_delay_min_ms;
    let max = config.censorship.server_hello_delay_max_ms.max(min);
    let delay_ms = if max == min {
        max
    } else {
        crate::proxy::masking::sample_lognormal_percentile_bounded(min, max, &mut rand::rng())
    };

    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}
