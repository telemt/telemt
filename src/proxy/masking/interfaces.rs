use super::*;

pub(super) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

#[cfg(unix)]
pub(super) fn collect_local_interface_ips() -> Vec<IpAddr> {
    #[cfg(test)]
    LOCAL_INTERFACE_ENUMERATIONS.fetch_add(1, Ordering::Relaxed);

    let mut out = Vec::new();
    if let Ok(addrs) = getifaddrs() {
        for iface in addrs {
            if let Some(address) = iface.address {
                if let Some(v4) = address.as_sockaddr_in() {
                    out.push(canonical_ip(IpAddr::V4(v4.ip())));
                } else if let Some(v6) = address.as_sockaddr_in6() {
                    out.push(canonical_ip(IpAddr::V6(v6.ip())));
                }
            }
        }
    }
    out
}

pub(super) fn choose_interface_snapshot(
    previous: &[IpAddr],
    refreshed: Vec<IpAddr>,
) -> Vec<IpAddr> {
    if refreshed.is_empty() && !previous.is_empty() {
        return previous.to_vec();
    }

    refreshed
}

#[cfg(unix)]
#[derive(Default)]
struct LocalInterfaceCache {
    ips: Vec<IpAddr>,
    refreshed_at: Option<StdInstant>,
}

#[cfg(unix)]
static LOCAL_INTERFACE_CACHE: OnceLock<Mutex<LocalInterfaceCache>> = OnceLock::new();

#[cfg(unix)]
pub(super) static LOCAL_INTERFACE_REFRESH_LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();

#[cfg(all(unix, test))]
pub(super) fn local_interface_ips() -> Vec<IpAddr> {
    let cache = LOCAL_INTERFACE_CACHE.get_or_init(|| Mutex::new(LocalInterfaceCache::default()));
    let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());

    let stale = guard
        .refreshed_at
        .is_none_or(|at| at.elapsed() >= LOCAL_INTERFACE_CACHE_TTL);
    if stale {
        let refreshed = collect_local_interface_ips();
        guard.ips = choose_interface_snapshot(&guard.ips, refreshed);
        guard.refreshed_at = Some(StdInstant::now());
    }

    guard.ips.clone()
}

#[cfg(unix)]
pub(super) async fn local_interface_ips_async() -> Vec<IpAddr> {
    let cache = LOCAL_INTERFACE_CACHE.get_or_init(|| Mutex::new(LocalInterfaceCache::default()));

    {
        let guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
        let stale = guard
            .refreshed_at
            .is_none_or(|at| at.elapsed() >= LOCAL_INTERFACE_CACHE_TTL);
        if !stale {
            return guard.ips.clone();
        }
    }

    let refresh_lock = LOCAL_INTERFACE_REFRESH_LOCK.get_or_init(|| AsyncMutex::new(()));
    let _refresh_guard = refresh_lock.lock().await;

    {
        let guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
        let stale = guard
            .refreshed_at
            .is_none_or(|at| at.elapsed() >= LOCAL_INTERFACE_CACHE_TTL);
        if !stale {
            return guard.ips.clone();
        }
    }

    let refreshed = tokio::task::spawn_blocking(collect_local_interface_ips)
        .await
        .unwrap_or_default();

    let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
    let stale = guard
        .refreshed_at
        .is_none_or(|at| at.elapsed() >= LOCAL_INTERFACE_CACHE_TTL);
    if stale {
        guard.ips = choose_interface_snapshot(&guard.ips, refreshed);
        guard.refreshed_at = Some(StdInstant::now());
    }

    guard.ips.clone()
}

#[cfg(all(not(unix), test))]
pub(super) fn local_interface_ips() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(not(unix))]
pub(super) async fn local_interface_ips_async() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(test)]
static LOCAL_INTERFACE_ENUMERATIONS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(super) fn reset_local_interface_enumerations_for_tests() {
    LOCAL_INTERFACE_ENUMERATIONS.store(0, Ordering::Relaxed);

    #[cfg(unix)]
    if let Some(cache) = LOCAL_INTERFACE_CACHE.get() {
        let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
        guard.ips.clear();
        guard.refreshed_at = None;
    }
}

#[cfg(test)]
pub(super) fn local_interface_enumerations_for_tests() -> usize {
    LOCAL_INTERFACE_ENUMERATIONS.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(super) fn interface_cache_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(super) fn is_mask_target_local_listener_with_interfaces(
    mask_host: &str,
    mask_port: u16,
    local_addr: SocketAddr,
    resolved_addrs: &[SocketAddr],
    interface_ips: &[IpAddr],
) -> bool {
    if mask_port != local_addr.port() {
        return false;
    }

    let local_ip = canonical_ip(local_addr.ip());
    let literal_mask_ip = parse_mask_host_ip_literal(mask_host).map(canonical_ip);

    for addr in resolved_addrs {
        let resolved_ip = canonical_ip(addr.ip());
        if resolved_ip == local_ip {
            return true;
        }

        if local_ip.is_unspecified()
            && (resolved_ip.is_loopback()
                || resolved_ip.is_unspecified()
                || interface_ips.contains(&resolved_ip))
        {
            return true;
        }
    }

    if let Some(mask_ip) = literal_mask_ip {
        if mask_ip == local_ip {
            return true;
        }

        if local_ip.is_unspecified()
            && (mask_ip.is_loopback()
                || mask_ip.is_unspecified()
                || interface_ips.contains(&mask_ip))
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
pub(super) fn is_mask_target_local_listener(
    mask_host: &str,
    mask_port: u16,
    local_addr: SocketAddr,
    resolved_addrs: &[SocketAddr],
) -> bool {
    if mask_port != local_addr.port() {
        return false;
    }

    let interfaces = local_interface_ips();
    is_mask_target_local_listener_with_interfaces(
        mask_host,
        mask_port,
        local_addr,
        resolved_addrs,
        &interfaces,
    )
}

pub(super) async fn is_mask_target_local_listener_async(
    mask_host: &str,
    mask_port: u16,
    local_addr: SocketAddr,
    resolved_addrs: &[SocketAddr],
) -> bool {
    if mask_port != local_addr.port() {
        return false;
    }

    let interfaces = local_interface_ips_async().await;
    is_mask_target_local_listener_with_interfaces(
        mask_host,
        mask_port,
        local_addr,
        resolved_addrs,
        &interfaces,
    )
}
