use super::*;

impl MePool {
    pub(in crate::transport::middle_proxy) fn single_endpoint_outage_mode_enabled(&self) -> bool {
        self.single_endpoint_runtime
            .me_single_endpoint_outage_mode_enabled
            .load(Ordering::Relaxed)
    }

    pub(in crate::transport::middle_proxy) fn single_endpoint_outage_disable_quarantine(
        &self,
    ) -> bool {
        self.single_endpoint_runtime
            .me_single_endpoint_outage_disable_quarantine
            .load(Ordering::Relaxed)
    }

    pub(in crate::transport::middle_proxy) fn single_endpoint_outage_backoff_bounds_ms(
        &self,
    ) -> (u64, u64) {
        let min_ms = self
            .single_endpoint_runtime
            .me_single_endpoint_outage_backoff_min_ms
            .load(Ordering::Relaxed);
        let max_ms = self
            .single_endpoint_runtime
            .me_single_endpoint_outage_backoff_max_ms
            .load(Ordering::Relaxed);
        if min_ms <= max_ms {
            (min_ms, max_ms)
        } else {
            (max_ms, min_ms)
        }
    }

    pub(in crate::transport::middle_proxy) fn single_endpoint_shadow_rotate_interval(
        &self,
    ) -> Option<Duration> {
        let secs = self
            .single_endpoint_runtime
            .me_single_endpoint_shadow_rotate_every_secs
            .load(Ordering::Relaxed);
        if secs == 0 {
            None
        } else {
            Some(Duration::from_secs(secs))
        }
    }

    pub(in crate::transport::middle_proxy) fn family_order(&self) -> Vec<IpFamily> {
        let mut order = Vec::new();
        if self.decision.prefer_ipv6() {
            if self.decision.ipv6_me {
                order.push(IpFamily::V6);
            }
            if self.decision.ipv4_me {
                order.push(IpFamily::V4);
            }
        } else {
            if self.decision.ipv4_me {
                order.push(IpFamily::V4);
            }
            if self.decision.ipv6_me {
                order.push(IpFamily::V6);
            }
        }
        order
    }

    pub(in crate::transport::middle_proxy) fn default_dc_for_routing(&self) -> i32 {
        let dc = self.default_dc.load(Ordering::Relaxed);
        if dc == 0 { 2 } else { dc }
    }

    pub(in crate::transport::middle_proxy) async fn has_configured_endpoints_for_dc(
        &self,
        dc: i32,
    ) -> bool {
        if self.decision.ipv4_me {
            let map = self.proxy_map_v4.read().await;
            if map.get(&dc).is_some_and(|endpoints| !endpoints.is_empty()) {
                return true;
            }
        }

        if self.decision.ipv6_me {
            let map = self.proxy_map_v6.read().await;
            if map.get(&dc).is_some_and(|endpoints| !endpoints.is_empty()) {
                return true;
            }
        }

        false
    }

    pub(in crate::transport::middle_proxy) async fn resolve_target_dc_for_routing(
        &self,
        target_dc: i32,
    ) -> (i32, bool) {
        if target_dc == 0 {
            return (self.default_dc_for_routing(), true);
        }

        if self.has_configured_endpoints_for_dc(target_dc).await {
            return (target_dc, false);
        }

        (self.default_dc_for_routing(), true)
    }

    pub(in crate::transport::middle_proxy) async fn resolve_dc_for_endpoint(
        &self,
        addr: SocketAddr,
    ) -> i32 {
        if let Some(cached) = self.endpoint_dc_map.read().await.get(&addr).copied()
            && let Some(dc) = cached
        {
            return dc;
        }

        self.default_dc_for_routing()
    }

    pub(in crate::transport::middle_proxy) async fn proxy_map_for_family(
        &self,
        family: IpFamily,
    ) -> HashMap<i32, Vec<(IpAddr, u16)>> {
        match family {
            IpFamily::V4 => self.proxy_map_v4.read().await.clone(),
            IpFamily::V6 => self.proxy_map_v6.read().await.clone(),
        }
    }

    pub(in crate::transport::middle_proxy) fn merge_endpoint_dc(
        endpoint_dc_map: &mut HashMap<SocketAddr, Option<i32>>,
        dc: i32,
        ip: IpAddr,
        port: u16,
    ) {
        let endpoint = SocketAddr::new(ip, port);
        match endpoint_dc_map.get_mut(&endpoint) {
            None => {
                endpoint_dc_map.insert(endpoint, Some(dc));
            }
            Some(existing) => {
                if existing.is_some_and(|existing_dc| existing_dc != dc) {
                    *existing = None;
                }
            }
        }
    }

    pub(in crate::transport::middle_proxy) fn build_preferred_endpoints_by_dc(
        decision: &NetworkDecision,
        map_v4: &HashMap<i32, Vec<(IpAddr, u16)>>,
        map_v6: &HashMap<i32, Vec<(IpAddr, u16)>>,
    ) -> HashMap<i32, Vec<SocketAddr>> {
        let mut out = HashMap::<i32, Vec<SocketAddr>>::new();
        let mut dcs = HashSet::<i32>::new();
        dcs.extend(map_v4.keys().copied());
        dcs.extend(map_v6.keys().copied());

        for dc in dcs {
            let v4 = map_v4
                .get(&dc)
                .map(|items| {
                    items
                        .iter()
                        .map(|(ip, port)| SocketAddr::new(*ip, *port))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let v6 = map_v6
                .get(&dc)
                .map(|items| {
                    items
                        .iter()
                        .map(|(ip, port)| SocketAddr::new(*ip, *port))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let mut selected = if decision.effective_multipath {
                let mut both = Vec::<SocketAddr>::with_capacity(v4.len().saturating_add(v6.len()));
                if decision.prefer_ipv6() {
                    both.extend(v6.iter().copied());
                    both.extend(v4.iter().copied());
                } else {
                    both.extend(v4.iter().copied());
                    both.extend(v6.iter().copied());
                }
                both
            } else if decision.prefer_ipv6() {
                if !v6.is_empty() { v6 } else { v4 }
            } else if !v4.is_empty() {
                v4
            } else {
                v6
            };

            selected.sort_unstable();
            selected.dedup();
            out.insert(dc, selected);
        }

        out
    }

    pub(in crate::transport::middle_proxy) fn build_endpoint_dc_map_from_maps(
        map_v4: &HashMap<i32, Vec<(IpAddr, u16)>>,
        map_v6: &HashMap<i32, Vec<(IpAddr, u16)>>,
    ) -> HashMap<SocketAddr, Option<i32>> {
        let mut endpoint_dc_map = HashMap::<SocketAddr, Option<i32>>::new();
        for (dc, endpoints) in map_v4 {
            for (ip, port) in endpoints {
                Self::merge_endpoint_dc(&mut endpoint_dc_map, *dc, *ip, *port);
            }
        }
        for (dc, endpoints) in map_v6 {
            for (ip, port) in endpoints {
                Self::merge_endpoint_dc(&mut endpoint_dc_map, *dc, *ip, *port);
            }
        }
        endpoint_dc_map
    }

    pub(in crate::transport::middle_proxy) async fn rebuild_endpoint_dc_map(&self) {
        let map_v4 = self.proxy_map_v4.read().await.clone();
        let map_v6 = self.proxy_map_v6.read().await.clone();
        let rebuilt = Self::build_endpoint_dc_map_from_maps(&map_v4, &map_v6);
        let preferred = Self::build_preferred_endpoints_by_dc(&self.decision, &map_v4, &map_v6);
        *self.endpoint_dc_map.write().await = rebuilt;
        self.preferred_endpoints_by_dc.store(Arc::new(preferred));
        let configured_endpoints = self
            .endpoint_dc_map
            .read()
            .await
            .keys()
            .copied()
            .collect::<HashSet<SocketAddr>>();
        {
            let mut quarantine = self.endpoint_quarantine.lock().await;
            let now = Instant::now();
            quarantine.retain(|addr, expiry| *expiry > now && configured_endpoints.contains(addr));
        }
        {
            let mut kdf_fp = self.kdf_material_fingerprint.write().await;
            kdf_fp.retain(|addr, _| configured_endpoints.contains(addr));
        }
    }

    pub(in crate::transport::middle_proxy) async fn preferred_endpoints_for_dc(
        &self,
        dc: i32,
    ) -> Vec<SocketAddr> {
        let guard = self.preferred_endpoints_by_dc.load();
        guard.get(&dc).cloned().unwrap_or_default()
    }

    pub(in crate::transport::middle_proxy) fn health_interval_unhealthy(&self) -> Duration {
        Duration::from_millis(
            self.health_runtime
                .me_health_interval_ms_unhealthy
                .load(Ordering::Relaxed)
                .max(1),
        )
    }

    pub(in crate::transport::middle_proxy) fn health_interval_healthy(&self) -> Duration {
        Duration::from_millis(
            self.health_runtime
                .me_health_interval_ms_healthy
                .load(Ordering::Relaxed)
                .max(1),
        )
    }

    pub(in crate::transport::middle_proxy) fn warn_rate_limit_duration(&self) -> Duration {
        Duration::from_millis(
            self.health_runtime
                .me_warn_rate_limit_ms
                .load(Ordering::Relaxed)
                .max(1),
        )
    }
}
