use super::*;

impl UpstreamManager {
    /// Select upstream using latency-weighted random selection.
    pub(super) async fn select_upstream(
        &self,
        dc_idx: Option<i16>,
        scope: Option<&str>,
    ) -> Option<usize> {
        let upstreams = self.upstreams.read().await;
        if upstreams.is_empty() {
            return None;
        }
        // Scope filter:
        //   If scope is set: only scoped and matched items
        //   If scope is not set: only unscoped items
        let filtered_upstreams: Vec<usize> = upstreams
            .iter()
            .enumerate()
            .filter(|(_, u)| {
                scope.map_or(u.config.scopes.is_empty(), |req_scope| {
                    u.config
                        .scopes
                        .split(',')
                        .map(str::trim)
                        .any(|s| s == req_scope)
                })
            })
            .map(|(i, _)| i)
            .collect();

        // Healthy filter
        let healthy: Vec<usize> = filtered_upstreams
            .iter()
            .filter(|&&i| upstreams[i].healthy)
            .copied()
            .collect();

        if filtered_upstreams.is_empty() {
            if Self::should_emit_warn(self.no_upstreams_warn_epoch_ms.as_ref(), 5_000) {
                warn!(
                    scope = scope,
                    "No upstreams available! Using first (direct?)"
                );
            }
            return None;
        }

        if healthy.is_empty() {
            if Self::should_emit_warn(self.no_healthy_warn_epoch_ms.as_ref(), 5_000) {
                warn!(
                    scope = scope,
                    "No healthy upstreams available! Using random."
                );
            }
            return Some(filtered_upstreams[rand::rng().random_range(0..filtered_upstreams.len())]);
        }

        if healthy.len() == 1 {
            return Some(healthy[0]);
        }

        let weights: Vec<(usize, f64)> = healthy
            .iter()
            .map(|&i| {
                let base = upstreams[i].config.weight as f64;
                let latency_factor = upstreams[i]
                    .effective_latency(dc_idx)
                    .map(|ms| if ms > 1.0 { 1000.0 / ms } else { 1000.0 })
                    .unwrap_or(1.0);

                (i, base * latency_factor)
            })
            .collect();

        let total: f64 = weights.iter().map(|(_, w)| w).sum();

        if total <= 0.0 {
            return Some(healthy[rand::rng().random_range(0..healthy.len())]);
        }

        let mut choice: f64 = rand::rng().random_range(0.0..total);

        for &(idx, weight) in &weights {
            if choice < weight {
                trace!(
                    upstream = idx,
                    dc = ?dc_idx,
                    weight = format!("{:.2}", weight),
                    total = format!("{:.2}", total),
                    "Upstream selected"
                );
                return Some(idx);
            }
            choice -= weight;
        }

        Some(healthy[0])
    }

    /// Connect to target through a selected upstream.
    pub async fn connect(
        &self,
        target: SocketAddr,
        dc_idx: Option<i16>,
        scope: Option<&str>,
    ) -> Result<UpstreamStream> {
        let idx = self
            .select_upstream(dc_idx, scope)
            .await
            .ok_or_else(|| ProxyError::Config("No upstreams available".to_string()))?;

        let (mut upstream, bind_rr, dc_preference) = {
            let guard = self.upstreams.read().await;
            let state = &guard[idx];
            let dc_preference = dc_idx
                .and_then(UpstreamState::dc_array_idx)
                .map(|dc_array_idx| state.dc_ip_pref[dc_array_idx])
                .unwrap_or(IpPreference::Unknown);
            (
                state.config.clone(),
                Some(state.bind_rr.clone()),
                dc_preference,
            )
        };

        if let Some(s) = scope {
            upstream.selected_scope = s.to_string();
        }

        let target = if dc_idx.is_some() {
            Self::resolve_runtime_dc_target(target, dc_idx, &upstream, dc_preference)?
        } else {
            target
        };

        let (stream, _) = self
            .connect_selected_upstream(idx, upstream, target, dc_idx, bind_rr)
            .await?;
        Ok(stream)
    }

    /// Connect to target through a selected upstream and return egress details.
    pub async fn connect_with_details(
        &self,
        target: SocketAddr,
        dc_idx: Option<i16>,
        scope: Option<&str>,
    ) -> Result<(TcpStream, UpstreamEgressInfo)> {
        let idx = self
            .select_upstream(dc_idx, scope)
            .await
            .ok_or_else(|| ProxyError::Config("No upstreams available".to_string()))?;

        let (mut upstream, bind_rr, dc_preference) = {
            let guard = self.upstreams.read().await;
            let state = &guard[idx];
            let dc_preference = dc_idx
                .and_then(UpstreamState::dc_array_idx)
                .map(|dc_array_idx| state.dc_ip_pref[dc_array_idx])
                .unwrap_or(IpPreference::Unknown);
            (
                state.config.clone(),
                Some(state.bind_rr.clone()),
                dc_preference,
            )
        };

        // Set scope for configuration copy
        if let Some(s) = scope {
            upstream.selected_scope = s.to_string();
        }

        let target = if dc_idx.is_some() {
            Self::resolve_runtime_dc_target(target, dc_idx, &upstream, dc_preference)?
        } else {
            target
        };

        let (stream, egress) = self
            .connect_selected_upstream(idx, upstream, target, dc_idx, bind_rr)
            .await?;
        Ok((stream.into_tcp()?, egress))
    }
}
