use super::*;

impl MePool {
    pub(in crate::transport::middle_proxy) async fn active_coverage_required_total(&self) -> usize {
        let now_epoch_secs = Self::now_epoch_secs();
        let mut endpoints_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();

        if self.family_enabled_for_drain_coverage(IpFamily::V4, now_epoch_secs) {
            let map = self.proxy_map_v4.read().await;
            for (dc, addrs) in map.iter() {
                let entry = endpoints_by_dc.entry(*dc).or_default();
                for (ip, port) in addrs.iter().copied() {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        if self.family_enabled_for_drain_coverage(IpFamily::V6, now_epoch_secs) {
            let map = self.proxy_map_v6.read().await;
            for (dc, addrs) in map.iter() {
                let entry = endpoints_by_dc.entry(*dc).or_default();
                for (ip, port) in addrs.iter().copied() {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        endpoints_by_dc
            .values()
            .map(|endpoints| self.required_writers_for_dc_with_floor_mode(endpoints.len(), false))
            .sum()
    }

    pub(in crate::transport::middle_proxy) async fn can_open_writer_for_contour(
        &self,
        contour: WriterContour,
        allow_coverage_override: bool,
        writer_dc: i32,
    ) -> bool {
        let (active_writers, warm_writers, _) = self.non_draining_writer_counts_by_contour().await;
        match contour {
            WriterContour::Active => {
                let active_cap = self.adaptive_floor_active_cap_configured_total();
                if active_writers < active_cap {
                    return true;
                }
                if !allow_coverage_override {
                    return false;
                }

                let mut endpoints_len = 0;
                let now_epoch = Self::now_epoch_secs();
                if self.family_enabled_for_drain_coverage(IpFamily::V4, now_epoch) {
                    if let Some(addrs) = self.proxy_map_v4.read().await.get(&writer_dc) {
                        endpoints_len += addrs.len();
                    }
                }
                if self.family_enabled_for_drain_coverage(IpFamily::V6, now_epoch) {
                    if let Some(addrs) = self.proxy_map_v6.read().await.get(&writer_dc) {
                        endpoints_len += addrs.len();
                    }
                }

                if endpoints_len > 0 {
                    let base_req =
                        self.required_writers_for_dc_with_floor_mode(endpoints_len, false);
                    let active_for_dc = {
                        let ws = self.writers.read().await;
                        ws.iter()
                            .filter(|w| {
                                !w.draining.load(std::sync::atomic::Ordering::Relaxed)
                                    && w.writer_dc == writer_dc
                                    && matches!(
                                        WriterContour::from_u8(
                                            w.contour.load(std::sync::atomic::Ordering::Relaxed),
                                        ),
                                        WriterContour::Active
                                    )
                            })
                            .count()
                    };
                    if active_for_dc < base_req {
                        return true;
                    }
                }

                let coverage_required = self.active_coverage_required_total().await;
                active_writers < coverage_required
            }
            WriterContour::Warm => warm_writers < self.adaptive_floor_warm_cap_configured_total(),
            WriterContour::Draining => true,
        }
    }

    pub(in crate::transport::middle_proxy) async fn reserve_writer_open(
        &self,
        contour: WriterContour,
        allow_coverage_override: bool,
        writer_dc: i32,
    ) -> Option<WriterOpenReservation<'_>> {
        let counter = match contour {
            WriterContour::Active => &self.writer_connect_active_reserved,
            WriterContour::Warm => &self.writer_connect_warm_reserved,
            WriterContour::Draining => {
                return Some(WriterOpenReservation { counter: None });
            }
        };

        loop {
            if !self
                .can_open_writer_for_contour(contour, allow_coverage_override, writer_dc)
                .await
            {
                return None;
            }
            let (active_writers, warm_writers, _) =
                self.non_draining_writer_counts_by_contour().await;
            let live = match contour {
                WriterContour::Active => active_writers,
                WriterContour::Warm => warm_writers,
                WriterContour::Draining => 0,
            };
            let mut limit = match contour {
                WriterContour::Active => self.adaptive_floor_active_cap_configured_total(),
                WriterContour::Warm => self.adaptive_floor_warm_cap_configured_total(),
                WriterContour::Draining => usize::MAX,
            };
            if contour == WriterContour::Active && allow_coverage_override {
                limit = limit
                    .max(self.active_coverage_required_total().await)
                    .saturating_add(
                        self.reconnect_runtime
                            .me_reconnect_max_concurrent_per_dc
                            .max(1) as usize,
                    );
            }

            let reserved = counter.load(Ordering::Acquire);
            if live.saturating_add(reserved) >= limit {
                return None;
            }
            if counter
                .compare_exchange_weak(reserved, reserved + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(WriterOpenReservation {
                    counter: Some(counter),
                });
            }
        }
    }

    pub(in crate::transport::middle_proxy) fn required_writers_for_dc_with_floor_mode(
        &self,
        endpoint_count: usize,
        reduce_for_idle: bool,
    ) -> usize {
        let base_required = self.required_writers_for_dc(endpoint_count);
        if !reduce_for_idle {
            return base_required;
        }
        if self.floor_mode() != MeFloorMode::Adaptive {
            return base_required;
        }
        let min_writers = if endpoint_count == 1 {
            (self
                .floor_runtime
                .me_adaptive_floor_min_writers_single_endpoint
                .load(Ordering::Relaxed) as usize)
                .max(1)
        } else {
            (self
                .floor_runtime
                .me_adaptive_floor_min_writers_multi_endpoint
                .load(Ordering::Relaxed) as usize)
                .max(1)
        };
        base_required.min(min_writers)
    }
}
