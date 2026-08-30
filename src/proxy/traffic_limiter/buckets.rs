use super::*;

impl ScopeMetrics {
    pub(super) fn throttle(&self, direction: RateDirection) {
        match direction {
            RateDirection::Up => {
                self.throttle_up_total.fetch_add(1, Ordering::Relaxed);
            }
            RateDirection::Down => {
                self.throttle_down_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn wait_ms(&self, direction: RateDirection, wait_ms: u64) {
        match direction {
            RateDirection::Up => {
                self.wait_up_ms_total.fetch_add(wait_ms, Ordering::Relaxed);
            }
            RateDirection::Down => {
                self.wait_down_ms_total
                    .fetch_add(wait_ms, Ordering::Relaxed);
            }
        }
    }
}

impl AtomicRatePair {
    pub(super) fn set(&self, limits: RateLimitBps) {
        self.up_bps.store(limits.up_bps, Ordering::Relaxed);
        self.down_bps.store(limits.down_bps, Ordering::Relaxed);
    }

    pub(super) fn get(&self, direction: RateDirection) -> u64 {
        match direction {
            RateDirection::Up => self.up_bps.load(Ordering::Relaxed),
            RateDirection::Down => self.down_bps.load(Ordering::Relaxed),
        }
    }
}

impl DirectionBucket {
    pub(super) fn sync_epoch(&self, epoch: u64) {
        let current = self.epoch.load(Ordering::Relaxed);
        if current == epoch {
            return;
        }
        if current < epoch
            && self
                .epoch
                .compare_exchange(current, epoch, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.used.store(0, Ordering::Relaxed);
        }
    }

    pub(super) fn try_consume(&self, cap_bps: u64, requested: u64) -> u64 {
        if requested == 0 {
            return 0;
        }
        if cap_bps == 0 {
            return requested;
        }

        let epoch = current_epoch();
        self.sync_epoch(epoch);
        let cap_epoch = bytes_per_epoch(cap_bps);

        loop {
            let used = self.used.load(Ordering::Relaxed);
            if used >= cap_epoch {
                return 0;
            }
            let remaining = cap_epoch.saturating_sub(used);
            let grant = requested.min(remaining);
            if grant == 0 {
                return 0;
            }
            let next = used.saturating_add(grant);
            if self
                .used
                .compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return grant;
            }
        }
    }

    pub(super) fn refund(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        decrement_atomic_saturating(&self.used, bytes);
    }
}

impl UserBucket {
    pub(super) fn new(limits: RateLimitBps) -> Self {
        let rates = AtomicRatePair::default();
        rates.set(limits);
        Self {
            rates,
            up: DirectionBucket::default(),
            down: DirectionBucket::default(),
            active_leases: AtomicU64::new(0),
        }
    }

    pub(super) fn set_rates(&self, limits: RateLimitBps) {
        self.rates.set(limits);
    }

    pub(super) fn try_consume(&self, direction: RateDirection, requested: u64) -> u64 {
        let cap_bps = self.rates.get(direction);
        match direction {
            RateDirection::Up => self.up.try_consume(cap_bps, requested),
            RateDirection::Down => self.down.try_consume(cap_bps, requested),
        }
    }

    pub(super) fn refund(&self, direction: RateDirection, bytes: u64) {
        match direction {
            RateDirection::Up => self.up.refund(bytes),
            RateDirection::Down => self.down.refund(bytes),
        }
    }
}

impl CidrDirectionBucket {
    pub(super) fn sync_epoch(&self, epoch: u64) {
        let current = self.epoch.load(Ordering::Relaxed);
        if current == epoch {
            return;
        }
        if current < epoch
            && self
                .epoch
                .compare_exchange(current, epoch, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.used.store(0, Ordering::Relaxed);
            self.active_users.store(0, Ordering::Relaxed);
        }
    }

    pub(super) fn try_consume(
        &self,
        user_state: &CidrUserDirectionState,
        cap_epoch: u64,
        requested: u64,
    ) -> u64 {
        if requested == 0 || cap_epoch == 0 {
            return 0;
        }

        let epoch = current_epoch();
        self.sync_epoch(epoch);
        user_state.sync_epoch_and_mark_active(epoch, &self.active_users);
        let active_users = self.active_users.load(Ordering::Relaxed).max(1);
        let fair_share = cap_epoch.saturating_div(active_users).max(1);

        loop {
            let total_used = self.used.load(Ordering::Relaxed);
            if total_used >= cap_epoch {
                return 0;
            }
            let total_remaining = cap_epoch.saturating_sub(total_used);
            let user_used = user_state.used.load(Ordering::Relaxed);
            let guaranteed_remaining = fair_share.saturating_sub(user_used);

            let grant = if guaranteed_remaining > 0 {
                requested.min(guaranteed_remaining).min(total_remaining)
            } else {
                requested.min(total_remaining).min(MAX_BORROW_CHUNK_BYTES)
            };

            if grant == 0 {
                return 0;
            }

            let next_total = total_used.saturating_add(grant);
            if self
                .used
                .compare_exchange_weak(total_used, next_total, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                user_state.used.fetch_add(grant, Ordering::Relaxed);
                return grant;
            }
        }
    }

    pub(super) fn refund(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        decrement_atomic_saturating(&self.used, bytes);
    }
}

impl CidrUserDirectionState {
    pub(super) fn sync_epoch_and_mark_active(&self, epoch: u64, active_users: &AtomicU64) {
        let current = self.epoch.load(Ordering::Relaxed);
        if current == epoch {
            return;
        }
        if current < epoch
            && self
                .epoch
                .compare_exchange(current, epoch, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.used.store(0, Ordering::Relaxed);
            active_users.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn refund(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        decrement_atomic_saturating(&self.used, bytes);
    }
}

impl CidrUserShare {
    pub(super) fn new() -> Self {
        Self {
            active_conns: AtomicU64::new(0),
            up: CidrUserDirectionState::default(),
            down: CidrUserDirectionState::default(),
        }
    }
}

impl CidrBucket {
    pub(super) fn new(limits: RateLimitBps) -> Self {
        let rates = AtomicRatePair::default();
        rates.set(limits);
        Self {
            rates,
            up: CidrDirectionBucket::default(),
            down: CidrDirectionBucket::default(),
            users: ShardedRegistry::new(REGISTRY_SHARDS),
            active_leases: AtomicU64::new(0),
        }
    }

    pub(super) fn set_rates(&self, limits: RateLimitBps) {
        self.rates.set(limits);
    }

    pub(super) fn acquire_user_share(&self, user: &str) -> Arc<CidrUserShare> {
        self.users
            .get_or_insert_with(user, CidrUserShare::new, |share| {
                share.active_conns.fetch_add(1, Ordering::Relaxed);
            })
    }

    pub(super) fn release_user_share(&self, user: &str, share: &Arc<CidrUserShare>) {
        decrement_atomic_saturating(&share.active_conns, 1);
        let share_for_remove = Arc::clone(share);
        let _ = self.users.remove_if(user, |candidate| {
            Arc::ptr_eq(candidate, &share_for_remove)
                && candidate.active_conns.load(Ordering::Relaxed) == 0
        });
    }

    pub(super) fn try_consume_for_user(
        &self,
        direction: RateDirection,
        share: &CidrUserShare,
        requested: u64,
    ) -> u64 {
        let cap_bps = self.rates.get(direction);
        if cap_bps == 0 {
            return requested;
        }
        let cap_epoch = bytes_per_epoch(cap_bps);
        match direction {
            RateDirection::Up => self.up.try_consume(&share.up, cap_epoch, requested),
            RateDirection::Down => self.down.try_consume(&share.down, cap_epoch, requested),
        }
    }

    pub(super) fn refund_for_user(
        &self,
        direction: RateDirection,
        share: &CidrUserShare,
        bytes: u64,
    ) {
        match direction {
            RateDirection::Up => {
                self.up.refund(bytes);
                share.up.refund(bytes);
            }
            RateDirection::Down => {
                self.down.refund(bytes);
                share.down.refund(bytes);
            }
        }
    }

    pub(super) fn cleanup_idle_users(&self) {
        self.users
            .retain(|_, share| share.active_conns.load(Ordering::Relaxed) > 0);
    }
}
