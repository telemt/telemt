use super::*;

impl TrafficLease {
    pub fn try_consume(&self, direction: RateDirection, requested: u64) -> TrafficConsumeResult {
        if requested == 0 {
            return TrafficConsumeResult {
                granted: 0,
                blocked_user: false,
                blocked_cidr: false,
            };
        }

        let mut granted = requested;
        if let Some(user_bucket) = self.user_bucket.as_ref() {
            let user_granted = user_bucket.try_consume(direction, granted);
            if user_granted == 0 {
                self.limiter.observe_throttle(direction, true, false);
                return TrafficConsumeResult {
                    granted: 0,
                    blocked_user: true,
                    blocked_cidr: false,
                };
            }
            granted = user_granted;
        }

        if let (Some(cidr_bucket), Some(cidr_user_share)) =
            (self.cidr_bucket.as_ref(), self.cidr_user_share.as_ref())
        {
            let cidr_granted =
                cidr_bucket.try_consume_for_user(direction, cidr_user_share, granted);
            if cidr_granted < granted
                && let Some(user_bucket) = self.user_bucket.as_ref()
            {
                user_bucket.refund(direction, granted.saturating_sub(cidr_granted));
            }
            if cidr_granted == 0 {
                self.limiter.observe_throttle(direction, false, true);
                return TrafficConsumeResult {
                    granted: 0,
                    blocked_user: false,
                    blocked_cidr: true,
                };
            }
            granted = cidr_granted;
        }

        TrafficConsumeResult {
            granted,
            blocked_user: false,
            blocked_cidr: false,
        }
    }

    pub fn refund(&self, direction: RateDirection, bytes: u64) {
        if bytes == 0 {
            return;
        }

        if let Some(user_bucket) = self.user_bucket.as_ref() {
            user_bucket.refund(direction, bytes);
        }
        if let (Some(cidr_bucket), Some(cidr_user_share)) =
            (self.cidr_bucket.as_ref(), self.cidr_user_share.as_ref())
        {
            cidr_bucket.refund_for_user(direction, cidr_user_share, bytes);
        }
    }

    pub fn observe_wait_ms(
        &self,
        direction: RateDirection,
        blocked_user: bool,
        blocked_cidr: bool,
        wait_ms: u64,
    ) {
        if wait_ms == 0 {
            return;
        }
        self.limiter
            .observe_wait(direction, blocked_user, blocked_cidr, wait_ms);
    }
}

impl Drop for TrafficLease {
    fn drop(&mut self) {
        if let Some(bucket) = self.user_bucket.as_ref() {
            decrement_atomic_saturating(&bucket.active_leases, 1);
            decrement_atomic_saturating(&self.limiter.user_scope.active_leases, 1);
        }

        if let Some(bucket) = self.cidr_bucket.as_ref() {
            if let (Some(user_key), Some(share)) =
                (self.cidr_user_key.as_ref(), self.cidr_user_share.as_ref())
            {
                bucket.release_user_share(user_key, share);
            }
            decrement_atomic_saturating(&bucket.active_leases, 1);
            decrement_atomic_saturating(&self.limiter.cidr_scope.active_leases, 1);
        }
    }
}
