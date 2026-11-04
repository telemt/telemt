use std::sync::atomic::{AtomicUsize, Ordering};

/// Exact lock-free admission budget for bounded concurrent registries.
pub(crate) struct SlotBudget {
    capacity: usize,
    used: AtomicUsize,
}

impl SlotBudget {
    /// Creates an empty budget with the given hard capacity.
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            used: AtomicUsize::new(0),
        }
    }

    /// Reserves one slot or returns `None` when the hard capacity is exhausted.
    pub(crate) fn try_acquire(&self) -> Option<SlotLease<'_>> {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            if current >= self.capacity {
                return None;
            }
            match self.used.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(SlotLease {
                        budget: self,
                        armed: true,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Releases one slot after its registry entry has been removed.
    pub(crate) fn release(&self) {
        self.release_many(1);
    }

    /// Releases a known number of slots after a batch registry removal completes.
    pub(crate) fn release_many(&self, amount: usize) {
        if amount == 0 {
            return;
        }
        let released = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(amount)
            });
        debug_assert!(
            released.is_ok(),
            "slot budget release must match acquisitions"
        );
    }

    /// Returns the exact number of currently committed or reserved slots.
    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

/// Provisional slot ownership that rolls back unless committed to a registry entry.
pub(crate) struct SlotLease<'a> {
    budget: &'a SlotBudget,
    armed: bool,
}

impl SlotLease<'_> {
    /// Transfers the reserved slot to the registry entry being published.
    pub(crate) fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for SlotLease<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.budget.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn parallel_reservations_never_exceed_the_hard_capacity() {
        const CAPACITY: usize = 127;
        const ATTEMPTS: usize = 10_000;

        let budget = Arc::new(SlotBudget::new(CAPACITY));
        let admitted = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for worker in 0..16 {
                let budget = Arc::clone(&budget);
                let admitted = Arc::clone(&admitted);
                scope.spawn(move || {
                    for attempt in (worker..ATTEMPTS).step_by(16) {
                        if let Some(lease) = budget.try_acquire() {
                            admitted.fetch_add(1, Ordering::Relaxed);
                            lease.commit();
                        }
                        std::hint::black_box(attempt);
                    }
                });
            }
        });

        assert_eq!(admitted.load(Ordering::Relaxed), CAPACITY);
        assert_eq!(budget.used(), CAPACITY);
    }

    #[test]
    fn dropped_provisional_lease_returns_its_slot() {
        let budget = SlotBudget::new(1);
        drop(budget.try_acquire().unwrap());

        assert!(budget.try_acquire().is_some());
    }
}
