use super::*;

#[test]
fn lease_drop_releases_the_complete_reservation() {
    let budget = DirectBufferBudget::new(16 * 1024);
    {
        let lease = budget
            .try_reserve(12 * 1024, false)
            .expect("minimum reservation must fit");
        assert_eq!(lease.reserved_bytes(), 12 * 1024);
        assert_eq!(budget.snapshot().reserved_bytes, 12 * 1024);
    }
    assert_eq!(budget.snapshot().reserved_bytes, 0);
}

#[test]
fn absolute_ceiling_rejects_excess_minimum_reservations() {
    let budget = DirectBufferBudget::new(16 * 1024);
    let _lease = budget
        .try_reserve(12 * 1024, true)
        .expect("first minimum reservation must fit");
    assert!(budget.try_reserve(8 * 1024, true).is_none());
    assert_eq!(budget.snapshot().reserved_bytes, 12 * 1024);
}

#[test]
fn growth_and_shrink_keep_accounting_balanced() {
    let budget = DirectBufferBudget::new(32 * 1024);
    let mut lease = budget
        .try_reserve(12 * 1024, false)
        .expect("base reservation must fit");
    assert!(lease.try_grow_to(24 * 1024));
    assert_eq!(budget.snapshot().reserved_bytes, 24 * 1024);
    lease.shrink_to(16 * 1024);
    assert_eq!(budget.snapshot().reserved_bytes, 16 * 1024);
    drop(lease);
    assert_eq!(budget.snapshot().reserved_bytes, 0);
}
