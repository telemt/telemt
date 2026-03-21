use super::*;
use dashmap::DashMap;
use std::sync::Arc;

#[test]
fn saturation_uses_stable_overflow_lock_without_cache_growth() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let prefix = format!("middle-quota-held-{}", std::process::id());
    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("{prefix}-{idx}")));
    }

    assert_eq!(map.len(), QUOTA_USER_LOCKS_MAX);

    let user = format!("middle-quota-overflow-{}", std::process::id());
    let first = quota_user_lock(&user);
    let second = quota_user_lock(&user);

    assert!(
        Arc::ptr_eq(&first, &second),
        "overflow user must get deterministic same lock while cache is saturated"
    );
    assert_eq!(
        map.len(),
        QUOTA_USER_LOCKS_MAX,
        "overflow path must not grow bounded lock map"
    );
    assert!(
        map.get(&user).is_none(),
        "overflow user should stay outside bounded lock map under saturation"
    );

    drop(retained);
}

#[test]
fn overflow_striping_keeps_different_users_distributed() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let prefix = format!("middle-quota-dist-held-{}", std::process::id());
    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("{prefix}-{idx}")));
    }

    let a = quota_user_lock("middle-overflow-user-a");
    let b = quota_user_lock("middle-overflow-user-b");
    let c = quota_user_lock("middle-overflow-user-c");

    let distinct = [
        Arc::as_ptr(&a) as usize,
        Arc::as_ptr(&b) as usize,
        Arc::as_ptr(&c) as usize,
    ]
    .iter()
    .copied()
    .collect::<std::collections::HashSet<_>>()
    .len();

    assert!(
        distinct >= 2,
        "striped overflow lock set should avoid collapsing all users to one lock"
    );

    drop(retained);
}

#[test]
fn reclaim_path_caches_new_user_after_stale_entries_drop() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let prefix = format!("middle-quota-reclaim-held-{}", std::process::id());
    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("{prefix}-{idx}")));
    }

    drop(retained);

    let user = format!("middle-quota-reclaim-user-{}", std::process::id());
    let got = quota_user_lock(&user);
    assert!(map.get(&user).is_some());
    assert!(
        Arc::strong_count(&got) >= 2,
        "after reclaim, lock should be held both by caller and map"
    );
}

#[test]
fn overflow_path_same_user_is_stable_across_parallel_threads() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!(
            "middle-quota-thread-held-{}-{idx}",
            std::process::id()
        )));
    }

    let user = format!("middle-quota-overflow-thread-user-{}", std::process::id());
    let mut workers = Vec::new();
    for _ in 0..32 {
        let user = user.clone();
        workers.push(std::thread::spawn(move || quota_user_lock(&user)));
    }

    let first = workers
        .remove(0)
        .join()
        .expect("thread must return lock handle");
    for worker in workers {
        let got = worker.join().expect("thread must return lock handle");
        assert!(
            Arc::ptr_eq(&first, &got),
            "same overflow user should resolve to one striped lock even under contention"
        );
    }

    drop(retained);
}
