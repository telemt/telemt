#![cfg(unix)]

use super::*;
use std::sync::{Mutex, OnceLock};
use tokio::sync::Barrier;

fn interface_cache_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_parallel_cold_miss_performs_single_interface_refresh() {
    let _guard = interface_cache_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    reset_local_interface_enumerations_for_tests();

    let local_addr: SocketAddr = "0.0.0.0:443".parse().expect("valid local addr");
    let workers = 32usize;
    let barrier = std::sync::Arc::new(Barrier::new(workers));
    let mut tasks = Vec::with_capacity(workers);

    for _ in 0..workers {
        let barrier = std::sync::Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            is_mask_target_local_listener_async("127.0.0.1", 443, local_addr, None).await
        }));
    }

    for task in tasks {
        let _ = task.await.expect("parallel cache task must not panic");
    }

    assert_eq!(
        local_interface_enumerations_for_tests(),
        1,
        "parallel cold misses must coalesce into a single interface enumeration"
    );
}
