#![cfg(unix)]

use super::*;
use std::sync::{Mutex, OnceLock};

fn interface_cache_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn tdd_repeated_local_listener_checks_do_not_repeat_interface_enumeration_within_window() {
    let _guard = interface_cache_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    reset_local_interface_enumerations_for_tests();

    let local_addr: SocketAddr = "0.0.0.0:443".parse().expect("valid local addr");

    let _ = is_mask_target_local_listener_async("127.0.0.1", 443, local_addr, None).await;
    let _ = is_mask_target_local_listener_async("127.0.0.1", 443, local_addr, None).await;

    assert_eq!(
        local_interface_enumerations_for_tests(),
        1,
        "interface enumeration must be cached across repeated bad-client checks"
    );
}

#[tokio::test]
async fn tdd_non_local_port_short_circuit_does_not_enumerate_interfaces() {
    let _guard = interface_cache_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    reset_local_interface_enumerations_for_tests();

    let local_addr: SocketAddr = "0.0.0.0:443".parse().expect("valid local addr");
    let is_local = is_mask_target_local_listener_async("127.0.0.1", 8443, local_addr, None).await;

    assert!(
        !is_local,
        "different port must not be treated as local listener"
    );
    assert_eq!(
        local_interface_enumerations_for_tests(),
        0,
        "port mismatch should bypass interface enumeration entirely"
    );
}
