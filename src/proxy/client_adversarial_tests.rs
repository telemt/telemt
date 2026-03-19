use super::*;
use crate::config::ProxyConfig;
use crate::stats::Stats;
use crate::ip_tracker::UserIpTracker;
use crate::error::ProxyError;
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// ------------------------------------------------------------------
// Priority 3: Massive Concurrency Stress (OWASP ASVS 5.1.6)
// ------------------------------------------------------------------

#[tokio::test]
async fn client_stress_10k_connections_limit_strict() {
    let user = "stress-user";
    let limit = 512;
    
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    
    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), limit);
    
    let iterations = 1000;
    let mut tasks = Vec::new();

    for i in 0..iterations {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();
        let user_str = user.to_string();
        
        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, (i % 254 + 1) as u8)),
                10000 + (i % 1000) as u16,
            );
            
            match RunningClientHandler::acquire_user_connection_reservation_static(
                &user_str,
                &config,
                stats,
                peer,
                ip_tracker,
            ).await {
                Ok(res) => Ok(res),
                Err(ProxyError::ConnectionLimitExceeded { .. }) => Err(()),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }));
    }

    let results = futures::future::join_all(tasks).await;
    let mut successes = 0;
    let mut failures = 0;
    let mut reservations = Vec::new();

    for res in results {
        match res.unwrap() {
            Ok(r) => {
                successes += 1;
                reservations.push(r);
            }
            Err(_) => failures += 1,
        }
    }

    assert_eq!(successes, limit, "Should allow exactly 'limit' connections");
    assert_eq!(failures, iterations - limit, "Should fail the rest with LimitExceeded");
    assert_eq!(stats.get_user_curr_connects(user), limit as u64);

    drop(reservations);
    
    ip_tracker.drain_cleanup_queue().await;
    
    assert_eq!(stats.get_user_curr_connects(user), 0, "Stats must converge to 0 after all drops");
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0, "IP tracker must converge to 0");
}

// ------------------------------------------------------------------
// Priority 3: IP Tracker Race Stress
// ------------------------------------------------------------------

#[tokio::test]
async fn client_ip_tracker_race_condition_stress() {
    let user = "race-user";
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 100).await;
    
    let iterations = 1000;
    let mut tasks = Vec::new();

    for i in 0..iterations {
        let ip_tracker = Arc::clone(&ip_tracker);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i % 254 + 1) as u8));
        
        tasks.push(tokio::spawn(async move {
            for _ in 0..10 {
                if let Ok(()) = ip_tracker.check_and_add("race-user", ip).await {
                    ip_tracker.remove_ip("race-user", ip).await;
                }
            }
        }));
    }

    futures::future::join_all(tasks).await;
    
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0, "IP count must be zero after balanced add/remove burst");
}
