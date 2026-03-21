#![allow(clippy::too_many_arguments)]

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;
use tracing::info;

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::network::probe::NetworkDecision;
use crate::startup::{
    COMPONENT_DC_CONNECTIVITY_PING, COMPONENT_ME_CONNECTIVITY_PING, COMPONENT_RUNTIME_READY,
    StartupTracker,
};
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::{
    MePingFamily, MePingSample, MePool, format_me_route, format_sample_line, run_me_ping,
};

pub(crate) async fn run_startup_connectivity(
    config: &Arc<ProxyConfig>,
    me_pool: &Option<Arc<MePool>>,
    rng: Arc<SecureRandom>,
    startup_tracker: &Arc<StartupTracker>,
    upstream_manager: Arc<UpstreamManager>,
    prefer_ipv6: bool,
    decision: &NetworkDecision,
    process_started_at: Instant,
    api_me_pool: Arc<RwLock<Option<Arc<MePool>>>>,
) {
    if me_pool.is_some() {
        startup_tracker
            .start_component(
                COMPONENT_ME_CONNECTIVITY_PING,
                Some("run startup ME connectivity check".to_string()),
            )
            .await;
    } else {
        startup_tracker
            .skip_component(
                COMPONENT_ME_CONNECTIVITY_PING,
                Some("ME pool is not available".to_string()),
            )
            .await;
    }
    if let Some(pool) = me_pool {
        let me_results = run_me_ping(pool, &rng).await;

        let v4_ok = me_results.iter().any(|r| {
            matches!(r.family, MePingFamily::V4)
                && r.samples
                    .iter()
                    .any(|s| s.error.is_none() && s.handshake_ms.is_some())
        });
        let v6_ok = me_results.iter().any(|r| {
            matches!(r.family, MePingFamily::V6)
                && r.samples
                    .iter()
                    .any(|s| s.error.is_none() && s.handshake_ms.is_some())
        });

        info!("================= Telegram ME Connectivity =================");
        if v4_ok && v6_ok {
            info!("  IPv4 and IPv6 available");
        } else if v4_ok {
            info!("  IPv4 only / IPv6 unavailable");
        } else if v6_ok {
            info!("  IPv6 only / IPv4 unavailable");
        } else {
            info!("  No ME connectivity");
        }
        let me_route =
            format_me_route(&config.upstreams, &me_results, prefer_ipv6, v4_ok, v6_ok).await;
        info!("  via {}", me_route);
        info!("============================================================");

        use std::collections::BTreeMap;
        let mut grouped: BTreeMap<i32, Vec<MePingSample>> = BTreeMap::new();
        for report in me_results {
            for s in report.samples {
                grouped.entry(s.dc).or_default().push(s);
            }
        }

        let family_order = if prefer_ipv6 {
            vec![MePingFamily::V6, MePingFamily::V4]
        } else {
            vec![MePingFamily::V4, MePingFamily::V6]
        };

        for (dc, samples) in grouped {
            for family in &family_order {
                let fam_samples: Vec<&MePingSample> = samples
                    .iter()
                    .filter(|s| matches!(s.family, f if &f == family))
                    .collect();
                if fam_samples.is_empty() {
                    continue;
                }

                let fam_label = match family {
                    MePingFamily::V4 => "IPv4",
                    MePingFamily::V6 => "IPv6",
                };
                info!("    DC{} [{}]", dc, fam_label);
                for sample in fam_samples {
                    let line = format_sample_line(sample);
                    info!("{}", line);
                }
            }
        }
        info!("============================================================");
        startup_tracker
            .complete_component(
                COMPONENT_ME_CONNECTIVITY_PING,
                Some("startup ME connectivity check completed".to_string()),
            )
            .await;
    }

    info!("================= Telegram DC Connectivity =================");
    startup_tracker
        .start_component(
            COMPONENT_DC_CONNECTIVITY_PING,
            Some("run startup DC connectivity check".to_string()),
        )
        .await;

    let ping_results = upstream_manager
        .ping_all_dcs(
            prefer_ipv6,
            &config.dc_overrides,
            decision.ipv4_dc,
            decision.ipv6_dc,
        )
        .await;

    for upstream_result in &ping_results {
        let v6_works = upstream_result
            .v6_results
            .iter()
            .any(|r| r.rtt_ms.is_some());
        let v4_works = upstream_result
            .v4_results
            .iter()
            .any(|r| r.rtt_ms.is_some());

        if upstream_result.both_available {
            if prefer_ipv6 {
                info!("  IPv6 in use / IPv4 is fallback");
            } else {
                info!("  IPv4 in use / IPv6 is fallback");
            }
        } else if v6_works && !v4_works {
            info!("  IPv6 only / IPv4 unavailable");
        } else if v4_works && !v6_works {
            info!("  IPv4 only / IPv6 unavailable");
        } else if !v6_works && !v4_works {
            info!("  No DC connectivity");
        }

        info!("  via {}", upstream_result.upstream_name);
        info!("============================================================");

        if v6_works {
            for dc in &upstream_result.v6_results {
                let addr_str = format!("{}:{}", dc.dc_addr.ip(), dc.dc_addr.port());
                match &dc.rtt_ms {
                    Some(rtt) => {
                        info!("    DC{} [IPv6] {} - {:.0} ms", dc.dc_idx, addr_str, rtt);
                    }
                    None => {
                        let err = dc.error.as_deref().unwrap_or("fail");
                        info!("    DC{} [IPv6] {} - FAIL ({})", dc.dc_idx, addr_str, err);
                    }
                }
            }

            info!("============================================================");
        }

        if v4_works {
            for dc in &upstream_result.v4_results {
                let addr_str = format!("{}:{}", dc.dc_addr.ip(), dc.dc_addr.port());
                match &dc.rtt_ms {
                    Some(rtt) => {
                        info!(
                            "    DC{} [IPv4] {}\t\t\t\t{:.0} ms",
                            dc.dc_idx, addr_str, rtt
                        );
                    }
                    None => {
                        let err = dc.error.as_deref().unwrap_or("fail");
                        info!(
                            "    DC{} [IPv4] {}:\t\t\t\tFAIL ({})",
                            dc.dc_idx, addr_str, err
                        );
                    }
                }
            }

            info!("============================================================");
        }
    }
    startup_tracker
        .complete_component(
            COMPONENT_DC_CONNECTIVITY_PING,
            Some("startup DC connectivity check completed".to_string()),
        )
        .await;

    let initialized_secs = process_started_at.elapsed().as_secs();
    let second_suffix = if initialized_secs == 1 { "" } else { "s" };
    startup_tracker
        .start_component(
            COMPONENT_RUNTIME_READY,
            Some("finalize startup runtime state".to_string()),
        )
        .await;
    info!("===================== Telegram Startup =====================");
    info!(
        "  DC/ME Initialized in {} second{}",
        initialized_secs, second_suffix
    );
    info!("============================================================");

    if let Some(pool) = me_pool {
        pool.set_runtime_ready(true);
    }
    *api_me_pool.write().await = me_pool.clone();
}
