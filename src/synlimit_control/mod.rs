use std::sync::Arc;

use tokio::sync::watch;
use tracing::warn;

use crate::config::{ProxyConfig, SynLimitMode};

mod command;
mod iptables;
mod model;
mod nftables;

use self::command::has_cap_net_admin;
use self::model::synlimit_targets;

pub(crate) fn spawn_synlimit_controller(config_rx: watch::Receiver<Arc<ProxyConfig>>) {
    if !cfg!(target_os = "linux") {
        if has_synlimit_config(&config_rx.borrow()) {
            warn!("SYN limiter is configured but unsupported on this OS; skipping netfilter rules");
        }
        return;
    }

    tokio::spawn(async move {
        wait_for_config_channel_close_and_reconcile(config_rx).await;
        if let Err(error) = clear_synlimit_rules_all_backends().await {
            warn!(error = %error, "Failed to clear SYN limiter rules after config channel close");
        }
    });
}

async fn wait_for_config_channel_close_and_reconcile(
    mut config_rx: watch::Receiver<Arc<ProxyConfig>>,
) {
    while config_rx.changed().await.is_ok() {
        let cfg = config_rx.borrow_and_update().clone();
        reconcile_synlimit_rules(&cfg).await;
    }
}

pub(crate) async fn reconcile_synlimit_rules(cfg: &ProxyConfig) {
    match clear_synlimit_rules_all_backends().await {
        Ok(true) => {
            warn!("Removed stale SYN limiter rules left by a previous run before reconcile");
        }
        Ok(false) => {}
        Err(error) => {
            warn!(error = %error, "Failed to clear stale SYN limiter rules before reconcile");
        }
    }

    let targets = synlimit_targets(cfg);
    if targets.is_empty() {
        return;
    }
    if !has_cap_net_admin() {
        warn!(
            "SYN limiter configured but CAP_NET_ADMIN is not available; netfilter rules not applied"
        );
        return;
    }

    if targets.has_iptables_targets()
        && let Err(error) = iptables::apply_synlimit_rules(&targets).await
    {
        warn!(error = %error, "Failed to apply iptables SYN limiter rules");
    }
    if targets.has_nft_targets()
        && let Err(error) = nftables::apply_synlimit_rules(&targets).await
    {
        warn!(error = %error, "Failed to apply nftables SYN limiter rules");
    }
}

pub(crate) async fn clear_synlimit_rules_all_backends() -> Result<bool, String> {
    if !has_cap_net_admin() {
        return Ok(false);
    }

    let mut errors = Vec::new();
    let mut removed = false;
    match nftables::clear_rules_all_families().await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }
    match iptables::clear_rules_for_binary("iptables").await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }
    match iptables::clear_rules_for_binary("ip6tables").await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }

    if errors.is_empty() {
        Ok(removed)
    } else {
        Err(errors.join("; "))
    }
}

fn has_synlimit_config(cfg: &ProxyConfig) -> bool {
    cfg.server
        .listeners
        .iter()
        .any(|listener| !matches!(listener.synlimit, SynLimitMode::Off))
}
