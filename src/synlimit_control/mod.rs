use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use tracing::warn;

use crate::config::{ProxyConfig, SynLimitMode};

mod command;
mod iptables;
mod model;
mod nftables;

use self::command::has_cap_net_admin;
use self::model::{SynLimitNamespace, synlimit_namespace, synlimit_targets};

static ACTIVE_SYNLIMIT_NAMESPACE: Mutex<Option<SynLimitNamespace>> = Mutex::new(None);

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
    let targets = synlimit_targets(cfg);
    let namespace = synlimit_namespace(&targets);
    if let Some(previous_namespace) = set_active_synlimit_namespace(namespace.clone()) {
        match clear_synlimit_rules_for_namespace(&previous_namespace).await {
            Ok(true) => {
                warn!("Removed previous SYN limiter namespace before reconcile");
            }
            Ok(false) => {}
            Err(error) => {
                warn!(error = %error, "Failed to clear previous SYN limiter namespace before reconcile");
            }
        }
    }

    if targets.is_empty() {
        return;
    }
    let Some(namespace) = namespace else {
        return;
    };
    if !has_cap_net_admin() {
        warn!(
            "SYN limiter configured but CAP_NET_ADMIN is not available; netfilter rules not applied"
        );
        return;
    }

    match clear_synlimit_rules_for_namespace(&namespace).await {
        Ok(true) => {
            warn!("Removed stale SYN limiter rules left by a previous run before reconcile");
        }
        Ok(false) => {}
        Err(error) => {
            warn!(error = %error, "Failed to clear stale SYN limiter rules before reconcile");
        }
    }

    if targets.has_iptables_targets()
        && let Err(error) = iptables::apply_synlimit_rules(&targets, &namespace).await
    {
        warn!(error = %error, "Failed to apply iptables SYN limiter rules");
    }
    if targets.has_nft_targets()
        && let Err(error) = nftables::apply_synlimit_rules(&targets, &namespace).await
    {
        warn!(error = %error, "Failed to apply nftables SYN limiter rules");
    }
}

pub(crate) async fn clear_synlimit_rules_all_backends() -> Result<bool, String> {
    let Some(namespace) = take_active_synlimit_namespace() else {
        return Ok(false);
    };
    clear_synlimit_rules_for_namespace(&namespace).await
}

async fn clear_synlimit_rules_for_namespace(namespace: &SynLimitNamespace) -> Result<bool, String> {
    if !has_cap_net_admin() {
        return Ok(false);
    }

    let mut errors = Vec::new();
    let mut removed = false;
    match nftables::clear_rules_all_families(namespace).await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }
    match iptables::clear_rules_for_binary("iptables", namespace).await {
        Ok(value) => {
            removed |= value;
        }
        Err(error) => {
            errors.push(error);
        }
    }
    match iptables::clear_rules_for_binary("ip6tables", namespace).await {
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

fn set_active_synlimit_namespace(next: Option<SynLimitNamespace>) -> Option<SynLimitNamespace> {
    match ACTIVE_SYNLIMIT_NAMESPACE.lock() {
        Ok(mut active) => {
            if *active == next {
                None
            } else {
                std::mem::replace(&mut *active, next)
            }
        }
        Err(error) => {
            warn!(error = %error, "Failed to update active SYN limiter namespace");
            None
        }
    }
}

fn take_active_synlimit_namespace() -> Option<SynLimitNamespace> {
    match ACTIVE_SYNLIMIT_NAMESPACE.lock() {
        Ok(mut active) => active.take(),
        Err(error) => {
            warn!(error = %error, "Failed to read active SYN limiter namespace");
            None
        }
    }
}

fn has_synlimit_config(cfg: &ProxyConfig) -> bool {
    cfg.server
        .listeners
        .iter()
        .any(|listener| !matches!(listener.synlimit, SynLimitMode::Off))
}
