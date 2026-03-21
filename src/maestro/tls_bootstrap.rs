use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use tracing::warn;

use crate::config::ProxyConfig;
use crate::startup::{COMPONENT_TLS_FRONT_BOOTSTRAP, StartupTracker};
use crate::tls_front::TlsFrontCache;
use crate::transport::UpstreamManager;

pub(crate) async fn bootstrap_tls_front(
    config: &ProxyConfig,
    tls_domains: &[String],
    upstream_manager: Arc<UpstreamManager>,
    startup_tracker: &Arc<StartupTracker>,
) -> Option<Arc<TlsFrontCache>> {
    startup_tracker
        .start_component(
            COMPONENT_TLS_FRONT_BOOTSTRAP,
            Some("initialize TLS front cache/bootstrap tasks".to_string()),
        )
        .await;

    let tls_cache: Option<Arc<TlsFrontCache>> = if config.censorship.tls_emulation {
        let cache = Arc::new(TlsFrontCache::new(
            tls_domains,
            config.censorship.fake_cert_len,
            &config.censorship.tls_front_dir,
        ));
        cache.load_from_disk().await;

        let port = config.censorship.mask_port;
        let proxy_protocol = config.censorship.mask_proxy_protocol;
        let mask_host = config
            .censorship
            .mask_host
            .clone()
            .unwrap_or_else(|| config.censorship.tls_domain.clone());
        let mask_unix_sock = config.censorship.mask_unix_sock.clone();
        let tls_fetch_scope = (!config.censorship.tls_fetch_scope.is_empty())
            .then(|| config.censorship.tls_fetch_scope.clone());
        let fetch_timeout = Duration::from_secs(5);

        let cache_initial = cache.clone();
        let domains_initial = tls_domains.to_vec();
        let host_initial = mask_host.clone();
        let unix_sock_initial = mask_unix_sock.clone();
        let scope_initial = tls_fetch_scope.clone();
        let upstream_initial = upstream_manager.clone();
        tokio::spawn(async move {
            let mut join = tokio::task::JoinSet::new();
            for domain in domains_initial {
                let cache_domain = cache_initial.clone();
                let host_domain = host_initial.clone();
                let unix_sock_domain = unix_sock_initial.clone();
                let scope_domain = scope_initial.clone();
                let upstream_domain = upstream_initial.clone();
                join.spawn(async move {
                    match crate::tls_front::fetcher::fetch_real_tls(
                        &host_domain,
                        port,
                        &domain,
                        fetch_timeout,
                        Some(upstream_domain),
                        scope_domain.as_deref(),
                        proxy_protocol,
                        unix_sock_domain.as_deref(),
                    )
                    .await
                    {
                        Ok(res) => cache_domain.update_from_fetch(&domain, res).await,
                        Err(e) => {
                            warn!(domain = %domain, error = %e, "TLS emulation initial fetch failed")
                        }
                    }
                });
            }
            while let Some(res) = join.join_next().await {
                if let Err(e) = res {
                    warn!(error = %e, "TLS emulation initial fetch task join failed");
                }
            }
        });

        let cache_timeout = cache.clone();
        let domains_timeout = tls_domains.to_vec();
        let fake_cert_len = config.censorship.fake_cert_len;
        tokio::spawn(async move {
            tokio::time::sleep(fetch_timeout).await;
            for domain in domains_timeout {
                let cached = cache_timeout.get(&domain).await;
                if cached.domain == "default" {
                    warn!(
                        domain = %domain,
                        timeout_secs = fetch_timeout.as_secs(),
                        fake_cert_len,
                        "TLS-front fetch not ready within timeout; using cache/default fake cert fallback"
                    );
                }
            }
        });

        let cache_refresh = cache.clone();
        let domains_refresh = tls_domains.to_vec();
        let host_refresh = mask_host.clone();
        let unix_sock_refresh = mask_unix_sock.clone();
        let scope_refresh = tls_fetch_scope.clone();
        let upstream_refresh = upstream_manager.clone();
        tokio::spawn(async move {
            loop {
                let base_secs = rand::rng().random_range(4 * 3600..=6 * 3600);
                let jitter_secs = rand::rng().random_range(0..=7200);
                tokio::time::sleep(Duration::from_secs(base_secs + jitter_secs)).await;

                let mut join = tokio::task::JoinSet::new();
                for domain in domains_refresh.clone() {
                    let cache_domain = cache_refresh.clone();
                    let host_domain = host_refresh.clone();
                    let unix_sock_domain = unix_sock_refresh.clone();
                    let scope_domain = scope_refresh.clone();
                    let upstream_domain = upstream_refresh.clone();
                    join.spawn(async move {
                        match crate::tls_front::fetcher::fetch_real_tls(
                            &host_domain,
                            port,
                            &domain,
                            fetch_timeout,
                            Some(upstream_domain),
                            scope_domain.as_deref(),
                            proxy_protocol,
                            unix_sock_domain.as_deref(),
                        )
                        .await
                        {
                            Ok(res) => cache_domain.update_from_fetch(&domain, res).await,
                            Err(e) => {
                                warn!(domain = %domain, error = %e, "TLS emulation refresh failed")
                            }
                        }
                    });
                }

                while let Some(res) = join.join_next().await {
                    if let Err(e) = res {
                        warn!(error = %e, "TLS emulation refresh task join failed");
                    }
                }
            }
        });

        Some(cache)
    } else {
        startup_tracker
            .skip_component(
                COMPONENT_TLS_FRONT_BOOTSTRAP,
                Some("censorship.tls_emulation is false".to_string()),
            )
            .await;
        None
    };

    if tls_cache.is_some() {
        startup_tracker
            .complete_component(
                COMPONENT_TLS_FRONT_BOOTSTRAP,
                Some("tls front cache is initialized".to_string()),
            )
            .await;
    }

    tls_cache
}
