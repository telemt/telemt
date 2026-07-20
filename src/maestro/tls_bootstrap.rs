use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use tracing::warn;

use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::startup::{COMPONENT_TLS_FRONT_BOOTSTRAP, StartupTracker};
use crate::tls_front::TlsFrontCache;
use crate::tls_front::fetcher::TlsFetchStrategy;
use crate::transport::UpstreamManager;

use super::generation::RuntimeTaskScope;

/// Readiness requirement for TLS-front cache initialization.
#[derive(Clone, Copy)]
pub(crate) enum TlsBootstrapPolicy {
    BestEffort,
    RequireReady,
}

#[derive(Clone)]
struct TlsFetchContext {
    cache: Arc<TlsFrontCache>,
    domains: Vec<String>,
    mask_host: String,
    primary_domain: String,
    mask_unix_sock: Option<String>,
    tls_fetch_scope: Option<String>,
    upstream_manager: Arc<UpstreamManager>,
    strategy: TlsFetchStrategy,
    port: u16,
    proxy_protocol: u8,
}

impl TlsFetchContext {
    async fn fetch_all(&self, failure_message: &'static str) {
        let mut join = tokio::task::JoinSet::new();
        for domain in self.domains.clone() {
            let cache = self.cache.clone();
            let host = tls_fetch_host_for_domain(&self.mask_host, &self.primary_domain, &domain);
            let unix_sock = self.mask_unix_sock.clone();
            let scope = self.tls_fetch_scope.clone();
            let upstream = self.upstream_manager.clone();
            let strategy = self.strategy.clone();
            let port = self.port;
            let proxy_protocol = self.proxy_protocol;
            join.spawn(async move {
                match crate::tls_front::fetcher::fetch_real_tls_with_strategy(
                    &host,
                    port,
                    &domain,
                    &strategy,
                    Some(upstream),
                    scope.as_deref(),
                    proxy_protocol,
                    unix_sock.as_deref(),
                )
                .await
                {
                    Ok(result) => cache.update_from_fetch(&domain, result).await,
                    Err(error) => warn!(domain = %domain, error = %error, failure_message),
                }
            });
        }
        while let Some(result) = join.join_next().await {
            if let Err(error) = result {
                warn!(error = %error, "TLS emulation fetch task join failed");
            }
        }
    }

    async fn fetch_all_with_budget(&self, phase: &'static str) {
        if tokio::time::timeout(self.strategy.total_budget, self.fetch_all(phase))
            .await
            .is_err()
        {
            warn!(
                phase,
                timeout_ms = self.strategy.total_budget.as_millis(),
                "TLS emulation fetch budget exhausted"
            );
        }
    }
}

fn tls_fetch_host_for_domain(mask_host: &str, primary_tls_domain: &str, domain: &str) -> String {
    if mask_host.eq_ignore_ascii_case(primary_tls_domain) {
        domain.to_string()
    } else {
        mask_host.to_string()
    }
}

fn readiness_error(default_domains: &[String]) -> Option<String> {
    (!default_domains.is_empty()).then(|| {
        format!(
            "TLS-front profiles are not ready for domains: {}",
            default_domains.join(", ")
        )
    })
}

/// Initializes the TLS-front cache and generation-owned refresh tasks.
pub(crate) async fn bootstrap_tls_front(
    config: &ProxyConfig,
    tls_domains: &[String],
    upstream_manager: Arc<UpstreamManager>,
    startup_tracker: &Arc<StartupTracker>,
    task_scope: RuntimeTaskScope,
    policy: TlsBootstrapPolicy,
) -> Result<Option<Arc<TlsFrontCache>>> {
    startup_tracker
        .start_component(
            COMPONENT_TLS_FRONT_BOOTSTRAP,
            Some("initialize TLS front cache/bootstrap tasks".to_string()),
        )
        .await;

    if !config.censorship.tls_emulation {
        startup_tracker
            .skip_component(
                COMPONENT_TLS_FRONT_BOOTSTRAP,
                Some("censorship.tls_emulation is false".to_string()),
            )
            .await;
        return Ok(None);
    }

    let cache = Arc::new(TlsFrontCache::new(
        tls_domains,
        config.censorship.fake_cert_len,
        &config.censorship.tls_front_dir,
    ));
    cache.load_from_disk().await;

    let tls_fetch = config.censorship.tls_fetch.clone();
    let fetch_context = TlsFetchContext {
        cache: cache.clone(),
        domains: tls_domains.to_vec(),
        mask_host: config
            .censorship
            .mask_host
            .clone()
            .unwrap_or_else(|| config.censorship.tls_domain.clone()),
        primary_domain: config.censorship.tls_domain.clone(),
        mask_unix_sock: config.censorship.mask_unix_sock.clone(),
        tls_fetch_scope: (!config.censorship.tls_fetch_scope.is_empty())
            .then(|| config.censorship.tls_fetch_scope.clone()),
        upstream_manager,
        strategy: TlsFetchStrategy {
            profiles: tls_fetch.profiles,
            strict_route: tls_fetch.strict_route,
            attempt_timeout: Duration::from_millis(tls_fetch.attempt_timeout_ms.max(1)),
            total_budget: Duration::from_millis(tls_fetch.total_budget_ms.max(1)),
            grease_enabled: tls_fetch.grease_enabled,
            deterministic: tls_fetch.deterministic,
            profile_cache_ttl: Duration::from_secs(tls_fetch.profile_cache_ttl_secs),
        },
        port: config.censorship.mask_port,
        proxy_protocol: config.censorship.mask_proxy_protocol,
    };

    match policy {
        TlsBootstrapPolicy::BestEffort => {
            let initial_fetch = fetch_context.clone();
            let fake_cert_len = config.censorship.fake_cert_len;
            task_scope.spawn(async move {
                initial_fetch
                    .fetch_all_with_budget("TLS emulation initial fetch failed")
                    .await;
                for domain in initial_fetch
                    .cache
                    .default_profile_domains(&initial_fetch.domains)
                    .await
                {
                    warn!(
                        domain = %domain,
                        timeout_ms = initial_fetch.strategy.total_budget.as_millis(),
                        fake_cert_len,
                        "TLS-front fetch not ready within timeout; using cache/default fake cert fallback"
                    );
                }
            });
        }
        TlsBootstrapPolicy::RequireReady => {
            fetch_context
                .fetch_all_with_budget("TLS emulation initial fetch failed")
                .await;
            let default_domains = cache.default_profile_domains(tls_domains).await;
            if let Some(error) = readiness_error(&default_domains) {
                startup_tracker
                    .fail_component(COMPONENT_TLS_FRONT_BOOTSTRAP, Some(error.clone()))
                    .await;
                return Err(ProxyError::Proxy(error));
            }
        }
    }

    let refresh_context = fetch_context;
    task_scope.spawn(async move {
        loop {
            let base_secs = rand::rng().random_range(4 * 3600..=6 * 3600);
            let jitter_secs = rand::rng().random_range(0..=7200);
            tokio::time::sleep(Duration::from_secs(base_secs + jitter_secs)).await;
            refresh_context
                .fetch_all_with_budget("TLS emulation refresh failed")
                .await;
        }
    });

    startup_tracker
        .complete_component(
            COMPONENT_TLS_FRONT_BOOTSTRAP,
            Some("tls front cache is initialized".to_string()),
        )
        .await;
    Ok(Some(cache))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::StartupComponentStatus;
    use crate::stats::Stats;

    fn test_config(cache_dir: &std::path::Path) -> ProxyConfig {
        let mut config = ProxyConfig::default();
        config.censorship.tls_emulation = true;
        config.censorship.tls_domain = "front.example".to_string();
        config.censorship.mask_host = Some("127.0.0.1".to_string());
        config.censorship.mask_port = 1;
        config.censorship.tls_front_dir = cache_dir.display().to_string();
        config.censorship.tls_fetch.profiles.truncate(1);
        config.censorship.tls_fetch.attempt_timeout_ms = 10;
        config.censorship.tls_fetch.total_budget_ms = 20;
        config
    }

    fn upstream_manager(config: &ProxyConfig) -> Arc<UpstreamManager> {
        Arc::new(UpstreamManager::new(
            Vec::new(),
            config.general.upstream_connect_retry_attempts,
            config.general.upstream_connect_retry_backoff_ms,
            config.general.upstream_connect_budget_ms,
            config.general.tg_connect,
            config.general.upstream_unhealthy_fail_threshold,
            config.general.upstream_connect_failfast_hard_errors,
            Arc::new(Stats::new()),
        ))
    }

    async fn tls_component_status(tracker: &StartupTracker) -> StartupComponentStatus {
        tracker
            .snapshot()
            .await
            .components
            .into_iter()
            .find(|component| component.id == COMPONENT_TLS_FRONT_BOOTSTRAP)
            .unwrap()
            .status
    }

    #[test]
    fn tls_fetch_host_uses_each_domain_when_mask_host_is_primary_default() {
        assert_eq!(
            tls_fetch_host_for_domain("a.com", "a.com", "b.com"),
            "b.com"
        );
    }

    #[test]
    fn tls_fetch_host_preserves_explicit_non_primary_mask_host() {
        assert_eq!(
            tls_fetch_host_for_domain("origin.example", "a.com", "b.com"),
            "origin.example"
        );
    }

    #[test]
    fn readiness_rejects_only_default_profiles() {
        assert!(readiness_error(&[]).is_none());
        assert_eq!(
            readiness_error(&["front.example".to_string()]),
            Some("TLS-front profiles are not ready for domains: front.example".to_string())
        );
    }

    #[tokio::test]
    async fn require_ready_rejects_default_cache_after_bounded_fetch_failure() {
        let cache_dir = tempfile::tempdir().unwrap();
        let config = test_config(cache_dir.path());
        let domains = vec![config.censorship.tls_domain.clone()];
        let tracker = Arc::new(StartupTracker::new(1));
        let scope = RuntimeTaskScope::new();

        let result = bootstrap_tls_front(
            &config,
            &domains,
            upstream_manager(&config),
            &tracker,
            scope.clone(),
            TlsBootstrapPolicy::RequireReady,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            tls_component_status(&tracker).await,
            StartupComponentStatus::Failed
        );
        scope.stop().await;
    }

    #[tokio::test]
    async fn require_ready_accepts_non_default_disk_cache_when_refresh_fails() {
        let cache_dir = tempfile::tempdir().unwrap();
        let config = test_config(cache_dir.path());
        let domains = vec![config.censorship.tls_domain.clone()];
        let seed = TlsFrontCache::new(&domains, config.censorship.fake_cert_len, cache_dir.path());
        let mut cached = seed.default_entry().as_ref().clone();
        cached.domain = domains[0].clone();
        tokio::fs::write(
            cache_dir.path().join("front.example.json"),
            serde_json::to_vec(&cached).unwrap(),
        )
        .await
        .unwrap();
        let tracker = Arc::new(StartupTracker::new(1));
        let scope = RuntimeTaskScope::new();

        let cache = bootstrap_tls_front(
            &config,
            &domains,
            upstream_manager(&config),
            &tracker,
            scope.clone(),
            TlsBootstrapPolicy::RequireReady,
        )
        .await
        .unwrap()
        .unwrap();

        assert!(cache.default_profile_domains(&domains).await.is_empty());
        assert_eq!(
            tls_component_status(&tracker).await,
            StartupComponentStatus::Ready
        );
        scope.stop().await;
    }

    #[tokio::test]
    async fn best_effort_returns_ready_and_refresh_tasks_are_scope_owned() {
        let cache_dir = tempfile::tempdir().unwrap();
        let config = test_config(cache_dir.path());
        let domains = vec![config.censorship.tls_domain.clone()];
        let tracker = Arc::new(StartupTracker::new(1));
        let scope = RuntimeTaskScope::new();

        let cache = bootstrap_tls_front(
            &config,
            &domains,
            upstream_manager(&config),
            &tracker,
            scope.clone(),
            TlsBootstrapPolicy::BestEffort,
        )
        .await
        .unwrap();

        assert!(cache.is_some());
        assert_eq!(
            tls_component_status(&tracker).await,
            StartupComponentStatus::Ready
        );
        tokio::time::timeout(Duration::from_secs(1), scope.stop())
            .await
            .unwrap();
    }
}
